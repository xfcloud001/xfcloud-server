#!/usr/bin/env bash
# xfcloud-tunnel-server 后台服务管理脚本（Linux，随集群部署分发到从节点）
# 用法: ./service.sh {start|stop|restart|status|logs}
#       start   后台启动（自动清理本目录遗留的旧进程，避免端口被占）
#       stop    停止
#       restart 重启
#       status  查看运行状态
#       logs    查看日志（./service.sh logs 500 指定行数，Ctrl+C 退出跟随）
# 说明: systemd 部署（xfcloud-slave.service）场景下优先用 systemctl 管理；
#       本脚本用于手动排查/紧急接管（在线更新后的脱离进程可被 start 接管）。
set -u
cd -- "$(dirname -- "$0")" || exit 1

APP_NAME="xfcloud-tunnel-server"
ENTRY_KEY="server/app.js"
PID_FILE="data/service.pid"
LOG_DIR="logs"
LOG_FILE="$LOG_DIR/service.log"
PORT="${MANAGER_PORT:-8080}"

# 启动前加载同目录 .env（KEY=VALUE 格式），后台进程会继承这些环境变量。
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

mkdir -p "$LOG_DIR" data

# 解析 Node 可执行文件：优先 NODE_BIN 环境变量，其次 PATH 中的 node。
# 使用绝对路径可避免后台/重启环境下 PATH 不同而用到旧版 Node（本项目要求 22.5+）。
if [ -n "${NODE_BIN:-}" ] && [ -x "$NODE_BIN" ]; then
  :
else
  NODE_BIN="$(command -v node 2>/dev/null || true)"
fi
if [ -z "$NODE_BIN" ]; then
  echo "错误: 未找到 node，请先安装 Node.js 22.5+，或通过 NODE_BIN 环境变量指定其绝对路径。"
  exit 1
fi
if ! "$NODE_BIN" -e 'const v=process.versions.node.split(".").map(Number); process.exit(v[0]>22||(v[0]===22&&v[1]>=5)?0:1)' 2>/dev/null; then
  echo "错误: 当前 Node 版本过低（$("$NODE_BIN" -v)）。本项目要求 Node.js 22.5 或更高版本（依赖内置 node:sqlite）。"
  echo "       请升级 Node，或在 .env 中设置 NODE_BIN 指向高版本 node 的绝对路径。"
  exit 1
fi

pid_alive() {
  # PID 文件存在且进程存活，且确实是本应用进程（防止 PID 被复用后误判/误杀）。
  [ -f "$PID_FILE" ] || return 1
  PID="$(cat "$PID_FILE" 2>/dev/null)"
  [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null && pid_matches "$PID"
}

legacy_pids() {
  pgrep -f "$ENTRY_KEY" 2>/dev/null || true
}

pid_matches() {
  tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null | grep -qF "$ENTRY_KEY"
}

port_free() {
  # 通过主动连接判断端口是否被监听，比再次 bind 更可靠。
  "$NODE_BIN" -e "
const net = require('node:net');
const s = net.connect($PORT, '127.0.0.1');
s.once('connect', () => { s.destroy(); process.exit(1); });
s.once('error', () => process.exit(0));
setTimeout(() => process.exit(0), 1000);
" >/dev/null 2>&1
}

wait_port_free() {
  i=0
  while [ $i -lt 20 ]; do
    if port_free; then return 0; fi
    sleep 0.3
    i=$((i + 1))
  done
  return 1
}

health_ok() {
  "$NODE_BIN" -e "
fetch('http://127.0.0.1:' + $PORT + '/healthz', { signal: AbortSignal.timeout(2000) })
  .then((r) => process.exit(r.ok ? 0 : 1))
  .catch(() => process.exit(1));
" >/dev/null 2>&1
}

stop_all() {
  stopped=0
  if pid_alive; then
    PID="$(cat "$PID_FILE")"
    if pid_matches "$PID"; then
      echo "停止运行中的进程 (pid $PID) ..."
      kill "$PID" 2>/dev/null || true
      stopped=1
    fi
  fi
  for PID in $(legacy_pids); do
    [ "$PID" = "$$" ] && continue
    echo "停止遗留进程 (pid $PID) ..."
    kill "$PID" 2>/dev/null || true
    stopped=1
  done
  if [ "$stopped" -eq 0 ]; then
    rm -f "$PID_FILE"
    return 1
  fi
  i=0
  while [ $i -lt 20 ]; do
    sleep 0.25
    if [ -z "$(legacy_pids)" ] && ! pid_alive; then break; fi
    i=$((i + 1))
  done
  for PID in $(legacy_pids); do
    kill -9 "$PID" 2>/dev/null
  done
  if pid_alive; then
    kill -9 "$(cat "$PID_FILE")" 2>/dev/null
  fi
  rm -f "$PID_FILE"
  return 0
}

cmd_start() {
  if pid_alive; then
    echo "已在运行 (pid $(cat "$PID_FILE"))，如需重启请执行 ./service.sh restart"
    exit 0
  fi
  # systemd 管理中的服务由 systemctl 负责，提示而不是抢启。
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xfcloud-slave.service 2>/dev/null; then
    echo "服务由 systemd 管理（xfcloud-slave.service）且运行中。"
    echo "手动管理请先: systemctl stop xfcloud-slave.service"
    exit 0
  fi
  # 在线更新会产生一个脱离 PID 文件的新进程，接管它而不是杀掉重启。
  for PID in $(legacy_pids); do
    [ "$PID" = "$$" ] && continue
    if pid_matches "$PID" && health_ok; then
      echo "$PID" > "$PID_FILE"
      echo "已接管在线更新后重启的进程 (pid $PID, 端口 $PORT)"
      exit 0
    fi
  done
  stop_all >/dev/null 2>&1 || true
  if ! wait_port_free; then
    echo "错误: 端口 $PORT 仍被占用，可能被 nginx/caddy 等其他程序使用。"
    echo "执行 ss -ltnp | grep :$PORT 查看占用进程，先停用对方或改用其他端口。"
    exit 1
  fi
  nohup "$NODE_BIN" --experimental-sqlite "$ENTRY_KEY" >>"$LOG_FILE" 2>&1 &
  PID=$!
  echo "$PID" > "$PID_FILE"
  sleep 1
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "启动失败，最近日志如下（完整日志: $LOG_FILE）:"
    tail -n 30 "$LOG_FILE" 2>/dev/null || true
    rm -f "$PID_FILE"
    exit 1
  fi
  echo "已在后台启动 $APP_NAME (pid $PID, 端口 $PORT)"
  echo "查看日志: ./service.sh logs    停止: ./service.sh stop    状态: ./service.sh status"
}

cmd_stop() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xfcloud-slave.service 2>/dev/null; then
    echo "服务由 systemd 管理（xfcloud-slave.service），请使用: systemctl stop xfcloud-slave.service"
    exit 0
  fi
  if stop_all; then
    echo "已停止 $APP_NAME"
  else
    echo "未在运行"
  fi
}

cmd_restart() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-enabled --quiet xfcloud-slave.service 2>/dev/null; then
    systemctl restart xfcloud-slave.service
    echo "已通过 systemd 重启 xfcloud-slave.service"
    exit 0
  fi
  stop_all >/dev/null 2>&1 || true
  sleep 0.5
  cmd_start
}

cmd_status() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet xfcloud-slave.service 2>/dev/null; then
    echo "运行中: systemd xfcloud-slave.service (健康检查$(health_ok && echo 正常 || echo 无响应))"
    exit 0
  fi
  if pid_alive; then
    PID="$(cat "$PID_FILE")"
    if health_ok; then
      echo "运行中: $APP_NAME (pid $PID, 端口 $PORT, 健康检查正常)"
    else
      echo "运行中: $APP_NAME (pid $PID, 端口 $PORT, 健康检查无响应——若启用 HTTPS 或正在启动属正常，可执行 ./service.sh logs 查看)"
    fi
    exit 0
  fi
  PIDS="$(legacy_pids)"
  if [ -n "$PIDS" ]; then
    echo "检测到未纳管的进程: $PIDS"
    echo "（通常是手动 ./start.sh 或在线更新自动重启的进程，执行 ./service.sh stop 可清理）"
    exit 1
  fi
  echo "未运行"
  exit 1
}

cmd_logs() {
  if [ ! -f "$LOG_FILE" ]; then
    echo "暂无日志: $LOG_FILE（systemd 部署请用 journalctl -u xfcloud-slave.service -f）"
    exit 0
  fi
  tail -n "${1:-200}" -f "$LOG_FILE"
}

case "${1:-}" in
  start) cmd_start ;;
  stop) cmd_stop ;;
  restart) cmd_restart ;;
  status) cmd_status ;;
  logs) shift 2>/dev/null || true; cmd_logs "${1:-}" ;;
  *)
    echo "用法: ./service.sh {start|stop|restart|status|logs}"
    exit 1
    ;;
esac
