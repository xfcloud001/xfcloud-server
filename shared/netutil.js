// 0.9.2：网络端口工具。零第三方依赖，仅使用 Node 内置模块。
// - probeTcpPort：真实 listen 探测端口是否可绑定（TLS 缓存，避免分配时反复探测）。
// - listTcpListeners / findListenersByPort：跨平台解析 LISTENING 端口归属进程。
import { createServer } from "node:net";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const PROBE_TTL_MS = 3_000;
const probeCache = new Map();

function run(command, args, timeoutMs = 4_000) {
  return execFileAsync(command, args, {
    timeout: timeoutMs,
    windowsHide: true,
    maxBuffer: 8 * 1024 * 1024,
  })
    .then((result) => String(result.stdout || ""))
    .catch(() => "");
}

// 真实尝试绑定 0.0.0.0:port；frps/frpc 同样绑定 0.0.0.0，判定结果一致。
export function probeTcpPort(port, { useCache = true, host = "0.0.0.0" } = {}) {
  const p = Number(port);
  if (!Number.isInteger(p) || p < 1 || p > 65535) {
    return Promise.resolve({ port: p, free: false, reason: "端口号非法" });
  }
  const cacheKey = `${host}:${p}`;
  if (useCache) {
    const cached = probeCache.get(cacheKey);
    if (cached && Date.now() - cached.at < PROBE_TTL_MS) {
      return Promise.resolve(cached.result);
    }
  }
  return new Promise((resolve) => {
    const server = createServer();
    server.on("error", (error) => {
      const result =
        error.code === "EADDRINUSE"
          ? { port: p, free: false, reason: "端口已被占用" }
          : { port: p, free: false, reason: error.message };
      probeCache.set(cacheKey, { at: Date.now(), result });
      resolve(result);
    });
    server.listen(p, host, () => {
      server.close(() => {
        const result = { port: p, free: true };
        probeCache.set(cacheKey, { at: Date.now(), result });
        resolve(result);
      });
    });
  });
}

// 批量探测；返回全部占用项 [{ port, reason }]。
export async function probeTcpPorts(ports, { useCache = true } = {}) {
  const unique = [...new Set(ports.map(Number).filter((p) => Number.isInteger(p)))];
  const results = await Promise.all(unique.map((port) => probeTcpPort(port, { useCache })));
  return results.filter((result) => !result.free);
}

export function clearProbeCache() {
  probeCache.clear();
}

// ---- LISTENING 端口归属解析（防火墙"谁在用"与端口预检提示共用）----

async function listTcpListenersWindows() {
  const out = await run("netstat", ["-ano", "-p", "tcp"]);
  const listeners = [];
  for (const line of out.split(/\r?\n/)) {
    const match = line.trim().match(/^TCP\s+(\S+):(\d+)\s+\S+:\d+\s+LISTENING\s+(\d+)/i);
    if (!match) continue;
    listeners.push({ address: match[1], port: Number(match[2]), pid: Number(match[3]) });
  }
  return listeners;
}

async function listTcpListenersLinux() {
  // 优先 ss（现代发行版自带），退回 netstat，再退回 lsof。
  const ss = await run("ss", ["-ltnp"]);
  const listeners = [];
  if (ss) {
    for (const line of ss.split(/\r?\n/)) {
      const match = line.match(/LISTEN\S*\s+\d+\s+\d+\s+(\S+?):(\d+)\s+\S+\s*(.*)$/);
      if (!match) continue;
      const pidMatch = match[3].match(/pid=(\d+)/);
      const nameMatch = match[3].match(/\(\("([^"]+)"/);
      listeners.push({
        address: match[1],
        port: Number(match[2]),
        pid: pidMatch ? Number(pidMatch[1]) : null,
        processName: nameMatch ? nameMatch[1] : null,
      });
    }
    if (listeners.length) return listeners;
  }
  const netstat = await run("netstat", ["-ltnp"]);
  if (netstat) {
    for (const line of netstat.split(/\r?\n/)) {
      const match = line.match(/tcp\s+\d+\s+\d+\s+(\S+?):(\d+)\s+\S+\s+LISTEN\s+(\S+)?/);
      if (!match) continue;
      const program = match[3] ? match[3].match(/^(\d+)\/(.+)$/) : null;
      listeners.push({
        address: match[1],
        port: Number(match[2]),
        pid: program ? Number(program[1]) : null,
        processName: program ? program[2] : null,
      });
    }
    if (listeners.length) return listeners;
  }
  return listTcpListenersLsof();
}

async function listTcpListenersLsof() {
  const out = await run("lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"]);
  const listeners = [];
  for (const line of out.split(/\r?\n/)) {
    const match = line.match(/^(\S+)\s+(\d+)\s+\S+\s+\S+\s+(?:IPv4|IPv6)\s+\S+\s+\S+\s+TCP\s+(\S+?):(\d+)/);
    if (!match) continue;
    listeners.push({
      address: match[3].includes(":") ? match[3].split(":").slice(0, -1).join(":") : match[3],
      port: Number(match[4]),
      pid: Number(match[2]),
      processName: match[1],
    });
  }
  return listeners;
}

export async function listTcpListeners() {
  if (process.platform === "win32") {
    const listeners = await listTcpListenersWindows();
    await attachWindowsProcessNames(listeners);
    return listeners;
  }
  if (process.platform === "linux") return listTcpListenersLinux();
  return listTcpListenersLsof();
}

async function attachWindowsProcessNames(listeners) {
  const pids = new Set(listeners.map((item) => item.pid).filter((pid) => pid > 0));
  if (pids.size === 0) return;
  // 单次 tasklist 拉全量进程再按 PID 映射，避免按 PID 并发 spawn 几十个进程导致排队超时。
  const out = await run("tasklist", ["/fo", "csv", "/nh"]);
  const names = new Map();
  for (const line of out.split(/\r?\n/)) {
    // CSV 列："映像名称","PID","会话名","会话#","内存使用"
    const match = line.match(/^"([^"]+)","(\d+)"/);
    if (match) names.set(Number(match[2]), match[1]);
  }
  for (const item of listeners) {
    if (!item.processName && names.has(item.pid)) item.processName = names.get(item.pid);
  }
}

// 查指定端口（可多个）的 LISTENING 归属；返回 [{ address, port, pid, processName }]。
export async function findListenersByPort(ports) {
  const wanted = new Set([...ports].map(Number));
  const listeners = await listTcpListeners();
  return listeners.filter((item) => wanted.has(item.port));
}

// 预检一组端口：全部空闲返回 null；否则抛出带明细的错误。
export async function assertTcpPortsFree(ports, { label = "端口" } = {}) {
  const busy = await probeTcpPorts(ports);
  if (busy.length === 0) return null;
  const owners = await findListenersByPort(busy.map((item) => item.port));
  const detail = busy
    .map((item) => {
      const owner = owners.find((o) => o.port === item.port);
      const who = owner?.processName ? `（占用进程：${owner.processName}）` : "";
      return `${item.port}${who}`;
    })
    .join("、");
  throw new Error(`${label} ${detail} 已被占用，请先释放或更换`);
}
