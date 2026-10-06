// 0.9.2：系统防火墙操作模块。零第三方依赖，仅使用 Node 内置模块。
// 支持：Linux firewalld / ufw / iptables，Windows netsh advfirewall；其余环境 unsupported。
// 所有命令执行可通过 options.runner 注入（便于单元测试断言命令数组）。
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const RULE_PREFIX = "XFCloud-Tunnel";

// 默认 runner：非零退出码抛错（stderr 在 error.message 中）。
const defaultRunner = (command, args, { timeout = 6_000 } = {}) =>
  execFileAsync(command, args, { timeout, windowsHide: true, maxBuffer: 8 * 1024 * 1024 });

function normalizeRunner(options = {}) {
  return options.runner || defaultRunner;
}

function isRoot() {
  return typeof process.getuid === "function" && process.getuid() === 0;
}

// 探测防火墙后端。返回 { backend, privileged, ... } 或 { supported:false, reason }。
export async function detectFirewall(options = {}) {
  const runner = normalizeRunner(options);
  if (process.platform === "win32") {
    try {
      await runner("netsh", ["advfirewall", "show", "currentprofile"]);
    } catch {
      return {
        supported: false,
        backend: null,
        reason: "未检测到可用的 Windows 高级防火墙（netsh advfirewall 不可用）",
      };
    }
    // net session 需要管理员权限；失败即非提权。
    let privileged = true;
    try {
      await runner("net", ["session"]);
    } catch {
      privileged = false;
    }
    return {
      supported: true,
      backend: "netsh",
      backendName: "Windows 高级防火墙 (netsh)",
      privileged,
      rulePrefix: RULE_PREFIX,
      lifecycleSupported: true,
    };
  }
  if (process.platform === "linux") {
    // 1) firewalld（已安装但停止时也识别为 firewalld 后端，active=false）
    try {
      const result = await runner("firewall-cmd", ["--state"]);
      const stateText = String(result.stdout || "");
      if (/running/i.test(stateText) || /not\s+running/i.test(stateText)) {
        return {
          supported: true,
          backend: "firewalld",
          backendName: "firewalld (firewall-cmd)",
          privileged: isRoot(),
          rulePrefix: null,
          lifecycleSupported: true,
          active: /running/i.test(stateText) && !/not\s+running/i.test(stateText),
        };
      }
    } catch (error) {
      const out = `${error.stdout || ""} ${error.stderr || ""}`;
      if (/not\s+running/i.test(out)) {
        return {
          supported: true,
          backend: "firewalld",
          backendName: "firewalld (firewall-cmd)",
          privileged: isRoot(),
          rulePrefix: null,
          lifecycleSupported: true,
          active: false,
        };
      }
      /* 未安装，继续探测 */
    }
    // 2) ufw
    try {
      const result = await runner("ufw", ["status"]);
      const out = String(result.stdout || "");
      if (/Status:\s*active/i.test(out) || /Status:\s*inactive/i.test(out)) {
        return {
          supported: true,
          backend: "ufw",
          backendName: "UFW (ufw)",
          privileged: isRoot(),
          rulePrefix: null,
          lifecycleSupported: true,
          active: /Status:\s*active/i.test(out),
        };
      }
    } catch {
      /* 未安装，继续探测 */
    }
    // 3) iptables（能列出规则即视为可用；非 root 通常失败）
    try {
      await runner("iptables", ["-L", "INPUT", "-n"]);
      return {
        supported: true,
        backend: "iptables",
        backendName: "iptables",
        privileged: isRoot(),
        rulePrefix: null,
        lifecycleSupported: false,
        active: true,
        note: "iptables 规则重启后失效，建议另行持久化（如 iptables-save / netfilter-persistent）",
      };
    } catch {
      /* 不可用 */
    }
    return {
      supported: false,
      backend: null,
      reason: "未检测到 firewalld / ufw / iptables，或当前权限不足无法管理防火墙",
    };
  }
  return {
    supported: false,
    backend: null,
    reason: `当前系统（${process.platform}）暂不支持自动防火墙管理，请手动放行端口`,
  };
}

// 状态：后端 + 已放行端口集合（字符串形式 "10000/tcp"，段为 "10000-10010/tcp"）。
export async function firewallStatus(options = {}) {
  const runner = normalizeRunner(options);
  const info = await detectFirewall(options);
  if (!info.supported) return info;
  let openPorts = [];
  try {
    openPorts = await listOpenPorts({ ...options, runner, backend: info.backend });
  } catch {
    openPorts = [];
  }
  let active = info.active;
  if (typeof active !== "boolean") {
    try {
      active = await isFirewallActive({ ...options, runner, backend: info.backend });
    } catch {
      active = true;
    }
  }
  return { ...info, active, openPorts };
}

// 0.9.3：防火墙整体生命周期控制。action: "start" | "stop" | "restart"。
// iptables 无服务单元，不提供关闭/开启（避免 flush/默认策略带来的断网风险）。
export async function controlFirewall(action, options = {}) {
  const runner = normalizeRunner(options);
  const info = await detectFirewall(options);
  if (!info.supported) {
    const error = new Error(info.reason || "当前环境不支持防火墙管理");
    error.code = "FIREWALL_UNSUPPORTED";
    throw error;
  }
  if (!info.privileged) {
    const error = new Error(
      info.backend === "netsh"
        ? "控制防火墙需要管理员权限：请以管理员身份运行服务端"
        : "控制防火墙需要 root 权限：请使用 root 运行服务端",
    );
    error.code = "FIREWALL_FORBIDDEN";
    throw error;
  }
  if (!["start", "stop", "restart"].includes(action)) {
    throw new Error(`不支持的防火墙操作：${action}`);
  }
  if (info.backend === "iptables") {
    const error = new Error(
      "iptables 后端不支持关闭/开启/重启整体防火墙（无服务单元，且 flush/改默认策略可能导致断网）；" +
        "请改用 firewalld / ufw，或手动管理 iptables 规则",
    );
    error.code = "FIREWALL_LIFECYCLE";
    throw error;
  }
  const commands = [];
  const run = async (command, args) => {
    commands.push([command, ...args]);
    await runner(command, args);
  };
  // 依次尝试候选命令（systemctl 不存在时回退 service），全部失败才抛最后一个错误。
  const runFirstWorking = async (candidates) => {
    let lastError = null;
    for (const [command, args] of candidates) {
      try {
        await run(command, args);
        return;
      } catch (error) {
        lastError = error;
      }
    }
    throw lastError || new Error("防火墙控制命令执行失败");
  };

  if (info.backend === "firewalld") {
    const sub = action === "start" ? "start" : action; // restart 直接透传
    await runFirstWorking([
      ["systemctl", [sub, "firewalld"]],
      ["service", ["firewalld", sub]],
    ]);
  } else if (info.backend === "ufw") {
    if (action === "start") {
      // ufw enable 会提示确认，--force 跳过（防止中断 SSH 时卡住）。
      await run("ufw", ["--force", "enable"]);
    } else if (action === "stop") {
      await run("ufw", ["disable"]);
    } else {
      // restart：优先 reload（不断网重载规则）；未启用时 reload 失败则 enable。
      try {
        await run("ufw", ["reload"]);
      } catch {
        await run("ufw", ["--force", "enable"]);
      }
    }
  } else if (info.backend === "netsh") {
    if (action === "restart") {
      // restart = 先关闭再开启；开启失败时必须尽力恢复，避免防火墙停留在关闭态。
      await run("netsh", ["advfirewall", "set", "allprofiles", "state", "off"]);
      try {
        await run("netsh", ["advfirewall", "set", "allprofiles", "state", "on"]);
      } catch (firstError) {
        try {
          await run("netsh", ["advfirewall", "set", "allprofiles", "state", "on"]);
        } catch {
          const error = new Error(
            "防火墙已关闭但重新开启失败，当前处于关闭状态，请手动执行 " +
              "netsh advfirewall set allprofiles state on 恢复",
          );
          error.code = "FIREWALL_PARTIAL";
          error.cause = firstError;
          throw error;
        }
      }
    } else {
      await run("netsh", [
        "advfirewall",
        "set",
        "allprofiles",
        "state",
        action === "stop" ? "off" : "on",
      ]);
    }
  }
  return { action, backend: info.backend, commands };
}

// 查询防火墙是否处于活动状态。
async function isFirewallActive(options) {
  const runner = normalizeRunner(options);
  const backend = options.backend;
  if (backend === "firewalld") {
    try {
      const result = await runner("firewall-cmd", ["--state"]);
      return /running/i.test(String(result.stdout || "")) &&
        !/not\s+running/i.test(String(result.stdout || ""));
    } catch (error) {
      const out = `${error.stdout || ""} ${error.stderr || ""}`;
      if (/not\s+running/i.test(out)) return false;
      return true;
    }
  }
  if (backend === "ufw") {
    const result = await runner("ufw", ["status"]);
    return /Status:\s*active/i.test(String(result.stdout || ""));
  }
  if (backend === "netsh") {
    const result = await runner("netsh", ["advfirewall", "show", "currentprofile"]);
    const text = String(result.stdout || "");
    if (/\boff\b/i.test(text) || /状态[^\r\n]*关/.test(text)) return false;
    if (/\bon\b/i.test(text) || /状态[^\r\n]*开/.test(text)) return true;
    return true;
  }
  return true;
}

// 开放端口。ports：数字或字符串（"10000" / "10000-10010"）数组；proto: "tcp"|"udp"|"both"。
// 返回 { opened:[{port,proto}], commands:[[cmd,args...]] }；权限不足/不支持抛错。
export async function openFirewallPorts(ports, proto = "tcp", options = {}) {
  const runner = normalizeRunner(options);
  const info = await detectFirewall(options);
  if (!info.supported) {
    const error = new Error(info.reason || "当前环境不支持防火墙管理");
    error.code = "FIREWALL_UNSUPPORTED";
    throw error;
  }
  if (!info.privileged) {
    const error = new Error(
      info.backend === "netsh"
        ? "防火墙放行需要管理员权限：请以管理员身份运行服务端（或手动在 Windows 防火墙中放行端口）"
        : "防火墙放行需要 root 权限：请使用 root 运行服务端，或手动执行防火墙放行命令",
    );
    error.code = "FIREWALL_FORBIDDEN";
    throw error;
  }
  const specs = normalizePortSpecs(ports, proto);
  if (specs.length === 0) throw new Error("没有可放行的端口");
  const commands = [];
  const run = async (command, args) => {
    commands.push([command, ...args]);
    await runner(command, args);
  };

  if (info.backend === "firewalld") {
    for (const spec of specs) {
      await run("firewall-cmd", ["--permanent", "--add-port", `${spec.port}/${spec.proto}`]);
    }
    await run("firewall-cmd", ["--reload"]);
  } else if (info.backend === "ufw") {
    for (const spec of specs) {
      await run("ufw", ["allow", `${spec.port}/${spec.proto}`]);
    }
  } else if (info.backend === "iptables") {
    for (const spec of specs) {
      if (spec.port.includes("-")) {
        const [from, to] = spec.port.split("-").map(Number);
        await run("iptables", [
          "-I", "INPUT", "-p", spec.proto, "--dport", `${from}:${to}`, "-j", "ACCEPT",
        ]);
      } else {
        await run("iptables", [
          "-I", "INPUT", "-p", spec.proto, "--dport", String(spec.port), "-j", "ACCEPT",
        ]);
      }
    }
  } else if (info.backend === "netsh") {
    for (const spec of specs) {
      await run("netsh", [
        "advfirewall", "firewall", "add", "rule",
        `name=${RULE_PREFIX}-${spec.port}-${spec.proto}`,
        "dir=in", "action=allow",
        `protocol=${spec.proto === "tcp" ? "TCP" : "UDP"}`,
        `localport=${spec.port}`,
      ]);
    }
  }
  return { opened: specs, commands };
}

function normalizePortSpecs(ports, proto) {
  const protos = proto === "both" ? ["tcp", "udp"] : [String(proto || "tcp").toLowerCase()];
  const specs = [];
  for (const raw of Array.isArray(ports) ? ports : [ports]) {
    const text = String(raw).trim();
    const match = /^(\d+)(?:-(\d+))?$/.exec(text);
    if (!match) throw new Error(`端口格式非法：${text}（示例：10000 或 10000-10010）`);
    const from = Number(match[1]);
    const to = match[2] ? Number(match[2]) : from;
    if (from < 1 || to > 65535 || from > to) throw new Error(`端口范围非法：${text}`);
    for (const p of protos) {
      specs.push({ port: from === to ? String(from) : `${from}-${to}`, proto: p });
    }
  }
  // 去重
  const seen = new Set();
  return specs.filter((spec) => {
    const key = `${spec.port}/${spec.proto}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// 已放行端口解析。
export async function listOpenPorts(options = {}) {
  const runner = normalizeRunner(options);
  const backend = options.backend || (await detectFirewall(options)).backend;
  if (backend === "firewalld") {
    const result = await runner("firewall-cmd", ["--list-ports"]);
    return [...String(result.stdout || "").matchAll(/(\d+(?:-\d+)?\/(?:tcp|udp))/g)].map((m) => m[1]);
  }
  if (backend === "ufw") {
    const result = await runner("ufw", ["status"]);
    const ports = new Set();
    for (const line of String(result.stdout || "").split(/\r?\n/)) {
      if (!/\bALLOW\b/i.test(line)) continue;
      for (const match of line.matchAll(/(\d+(?:-\d+)?)\/(tcp|udp)/gi)) {
        ports.add(`${match[1]}/${match[2].toLowerCase()}`);
      }
    }
    return [...ports];
  }
  if (backend === "iptables") {
    const result = await runner("iptables", ["-L", "INPUT", "-n"]);
    const ports = new Set();
    for (const line of String(result.stdout || "").split(/\r?\n/)) {
      if (!/\bACCEPT\b/.test(line)) continue;
      const proto = /\btcp\b/.test(line) ? "tcp" : /\budp\b/.test(line) ? "udp" : null;
      if (!proto) continue;
      for (const match of line.matchAll(/dpts?:(\d+(?:,\d+)*)/g)) {
        for (const port of match[1].split(",")) ports.add(`${port}/${proto}`);
      }
    }
    return [...ports];
  }
  if (backend === "netsh") {
    const result = await runner("netsh", ["advfirewall", "firewall", "show", "rule", "name=all"]);
    return parseNetshRules(String(result.stdout || ""));
  }
  return [];
}

function parseNetshRules(text) {
  const ports = new Set();
  let enabled = false;
  let localPorts = "";
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (/^规则名称|^Rule Name/i.test(line)) {
      enabled = false;
      localPorts = "";
    }
    if (/^已启用|^Enabled/i.test(line)) enabled = /\bYes\b|是/.test(line);
    if (/^本地端口|^LocalPort/i.test(line)) localPorts = line.split(/[:：]/)[1] || "";
    if (line === "" && localPorts && enabled) {
      for (const port of localPorts.split(",")) {
        const text = port.trim();
        if (/^\d+(?:-\d+)?$/.test(text)) ports.add(`${text}/tcp?`);
      }
      localPorts = "";
    }
  }
  // netsh 输出中协议与端口分属不同行；netsh 无法在不解析协议行的情况下区分 tcp/udp，
  // 统一返回端口号，归属判定时 tcp/udp 均视为已放行。
  return [...ports].map((item) => item.replace("/tcp?", ""));
}

// 判断端口是否已放行（openPorts 来自 firewallStatus）。段形式也命中。
export function isPortOpen(openPorts, port, proto = "tcp") {
  const target = Number(port);
  for (const entry of openPorts || []) {
    const [range, entryProto] = String(entry).split("/");
    if (entryProto && entryProto !== "tcp?" && entryProto !== proto) continue;
    const match = /^(\d+)(?:-(\d+))?$/.exec(range);
    if (!match) continue;
    const from = Number(match[1]);
    const to = match[2] ? Number(match[2]) : from;
    if (target >= from && target <= to) return true;
  }
  return false;
}
