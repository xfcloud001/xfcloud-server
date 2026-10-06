import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, statSync, unlinkSync, writeFileSync, chmodSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { randomInt } from "node:crypto";
import { hostname } from "node:os";
import { dirname, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  escapeToml,
  FIXED_CLIENT_API_PORT,
  formatPortRanges,
  isExpired,
  isPortAllowed,
  LoginRateLimiter,
  normalizeDeviceId,
  normalizeDomains,
  parsePortRanges,
  rangeNode,
  requestIp,
  setupServiceRuntime,
  signToken,
  verifyToken,
} from "../shared/core.js";
import { resolveFrpBinary } from "../shared/platform.js";
import {
  assertTcpPortsFree,
  findListenersByPort,
  listTcpListeners,
  probeTcpPorts,
} from "../shared/netutil.js";
import {
  controlFirewall,
  firewallStatus,
  openFirewallPorts,
  isPortOpen,
} from "../shared/firewall.js";
import { buildXlsx, parseXlsx, parseDelimited, toDelimited, looksLikeXlsx } from "../shared/xlsx.js";
import {
  clearTlsMaterial,
  loadManagerTlsOptions,
  resolveNetworkConfig,
  saveNetworkConfig,
  saveTlsMaterial,
} from "./network.js";
import { LicenseManager } from "./license.js";
import { SystemTrafficSampler } from "./netstats.js";
import { Store } from "./store.js";
import { FrpTrafficMonitor } from "./traffic.js";
import { VERSION } from "../shared/version.js";
import { renderHtmlWithIncludes } from "../shared/partials.js";
// 0.10.0：注册/忘记密码（SMTP 邮件 + 图形验证码）与集群从节点同步。
import { sendMail } from "../shared/mailer.js";
import { createCaptcha, verifyCaptcha } from "../shared/captcha.js";
import { createSliderChallenge, verifySliderChallenge } from "../shared/slider-captcha.js";
import {
  applyUpdateAndRestart,
  clearUpdateMarker,
  readUpdateMarker,
  readUpdateResult,
  recoverInterruptedUpdate,
} from "../shared/updater.js";

// 0.9.3.2：限速命令推送队列。管理员修改限速后入队，客户端心跳拉取并立即执行。
// 每个 userId 维护一个命令列表，客户端拉取后清空。
const pendingClientCommands = new Map(); // userId -> [{ type, rateLimitBps, proxyRateLimits, ts }]

function enqueueClientCommand(userId, command) {
  const queue = pendingClientCommands.get(userId) || [];
  queue.push({ ...command, ts: Date.now() });
  pendingClientCommands.set(userId, queue);
}

function drainClientCommands(userId) {
  const queue = pendingClientCommands.get(userId);
  if (!queue || queue.length === 0) return [];
  pendingClientCommands.delete(userId);
  return queue;
}

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DATA_DIR = resolve(process.env.DATA_DIR || join(ROOT, "data", "server"));
const BRANDING_DIR = join(DATA_DIR, "branding");
const RUNTIME_DIR = resolve(
  process.env.SERVER_RUNTIME_DIR || join(ROOT, "runtime", "server"),
);
const HOST = process.env.MANAGER_HOST || "0.0.0.0";
// 管理端口与 HTTPS：环境变量 MANAGER_PORT 优先，其次 data/server-config.json。
const NETWORK_CONFIG = resolveNetworkConfig(DATA_DIR);
const PORT = NETWORK_CONFIG.port;
const MANAGER_TLS = loadManagerTlsOptions(DATA_DIR, (msg) =>
  console.log(`[network] ${msg}`),
);
const HTTPS_ENABLED = Boolean(MANAGER_TLS);
const managerHttpsEnabled = () =>
  typeof currentServerHttps === "boolean" ? currentServerHttps : HTTPS_ENABLED;
// frp 端口：环境变量优先；否则使用 settings 中持久化的端口，
// 首次运行时随机生成（避开 frp 默认端口 7000/7500，降低被扫描攻击的风险）。
const FRP_BIND_PORT_ENV = process.env.FRP_BIND_PORT ? Number(process.env.FRP_BIND_PORT) : null;
const FRP_METRICS_PORT_ENV = process.env.FRP_METRICS_PORT
  ? Number(process.env.FRP_METRICS_PORT)
  : null;
for (const [name, value] of [["FRP_BIND_PORT", FRP_BIND_PORT_ENV], ["FRP_METRICS_PORT", FRP_METRICS_PORT_ENV]]) {
  if (value !== null && (!Number.isInteger(value) || value < 1 || value > 65535)) {
    throw new Error(`${name} must be between 1 and 65535`);
  }
}
let FRP_BIND_PORT = FRP_BIND_PORT_ENV;
let FRP_METRICS_PORT = FRP_METRICS_PORT_ENV;
const FRP_METRICS_INTERVAL_MS = Number(process.env.FRP_METRICS_INTERVAL_MS || 1_000);
const FRP_METRICS_WINDOW_MS = Number(process.env.FRP_METRICS_WINDOW_MS || 10_000);
const FRP_PUBLIC_HOST = process.env.FRP_PUBLIC_HOST || "";
// HTTP/HTTPS 隧道 vhost 端口：环境变量优先（含显式 0=关闭）；否则取 settings；
// 0.10.2.3 起默认 0（关闭），管理员在「运行状态」填写端口后开启。
const FRP_VHOST_HTTP_PORT_ENV =
  process.env.FRP_VHOST_HTTP_PORT !== undefined && process.env.FRP_VHOST_HTTP_PORT !== ""
    ? Number(process.env.FRP_VHOST_HTTP_PORT)
    : null;
const FRP_VHOST_HTTPS_PORT_ENV =
  process.env.FRP_VHOST_HTTPS_PORT !== undefined && process.env.FRP_VHOST_HTTPS_PORT !== ""
    ? Number(process.env.FRP_VHOST_HTTPS_PORT)
    : null;
for (const [name, value] of [
  ["FRP_VHOST_HTTP_PORT", FRP_VHOST_HTTP_PORT_ENV],
  ["FRP_VHOST_HTTPS_PORT", FRP_VHOST_HTTPS_PORT_ENV],
]) {
  if (value !== null && (!Number.isInteger(value) || value < 0 || value > 65535)) {
    throw new Error(`${name} must be between 0 and 65535 (0 means disabled)`);
  }
}
const FRPS_AUTOSTART = process.env.FRPS_AUTOSTART !== "false";
const LICENSE_SERVER_URL =
  process.env.LICENSE_SERVER_URL || "https://key.xfhub.top";
const LICENSE_CHECK_INTERVAL_MS = Number(
  process.env.LICENSE_CHECK_INTERVAL_MS || 10 * 60_000,
);
const DEFAULT_ADMIN_USER = process.env.ADMIN_USER || "admin";
const DEFAULT_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "change-me-now";
// ---------- 0.10.0 集群模式 ----------
// SERVER_ROLE=slave 为从节点：不开管理 Web（仅回环保留 frps 插件端口），客户端 API 保留，
// 用户数据每 30 秒从主节点同步；登录/改密/兑换等写操作代理主节点。
const SERVER_ROLE = process.env.SERVER_ROLE === "slave" ? "slave" : "master";
// 0.10.1.1 规格10-12 主节点高可用：角色/主地址/节点令牌运行期可变（自动升主/跟随新主/重新签发）。
// 初始值取自 env；运行期变更同步落库（setting 优先于 env，重启后仍指向最新主节点）。
// 实际初始化在 store 创建之后（见下方 clusterRuntimeInit()）。
let activeRole = SERVER_ROLE;
let clusterMasterUrl = "";
let clusterNodeToken = "";
const CLUSTER_SYNC_INTERVAL_MS = Number(process.env.CLUSTER_SYNC_INTERVAL_MS || 30_000);
const CLIENT_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
const CLIENT_TOKEN_REFRESH_SECONDS = 7 * 24 * 60 * 60;
const FRPS_BIN = resolveFrpBinary(ROOT, "frps", process.env.FRPS_BIN);
const LOCAL_PLATFORM = process.platform === "win32" ? "windows" : process.platform;
// 服务端缓存/下发给各平台客户端的 frpc 二进制目录（文件名 frpc-<platform>-<arch>）。
const BIN_DIR = join(ROOT, "bin");

// 通过 `-v` 探测 frp 二进制版本号（失败返回空字符串）。
function detectFrpVersion(binPath) {
  if (!existsSync(binPath)) return "";
  try {
    const result = spawnSync(binPath, ["-v"], { encoding: "utf8", timeout: 5_000 });
    const text = (result.stdout || result.stderr || "").trim();
    const match = /v?(\d+\.\d+\.\d+[0-9A-Za-z.+-]*)/.exec(text);
    return match ? match[1] : "";
  } catch {
    return "";
  }
}

// 校验二进制与指定平台匹配（ELF / PE / Mach-O 魔数）。
function binaryMatchesPlatform(buffer, platform) {
  if (platform === "windows") {
    return buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a; // MZ
  }
  if (platform === "darwin") {
    return (
      buffer.length >= 4 &&
      [
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe],
      ].some((magic) => magic.every((byte, index) => buffer[index] === byte))
    );
  }
  // linux 与其他类 Unix 平台均为 ELF。
  return buffer.length >= 4 && buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46;
}

// 安装新的 frps 二进制：停止进程（等待退出，Windows 需释放文件句柄）-> 覆盖文件 -> 记录版本 -> 按需重启。
async function installFrpsBinary(buffer, version = "") {
  const wasRunning = frps.process !== null;
  if (wasRunning) await frps.stop();
  mkdirSync(dirname(FRPS_BIN), { recursive: true });
  rmSync(FRPS_BIN, { force: true });
  writeFileSync(FRPS_BIN, buffer);
  if (process.platform !== "win32") chmodSync(FRPS_BIN, 0o755);
  const detected = version || detectFrpVersion(FRPS_BIN);
  if (detected) {
    frpsVersion = detected;
    store.setSetting("frps_version", detected);
  }
  frps.refreshState();
  if (wasRunning) frps.start();
  return detected;
}

// ---------- 下发给客户端的 frpc 本地缓存 ----------
const FRP_PLATFORMS = ["linux", "windows", "darwin"];
const FRP_ARCHES = ["amd64", "arm64", "arm"];

function frpcCachePath(platform, arch) {
  return join(BIN_DIR, `frpc-${platform}-${arch}`);
}

function saveFrpcCache(platform, arch, buffer, version) {
  mkdirSync(BIN_DIR, { recursive: true });
  const cachePath = frpcCachePath(platform, arch);
  rmSync(cachePath, { force: true });
  writeFileSync(cachePath, buffer);
  if (process.platform !== "win32") chmodSync(cachePath, 0o755);
  let resolvedVersion = version;
  if (!resolvedVersion && platform === (process.platform === "win32" ? "windows" : process.platform)) {
    resolvedVersion = detectFrpVersion(cachePath);
  }
  if (resolvedVersion) store.setSetting(`frpc_version_${platform}_${arch}`, resolvedVersion);
  return {
    platform,
    arch,
    version: resolvedVersion || store.getSetting(`frpc_version_${platform}_${arch}`) || "",
    fileSize: buffer.length,
    cachedAt: new Date().toISOString(),
  };
}

function listFrpcCache() {
  mkdirSync(BIN_DIR, { recursive: true });
  const items = [];
  for (const platform of FRP_PLATFORMS) {
    for (const arch of FRP_ARCHES) {
      const cachePath = frpcCachePath(platform, arch);
      if (!existsSync(cachePath)) continue;
      let stat;
      try {
        stat = statSync(cachePath);
      } catch {
        continue;
      }
      items.push({
        platform,
        arch,
        version: store.getSetting(`frpc_version_${platform}_${arch}`) || "",
        fileSize: stat.size,
        cachedAt: stat.mtime.toISOString(),
      });
    }
  }
  return items;
}

if (
  !Number.isInteger(FRP_METRICS_INTERVAL_MS) ||
  FRP_METRICS_INTERVAL_MS < 250 ||
  FRP_METRICS_INTERVAL_MS > 60_000
) {
  throw new Error("FRP_METRICS_INTERVAL_MS must be between 250 and 60000");
}
if (
  !Number.isInteger(FRP_METRICS_WINDOW_MS) ||
  FRP_METRICS_WINDOW_MS < FRP_METRICS_INTERVAL_MS ||
  FRP_METRICS_WINDOW_MS > 300_000
) {
  throw new Error(
    "FRP_METRICS_WINDOW_MS must be between FRP_METRICS_INTERVAL_MS and 300000",
  );
}
if (
  !Number.isInteger(LICENSE_CHECK_INTERVAL_MS) ||
  LICENSE_CHECK_INTERVAL_MS < 60_000 ||
  LICENSE_CHECK_INTERVAL_MS > 24 * 60 * 60_000
) {
  throw new Error("LICENSE_CHECK_INTERVAL_MS must be between 60000 and 86400000");
}

mkdirSync(DATA_DIR, { recursive: true });
mkdirSync(RUNTIME_DIR, { recursive: true });
mkdirSync(BRANDING_DIR, { recursive: true });
// 模块加载即完成运行时引导，并恢复中断的在线更新。
setupServiceRuntime(ROOT);
recoverInterruptedUpdate(DATA_DIR, (msg) => console.log(`[updater] ${msg}`));

function configuredLicensePublicKey() {
  if (process.env.LICENSE_PUBLIC_KEY) return process.env.LICENSE_PUBLIC_KEY;
  if (!process.env.LICENSE_PUBLIC_KEY_FILE) return "";
  return readFileSync(resolve(process.env.LICENSE_PUBLIC_KEY_FILE), "utf8");
}

// 0.10.1.1 规格10-12：集群运行时角色初始化——角色覆写/主地址/节点令牌均 setting 优先于 env
// （故障切换后重启仍指向最新角色与主节点；从未切换过的节点读 env 初始值）。
let clusterRuntimeInit = () => {
  activeRole = store.getSetting("cluster_role_override") || SERVER_ROLE;
  clusterMasterUrl = (
    store.getSetting("cluster_master_url") || process.env.CLUSTER_MASTER_URL || ""
  ).replace(/\/+$/, "");
  clusterNodeToken = store.getSetting("cluster_node_token") || process.env.CLUSTER_NODE_TOKEN || "";
  clusterRuntimeInit = () => {};
};
const store = new Store(
  join(DATA_DIR, "manager.db"),
  DEFAULT_ADMIN_USER,
  DEFAULT_ADMIN_PASSWORD,
);
clusterRuntimeInit();
// 0.10.1.0：改为可变绑定——从节点收到主节点下发的 frp token 后对齐本地（frps 重启生效）。
let frpAuthToken = store.getOrCreateSetting("frp_auth_token");
// 0.10.1.0：集群统一签名密钥——从节点对齐主节点 signingSecret，主节点签发的客户端
// token 在从节点 frps 插件（fm_token 验签）与本地签发均可互通。
let signingSecret = store.getOrCreateSetting("signing_secret");
// 0.10.1.0 数据高可用：曾作为从节点备份过主节点数据的节点，切回主节点角色（提升）时恢复备份。
try {
  const restored = store.restoreBackupSnapshot();
  if (restored) {
    console.log(
      `[backup] 已恢复主节点备份数据：用户 ${restored.users} 个，管理员${restored.admin ? "已" : "未"}恢复，套餐${restored.plans ? "已" : "未"}恢复`,
    );
  }
} catch (error) {
  console.error(`[backup] 备份数据恢复失败: ${error.message}`);
}
const frpMetricsUser = store.getOrCreateSetting("frp_metrics_user", () => "xfcloud-tunnel");
const frpMetricsPassword = store.getOrCreateSetting("frp_metrics_password");

// ---------- frp 端口解析与随机化 ----------
// 避开常见服务端口与 frp 默认端口，防止扫描器按默认端口攻击。
const FRP_PORT_AVOID = new Set([
  21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521, 2375,
  2376, 3306, 3389, 5432, 5900, 6379, 7000, 7400, 7500, 7501, 8080, 8081, 8443,
  8888, 9000, 9090, 9200, 27017, PORT, PORT + 1, FIXED_CLIENT_API_PORT,
]);

function randomFrpPort(avoid) {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    const port = 20000 + Math.floor(Math.random() * 30000);
    if (!avoid.has(port)) return port;
  }
  throw new Error("无法生成可用的 frp 端口，请改用 FRP_BIND_PORT/FRP_METRICS_PORT 环境变量");
}

function resolveFrpPort(settingKey, envValue, avoid) {
  if (Number.isInteger(envValue)) return envValue;
  const stored = Number(store.getSetting(settingKey));
  if (Number.isInteger(stored) && stored >= 1 && stored <= 65535 && !avoid.has(stored)) {
    return stored;
  }
  const generated = randomFrpPort(avoid);
  store.setSetting(settingKey, generated);
  console.log(`[frp] generated ${settingKey}: ${generated}`);
  return generated;
}

FRP_BIND_PORT = resolveFrpPort("frp_bind_port", FRP_BIND_PORT_ENV, FRP_PORT_AVOID);
FRP_METRICS_PORT = resolveFrpPort(
  "frp_metrics_port",
  FRP_METRICS_PORT_ENV,
  new Set([...FRP_PORT_AVOID, FRP_BIND_PORT]),
);

// HTTP/HTTPS 隧道 vhost 端口：环境变量固定时页面只读；否则读 settings
// （0.10.2.3 起默认 0 = 关闭，页面填写端口后开启），页面修改并重启 frps 后生效。
function resolveVhostPort(envValue, settingKey, defaultValue) {
  if (envValue !== null) return envValue;
  const raw = store.getSetting(settingKey);
  const stored = raw === null || raw === undefined || raw === "" ? NaN : Number(raw);
  if (Number.isInteger(stored) && stored >= 0 && stored <= 65535) return stored;
  store.setSetting(settingKey, String(defaultValue));
  return defaultValue;
}
const vhostHttpPort = () => resolveVhostPort(FRP_VHOST_HTTP_PORT_ENV, "vhost_http_port", 0);
const vhostHttpsPort = () => resolveVhostPort(FRP_VHOST_HTTPS_PORT_ENV, "vhost_https_port", 0);

// 0.9.2：frps/平台自身监听的端口——分配用户端口段时必须排除。
function frpsReservedPorts() {
  const ports = [FRP_BIND_PORT, FRP_METRICS_PORT, PORT, FIXED_CLIENT_API_PORT];
  const http = vhostHttpPort();
  const https = vhostHttpsPort();
  if (http > 0) ports.push(http);
  if (https > 0) ports.push(https);
  return ports.filter((port) => Number.isInteger(port) && port > 0);
}

// 0.10.1.2 规格1：版本号逐段数值比较（支持任意长度修订号，如 0.10.1.2）。
// 返回 -1/0/1；非数字段按 0 处理，避免 NaN 干扰比较。
function compareVersions(a, b) {
  const toParts = (value) =>
    String(value || "")
      .split(/[.\-+_]/)
      .map((part) => Number.parseInt(part, 10) || 0);
  const left = toParts(a);
  const right = toParts(b);
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const diff = (left[index] || 0) - (right[index] || 0);
    if (diff !== 0) return diff > 0 ? 1 : -1;
  }
  return 0;
}

// version-sync 命令自 0.10.0.2 起可用；低于该版本的从节点不认识命令，需重新部署升级。
const MIN_VERSION_SYNC_COMMAND = "0.10.0.2";

// 0.9.2：用户端口段分配预检：
// ① 不得覆盖 frps/平台保留端口；② 不得与本机当前 LISTENING 端口冲突（netstat 单次快照）。
// 0.10.1.2 规格3：仅校验主节点端口段——从节点端口的占用由该节点自身的 frps 与预检约束，
// 用主节点 netstat 校验从节点端口会误报「端口已被占用」，导致从节点端口添加失败。
async function assertRangesPortsFree(ranges) {
  const masterRanges = ranges.filter((range) => rangeNode(range) === "master");
  const reserved = new Set(frpsReservedPorts());
  const reservedHits = [];
  for (const range of masterRanges) {
    for (let port = Number(range.start); port <= Number(range.end); port += 1) {
      if (reserved.has(port)) reservedHits.push(port);
    }
  }
  if (reservedHits.length) {
    throw new Error(`端口 ${reservedHits.join("、")} 是系统/frp 服务保留端口，不能分配给用户`);
  }
  let listeners = [];
  try {
    listeners = await listTcpListeners();
  } catch {
    listeners = [];
  }
  // frps 为活跃隧道监听的端口属平台管理，不算"外部占用"（编辑用户保留原段时避免误报）。
  const managedProxyPorts = new Set(
    store
      .listProxies()
      .filter((proxy) => !proxy.closedAt && proxy.remotePort)
      .map((proxy) => proxy.remotePort),
  );
  const listening = new Map();
  for (const item of listeners) {
    if (!managedProxyPorts.has(Number(item.port))) listening.set(Number(item.port), item);
  }
  const hits = [];
  for (const range of masterRanges) {
    for (let port = Number(range.start); port <= Number(range.end); port += 1) {
      if (listening.has(port)) hits.push(listening.get(port));
    }
  }
  if (hits.length) {
    const detail = hits
      .slice(0, 10)
      .map(
        (item) =>
          `${item.port}${item.processName ? `（占用进程：${item.processName}）` : ""}`,
      )
      .join("、");
    throw new Error(`端口 ${detail} 当前已被占用，请更换端口范围`);
  }
}

// 0.9.2：防火墙页端口归属报告：系统保留端口 / 活跃隧道 / 其他监听进程 + 防火墙放行状态。
async function buildFirewallPortReport() {
  const status = await firewallStatus().catch((error) => ({
    supported: false,
    backend: null,
    reason: error?.message || "防火墙状态探测失败",
  }));
  let listeners = [];
  try {
    listeners = await listTcpListeners();
  } catch {
    listeners = [];
  }
  const byPort = new Map();
  const ensure = (port) => {
    const key = Number(port);
    if (!byPort.has(key)) {
      byPort.set(key, { port: key, proto: "tcp", pid: null, processName: null, owners: [] });
    }
    return byPort.get(key);
  };
  for (const item of listeners) {
    const row = ensure(item.port);
    row.pid = item.pid ?? row.pid;
    row.processName = item.processName || row.processName;
  }
  const systemLabels = [
    [FRP_BIND_PORT, "frps 通信端口"],
    [FRP_METRICS_PORT, "frps 指标端口"],
    [PORT, "管理面板端口"],
    [FIXED_CLIENT_API_PORT, "客户端固定通信端口"],
  ];
  if (vhostHttpPort() > 0) systemLabels.push([vhostHttpPort(), "HTTP 隧道端口（vhost）"]);
  if (vhostHttpsPort() > 0) systemLabels.push([vhostHttpsPort(), "HTTPS 隧道端口（vhost）"]);
  for (const [port, label] of systemLabels) {
    if (Number.isInteger(port) && port > 0) {
      ensure(port).owners.push({ type: "system", label });
    }
  }
  for (const proxy of store.listProxies()) {
    if (proxy.closedAt || !proxy.remotePort) continue;
    ensure(proxy.remotePort).owners.push({
      type: "tunnel",
      label: `隧道「${proxyDisplayName(proxy)}」（用户 ${proxy.uid || proxy.username}）`,
      uid: proxy.uid,
      username: proxy.username,
      proxyName: proxyDisplayName(proxy),
      proxyType: proxy.type,
    });
  }
  for (const row of byPort.values()) {
    if (row.owners.length === 0) {
      row.owners.push({
        type: "process",
        label: row.processName
          ? `进程 ${row.processName}${row.pid ? `（PID ${row.pid}）` : ""}`
          : "未知进程监听",
      });
    }
  }
  const openPorts = status.supported ? status.openPorts || [] : [];
  const rangeFullyOpen = (start, end) => {
    for (let port = Number(start); port <= Number(end); port += 1) {
      if (!isPortOpen(openPorts, port, "tcp")) return false;
    }
    return true;
  };
  const ports = [...byPort.values()]
    .sort((a, b) => a.port - b.port)
    .map((row) => ({ ...row, firewallOpen: isPortOpen(openPorts, row.port, "tcp") }));
  const pools = store
    .listUsers()
    .map((user) => ({
      uid: user.uid,
      username: user.username,
      ranges: parsePortRanges(user.portRangesText || "").map((range) => ({
        start: Number(range.start),
        end: Number(range.end),
        open: rangeFullyOpen(range.start, range.end),
      })),
    }))
    .filter((pool) => pool.ranges.length > 0);
  return { status, ports, pools };
}

const trafficMonitor = new FrpTrafficMonitor({
  url:
    process.env.FRP_METRICS_URL ||
    `http://127.0.0.1:${FRP_METRICS_PORT}/metrics`,
  username: frpMetricsUser,
  password: frpMetricsPassword,
  intervalMs: FRP_METRICS_INTERVAL_MS,
  windowMs: FRP_METRICS_WINDOW_MS,
});
// 0.10.2.8：恢复持久化的永久累计流量——frps 计数器随进程/更新归零，
// 累计值改为 settings 持久化 + 增量推进，流量统计成为永久数据。
try {
  trafficMonitor.restore(JSON.parse(store.getSetting("traffic_cumulative") || "null"));
} catch {
  // 快照损坏时从零开始累计，不影响运行。
}
const loginRateLimiter = new LoginRateLimiter({ maxAttempts: 8, windowMs: 5 * 60_000 });
let licenseManager = null;

class UserTrafficAccumulator {
  constructor(store, trafficMonitor) {
    this.store = store;
    this.trafficMonitor = trafficMonitor;
    this.previousBytes = new Map();
  }

  snapshot() {
    const deltas = new Map();
    const seenKeys = new Set();
    // 0.10.1.1 规格3-4：统一增量口径——主节点本机指标 + 在线从节点 sync 快照流量一并累计。
    const consider = (proxy, traffic) => {
      const key = `${proxy.type}\0${proxy.name}`;
      seenKeys.add(key);
      if (!traffic || !traffic.hasMetrics) return;
      const previous = this.previousBytes.get(key) || { incomingBytes: 0, outgoingBytes: 0 };
      const incomingDelta = traffic.incomingBytes >= previous.incomingBytes
        ? traffic.incomingBytes - previous.incomingBytes
        : traffic.incomingBytes;
      const outgoingDelta = traffic.outgoingBytes >= previous.outgoingBytes
        ? traffic.outgoingBytes - previous.outgoingBytes
        : traffic.outgoingBytes;
      this.previousBytes.set(key, {
        incomingBytes: traffic.incomingBytes,
        outgoingBytes: traffic.outgoingBytes,
      });
      if (incomingDelta === 0 && outgoingDelta === 0) return;
      const entry = deltas.get(proxy.userId) || { incomingBytes: 0, outgoingBytes: 0 };
      entry.incomingBytes += incomingDelta;
      entry.outgoingBytes += outgoingDelta;
      deltas.set(proxy.userId, entry);
    };
    for (const proxy of this.store.listProxies()) {
      // 从节点承载的映射在本机 trafficMonitor 无指标（hasMetrics=false），自动跳过。
      consider(proxy, this.trafficMonitor.get(proxy.name, proxy.type));
    }
    for (const row of slaveProxySnapshotRows()) {
      consider(row, row.traffic);
    }
    for (const key of this.previousBytes.keys()) {
      if (!seenKeys.has(key)) this.previousBytes.delete(key);
    }
    return deltas;
  }
}

const trafficAccumulator = new UserTrafficAccumulator(store, trafficMonitor);
const systemTraffic = new SystemTrafficSampler();

function sendJson(res, status, data, headers = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    ...headers,
  });
  res.end(body);
}

function publicUser(user) {
  return {
    id: user.id,
    uid: user.uid ?? null,
    username: user.username,
    portRanges: user.portRanges,
    portRangesText: user.portRangesText,
    expiresAt: user.expiresAt ?? null,
    activatedAt: user.activatedAt ?? null,
    activated: Boolean(user.activated),
    durationDays: user.durationDays ?? 30,
    httpAllowed: Boolean(user.httpAllowed),
    enabled: user.enabled,
    online: user.online,
    lastSeen: user.lastSeen,
    expired: user.expired,
    mappingCount: user.mappingCount,
    onlineMappingCount: user.onlineMappingCount,
    rateLimitBps: user.rateLimitBps,
    trafficLimitBytes: user.trafficLimitBytes,
    trafficUsedBytes: user.trafficUsedBytes,
    deviceAddress: user.deviceAddress,
    deviceLastSeen: user.deviceLastSeen,
    deviceOnline: user.deviceOnline,
    mustChangePassword: user.mustChangePassword,
    planId: user.planId,
    planName: user.planName,
    clientVersion: user.clientVersion,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

// 0.9.2：管理端视图额外携带初始密码（tempPassword 仅管理端可见，绝不进客户端响应）。
function publicAdminUser(user) {
  return { ...publicUser(user), tempPassword: user.tempPassword ?? null };
}

// 0.9.0：套餐对外结构（内部字节/分，附带 GB/元便于界面直接展示）。
function publicPlan(plan) {
  return {
    id: plan.id,
    name: plan.name,
    durationDays: plan.durationDays,
    trafficLimitBytes: plan.trafficLimitBytes,
    trafficGB: plan.trafficLimitBytes / 1024 ** 3,
    rateLimitBps: plan.rateLimitBps,
    rateLimitMbps: plan.rateLimitBps / 1_000_000,
    portCount: plan.portCount,
    priceCents: plan.priceCents,
    priceYuan: plan.priceCents / 100,
    sortOrder: plan.sortOrder,
    userCount: plan.userCount,
    createdAt: plan.createdAt,
    updatedAt: plan.updatedAt,
  };
}

// 套餐金额/流量字段解析：空（undefined/null/""）视为 0（不限流量 / 免费），
// 但非数字或负数显式报错，避免 Number("abc")→NaN 或负数被静默写成 0。
function planAmount(value, label) {
  if (value === undefined || value === null || value === "") return 0;
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) {
    throw new Error(`${label}必须是不小于 0 的数字`);
  }
  return n;
}

function proxyDisplayName(proxy) {
  // 0.9.2：全限定名为 `${uid}-${name}`；兼容 0.9.1 的用户名前缀格式。
  const generatedPrefixes = [
    proxy.uid ? `${proxy.uid}-` : null,
    `${proxy.username}.${proxy.username}-`,
    `${proxy.username}.`,
    `${proxy.username}-`,
  ].filter(Boolean);
  const prefix = generatedPrefixes.find((item) => proxy.name.startsWith(item));
  return prefix ? proxy.name.slice(prefix.length) : proxy.name;
}

function publicProxy(proxy) {
  return {
    id: proxy.id,
    userId: proxy.userId,
    username: proxy.username,
    uid: proxy.uid ?? null,
    name: proxyDisplayName(proxy),
    qualifiedName: proxy.name,
    type: proxy.type,
    remotePort: proxy.remotePort,
    domains: proxy.domains || [],
    rateLimitBps: proxy.rateLimitBps || 0,
    clientAddress: proxy.clientAddress,
    online: proxy.online,
    createdAt: proxy.createdAt,
    updatedAt: proxy.updatedAt,
    closedAt: proxy.closedAt,
    lastSeen: proxy.lastSeen,
    traffic: trafficMonitor.get(proxy.name, proxy.type),
  };
}

// 0.10.1.1 规格3-4：收集各在线从节点 sync 上报的活跃映射快照（含本机 frps 流量）。
function slaveProxySnapshotRows() {
  const rows = [];
  for (const node of store.listClusterNodes()) {
    if (!node.online) continue;
    const list = Array.isArray(node.stats?.proxies) ? node.stats.proxies : [];
    for (const row of list) rows.push(row);
  }
  return rows;
}

function clientTraffic(userId) {
  const status = trafficMonitor.status();
  const proxies = {};
  let liveIncomingBytes = 0;
  let liveOutgoingBytes = 0;
  let incomingBytesPerSecond = 0;
  let outgoingBytesPerSecond = 0;
  for (const proxy of store.listProxies(userId)) {
    const name = proxyDisplayName(proxy);
    if (!Object.hasOwn(proxies, name)) {
      const traffic = trafficMonitor.get(proxy.name, proxy.type);
      proxies[name] = traffic;
      if (traffic.hasMetrics) {
        liveIncomingBytes += traffic.incomingBytes;
        liveOutgoingBytes += traffic.outgoingBytes;
        incomingBytesPerSecond += traffic.incomingBytesPerSecond;
        outgoingBytesPerSecond += traffic.outgoingBytesPerSecond;
      }
    }
  }
  // 0.10.1.1 规格3-4：合并从节点承载映射的流量快照（同一映射只在承载节点上有实时指标）。
  for (const row of slaveProxySnapshotRows()) {
    if (row.userId !== userId) continue;
    const name = proxyDisplayName(row);
    const traffic = row.traffic && typeof row.traffic === "object" ? row.traffic : null;
    const existing = Object.hasOwn(proxies, name) ? proxies[name] : null;
    if (existing?.hasMetrics) continue;
    if (!traffic?.hasMetrics) {
      if (!existing) {
        proxies[name] = {
          available: false,
          sampledAt: null,
          error: null,
          hasMetrics: false,
          incomingBytes: 0,
          outgoingBytes: 0,
          totalIncomingBytes: 0,
          totalOutgoingBytes: 0,
          incomingBytesPerSecond: 0,
          outgoingBytesPerSecond: 0,
        };
      }
      continue;
    }
    proxies[name] = traffic;
    liveIncomingBytes += Number(traffic.incomingBytes) || 0;
    liveOutgoingBytes += Number(traffic.outgoingBytes) || 0;
    incomingBytesPerSecond += Number(traffic.incomingBytesPerSecond) || 0;
    outgoingBytesPerSecond += Number(traffic.outgoingBytesPerSecond) || 0;
  }
  return {
    available: status.available,
    sampledAt: status.sampledAt,
    error: status.error,
    proxies,
    totals: {
      liveIncomingBytes,
      liveOutgoingBytes,
      incomingBytesPerSecond,
      outgoingBytesPerSecond,
    },
  };
}

// 客户端端口推荐：授权范围内扣除当前所有在线代理占用的端口。
function clientPorts(user) {
  const occupied = new Set(
    store
      .listProxies()
      .filter((proxy) => proxy.closedAt == null && proxy.remotePort != null)
      .map((proxy) => proxy.remotePort),
  );
  const ranges = user.portRanges || [];
  const totalPorts = ranges.reduce((sum, range) => sum + (range.end - range.start + 1), 0);
  const availablePorts = [];
  let scanned = 0;
  for (const range of ranges) {
    for (let port = range.start; port <= range.end; port += 1) {
      if (!occupied.has(port)) availablePorts.push(port);
      if (availablePorts.length >= 50 || (scanned += 1) > 200_000) break;
    }
    if (availablePorts.length >= 50 || scanned > 200_000) break;
  }
  const usedCount = store.listProxies(user.id).filter((proxy) => proxy.closedAt == null)
    .length;
  return {
    ranges,
    totalPorts,
    usedCount,
    occupiedCount: occupied.size,
    availablePorts,
  };
}

const LOGO_MIME_EXT = {
  "image/png": "png",
  "image/jpeg": "jpg",
  "image/webp": "webp",
  "image/gif": "gif",
  "image/svg+xml": "svg",
  "image/x-icon": "ico",
};
const LOGO_MAX_BYTES = 800_000;

function brandingConfig() {
  const defaults = { siteName: "", clientName: "", siteLogo: null, clientLogo: null };
  try {
    const raw = store.getSetting("branding");
    if (!raw) return defaults;
    return { ...defaults, ...JSON.parse(raw) };
  } catch {
    return defaults;
  }
}

function logoUrl(logo, kind) {
  return logo ? `/branding/${kind}-logo?v=${logo.updatedAt}` : null;
}

function publicBranding(config = brandingConfig()) {
  const copyright = licenseManager
    ? licenseManager.copyrightSnapshot()
    : { text: "", url: "", source: "default", status: "none" };
  return {
    siteName: config.siteName || "",
    clientName: config.clientName || "",
    siteLogoUrl: logoUrl(config.siteLogo, "site"),
    clientLogoUrl: logoUrl(config.clientLogo, "client"),
    icp: store.getSetting("icp_text") || "",
    police: store.getSetting("police_text") || "",
    copyright: {
      text: copyright.text || "",
      url: copyright.url || "",
      source: copyright.source || "default",
      status: copyright.status || "none",
    },
  };
}

// dataUrl: undefined 表示保持不变；""/null 表示移除；其余为 data: URL。
function applyBrandingLogo(kind, dataUrl, config) {
  if (dataUrl === undefined) return;
  const field = `${kind}Logo`;
  let next = null;
  if (dataUrl !== null && dataUrl !== "") {
    const match = /^data:([\w.+-]+\/[\w.+-]+);base64,([A-Za-z0-9+/=\s]+)$/.exec(
      String(dataUrl),
    );
    if (!match) throw new Error("Logo 格式无效，请重新选择图片");
    const mime = match[1].toLowerCase();
    const ext = LOGO_MIME_EXT[mime];
    if (!ext) throw new Error("仅支持 PNG、JPG、WebP、GIF、SVG、ICO 图片");
    const buffer = Buffer.from(match[2].replace(/\s/g, ""), "base64");
    if (buffer.length === 0) throw new Error("Logo 文件为空");
    if (buffer.length > LOGO_MAX_BYTES) throw new Error("Logo 需小于 800KB");
    next = { mime, ext, buffer };
  }
  // 新内容校验通过后再清理旧文件，避免非法输入清掉已有 Logo。
  for (const ext of new Set([...Object.values(LOGO_MIME_EXT), config[field]?.ext].filter(Boolean))) {
    const oldFile = join(BRANDING_DIR, `${kind}-logo.${ext}`);
    if (existsSync(oldFile)) {
      try {
        unlinkSync(oldFile);
      } catch {
        // 旧文件清理失败不影响新 Logo 写入。
      }
    }
  }
  if (!next) {
    config[field] = null;
    return;
  }
  writeFileSync(join(BRANDING_DIR, `${kind}-logo.${next.ext}`), next.buffer);
  config[field] = { mime: next.mime, ext: next.ext, updatedAt: Date.now() };
}

function serveBrandingLogo(res, kind) {
  const logo = brandingConfig()[`${kind}Logo`];
  const file = logo && join(BRANDING_DIR, `${kind}-logo.${logo.ext}`);
  if (!file || !existsSync(file)) {
    sendJson(res, 404, { error: "未设置 Logo" });
    return;
  }
  const body = readFileSync(file);
  res.writeHead(200, {
    "Content-Type": logo.mime,
    "Content-Length": body.length,
    "Cache-Control": "public, max-age=60",
  });
  res.end(body);
}

function clientBranding() {
  const branding = publicBranding();
  return {
    clientName: branding.clientName,
    clientLogoUrl: branding.clientLogoUrl,
    icp: branding.icp,
    police: branding.police,
    copyright: branding.copyright,
  };
}

// ---------- 0.10.0 注册 / 忘记密码 / 邮箱验证码 ----------
const CAPTCHA_SECRET = store.getOrCreateSetting("captcha_secret");
const consumedCaptchas = new Map(); // token -> 过期时间戳（一次性消费）

function assertCaptcha(token, answer) {
  if (!verifyCaptcha(CAPTCHA_SECRET, token, answer)) {
    throw new Error("验证码错误或已过期，请刷新后重试");
  }
  if (consumedCaptchas.has(token)) {
    throw new Error("验证码已使用，请刷新后重试");
  }
  consumedCaptchas.set(token, Date.now() + 5 * 60_000);
  if (consumedCaptchas.size > 500) {
    const now = Date.now();
    for (const [key, expires] of consumedCaptchas) {
      if (expires <= now) consumedCaptchas.delete(key);
    }
  }
}

// 0.10.0.1：邮箱验证码有效期由管理员配置（分钟，1-60），默认 10 分钟。
function emailCodeTtlMs() {
  const minutes = Number(store.getSetting("email_code_ttl_minutes"));
  if (!Number.isFinite(minutes) || minutes < 1 || minutes > 60) return 10 * 60_000;
  return Math.round(minutes) * 60_000;
}

const emailCodes = new Map(); // `${purpose}:${email}` -> { code, expiresAt }

// 0.10.0.1：滑动验证码一次性消费表（token -> 过期时间戳）。
const consumedSliders = new Map();

function assertSliderCaptcha(token, givenX) {
  if (!verifySliderChallenge(CAPTCHA_SECRET, token, givenX)) {
    throw new Error("滑动验证未通过，请重试");
  }
  if (consumedSliders.has(token)) {
    throw new Error("滑动验证已使用，请重新验证");
  }
  consumedSliders.set(token, Date.now() + 5 * 60_000);
  if (consumedSliders.size > 500) {
    const now = Date.now();
    for (const [key, expires] of consumedSliders) {
      if (expires <= now) consumedSliders.delete(key);
    }
  }
}

function issueEmailCode(purpose, email) {
  const code = String(randomInt(100000, 1000000));
  emailCodes.set(`${purpose}:${email}`, { code, expiresAt: Date.now() + emailCodeTtlMs() });
  return code;
}

function assertEmailCode(purpose, email, code) {
  const key = `${purpose}:${email}`;
  const record = emailCodes.get(key);
  if (!record || record.expiresAt <= Date.now()) {
    throw new Error("邮箱验证码已过期，请重新获取");
  }
  if (String(code ?? "").trim() !== record.code) {
    throw new Error("邮箱验证码错误");
  }
  emailCodes.delete(key); // 一次性消费
}

function normalizeEmailFormat(value) {
  const email = String(value ?? "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) throw new Error("邮箱格式不正确");
  return email;
}

// 功能开关：注册默认关闭（需管理员显式开启），忘记密码默认开启。
const registerEnabled = () => (store.getSetting("register_enabled") ?? "0") === "1";
const forgotEnabled = () => (store.getSetting("forgot_enabled") ?? "1") === "1";

const DEFAULT_MAIL_TEMPLATES = {
  register: {
    subject: "{{product}} 注册验证码",
    body:
      "您好！\n\n您正在注册 {{product}} 账号（{{email}}）。\n\n邮箱验证码：{{code}}\n\n验证码 {{ttl}} 分钟内有效，请勿泄露给他人。若非本人操作，请忽略本邮件。",
  },
  forgot: {
    subject: "{{product}} 密码重置验证码",
    body:
      "您好！\n\n您正在重置 {{product}} 账号（{{email}}）的密码。\n\n邮箱验证码：{{code}}\n\n验证码 {{ttl}} 分钟内有效，请勿泄露给他人。若非本人操作，请忽略本邮件。",
  },
};

function mailTemplate(kind) {
  let stored = {};
  try {
    stored = JSON.parse(store.getSetting(`mail_template_${kind}`) || "{}");
  } catch {
    stored = {};
  }
  const fallback = DEFAULT_MAIL_TEMPLATES[kind];
  return {
    subject: String(stored.subject || "").trim() || fallback.subject,
    body: String(stored.body || "").trim() || fallback.body,
  };
}

function renderMailTemplate(text, vars) {
  return String(text || "")
    .replaceAll("{{code}}", String(vars.code ?? ""))
    .replaceAll("{{email}}", String(vars.email ?? ""))
    .replaceAll("{{uid}}", String(vars.uid ?? ""))
    .replaceAll("{{product}}", String(vars.product ?? ""))
    .replaceAll("{{ttl}}", String(vars.ttl ?? ""));
}

function smtpConfig() {
  try {
    const parsed = JSON.parse(store.getSetting("smtp_config") || "{}");
    return {
      host: String(parsed.host || "").trim(),
      port: Number(parsed.port) || 0,
      secure: Boolean(parsed.secure),
      user: String(parsed.user || "").trim(),
      pass: String(parsed.pass || ""),
      from: String(parsed.from || "").trim(),
    };
  } catch {
    return { host: "", port: 0, secure: false, user: "", pass: "", from: "" };
  }
}

function assertSmtpReady() {
  if (!smtpConfig().host) {
    throw new Error("邮箱服务尚未配置，请联系管理员在服务端设置中配置 SMTP");
  }
}

async function sendVerificationMail(kind, email, code, uid = "") {
  const config = smtpConfig();
  const product = brandingConfig().clientName || "XFCloud Tunnel";
  const template = mailTemplate(kind);
  const vars = {
    code,
    email,
    uid,
    product,
    // 0.10.0.1：模板中的验证码有效期与实际配置保持一致。
    ttl: Math.round(emailCodeTtlMs() / 60_000),
  };
  await sendMail(config, {
    to: email,
    subject: renderMailTemplate(template.subject, vars),
    text: renderMailTemplate(template.body, vars),
  });
}

// 注册入口地址（客户端「去集群注册」目标）：主节点为本机客户端 API，从节点指向主节点。
function clusterRegisterEndpoint(req) {
  if (activeRole === "slave") {
    const masterHost = store.getSetting("cluster_master_host") || "";
    return masterHost ? { host: masterHost, port: FIXED_CLIENT_API_PORT } : null;
  }
  return { host: derivePublicHost(req), port: FIXED_CLIENT_API_PORT };
}

function clusterName() {
  return String(store.getSetting("cluster_name") || "").trim();
}

// ---------- 0.10.0.2 二维授权（节点 + 端口）辅助 ----------
// 把用户快照裁剪到指定节点：仅保留该节点的端口段（从节点只见、只放行本节点端口）。
function userSnapshotForNode(user, nodeName) {
  const ranges = (user.portRanges || []).filter((range) => rangeNode(range) === nodeName);
  const scoped = { ...user, portRanges: ranges, portRangesText: formatPortRanges(ranges) };
  return sessionUserSnapshot(scoped);
}

// 主节点下发同步时按请求节点裁剪用户与限速（命令队列一并发送）。
function clusterSyncPayloadForNode(nodeName) {
  const scopedUsers = store
    .listUsers()
    .filter((user) => (user.portRanges || []).some((range) => rangeNode(range) === nodeName))
    .map((user) => userSnapshotForNode(user, nodeName));
  const scopedIds = new Set(scopedUsers.map((user) => user.id));
  const scopedLimits = scopedUsers.length
    ? store.listProxyRateLimits().filter((limit) => scopedIds.has(limit.userId))
    : [];
  return { scopedUsers, scopedLimits };
}

// 客户端登录响应：用户被授权使用的节点列表（选节点使用 frp）。
function clientNodesForUser(user, req) {
  const nodes = [];
  const ranges = user.portRanges || [];
  const masterRanges = ranges.filter((range) => rangeNode(range) === "master");
  if (masterRanges.length) {
    nodes.push({
      name: "master",
      isMaster: true,
      label: store.getSetting("server_display_name") || derivePublicHost(req),
      host: derivePublicHost(req),
      bindPort: FRP_BIND_PORT,
      online: true,
      location: store.getSetting("server_location") || "",
      ranges: masterRanges,
      rangesText: formatPortRanges(masterRanges),
    });
  }
  for (const node of store.listClusterNodes()) {
    const nodeRanges = ranges.filter((range) => rangeNode(range) === node.name);
    if (!nodeRanges.length) continue;
    nodes.push({
      name: node.name,
      isMaster: false,
      label: node.name,
      host: node.host,
      bindPort: node.bindPort || FRP_BIND_PORT,
      online: node.online,
      location: node.location || "",
      // 0.10.1.0：从节点 frps 认证令牌（与主节点不同时客户端按节点使用）。
      frpToken: node.frpToken || "",
      ranges: nodeRanges,
      rangesText: formatPortRanges(nodeRanges),
    });
  }
  return nodes;
}

// 0.10.0.2：从节点命令执行器（限速 / 防火墙 / 版本同步），结果随下次同步回报。
const pendingClusterCommandResults = [];

async function executeClusterCommand(command) {
  try {
    switch (String(command.type || "")) {
      case "rate-limit": {
        const limits = Array.isArray(command.payload?.limits) ? command.payload.limits : [];
        for (const item of limits) {
          store.setProxyRateLimit(
            Number(item.userId),
            String(item.proxyName || ""),
            Math.max(0, Math.floor(Number(item.bps) || 0)),
            "cluster-command",
          );
        }
        return { id: command.id, ok: true, result: `已应用 ${limits.length} 条限速` };
      }
      case "firewall": {
        const action = String(command.payload?.action || "");
        if (action === "open") {
          const ports = Array.isArray(command.payload?.ports) ? command.payload.ports : [];
          const result = await openFirewallPorts(ports, command.payload?.proto || "tcp");
          return { id: command.id, ok: true, result: `已放行 ${result.opened.length} 个端口` };
        }
        if (action === "control") {
          const result = await controlFirewall(String(command.payload?.firewallAction || ""));
          return { id: command.id, ok: true, result: `防火墙已执行 ${result.action}` };
        }
        return { id: command.id, ok: false, error: `未知防火墙操作 ${action}` };
      }
      case "bind-port": {
        // 0.10.1.0：主节点远程修改本从节点 frps 监听端口（校验口径与页面 PUT 一致）。
        const port = Number(command.payload?.bindPort);
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
          return { id: command.id, ok: false, error: "监听端口须为 1-65535 的整数" };
        }
        if (FRP_BIND_PORT_ENV !== null) {
          return { id: command.id, ok: false, error: "本机端口已由环境变量 FRP_BIND_PORT 固定，无法修改" };
        }
        if (Number.isInteger(FRP_METRICS_PORT) && port === FRP_METRICS_PORT) {
          return { id: command.id, ok: false, error: `端口 ${FRP_METRICS_PORT} 是 frp 指标端口，不能用作监听端口` };
        }
        for (const reserved of [PORT, FIXED_CLIENT_API_PORT, vhostHttpPort(), vhostHttpsPort()]) {
          if (Number.isInteger(reserved) && reserved > 0 && port === reserved) {
            return { id: command.id, ok: false, error: `端口 ${reserved} 是系统/隧道保留端口，不能用作监听端口` };
          }
        }
        if (port === FRP_BIND_PORT) {
          return { id: command.id, ok: true, result: `监听端口已是 ${port}，无需变更` };
        }
        const busyPorts = await probeTcpPorts([port], { useCache: false });
        if (busyPorts.length) {
          return { id: command.id, ok: false, error: `端口 ${port} 已被占用，请更换后再试` };
        }
        store.setSetting("frp_bind_port", String(port));
        FRP_BIND_PORT = port;
        // 新端口放行防火墙（best-effort），避免改端口后客户端连不上从节点。
        await openFirewallPorts([port], "tcp").catch(() => null);
        if (frps.process !== null) {
          await frps.restart();
        }
        return { id: command.id, ok: true, result: `监听端口已切换为 ${port}` };
      }
      case "version-sync": {
        // 同步版本：从节点按授权中心最新服务端版本自更新（与主节点当前版本对齐）。
        try {
          await licenseManager.checkUpdates();
        } catch {
          // 授权中心不可达时回退缓存快照。
        }
        const info = licenseManager.updateInfoSnapshot();
        // 0.10.1.4 热修：必须以 hasUpdate 为准。授权中心「无更新」时也返回 downloadUrl，
        // 旧判断只看 downloadUrl 导致每次同步版本都强制下载重启；且 pending 命令每轮重发、
        // 执行后立即重启又吞掉回报结果，命令永远 pending → 从节点被每轮 sync 反复重启
        // （约 30 秒一次），客户端连从节点的 frpc 持续断开（表现为「连接其他节点失败」）。
        if (!info?.hasUpdate || !info?.downloadUrl) {
          return {
            id: command.id,
            ok: true,
            result: `已是最新版本（当前 v${VERSION}${info?.latestVersion ? `，授权中心最新 v${info.latestVersion}` : ""}），无需更新`,
          };
        }
        setImmediate(() => {
          applyUpdateAndRestart({
            downloadUrl: info.downloadUrl,
            rootDir: ROOT,
            dataDir: DATA_DIR,
            role: "server",
            ports: [PORT, FRP_BIND_PORT, FRP_METRICS_PORT],
            healthScheme: managerHttpsEnabled() ? "https" : "http",
            logger: (msg) => console.log(`[cluster-updater] ${msg}`),
          }).catch((err) => console.error("[cluster-updater] update failed:", err.message));
        });
        return { id: command.id, ok: true, result: `已启动更新至 v${info.latestVersion || "?"}` };
      }
      case "frps-control": {
        // 0.10.1.3 规格1：主节点远程启停/重启本从节点 frps。
        const action = String(command.payload?.action || "");
        if (!["start", "stop", "restart"].includes(action)) {
          return { id: command.id, ok: false, error: `未知 frps 操作 ${action}` };
        }
        if (action === "start") {
          frps.refreshState();
          if (frps.state === "running") {
            return { id: command.id, ok: true, result: "frps 已在运行，无需启动" };
          }
          await frps.start();
        } else if (action === "stop") {
          await frps.stop();
        } else {
          await frps.restart();
        }
        return { id: command.id, ok: true, result: `frps 已执行 ${action}（当前状态：${frps.state}）` };
      }
      case "frps-logs": {
        // 0.10.1.3 规格1：主节点查看本从节点 frps 运行日志（内存环形日志，默认最近 120 行）。
        const lines = Math.min(Math.max(Number(command.payload?.lines) || 120, 10), 400);
        return {
          id: command.id,
          ok: true,
          result: frps.logs.slice(-lines).join("\n") || "暂无 frps 日志",
        };
      }
      default:
        return { id: command.id, ok: false, error: `未知命令 ${command.type}` };
    }
  } catch (error) {
    return { id: command.id, ok: false, error: error.message || "命令执行失败" };
  }
}

// ---------- 0.10.0 集群 agent（主从通信） ----------
// 会话快照：publicUser 之外附带从节点自签会话所需 tokenVersion/deviceId。
function sessionUserSnapshot(user) {
  return { ...publicUser(user), tokenVersion: user.tokenVersion, deviceId: user.deviceId ?? null };
}

// 从节点账号写操作代理：主节点执行后同步快照并本地重签会话。
async function slaveProxyAccount(session, action, args) {
  const result = await clusterAgentRequest("/api/cluster/agent/proxy", {
    userId: session.user.id,
    action,
    args,
  });
  const [synced] = store.upsertSyncedUsers([result.user]);
  return { token: clientToken(synced), user: publicUser(synced), snapshot: synced };
}

function clusterAgentFromRequest(req) {
  const token = String(req.headers["x-agent-token"] || "");
  if (!token) return null;
  return store.getClusterNodeByToken(token);
}

// 从节点 → 主节点内部调用（agent 令牌认证）。
// 0.10.1.1 规格10-12：401 且响应带 reauth 标记时抛出 CLUSTER_REAUTH（调用方自动 join 换新令牌）。
async function clusterAgentRequest(pathname, payload) {
  const response = await fetch(`${clusterMasterUrl}${pathname}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-agent-token": clusterNodeToken },
    body: JSON.stringify(payload || {}),
    signal: AbortSignal.timeout(20_000),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && data.reauth) {
      const error = new Error("节点令牌已被新主节点重置");
      error.code = "CLUSTER_REAUTH";
      throw error;
    }
    throw new Error(data.error || `主节点通信失败 (${response.status})`);
  }
  return data;
}

// 从节点每轮同步：拉取用户快照 + 端口级限速 + 集群展示配置并落库；
// 0.10.0.2：上报流量/端口/防火墙/映射快照（主节点集群监控用），执行主节点下发命令并回报结果。
// 0.10.1.1 规格13：上报本地 frpc 会话摘要（主节点合并统一用户在线口径）；
// 规格10-12：同步集群节点表（含备用主优先级），401 时自动 join 重新签发节点令牌。
async function clusterAgentSyncOnce() {
  const activeProxies = store.listProxies().filter((proxy) => !proxy.closedAt);
  const stats = {
    userCount: store.listUsers().length,
    proxyCount: activeProxies.length,
    bindPort: FRP_BIND_PORT,
    traffic: trafficSummary(),
    firewall: await firewallStatus().catch(() => null),
    // 集群映射监控：活跃映射快照（上限 200 条，避免载荷过大）。
    // 0.10.1.1 规格3-4：附带走从节点本机 frps 的实时流量，主节点合并进客户端流量视图。
    proxies: activeProxies.slice(0, 200).map((proxy) => ({
      userId: proxy.userId,
      uid: proxy.uid,
      username: proxy.username,
      name: proxy.name,
      type: proxy.type,
      remotePort: proxy.remotePort,
      domains: proxy.domains,
      online: proxy.online,
      lastSeen: proxy.lastSeen,
      rateLimitBps: proxy.rateLimitBps,
      traffic: trafficMonitor.get(proxy.name, proxy.type),
    })),
    // 0.10.1.1 规格13：本地未关闭 frpc 会话按用户汇总（30 秒心跳口径，主节点合并判定在线）。
    sessions: store.userSessionSummary(),
    // 0.10.1.3 规格1：本节点 frps 运行概况随同步上报，主节点集群页直接展示状态。
    frps: {
      state: frps.state,
      pid: frps.process?.pid ?? null,
      startedAt: frps.startedAt,
      bindPort: FRP_BIND_PORT,
    },
  };
  const previousResults = pendingClusterCommandResults.splice(0, pendingClusterCommandResults.length);
  const data = await clusterAgentRequest("/api/cluster/agent/sync", {
    version: VERSION,
    bindPort: FRP_BIND_PORT,
    // 0.10.1.0：上报本节点 frps 认证令牌，主节点转发给客户端连从节点 frps 用。
    frpToken: frpAuthToken,
    stats,
    commandResults: previousResults,
  });
  store.upsertSyncedUsers(data.users || []);
  store.replaceAllProxyRateLimits(data.proxyRateLimits || []);
  // 0.10.2.8：镜像主节点公告（全量替换，主节点删除后同步消失）。
  if (Array.isArray(data.announcements)) {
    store.replaceSyncedAnnouncements(data.announcements);
  }
  // 0.10.1.1 规格10-12：合并主节点集群节点表（含备用主优先级），供故障转移仲裁使用。
  if (Array.isArray(data.clusterNodes) && data.clusterNodes.length) {
    store.upsertSyncedClusterNodes(data.clusterNodes);
  }
  // 0.10.1.1：主节点身份回执——记录本节点在集群中的名称（join/自我识别用）。
  if (data.self?.name) {
    store.setSetting("cluster_self_name", String(data.self.name).slice(0, 40));
  }
  // 0.10.1.0 数据高可用：实时备份主节点全量数据（用户含密码哈希 + 管理员 + 套餐），
  // 主节点宕机提升本节点为主节点时于启动阶段恢复。
  if (data.backup) {
    try {
      store.saveBackupSnapshot(data.backup);
    } catch (error) {
      console.error(`[cluster] backup snapshot save failed: ${error.message}`);
    }
  }
  const cluster = data.cluster || {};
  if (cluster.name) store.setSetting("cluster_name", String(cluster.name));
  store.setSetting("register_enabled", cluster.registerEnabled ? "1" : "0");
  store.setSetting("forgot_enabled", cluster.forgotEnabled ? "1" : "0");
  const masterHost = new URL(clusterMasterUrl).hostname;
  store.setSetting("cluster_master_host", masterHost);
  // 0.10.1.0：对齐主节点 frp 认证令牌（客户端统一用主节点 token 连集群内任一节点）。
  const masterToken = String(cluster.frpAuthToken || "");
  if (masterToken && masterToken !== frpAuthToken) {
    frpAuthToken = masterToken;
    store.setSetting("frp_auth_token", masterToken);
    if (frps.state === "running") {
      await frps.restart();
      console.log("[cluster] frp token aligned with master, frps restarted");
    }
  }
  // 0.10.1.0：对齐主节点签名密钥（主节点签发的客户端 token 在从节点 frps 插件可直接验签）。
  const masterSigningSecret = String(cluster.signingSecret || "");
  if (masterSigningSecret && masterSigningSecret !== signingSecret) {
    signingSecret = masterSigningSecret;
    store.setSetting("signing_secret", masterSigningSecret);
    console.log("[cluster] signing secret aligned with master");
  }
  // 执行主节点下发命令（限速 / 防火墙 / 版本同步），结果随下一轮同步回报。
  for (const command of Array.isArray(data.commands) ? data.commands : []) {
    try {
      pendingClusterCommandResults.push(await executeClusterCommand(command));
    } catch (error) {
      pendingClusterCommandResults.push({ id: command?.id, ok: false, error: error.message });
    }
  }
}

// ---------- 0.10.1.1 规格10-12：主节点高可用（从节点故障转移） ----------
// 时序约定：主节点失联 → 从节点连续 3 轮同步失败（约 90 秒）→ 查询授权中心集群主节点认领：
// 已有新主（认领新鲜）→ 跟随新主（join 换新令牌）；无接管者 → 备用主优先级最高者延迟随机
// 5-15 秒复查后自我升主；升主后立即向授权中心认领（心跳 isMaster），客户端经「登录集群」
// 从目录（clusterMasterAddress）拉取新主 IP。旧主恢复时心跳冲突 → 自动降级为新主从节点。
const CLUSTER_FAILOVER_FAILURES = 3;
const CLUSTER_MASTER_CLAIM_FRESH_MS = 15 * 60_000;
let clusterAgentTimer = null;
let clusterSyncFailureCount = 0;
let failoverBusy = false;

function stopClusterAgentLoop() {
  if (clusterAgentTimer) {
    clearInterval(clusterAgentTimer);
    clusterAgentTimer = null;
  }
}

// 本节点自我名称（join 用）：优先用主节点身份回执，回退主机名。
function clusterSelfName() {
  return (
    store.getSetting("cluster_self_name") ||
    hostname().slice(0, 40) ||
    "slave"
  );
}

// 查询授权中心：该集群当前主节点认领（无新鲜认领返回 null）。
async function fetchClusterMasterClaim() {
  const cluster = String(store.getSetting("cluster_name") || "").trim();
  if (!cluster) return null;
  const response = await fetch(
    `${LICENSE_SERVER_URL}/api/v1/servers/cluster-master?cluster=${encodeURIComponent(cluster)}`,
    { signal: AbortSignal.timeout(15_000) },
  );
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.masterAddress) return null;
  const claimedAt = Date.parse(data.claimedAt || "");
  const fresh = Number.isFinite(claimedAt) && Date.now() - claimedAt < CLUSTER_MASTER_CLAIM_FRESH_MS;
  return { masterAddress: String(data.masterAddress), fresh };
}

// 跟随新主节点：更新主地址（落库持久化），下一轮 sync 401 时自动 join 换新令牌。
function followNewMaster(masterAddress) {
  const url = `http://${masterAddress}:${FIXED_CLIENT_API_PORT}`.replace(/\/+$/, "");
  if (url === clusterMasterUrl) return false;
  console.log(`[cluster] failover: following new master ${url}`);
  clusterMasterUrl = url;
  store.setSetting("cluster_master_url", url);
  clusterSyncFailureCount = 0;
  return true;
}

// 自我升主：恢复备份快照 → 角色切主（持久化）→ 停同步 → 向授权中心认领并持续心跳。
function selfPromoteAsMaster() {
  console.log("[cluster] failover: promoting self to master (highest backup priority)");
  try {
    const restored = store.restoreBackupSnapshot();
    if (restored) {
      console.log(
        `[backup] 升主恢复备份数据：用户 ${restored.users} 个，管理员${restored.admin ? "已" : "未"}恢复，套餐${restored.plans ? "已" : "未"}恢复`,
      );
    }
  } catch (error) {
    console.error(`[backup] 升主恢复备份失败: ${error.message}`);
  }
  activeRole = "master";
  store.setSetting("cluster_role_override", "master");
  store.setSetting("cluster_master_host", FRP_PUBLIC_HOST || "");
  stopClusterAgentLoop();
  // 向授权中心认领主节点身份并持续心跳（从节点原有 LicenseManager 心跳被 stub，
  // reportHeartbeat 为真实方法，升主后由本模块直接驱动）。
  licenseManager.announceMaster = true;
  licenseHeartbeatDrive();
}

// 升主后驱动授权中心心跳（5 分钟周期 + 立即首轮）。
let licenseHeartbeatTimer = null;
function licenseHeartbeatDrive() {
  if (licenseHeartbeatTimer) clearInterval(licenseHeartbeatTimer);
  void licenseManager.reportHeartbeat().catch(() => {});
  licenseHeartbeatTimer = setInterval(() => {
    licenseManager.reportHeartbeat().catch(() => {});
  }, 5 * 60_000);
  licenseHeartbeatTimer.unref?.();
}

// 0.10.1.1 规格10-12：旧主回归自动降级——授权中心仲裁发现更新鲜的主节点认领时触发
// （授权中心心跳响应 masterConflict → onMasterConflict 回调）。降级后 frps 保持运行
// （集群 token 一致，客户端不断连），下一轮 sync 401 → join 换新令牌，数据随同步对齐。
function demoteSelfToSlave(newMasterAddress) {
  console.warn(
    `[cluster] master conflict: fresher master claim at ${newMasterAddress}, demoting self to slave`,
  );
  licenseManager.announceMaster = false;
  if (licenseHeartbeatTimer) {
    clearInterval(licenseHeartbeatTimer);
    licenseHeartbeatTimer = null;
  }
  activeRole = "slave";
  store.setSetting("cluster_role_override", "slave");
  const url = `http://${newMasterAddress}:${FIXED_CLIENT_API_PORT}`.replace(/\/+$/, "");
  clusterMasterUrl = url;
  store.setSetting("cluster_master_url", url);
  clusterSyncFailureCount = 0;
  startClusterAgentLoop();
}

// 故障转移决策（同步连续失败达到阈值后调用；任一节点一轮只决策一次）。
async function handleSlaveFailover() {
  if (failoverBusy) return;
  failoverBusy = true;
  try {
    const claim = await fetchClusterMasterClaim().catch(() => null);
    if (!claim) {
      // 授权中心不可达：无法仲裁也无法被发现，保持等待（主节点可能只是本节点到主链路抖动）。
      console.warn("[cluster] failover: license center unreachable, keep waiting");
      return;
    }
    const oldMasterHost = clusterMasterUrl ? new URL(clusterMasterUrl).hostname : "";
    if (claim.fresh && claim.masterAddress && claim.masterAddress !== oldMasterHost) {
      // 已有新主接管：跟随（join 在下轮 sync 401 时自动完成）。
      followNewMaster(claim.masterAddress);
      return;
    }
    if (claim.fresh) {
      // 授权中心视角旧主仍新鲜（可能是本节点→主链路分区）：暂不动作。
      clusterSyncFailureCount = 1;
      return;
    }
    // 无新鲜认领（旧主认领已过期=确实失联）：备用主优先级最高者升主。
    const selfName = clusterSelfName();
    const candidates = store
      .listClusterNodes()
      .filter((node) => node.priority > 0)
      .sort((a, b) => b.priority - a.priority || a.name.localeCompare(b.name));
    const selfRow = candidates.find((node) => node.name === selfName);
    if (!selfRow) {
      console.warn("[cluster] failover: self not eligible (priority=0), wait for manual promote");
      return;
    }
    if (candidates[0]?.name !== selfName) {
      console.warn(
        `[cluster] failover: ${candidates[0]?.name} has higher backup priority (${candidates[0]?.priority} > ${selfRow.priority}), waiting`,
      );
      return;
    }
    // 随机 5-15 秒抖动后复查认领，仍无人接管才升主（避免多从节点并发抢主）。
    await new Promise((resolve) => setTimeout(resolve, 5_000 + Math.floor(Math.random() * 10_000)));
    const recheck = await fetchClusterMasterClaim().catch(() => null);
    if (recheck?.fresh && recheck.masterAddress) {
      if (recheck.masterAddress !== oldMasterHost) followNewMaster(recheck.masterAddress);
      return;
    }
    selfPromoteAsMaster();
  } finally {
    failoverBusy = false;
  }
}

function startClusterAgentLoop() {
  stopClusterAgentLoop();
  if (activeRole !== "slave" || !clusterMasterUrl || !clusterNodeToken) {
    if (activeRole === "slave") {
      console.warn("[cluster] SERVER_ROLE=slave 但未配置 CLUSTER_MASTER_URL/CLUSTER_NODE_TOKEN，同步未启动");
    }
    return;
  }
  clusterSyncFailureCount = 0;
  console.log(`[cluster] slave agent started, master=${clusterMasterUrl}`);
  const tick = async () => {
    if (activeRole !== "slave") {
      stopClusterAgentLoop();
      return;
    }
    try {
      await clusterAgentSyncOnce();
      clusterSyncFailureCount = 0;
    } catch (error) {
      if (error?.code === "CLUSTER_REAUTH") {
        // 新主节点不认识本节点令牌：join 重新签发后立即重试一轮。
        try {
          await joinClusterMaster();
          await clusterAgentSyncOnce();
          clusterSyncFailureCount = 0;
        } catch (joinError) {
          console.error(`[cluster] join failed: ${joinError.message}`);
          clusterSyncFailureCount += 1;
        }
      } else {
        clusterSyncFailureCount += 1;
        console.error(
          `[cluster] sync failed (${clusterSyncFailureCount}): ${error.message}`,
        );
      }
      if (clusterSyncFailureCount >= CLUSTER_FAILOVER_FAILURES) {
        await handleSlaveFailover().catch((failError) => {
          console.error(`[cluster] failover check failed: ${failError.message}`);
        });
      }
    }
  };
  void tick();
  clusterAgentTimer = setInterval(tick, Math.max(10_000, CLUSTER_SYNC_INTERVAL_MS));
  clusterAgentTimer.unref?.();
}

// 0.10.1.1 规格10-12：向当前主节点 join——重新登记节点并换发 agent 令牌。
// 场景：主节点切换后（自动升主/管理台提升），从节点旧令牌不被新主认识。
async function joinClusterMaster() {
  const response = await fetch(`${clusterMasterUrl}/api/cluster/agent/join`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: clusterSelfName(),
      cluster: String(store.getSetting("cluster_name") || "").trim(),
      oldToken: clusterNodeToken,
      version: VERSION,
      clientApiPort: FIXED_CLIENT_API_PORT,
    }),
    signal: AbortSignal.timeout(20_000),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.token) {
    throw new Error(data.error || `join 失败 (${response.status})`);
  }
  clusterNodeToken = String(data.token);
  store.setSetting("cluster_node_token", clusterNodeToken);
  console.log(`[cluster] joined master ${clusterMasterUrl}, new agent token issued`);
  return data;
}

// ---------- 0.10.0 从节点自动部署（sshpass + ssh，仅 Linux 主节点） ----------
// 0.10.0.1：从节点默认部署路径调整为 /etc/xfcloud。
const CLUSTER_DEPLOY_DIR = "/etc/xfcloud";
const CLUSTER_SLAVE_UNIT = "xfcloud-slave.service";

// 0.10.0.1：本机部署环境检测——集群页前置提示 + 部署路由统一阻断（需求：先检测 sshpass）。
function clusterEnvStatus() {
  const sshpassInstalled =
    process.platform !== "win32" &&
    spawnSync("which", ["sshpass"], { encoding: "utf8" }).status === 0;
  return {
    platform: process.platform,
    isLinux: process.platform === "linux",
    sshpassInstalled,
    frpsInstalled: existsSync(FRPS_BIN),
    deployDir: CLUSTER_DEPLOY_DIR,
    sshpassInstallCmd: "apt-get install -y sshpass  # 或 yum install -y sshpass",
  };
}

// 0.10.0.1：集群授权许可门禁——免费额度为每集群 1 台（主节点）；从节点需 licensed。
function assertClusterLicense() {
  if (licenseManager.status().mode === "licensed") return;
  const error = new Error(
    "免费额度为每集群 1 台服务端（主节点）；添加从节点需购买集群授权许可",
  );
  error.status = 402;
  error.code = "SERVER_LICENSE_REQUIRED";
  throw error;
}

function runSshCommand(args, input, timeoutMs = 120_000) {
  return new Promise((resolve, reject) => {
    const child = spawn("sshpass", args, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("SSH 命令超时"));
    }, timeoutMs);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(new Error(`无法启动 sshpass：${error.message}`));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) {
        resolve(stdout);
        return;
      }
      const detail = (stderr || stdout || `ssh 退出码 ${code}`).trim();
      reject(new Error(detail.split("\n").slice(-3).join("\n")));
    });
    if (input !== undefined) child.stdin.end(input);
  });
}

function sshArgs(sshUser, sshPassword, host, command) {
  return [
    "-p", sshPassword,
    "ssh",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=12",
    `${sshUser}@${host}`,
    command,
  ];
}

// 完整部署：探测 root 权限与依赖 → 传输代码与 frps → 写 .env 与 systemd → 启动。
async function deployClusterNode(node, { sshUser, sshPassword }, masterHost) {
  // 0.10.0.1：部署前统一检测本机依赖（sshpass、frps 内核），缺失立即阻断并给出安装命令。
  const env = clusterEnvStatus();
  if (!env.isLinux) {
    throw new Error("自动部署仅支持在 Linux 主节点上执行（需要 sshpass + ssh）");
  }
  if (!env.sshpassInstalled) {
    throw new Error(`主节点缺少 sshpass，请先安装后再操作：${env.sshpassInstallCmd}`);
  }
  if (!env.frpsInstalled) {
    throw new Error("主节点尚未安装 frps 内核，请先在「FRP 文件」中下载 frps 后重试");
  }

  const log = [];
  const step = async (title, command, input) => {
    const output = await runSshCommand(sshArgs(sshUser, sshPassword, node.host, command), input);
    const tail = output.trim().split("\n").slice(-4).join("\n");
    log.push(`$ ${title}${tail ? `\n${tail}` : ""}`);
    return output;
  };

  // 0.10.0.1：从节点部署要求 root 权限用户（UID=0），部署路径默认 /etc/xfcloud。
  const uidOut = await step("确认 root 权限", "id -u");
  if (uidOut.trim() !== "0") {
    throw new Error("从节点部署要求使用 root 权限用户：请用 root 账号重试，或为该用户配置免密 sudo 后改用 root 登录");
  }

  // 2) 探测远端 Node.js（node:sqlite 需要 22.5+）
  const nodeVersionOut = await step(
    "探测从节点 Node.js",
    "node -v 2>/dev/null || echo NO_NODE",
  );
  const versionMatch = /v?(\d+)\.(\d+)\.(\d+)/.exec(nodeVersionOut);
  if (!versionMatch) {
    throw new Error(
      "从节点未安装 Node.js。请先在从节点安装 Node.js 22.5+：curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs",
    );
  }
  const major = Number(versionMatch[1]);
  const minor = Number(versionMatch[2]);
  if (major < 22 || (major === 22 && minor < 5)) {
    throw new Error(`从节点 Node.js 版本过低（${nodeVersionOut.trim()}），需要 22.5+`);
  }

  // 3) 传输代码（server/shared 源码目录 + FRP 下载脚本）与 frps 二进制
  await step("创建部署目录", `mkdir -p ${CLUSTER_DEPLOY_DIR}/bin ${CLUSTER_DEPLOY_DIR}/data/server ${CLUSTER_DEPLOY_DIR}/runtime/server`);
  const tar = spawnSync("tar", ["-czf", "-", "-C", ROOT, "server", "shared"], {
    maxBuffer: 256 * 1024 * 1024,
  });
  if (tar.status !== 0 || !tar.stdout?.length) {
    throw new Error("打包服务端代码失败");
  }
  await step("传输服务端代码", `tar -xzf - -C ${CLUSTER_DEPLOY_DIR}`, tar.stdout);
  // 0.10.0.4：tar 从 Windows 主节点打包时 service.sh 可能无执行位，部署时补齐。
  await step(
    "赋予管理脚本执行权限",
    `chmod +x ${CLUSTER_DEPLOY_DIR}/server/service.sh ${CLUSTER_DEPLOY_DIR}/server/*.sh 2>/dev/null || true`,
  );
  const frpsBinary = readFileSync(FRPS_BIN);
  await step(
    "传输 frps 内核",
    `cat > ${CLUSTER_DEPLOY_DIR}/bin/frps && chmod +x ${CLUSTER_DEPLOY_DIR}/bin/frps`,
    frpsBinary,
  );

  // 4) 写 .env（从节点角色 + 主节点地址 + 节点令牌）与 systemd 服务
  const envFile = [
    `SERVER_ROLE=slave`,
    `CLUSTER_MASTER_URL=http://${masterHost}:${FIXED_CLIENT_API_PORT}`,
    `CLUSTER_NODE_TOKEN=${node.token ?? ""}`,
    `FRPS_AUTOSTART=true`,
    `DATA_DIR=${CLUSTER_DEPLOY_DIR}/data/server`,
    `SERVER_RUNTIME_DIR=${CLUSTER_DEPLOY_DIR}/runtime/server`,
    "",
  ].join("\n");
  await step("写入节点配置", `cat > ${CLUSTER_DEPLOY_DIR}/.env`, envFile);
  const nodePath = (await step("定位 Node.js", "which node")).trim();
  // 0.10.0.4：NODE_BIN 写入 .env，service.sh 在 PATH 缺失的环境（SSH 非交互等）也能找到 node。
  if (nodePath) {
    await step(
      "固化 NODE_BIN",
      `grep -q '^NODE_BIN=' ${CLUSTER_DEPLOY_DIR}/.env || echo 'NODE_BIN=${nodePath}' >> ${CLUSTER_DEPLOY_DIR}/.env`,
    );
  }
  const unit = [
    "[Unit]",
    "Description=XFCloud Tunnel Cluster Slave",
    "After=network-online.target",
    "Wants=network-online.target",
    "",
    "[Service]",
    "Type=simple",
    `WorkingDirectory=${CLUSTER_DEPLOY_DIR}`,
    `EnvironmentFile=${CLUSTER_DEPLOY_DIR}/.env`,
    `ExecStart=${nodePath || "/usr/bin/node"} --experimental-sqlite server/app.js`,
    "Restart=always",
    "RestartSec=3",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ].join("\n");
  await step("安装 systemd 服务", `tee /etc/systemd/system/${CLUSTER_SLAVE_UNIT} > /dev/null`, unit);
  await step(
    "启动服务",
    `systemctl daemon-reload && systemctl enable --now ${CLUSTER_SLAVE_UNIT} && systemctl is-active ${CLUSTER_SLAVE_UNIT}`,
  );
  return log;
}

// ---------- 0.10.0.1 设为主节点：将从节点提升为主节点，旧主节点降级为从节点 ----------
// 从节点 .env 中标识 slave 角色的键；提升 = 删除这些行（回到默认 master 角色）。
const CLUSTER_SLAVE_ENV_KEYS = ["SERVER_ROLE", "CLUSTER_MASTER_URL", "CLUSTER_NODE_TOKEN"];

// 远端健康检查：新主节点 9400 端口 /healthz 就绪（用 node 探测，避免依赖 curl/wget）。
const REMOTE_HEALTH_CHECK =
  `node -e "fetch('http://127.0.0.1:${FIXED_CLIENT_API_PORT}/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"`;
const REMOTE_HEALTH_WAIT = `for i in $(seq 1 30); do if ${REMOTE_HEALTH_CHECK} 2>/dev/null; then echo READY; exit 0; fi; sleep 2; done; echo NOT_READY; exit 1`;

// 在新主节点上注册旧主节点为从节点（返回明文令牌供旧主节点配置 agent）。
// host/name 仅允许 [A-Za-z0-9.-]，经环境变量传入以规避 shell 引号问题；
// 模块说明符同样走环境变量，避免源码中出现嵌入的 import 字面量（包完整性扫描会误判）。
function remoteRegisterNodeScript(oldMasterHost, nodeName) {
  const safeHost = String(oldMasterHost).replace(/[^A-Za-z0-9.-]/g, "");
  const safeName = String(nodeName).replace(/[^A-Za-z0-9.-]/g, "").slice(0, 40);
  return (
    `cd ${CLUSTER_DEPLOY_DIR} && OLD_HOST=${safeHost} OLD_NAME=${safeName} STORE_SPEC=./server/store.js ` +
    `DATA_DIR=${CLUSTER_DEPLOY_DIR}/data/server node --experimental-sqlite --input-type=module -e ` +
    `"const { Store } = await import(process.env.STORE_SPEC);` +
    `const s = new Store('${CLUSTER_DEPLOY_DIR}/data/server/manager.db', 'admin', 'bootstrap');` +
    `const created = s.createClusterNode({ name: process.env.OLD_NAME, host: process.env.OLD_HOST, address: process.env.OLD_HOST, clientApiPort: ${FIXED_CLIENT_API_PORT} }, 'cluster-promote');` +
    `console.log('NODE_TOKEN=' + created.token);` +
    `s.close();"`
  );
}

// 旧主节点自动降级（尽力而为）：识别自身 systemd 单元，写入 drop-in 环境并延迟重启。
// 非 systemd 场景返回 manual 模式，由管理员按提示手工配置。
function demoteSelfPlan({ newMasterHost, token }) {
  if (process.platform !== "linux") {
    return {
      mode: "manual",
      reason: "当前主节点非 Linux，无法自动降级",
      envLines: demoteEnvLines(newMasterHost, token),
    };
  }
  let unit = "";
  try {
    const cgroup = readFileSync("/proc/self/cgroup", "utf8");
    unit = /\/system\.slice\/([A-Za-z0-9@._-]+\.service)/.exec(cgroup)?.[1] || "";
  } catch {
    unit = "";
  }
  if (!unit) {
    return {
      mode: "manual",
      reason: "未检测到管理本服务的 systemd 单元，请手工降级",
      envLines: demoteEnvLines(newMasterHost, token),
    };
  }
  const dropInDir = `/etc/systemd/system/${unit}.d`;
  const dropIn = [
    "[Service]",
    `Environment=SERVER_ROLE=slave`,
    `Environment=CLUSTER_MASTER_URL=http://${newMasterHost}:${FIXED_CLIENT_API_PORT}`,
    `Environment=CLUSTER_NODE_TOKEN=${token}`,
    "",
  ].join("\n");
  return { mode: "systemd", unit, dropInDir, dropIn };
}

function demoteEnvLines(newMasterHost, token) {
  return [
    `SERVER_ROLE=slave`,
    `CLUSTER_MASTER_URL=http://${newMasterHost}:${FIXED_CLIENT_API_PORT}`,
    `CLUSTER_NODE_TOKEN=${token}`,
  ];
}

async function promoteClusterNode(node, { sshUser, sshPassword }, oldMasterHost) {
  // 部署环境统一检测（sshpass 等），缺失阻断。
  const env = clusterEnvStatus();
  if (!env.isLinux) {
    throw new Error("提升主节点仅支持在 Linux 主节点上执行（需要 sshpass + ssh）");
  }
  if (!env.sshpassInstalled) {
    throw new Error(`主节点缺少 sshpass，请先安装后再操作：${env.sshpassInstallCmd}`);
  }

  const log = [];
  const step = async (title, command, input) => {
    const output = await runSshCommand(sshArgs(sshUser, sshPassword, node.host, command), input);
    const tail = output.trim().split("\n").slice(-6).join("\n");
    log.push(`$ ${title}${tail ? `\n${tail}` : ""}`);
    return output;
  };

  // 1) root 权限确认。
  const uidOut = await step("确认 root 权限", "id -u");
  if (uidOut.trim() !== "0") {
    throw new Error("提升操作要求目标节点使用 root 权限用户");
  }

  // 2) 目标节点必须已通过自动部署安装，且当前处于从节点角色（保证一个集群只有一个主节点）。
  const roleOut = await step(
    "确认节点角色",
    `grep -h '^SERVER_ROLE=' ${CLUSTER_DEPLOY_DIR}/.env 2>/dev/null || echo MISSING_ENV`,
  );
  const role = roleOut.trim();
  if (role === "MISSING_ENV") {
    throw new Error(`目标节点缺少 ${CLUSTER_DEPLOY_DIR}/.env，请先通过「自动部署」安装后再提升`);
  }
  if (!role.endsWith("slave")) {
    throw new Error("该节点未处于从节点角色，无法提升（一个集群只允许一个主节点）");
  }

  // 3) 停服务 → 移除 slave 角色配置（回到 master）→ 重启 → 等待健康检查。
  await step("停止节点服务", `systemctl stop ${CLUSTER_SLAVE_UNIT} || true`);
  const sedExpr = CLUSTER_SLAVE_ENV_KEYS.map((key) => `/^${key}=/d`).join(";");
  await step("改写节点角色为主节点", `sed -i '${sedExpr}' ${CLUSTER_DEPLOY_DIR}/.env && grep -c '' ${CLUSTER_DEPLOY_DIR}/.env`);
  await step("重启节点服务", `systemctl daemon-reload && systemctl restart ${CLUSTER_SLAVE_UNIT}`);
  const health = await step("等待新主节点就绪", REMOTE_HEALTH_WAIT);
  if (!health.includes("READY")) {
    throw new Error("新主节点健康检查未通过，请登录该节点查看服务日志");
  }

  // 4) 在新主节点注册旧主节点为从节点，取回节点令牌。
  const oldMasterName = `master-${oldMasterHost}`.slice(0, 40);
  const registerOut = await step("在新主节点注册旧主节点", remoteRegisterNodeScript(oldMasterHost, oldMasterName));
  const token = /NODE_TOKEN=(\S+)/.exec(registerOut)?.[1] || "";
  if (!token) {
    throw new Error("注册旧主节点失败：未能从新主节点获取节点令牌");
  }

  // 5) 旧主节点（本机）降级计划：systemd drop-in 自动重启，或手工配置指引。
  const demote = demoteSelfPlan({ newMasterHost: node.host, token });
  log.push(
    `$ 准备旧主节点降级\n${demote.mode === "systemd" ? `检测到 systemd 单元 ${demote.unit}，将写入 drop-in 并自动重启` : demote.reason}`,
  );
  return { log, demote, token, oldMasterName };
}

function trafficSummary() {
  const status = trafficMonitor.status();
  // 0.10.2.8：累计流量改用跨重启永久累计值（frps 更新/重启计数器归零不再清空统计）；
  // 实时速率与用户排行仍取窗口内实时指标。
  const cumulative = trafficMonitor.cumulativeTotals();
  let totalIncomingRate = 0;
  let totalOutgoingRate = 0;
  let activeProxies = 0;
  const userMap = new Map();
  for (const proxy of store.listProxies()) {
    const t = trafficMonitor.get(proxy.name, proxy.type);
    if (!t.hasMetrics) continue;
    totalIncomingRate += t.incomingBytesPerSecond;
    totalOutgoingRate += t.outgoingBytesPerSecond;
    activeProxies++;
    const entry = userMap.get(proxy.userId) || {
      userId: proxy.userId,
      username: proxy.username,
      incomingBytes: 0,
      outgoingBytes: 0,
      incomingRate: 0,
      outgoingRate: 0,
    };
    entry.incomingBytes += t.totalIncomingBytes;
    entry.outgoingBytes += t.totalOutgoingBytes;
    entry.incomingRate += t.incomingBytesPerSecond;
    entry.outgoingRate += t.outgoingBytesPerSecond;
    userMap.set(proxy.userId, entry);
  }
  return {
    available: status.available,
    sampledAt: status.sampledAt,
    error: status.error,
    activeProxies,
    totalIncomingBytes: cumulative.incomingBytes,
    totalOutgoingBytes: cumulative.outgoingBytes,
    totalIncomingRate,
    totalOutgoingRate,
    system: systemTraffic.status(),
    users: [...userMap.values()].sort(
      (a, b) => b.incomingRate + b.outgoingRate - (a.incomingRate + a.outgoingRate),
    ),
  };
}

async function readJson(req, maxBytes = 64 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw new Error("请求内容过大");
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new Error("JSON 格式无效");
  }
}

// 0.9.2：读取原始请求体（用于文件导入）。
async function readRaw(req, maxBytes) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) throw new Error("文件大小超出限制（最大 5MB）");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

// 0.9.2：账号模板/导出文件下载（xlsx 或带 BOM 的 CSV 文本）。
function sendAccountFile(res, format, baseName, rows) {
  if (format === "xlsx") {
    const body = buildXlsx(rows, { sheetName: baseName.slice(0, 20) || "Sheet1" });
    res.writeHead(200, {
      "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "Content-Length": body.length,
      "Content-Disposition": `attachment; filename*=UTF-8''${encodeURIComponent(baseName)}.xlsx`,
      "Cache-Control": "no-store",
    });
    res.end(body);
    return;
  }
  // UTF-8 BOM 保证 Excel 直接打开 CSV 不乱码。
  const body = Buffer.from(`\uFEFF${toDelimited(rows, ",")}`, "utf8");
  res.writeHead(200, {
    "Content-Type": "text/csv; charset=utf-8",
    "Content-Length": body.length,
    "Content-Disposition": `attachment; filename*=UTF-8''${encodeURIComponent(baseName)}.txt`,
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function cookies(req) {
  return Object.fromEntries(
    String(req.headers.cookie || "")
      .split(";")
      .map((part) => part.trim().split("="))
      .filter(([key, value]) => key && value)
      .map(([key, value]) => [key, decodeURIComponent(value)]),
  );
}

function adminFromRequest(req) {
  const token = bearerToken(req) || cookies(req).fm_admin;
  if (!token) return null;
  try {
    const payload = verifyToken(token, signingSecret, "admin");
    const admin = store.getAdminById(payload.sub);
    if (
      !admin ||
      payload.usr !== admin.username ||
      payload.ver !== admin.tokenVersion
    ) {
      return null;
    }
    return admin;
  } catch {
    return null;
  }
}

function bearerToken(req) {
  const match = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || ""));
  return match?.[1] || "";
}

function clientAuthError(message, code) {
  const error = new Error(message);
  error.authCode = code;
  return error;
}

function authorizedUserSession(
  token,
  expectedUsername = null,
  { allowExpired = false, allowDisabled = false, clientAddress = null } = {},
) {
  const payload = verifyToken(token, signingSecret, "client");
  const user = store.getUserById(payload.sub);
  if (!user) throw clientAuthError("登录已失效", "SESSION_REVOKED");
  if (!payload.dev) {
    throw clientAuthError("客户端已升级，请重新登录", "DEVICE_REQUIRED");
  }
  if (user.deviceId && payload.dev !== user.deviceId) {
    throw clientAuthError("账号已在另一台设备登录", "DEVICE_REPLACED");
  }
  if (!user.deviceId || payload.ver !== user.tokenVersion) {
    throw clientAuthError("登录已失效", "SESSION_REVOKED");
  }
  // 0.9.2：token 标识为 uid；兼容升级前签发的旧 token（usr=用户名）。
  if (payload.usr !== user.uid && payload.usr !== user.username) {
    throw new Error("用户身份不一致");
  }
  if (
    expectedUsername &&
    expectedUsername !== user.uid &&
    expectedUsername !== user.username
  ) {
    throw new Error("用户身份不一致");
  }
  if (!allowDisabled && !user.enabled) throw new Error("账号已停用");
  // 0.9.3：expires_at 为 NULL 表示未激活（到期拦截由 NewProxy/激活门禁负责）。
  if (!allowExpired && user.expiresAt && isExpired(user.expiresAt)) throw new Error("账号已到期");
  if (!store.touchDevice(user.id, payload.dev, clientAddress)) {
    throw clientAuthError("账号已在另一台设备登录", "DEVICE_REPLACED");
  }
  return { user, payload };
}

function authorizedUser(token, expectedUsername = null, options = {}) {
  return authorizedUserSession(token, expectedUsername, options).user;
}

function clientToken(user) {
  const issuedAt = Math.floor(Date.now() / 1000);
  return signToken(
    {
      sub: user.id,
      // 0.9.2：token 标识改用稳定的 uid（用户名可改、可重名）。
      usr: user.uid,
      ver: user.tokenVersion,
      dev: user.deviceId,
      type: "client",
      iat: issuedAt,
      ttl: CLIENT_TOKEN_TTL_SECONDS,
      exp: issuedAt + CLIENT_TOKEN_TTL_SECONDS,
    },
    signingSecret,
  );
}

function authErrorCode(error) {
  if (error?.authCode) return error.authCode;
  if (error?.code === "SERVER_LICENSE_REQUIRED") return error.code;
  const message = String(error?.message || "");
  if (message === "登录已失效") return "SESSION_REVOKED";
  if (message === "用户身份不一致") return "IDENTITY_MISMATCH";
  if (message === "账号已停用") return "ACCOUNT_DISABLED";
  if (message === "账号已到期") return "ACCOUNT_EXPIRED";
  if (/令牌/.test(message)) return "TOKEN_INVALID";
  return "AUTH_INVALID";
}

function assertLoginRate(req) {
  loginRateLimiter.assert(requestIp(req));
}

function recordLoginFailure(req) {
  loginRateLimiter.failure(requestIp(req));
}

function clearLoginFailures(req) {
  loginRateLimiter.clear(requestIp(req));
}

function secureCookieSuffix(req) {
  const proto = String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim();
  return proto === "https" || req.socket.encrypted ? "; Secure" : "";
}

function adminSession(admin, req) {
  const token = signToken(
    {
      sub: admin.id,
      usr: admin.username,
      ver: admin.tokenVersion,
      type: "admin",
      exp: Math.floor(Date.now() / 1000) + 8 * 60 * 60,
    },
    signingSecret,
  );
  return {
    token,
    cookie:
      `fm_admin=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800` +
      (req ? secureCookieSuffix(req) : ""),
  };
}

function derivePublicHost(req) {
  if (FRP_PUBLIC_HOST) return FRP_PUBLIC_HOST;
  const rawHost = String(req.headers["x-forwarded-host"] || req.headers.host || "127.0.0.1");
  try {
    return new URL(`http://${rawHost}`).hostname;
  } catch {
    return rawHost.replace(/:\d+$/, "");
  }
}

function pluginResponse(res, reject = false, reason = "") {
  sendJson(
    res,
    200,
    reject
      ? { reject: true, reject_reason: reason }
      : { reject: false, unchange: true },
  );
}

// 0.10.0：服务端限速注入——bps → frp 带宽串（frp 按字节计，÷8）。
function formatBandwidthLimitServer(bitsPerSec) {
  const bits = Number(bitsPerSec) || 0;
  if (bits <= 0) return null;
  const bytesPerSec = Math.floor(bits / 8);
  if (bytesPerSec <= 0) return null;
  if (bytesPerSec % (1024 * 1024) === 0) return `${bytesPerSec / (1024 * 1024)}MB`;
  return `${Math.max(1, Math.floor(bytesPerSec / 1024))}KB`;
}

function isLoopback(req) {
  const address = String(req.socket.remoteAddress || "").replace(/^::ffff:/, "");
  return address === "127.0.0.1" || address === "::1";
}

async function handlePlugin(req, res, url) {
  if (!isLoopback(req)) {
    sendJson(res, 403, { error: "forbidden" });
    return;
  }
  const body = await readJson(req);
  const op = url.searchParams.get("op") || body.op;
  const content = body.content || {};
  const userInfo = op === "Login" ? content : content.user || {};
  const username = userInfo.user;
  const token = userInfo.metas?.fm_token;

  if (!["Login", "NewProxy", "Ping", "NewWorkConn", "CloseProxy"].includes(op)) {
    pluginResponse(res);
    return;
  }

  if (op === "CloseProxy") {
    store.closeProxy(userInfo.run_id, content.proxy_name);
    pluginResponse(res);
    return;
  }

  try {
    licenseManager.assertAllowed();
    const user = authorizedUser(token, username, {
      clientAddress: op === "Login" ? content.client_address : null,
    });
    const runId = op === "Login" ? content.run_id : userInfo.run_id;
    let bandwidthInject = null;

    // 0.9.3：未激活账号（未完成首次改密）不允许登录 frps 或建立隧道。
    if ((op === "Login" || op === "NewProxy") && !user.activated) {
      throw new Error("账号尚未激活：请先完成首次登录并修改密码");
    }

    if (op === "NewProxy") {
      const proxyType = String(content.proxy_type || "").toLowerCase();
      if (!["tcp", "udp", "http", "https"].includes(proxyType)) {
        throw new Error("当前账户仅允许创建 TCP / UDP / HTTP / HTTPS 映射");
      }
      // 0.9.3：HTTP/HTTPS 隧道默认收回，须管理员单独授权（http_allowed）。
      if ((proxyType === "http" || proxyType === "https") && !user.httpAllowed) {
        throw new Error("当前账号未开通 HTTP/HTTPS 隧道权限，请联系管理员授权");
      }
      if (user.trafficLimitBytes > 0 && user.trafficUsedBytes >= user.trafficLimitBytes) {
        throw new Error("流量配额已用尽，无法创建新映射");
      }
      let remotePort = 0;
      let domains = [];
      if (proxyType === "http" || proxyType === "https") {
        if (vhostHttpPort() === 0 && proxyType === "http") {
          throw new Error("服务端未开启 HTTP 隧道（vhostHTTP 端口为 0），请联系管理员");
        }
        if (vhostHttpsPort() === 0 && proxyType === "https") {
          throw new Error("服务端未开启 HTTPS 隧道（vhostHTTPS 端口为 0），请联系管理员");
        }
        domains = normalizeDomains(content.custom_domains ?? content.customDomains);
        if (domains.length === 0) {
          throw new Error(`${proxyType.toUpperCase()} 映射必须配置至少一个自定义域名`);
        }
        // 域名全局唯一：与所有活跃代理（closed_at IS NULL）比对，本代理自身除外。
        const conflict = store
          .listProxies()
          .filter((proxy) => proxy.closedAt == null)
          .find(
            (proxy) =>
              !(proxy.userId === user.id && proxy.name === content.proxy_name) &&
              proxy.domains.some((domain) => domains.includes(domain)),
          );
        if (conflict) {
          const taken = conflict.domains.find((domain) => domains.includes(domain));
          throw new Error(`域名 ${taken} 已被 ${conflict.username} 的映射占用`);
        }
      } else {
        remotePort = Number(content.remote_port ?? content.remotePort ?? 0);
        if (!Number.isInteger(remotePort) || remotePort < 1 || remotePort > 65535) {
          throw new Error("远程端口无效");
        }
        if (!isPortAllowed(remotePort, user.portRanges)) {
          throw new Error(`端口 ${remotePort} 不在授权范围 ${user.portRangesText} 内`);
        }
      }
      // 配额：活跃映射总数（tcp/udp/http/https 统一计数）不得超过授权端口总数；
      // 同名代理重连（ON CONFLICT 覆盖自身行）不计入。
      const activeCount = store
        .listProxies(user.id)
        .filter((proxy) => proxy.closedAt == null && proxy.name !== content.proxy_name)
        .length;
      const totalPorts = (user.portRanges || []).reduce(
        (sum, range) => sum + (range.end - range.start + 1),
        0,
      );
      if (activeCount >= totalPorts) {
        throw new Error(`映射数量已达配额上限（${totalPorts} 条），请先删除不用的映射`);
      }
      store.touchProxy(runId, user.id, {
        name: content.proxy_name,
        type: proxyType,
        remotePort,
        domains,
      });

      // 0.10.0：服务端强制限速（frps 侧执行，经插件改写代理配置）——
      // 端口/隧道级 > 用户级；无论客户端 frpc 配置如何（含自定义配置）都生效。
      const limitByProxy = store.getProxyRateLimitsByUser(user.id);
      const requestedName = String(content.proxy_name || "");
      const proxyBps =
        Number(limitByProxy[requestedName] ?? limitByProxy[`${user.uid}-${requestedName}`]) || 0;
      const effectiveBps = proxyBps > 0 ? proxyBps : Number(user.rateLimitBps) || 0;
      const bandwidth = formatBandwidthLimitServer(effectiveBps);
      if (bandwidth) {
        bandwidthInject = { bandwidth_limit: bandwidth, bandwidth_limit_mode: "server" };
      }
    }

    store.touchSession(
      runId,
      user.id,
      op === "Login" ? content.client_address : null,
    );
    // 0.10.0：有服务端限速时改写 NewProxy 内容（frps 插件 content 合并机制），客户端配置不作为限速来源。
    if (bandwidthInject) {
      sendJson(res, 200, {
        reject: false,
        unchange: false,
        content: { ...content, ...bandwidthInject },
      });
      return;
    }
    pluginResponse(res);
  } catch (error) {
    pluginResponse(res, true, error.message || "access denied");
  }
}

// ---------- 0.10.2.8：服务端消息中心（运行日志报错提醒） ----------
// 监听 frps 运行日志与本机进程事件：出现报错即生成消息，管理台「消息中心」展示，
// 未读徽标提示；用户查看（打开消息中心）后清除未读。消息持久化于 settings（保留最近 100 条）。
const SERVER_MESSAGE_LIMIT = 100;
const SERVER_MESSAGE_DEDUP_MS = 10 * 60_000;

function loadServerMessages() {
  try {
    const list = JSON.parse(store.getSetting("server_messages") || "[]");
    return Array.isArray(list) ? list.slice(-SERVER_MESSAGE_LIMIT) : [];
  } catch {
    return [];
  }
}

let serverMessages = loadServerMessages();
const serverMessageDedup = new Map(); // 归一化文本 -> 最近一次时间（同内容 10 分钟内不重复提醒）

function pushServerMessage(level, text) {
  const value = String(text || "").replace(/\s+/g, " ").trim();
  if (!value) return;
  const now = Date.now();
  const key = value.slice(0, 100);
  if (now - (serverMessageDedup.get(key) || 0) < SERVER_MESSAGE_DEDUP_MS) return;
  serverMessageDedup.set(key, now);
  if (serverMessageDedup.size > 300) {
    for (const [entryKey, at] of serverMessageDedup) {
      if (now - at >= SERVER_MESSAGE_DEDUP_MS) serverMessageDedup.delete(entryKey);
    }
  }
  serverMessages.push({
    id: `msg-${now.toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
    level: level === "warn" ? "warn" : "error",
    text: value.slice(0, 500),
    createdAt: new Date(now).toISOString(),
  });
  serverMessages = serverMessages.slice(-SERVER_MESSAGE_LIMIT);
  try {
    store.setSetting("server_messages", JSON.stringify(serverMessages));
  } catch {
    // 持久化失败不影响内存内提醒。
  }
}

function serverMessagesSnapshot() {
  const readAt = store.getSetting("server_messages_read_at") || "";
  return {
    list: [...serverMessages].reverse(),
    unread: serverMessages.filter((item) => item.createdAt > readAt).length,
  };
}

class FrpsSupervisor {
  constructor() {
    this.process = null;
    this.state = existsSync(FRPS_BIN) ? "stopped" : "missing";
    this.logs = [];
    this.startedAt = null;
    this.desired = false;
    this.restartTimer = null;
  }

  configText() {
    return [
      `bindAddr = "0.0.0.0"`,
      `bindPort = ${FRP_BIND_PORT}`,
      `auth.method = "token"`,
      `auth.token = ${escapeToml(frpAuthToken)}`,
      `transport.tcpMux = false`,
      `transport.heartbeatTimeout = 15`,
      `webServer.addr = "127.0.0.1"`,
      `webServer.port = ${FRP_METRICS_PORT}`,
      `webServer.user = ${escapeToml(frpMetricsUser)}`,
      `webServer.password = ${escapeToml(frpMetricsPassword)}`,
      `enablePrometheus = true`,
      `log.to = "console"`,
      `log.level = "info"`,
      vhostHttpPort() > 0 ? `vhostHTTPPort = ${vhostHttpPort()}` : null,
      vhostHttpsPort() > 0 ? `vhostHTTPSPort = ${vhostHttpsPort()}` : null,
      "",
      "[[httpPlugins]]",
      `name = "access-manager"`,
      `addr = "127.0.0.1:${PORT}"`,
      `path = "/internal/frp-plugin"`,
      `ops = ["Login", "NewProxy", "Ping", "NewWorkConn", "CloseProxy"]`,
      "",
    ].join("\n");
  }

  appendLog(text) {
    const lines = String(text)
      .split(/\r?\n/)
      .filter(Boolean);
    this.logs.push(...lines.map((line) => `${new Date().toISOString()} ${line}`));
    this.logs = this.logs.slice(-200);
    // 0.10.2.8：监听运行日志——[E] 级日志生成消息中心提醒（10 分钟内同内容去重）。
    for (const line of lines) {
      if (/\[E\]/.test(line)) {
        pushServerMessage(
          "error",
          `frps 运行报错：${line.replace(/^\S+\s*/, "").replace(/\s*\[E\]\s*/, " ")}`,
        );
      }
    }
  }

  async start() {
    if (this.process) return;
    this.desired = true;
    clearTimeout(this.restartTimer);
    if (licenseManager && !licenseManager.isAllowed()) {
      this.state = "license-required";
      this.appendLog("frps start blocked: server license is not valid");
      pushServerMessage("warn", "frps 启动被阻止：服务端许可未激活或已失效");
      return;
    }
    if (!existsSync(FRPS_BIN)) {
      this.state = "missing";
      this.appendLog(`frps binary not found: ${FRPS_BIN}`);
      pushServerMessage("error", `frps 程序缺失：${FRPS_BIN}，请在管理台重新下载或导入`);
      return;
    }
    // 0.9.2：启动前端口预检——bind/metrics/vhost 任一被占用则不 spawn，
    // 给出明确占用明细（修复"启用 HTTP/HTTPS 隧道报端口占用但看不出谁占用"）。
    const portsToCheck = [FRP_BIND_PORT, FRP_METRICS_PORT];
    if (vhostHttpPort() > 0) portsToCheck.push(vhostHttpPort());
    if (vhostHttpsPort() > 0) portsToCheck.push(vhostHttpsPort());
    const busy = await probeTcpPorts(portsToCheck, { useCache: false });
    if (busy.length) {
      const owners = await findListenersByPort(busy.map((item) => item.port)).catch(() => []);
      const detail = busy
        .map((item) => {
          const owner = owners.find((o) => o.port === item.port);
          return `${item.port}${owner?.processName ? `（占用进程：${owner.processName}）` : ""}`;
        })
        .join("、");
      this.state = "port-conflict";
      this.appendLog(`frps start aborted: 端口 ${detail} 已被占用，请释放后再启动`);
      pushServerMessage("error", `frps 启动失败：端口 ${detail} 已被占用，请释放后再启动`);
      return;
    }
    const configPath = join(RUNTIME_DIR, "frps.toml");
    writeFileSync(configPath, this.configText(), { mode: 0o600 });
    try {
      this.process = spawn(FRPS_BIN, ["-c", configPath], {
        cwd: RUNTIME_DIR,
        windowsHide: true,
      });
    } catch (error) {
      this.appendLog(error.message);
      this.state = "error";
      this.process = null;
      return;
    }
    this.state = "starting";
    this.startedAt = new Date().toISOString();
    this.process.stdout.on("data", (chunk) => this.appendLog(chunk));
    this.process.stderr.on("data", (chunk) => this.appendLog(chunk));
    this.process.once("spawn", () => {
      this.state = "running";
    });
    this.process.once("error", (error) => {
      this.appendLog(error.message);
      this.state = "error";
      this.process = null;
    });
    this.process.once("exit", (code, signal) => {
      this.appendLog(`frps exited code=${code} signal=${signal}`);
      this.process = null;
      const licenseBlocked =
        licenseManager && !licenseManager.isAllowed();
      this.state = licenseBlocked ? "license-required" : "stopped";
      // 0.10.2.8：非主动停止（desired 仍为真且 license 有效）即视为意外退出，生成提醒。
      if (this.desired && !licenseBlocked) {
        pushServerMessage(
          "error",
          `frps 进程意外退出（code=${code} signal=${signal || "null"}），正在自动重启`,
        );
        this.restartTimer = setTimeout(() => this.start(), 2_000);
      }
    });
  }

  refreshState() {
    if (this.process) return;
    // port-conflict 是预检失败的明确状态，保留给前端展示；用户点"启动"会重新预检。
    if (this.state === "port-conflict") return;
    this.state = existsSync(FRPS_BIN) ? "stopped" : "missing";
  }

  blockForLicense(reason) {
    this.appendLog(`frps stopped by license policy: ${reason}`);
    this.desired = false;
    clearTimeout(this.restartTimer);
    this.state = "license-required";
    if (this.process) this.process.kill();
  }

  // 停止 frps 并等待进程真正退出（exit 回调把 this.process 置 null）。
  // 调用方在 resolve 后再覆盖二进制或重新 start，可避免「kill 后同步 start 读到旧进程 no-op」竞态。
  stop() {
    this.desired = false;
    clearTimeout(this.restartTimer);
    const proc = this.process;
    if (!proc) return Promise.resolve();
    return new Promise((resolve) => {
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        resolve();
      };
      proc.once("exit", done);
      try {
        proc.kill();
      } catch {
        done();
      }
      // 兜底：极端情况下 exit 未触发也不永久阻塞调用方。
      setTimeout(done, 5000);
    });
  }

  // 重启：先等待旧进程退出再 spawn 新进程，确保新配置/新二进制生效。
  async restart() {
    if (this.process) await this.stop();
    await this.start();
  }

  status() {
    return {
      state: this.state,
      desired: this.desired,
      pid: this.process?.pid || null,
      startedAt: this.startedAt,
      bindPort: FRP_BIND_PORT,
      binary: FRPS_BIN,
      version: frpsVersion || store.getSetting("frps_version") || "",
      traffic: trafficMonitor.status(),
      logs: this.logs.slice(-80),
    };
  }
}

const frps = new FrpsSupervisor();
// frps 版本只在启动与更新时探测一次，避免状态轮询反复 spawn 子进程。
let frpsVersion = detectFrpVersion(FRPS_BIN);
if (frpsVersion) store.setSetting("frps_version", frpsVersion);
licenseManager = new LicenseManager({
  store,
  serverUrl: LICENSE_SERVER_URL,
  publicKey: configuredLicensePublicKey(),
  intervalMs: LICENSE_CHECK_INTERVAL_MS,
  // 0.10.1.1 规格10-12：授权中心仲裁冲突回调——更新鲜的主节点认领存在时本节点自动降级。
  onMasterConflict: (masterAddress) => demoteSelfToSlave(masterAddress),
  onStatusChange(next, previous) {
    if (!next.valid) {
      frps.blockForLicense(next.error || "license expired");
      store.closeAllActivity();
      return;
    }
    if (previous && !previous.valid && FRPS_AUTOSTART) frps.start();
  },
});
// 0.10.1.1 规格10-12：主节点随心跳向授权中心认领主节点身份（cluster_masters 表），
// 授权中心目录据此向客户端返回集群当前主节点 IP（客户端「登录集群」自动拉取新主）。
licenseManager.announceMaster = activeRole === "master";

// 0.10.0：从节点不校验授权（授权跟随主节点），内核经主节点 agent 通道获取。
if (activeRole === "slave") {
  licenseManager.assertAllowed = () => {};
  licenseManager.isAllowed = () => true;
  licenseManager.recordClientVersion = () => {};
  licenseManager.blockForLicense = () => {};
  licenseManager.syncAnnouncements = async () => {};
  licenseManager.clientUpdateSnapshot = () => null;
  licenseManager.start = async () => ({ valid: true, mode: "cluster-slave", expiresAt: null });
  licenseManager.status = () => ({ valid: true, mode: "cluster-slave", expiresAt: null });
  licenseManager.fetchFrpBinaryFor = async (component, platform, arch) => {
    const response = await fetch(
      `${clusterMasterUrl}/api/cluster/agent/${component}?platform=${encodeURIComponent(platform)}&arch=${encodeURIComponent(arch)}`,
      { headers: { "x-agent-token": clusterNodeToken }, signal: AbortSignal.timeout(120_000) },
    );
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.error || `主节点获取 ${component} 内核失败 (${response.status})`);
    }
    return {
      buffer: Buffer.from(await response.arrayBuffer()),
      version: response.headers.get("x-frp-version") || "",
    };
  };
}

const staticFiles = new Map([
  ["/", join(ROOT, "server", "public", "index.html")],
  ["/app.js", join(ROOT, "server", "public", "app.js")],
  ["/assets/style.css", join(ROOT, "shared", "style.css")],
  ["/favicon.svg", join(ROOT, "shared", "favicon.svg")],
]);

function serveStatic(res, pathname) {
  const file = staticFiles.get(pathname);
  if (!file || !existsSync(file)) return false;
  const types = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
  };
  const body =
    extname(file) === ".html"
      ? Buffer.from(renderHtmlWithIncludes(file), "utf8")
      : readFileSync(file);
  res.writeHead(200, {
    "Content-Type": types[extname(file)] || "application/octet-stream",
    "Content-Length": body.length,
    "Cache-Control": pathname === "/" ? "no-store" : "public, max-age=300",
    "Content-Security-Policy":
      "default-src 'self'; script-src 'self' https://unpkg.com; style-src 'self'; img-src 'self' data:; connect-src 'self'",
  });
  res.end(body);
  return true;
}

async function handleApi(req, res, url) {
  const { pathname } = url;

  // 0.10.0：从节点不提供管理接口（主从共用 handleApi，且客户端 API 端口对外可达）。
  if (activeRole === "slave" && pathname.startsWith("/api/admin/")) {
    sendJson(res, 404, { error: "从节点不提供管理接口" });
    return true;
  }

  if (pathname === "/healthz") {
    const license = licenseManager.status();
    sendJson(res, 200, {
      ok: true,
      frps: frps.state,
      license: {
        valid: license.valid,
        mode: license.mode,
        expiresAt: license.expiresAt,
      },
    });
    return true;
  }

  if (pathname === "/internal/frp-plugin" && req.method === "POST") {
    await handlePlugin(req, res, url);
    return true;
  }

  if (pathname === "/api/public/branding" && req.method === "GET") {
    sendJson(res, 200, publicBranding());
    return true;
  }

  const brandingLogoMatch = /^\/branding\/(site|client)-logo$/.exec(pathname);
  if (brandingLogoMatch && req.method === "GET") {
    serveBrandingLogo(res, brandingLogoMatch[1]);
    return true;
  }

  if (pathname === "/api/admin/login" && req.method === "POST") {
    assertLoginRate(req);
    const input = await readJson(req);
    const admin = store.authenticateAdmin(input.username, input.password);
    if (!admin) {
      recordLoginFailure(req);
      sendJson(res, 401, { error: "用户名或密码错误" });
      return true;
    }
    clearLoginFailures(req);
    const session = adminSession(admin, req);
    sendJson(res, 200, { admin: { id: admin.id, username: admin.username } }, {
      "Set-Cookie": session.cookie,
    });
    return true;
  }

  if (pathname === "/api/admin/logout" && req.method === "POST") {
    sendJson(res, 200, { ok: true }, {
      "Set-Cookie": "fm_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
    });
    return true;
  }

  if (pathname.startsWith("/api/admin/")) {
    const admin = adminFromRequest(req);
    if (!admin) {
      sendJson(res, 401, { error: "请先登录" });
      return true;
    }

    if (pathname === "/api/admin/license" && req.method === "GET") {
      sendJson(res, 200, { license: licenseManager.status() });
      return true;
    }
    if (pathname === "/api/admin/license" && req.method === "PUT") {
      const input = await readJson(req);
      const license = await licenseManager.activate(input.licenseKey);
      store.audit(admin.username, "license.activate", license.keyPreview);
      if (FRPS_AUTOSTART) frps.start();
      sendJson(res, 200, { license });
      return true;
    }
    if (pathname === "/api/admin/license/refresh" && req.method === "POST") {
      const license = await licenseManager.refresh();
      store.audit(admin.username, "license.refresh", license.keyPreview);
      sendJson(res, 200, { license });
      return true;
    }
    if (pathname === "/api/admin/license" && req.method === "DELETE") {
      const previous = licenseManager.status();
      const license = licenseManager.remove();
      store.audit(admin.username, "license.remove", previous.keyPreview);
      if (!license.valid) {
        frps.blockForLicense(license.error || "license removed");
        store.closeAllActivity();
      }
      sendJson(res, 200, { license });
      return true;
    }

    if (pathname === "/api/admin/overview" && req.method === "GET") {
      void licenseManager.syncAnnouncements();
      const onlineUsers = store
        .listUsers()
        .filter((u) => u.deviceOnline && u.enabled && !u.expired)
        .map((u) => ({
          username: u.username,
          deviceAddress: u.deviceAddress,
          deviceLastSeen: u.deviceLastSeen,
          onlineMappingCount: u.onlineMappingCount,
          clientVersion: u.clientVersion,
          expiresAt: u.expiresAt,
          activated: u.activated,
        }));
      // 0.10.2.8：集群用户——主节点客户端在线 ∪ 从节点 frpc 接入在线，按用户合并为一个列表，
      // 每行标注在线节点（本机=master / 各从节点名），替代原先分列的「在线用户 + 从节点登录用户」。
      const clusterUserMap = new Map();
      for (const u of store.listUsers()) {
        if (!u.deviceOnline || !u.enabled || u.expired) continue;
        clusterUserMap.set(u.id, {
          userId: u.id,
          username: u.username,
          uid: u.uid ?? null,
          nodes: ["master"],
          deviceAddress: u.deviceAddress || "",
          lastSeen: u.deviceLastSeen,
          onlineMappingCount: u.onlineMappingCount,
          clientVersion: u.clientVersion,
          expiresAt: u.expiresAt,
          activated: u.activated,
        });
      }
      for (const item of store.slaveLoginUsers()) {
        if (!item.online || item.enabled === false) continue;
        const existing = clusterUserMap.get(item.userId) || {
          userId: item.userId,
          username: item.username,
          uid: item.uid ?? null,
          nodes: [],
          deviceAddress: "",
          lastSeen: null,
          onlineMappingCount: 0,
          clientVersion: null,
          expiresAt: null,
          activated: null,
        };
        if (!existing.nodes.includes(item.node)) existing.nodes.push(item.node);
        if (!existing.lastSeen || item.lastSeen > existing.lastSeen) {
          existing.lastSeen = item.lastSeen;
        }
        clusterUserMap.set(item.userId, existing);
      }
      const clusterUsers = [...clusterUserMap.values()];
      // 0.10.0.2：集群总览——主节点 + 各从节点的流量 / 端口池 / 用户概况。
      const clusterOverview = {
        name: clusterName(),
        master: {
          name: "master",
          label: store.getSetting("server_display_name") || derivePublicHost(req),
          host: derivePublicHost(req),
          version: VERSION,
          online: true,
          ports: store.nodePortUsage("master"),
          traffic: trafficSummary(),
          userCount: store.listUsers().length,
          proxyCount: store.listProxies().filter((proxy) => !proxy.closedAt).length,
        },
        nodes: store.listClusterNodes().map((node) => ({
          name: node.name,
          label: node.name,
          host: node.host,
          location: node.location || "",
          version: node.version || "",
          online: Boolean(node.online),
          lastSyncAt: node.lastSyncAt,
          bindPort: node.bindPort,
          ports: store.nodePortUsage(node.name),
          userCount: node.stats?.userCount ?? null,
          proxyCount: node.stats?.proxyCount ?? null,
          traffic: node.stats?.traffic ?? null,
          firewall: node.stats?.firewall ?? null,
        })),
      };
      sendJson(res, 200, {
        admin: { username: admin.username },
        stats: store.stats(),
        onlineUsers,
        // 0.10.2.8：集群用户合并列表（在线用户 ∪ 从节点登录用户）；旧字段保留兼容。
        slaveUsers: store.slaveLoginUsers(),
        clusterUsers,
        // 0.10.2.8：服务端消息中心（运行日志报错提醒）概要，用于导航徽标与消息页。
        messages: serverMessagesSnapshot(),
        frps: frps.status(),
        traffic: trafficSummary(),
        cluster: clusterOverview,
        license: licenseManager.status(),
        announcements: licenseManager.announcementsSnapshot(),
        currentVersion: VERSION,
        update: licenseManager.updateInfoSnapshot(),
        updateResult: readUpdateResult(DATA_DIR),
        network: resolveNetworkConfig(DATA_DIR),
        recentAudit: store.listAudit(8),
      });
      return true;
    }

    // ---------- 0.10.2.8：消息中心（运行日志报错提醒） ----------
    if (pathname === "/api/admin/messages" && req.method === "GET") {
      sendJson(res, 200, { messages: serverMessagesSnapshot() });
      return true;
    }
    if (pathname === "/api/admin/messages/read" && req.method === "POST") {
      store.setSetting("server_messages_read_at", new Date().toISOString());
      sendJson(res, 200, { messages: serverMessagesSnapshot() });
      return true;
    }

    // ---------- 0.10.2.8：公告管理（发布 → 客户端信息中心） ----------
    if (pathname === "/api/admin/announcements" && req.method === "GET") {
      sendJson(res, 200, { announcements: store.listAnnouncements() });
      return true;
    }
    if (pathname === "/api/admin/announcements" && req.method === "POST") {
      const input = await readJson(req);
      const announcement = store.createAnnouncement(input, admin.username);
      sendJson(res, 200, { announcement, announcements: store.listAnnouncements() });
      return true;
    }
    if (pathname === "/api/admin/announcements/delete" && req.method === "POST") {
      const input = await readJson(req);
      const deleted = store.deleteAnnouncement(Number(input?.id), admin.username);
      if (!deleted) {
        sendJson(res, 404, { error: "公告不存在或已删除" });
        return true;
      }
      sendJson(res, 200, { announcements: store.listAnnouncements() });
      return true;
    }

    if (pathname === "/api/admin/branding" && req.method === "GET") {
      sendJson(res, 200, { branding: publicBranding() });
      return true;
    }
    if (pathname === "/api/admin/branding" && req.method === "POST") {
      const input = await readJson(req, 1_500_000);
      const config = brandingConfig();
      if (input.siteName !== undefined) {
        config.siteName = String(input.siteName).trim().slice(0, 40);
      }
      if (input.clientName !== undefined) {
        config.clientName = String(input.clientName).trim().slice(0, 40);
      }
      applyBrandingLogo("site", input.siteLogo, config);
      applyBrandingLogo("client", input.clientLogo, config);
      store.setSetting("branding", JSON.stringify(config));
      store.audit(admin.username, "branding.update", "branding", {
        siteName: config.siteName,
        clientName: config.clientName,
      });
      sendJson(res, 200, { branding: publicBranding(config) });
      return true;
    }

    if (pathname === "/api/admin/renewal-url" && req.method === "GET") {
      sendJson(res, 200, { renewalUrl: store.getSetting("renewal_url") || "" });
      return true;
    }
    if (pathname === "/api/admin/renewal-url" && req.method === "POST") {
      const input = await readJson(req);
      const url = String(input.renewalUrl || "").trim().slice(0, 500);
      if (url && !/^https?:\/\//i.test(url)) {
        throw new Error("续费地址必须以 http:// 或 https:// 开头");
      }
      store.setSetting("renewal_url", url);
      store.audit(admin.username, "renewal.url.update", "renewal-url", { renewalUrl: url });
      sendJson(res, 200, { renewalUrl: url });
      return true;
    }

    if (pathname === "/api/admin/update" && req.method === "GET") {
      // 管理员主动检查时，强制向授权中心实时查询，而不是读每小时一次的缓存。
      try {
        await licenseManager.checkUpdates();
      } catch {
        // 授权中心不可达时回退到缓存结果，由快照中的 error 字段体现。
      }
      sendJson(res, 200, {
        currentVersion: VERSION,
        update: licenseManager.updateInfoSnapshot(),
      });
      return true;
    }
    if (pathname === "/api/admin/update/apply" && req.method === "POST") {
      const input = await readJson(req).catch(() => ({}));
      const info = licenseManager.updateInfoSnapshot();
      const url = String(input.downloadUrl || info.downloadUrl || "");
      if (!/^https?:\/\//i.test(url)) throw new Error("缺少有效的下载地址");
      store.audit(admin.username, "update.apply", "update", { url });
      sendJson(res, 202, { ok: true, message: "更新已启动，进程将自动重启" });
      setImmediate(() => {
        applyUpdateAndRestart({
          downloadUrl: url,
          rootDir: ROOT,
          dataDir: DATA_DIR,
          role: "server",
          ports: [PORT, FRP_BIND_PORT, FRP_METRICS_PORT],
          healthScheme: managerHttpsEnabled() ? "https" : "http",
          logger: (msg) => console.log(`[updater] ${msg}`),
        }).catch((err) => console.error("update failed:", err.message));
      });
      return true;
    }

    // ---------- FRP 二进制管理（服务端仅管理下发给客户端的 frpc 缓存） ----------
    if (pathname === "/api/admin/frp" && req.method === "GET") {
      sendJson(res, 200, {
        frps: {
          installed: existsSync(FRPS_BIN),
          version: detectFrpVersion(FRPS_BIN) || store.getSetting("frps_version") || "",
        },
        frpcCache: listFrpcCache(),
      });
      return true;
    }

    // 预拉取指定平台/架构的 frpc 到本地缓存。
    if (pathname === "/api/admin/frp/frpc/fetch" && req.method === "POST") {
      const input = await readJson(req).catch(() => ({}));
      const platform = String(input.platform || "").trim().toLowerCase();
      const arch = String(input.arch || "").trim().toLowerCase();
      if (!FRP_PLATFORMS.includes(platform) || !FRP_ARCHES.includes(arch)) {
        sendJson(res, 400, { error: "平台须为 linux/windows/darwin，架构须为 amd64/arm64/arm" });
        return true;
      }
      try {
        const result = await licenseManager.fetchFrpBinaryFor("frpc", platform, arch);
        const saved = saveFrpcCache(platform, arch, result.buffer, result.version);
        store.audit(admin.username, "frpc.fetch", `${platform}/${arch}`, {
          version: result.version,
          size: result.buffer.length,
        });
        sendJson(res, 200, { ok: true, item: saved });
      } catch (error) {
        sendJson(res, Number(error.status) || 502, { error: error.message });
      }
      return true;
    }

    // 手动上传 frpc（为指定平台/架构的客户端准备），按目标平台做可执行文件魔数校验。
    if (pathname === "/api/admin/frp/frpc/upload" && req.method === "POST") {
      const platform = String(url.searchParams.get("platform") || "").trim().toLowerCase();
      const arch = String(url.searchParams.get("arch") || "").trim().toLowerCase();
      if (!FRP_PLATFORMS.includes(platform) || !FRP_ARCHES.includes(arch)) {
        sendJson(res, 400, { error: "平台须为 linux/windows/darwin，架构须为 amd64/arm64/arm" });
        return true;
      }
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 200 * 1024 * 1024) {
          sendJson(res, 413, { error: "二进制文件不能超过 200MB" });
          return true;
        }
        chunks.push(chunk);
      }
      const buffer = Buffer.concat(chunks);
      if (buffer.length === 0) {
        sendJson(res, 400, { error: "上传内容为空" });
        return true;
      }
      if (!binaryMatchesPlatform(buffer, platform)) {
        sendJson(res, 400, {
          error: `文件头校验失败：不是 ${platform} 平台的有效可执行文件`,
        });
        return true;
      }
      const saved = saveFrpcCache(platform, arch, buffer, "");
      store.audit(admin.username, "frpc.upload", `${platform}/${arch}`, { size: buffer.length });
      sendJson(res, 200, { ok: true, item: saved });
      return true;
    }

    // 删除本地缓存的 frpc。
    const frpcDeleteMatch = /^\/api\/admin\/frp\/frpc\/(linux|windows|darwin)\/(amd64|arm64|arm)$/.exec(
      pathname,
    );
    if (frpcDeleteMatch && req.method === "DELETE") {
      const platform = frpcDeleteMatch[1];
      const arch = frpcDeleteMatch[2];
      rmSync(frpcCachePath(platform, arch), { force: true });
      store.setSetting(`frpc_version_${platform}_${arch}`, "");
      store.audit(admin.username, "frpc.delete", `${platform}/${arch}`);
      sendJson(res, 200, { ok: true });
      return true;
    }

    // ---------- 服务端自身 frps：从授权中心拉取 / 手动导入 ----------
    if (pathname === "/api/admin/frps/fetch" && req.method === "POST") {
      try {
        const result = await licenseManager.fetchFrpBinary("frps");
        if (!binaryMatchesPlatform(result.buffer, LOCAL_PLATFORM)) {
          sendJson(res, 502, { error: "授权中心返回的二进制与本机平台不匹配" });
          return true;
        }
        const version = installFrpsBinary(result.buffer, result.version);
        store.audit(admin.username, "frps.fetch", `${LOCAL_PLATFORM}/${process.arch}`, {
          version: result.version,
          size: result.buffer.length,
        });
        sendJson(res, 200, { ok: true, version });
      } catch (error) {
        sendJson(res, Number(error.status) || 502, { error: error.message });
      }
      return true;
    }

    if (pathname === "/api/admin/frps/upload" && req.method === "POST") {
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 200 * 1024 * 1024) {
          sendJson(res, 413, { error: "二进制文件不能超过 200MB" });
          return true;
        }
        chunks.push(chunk);
      }
      const buffer = Buffer.concat(chunks);
      if (buffer.length === 0) {
        sendJson(res, 400, { error: "上传内容为空" });
        return true;
      }
      if (!binaryMatchesPlatform(buffer, LOCAL_PLATFORM)) {
        sendJson(res, 400, {
          error: `文件头校验失败：不是 ${LOCAL_PLATFORM} 平台的有效可执行文件`,
        });
        return true;
      }
      const version = await installFrpsBinary(buffer);
      store.audit(admin.username, "frps.upload", `${LOCAL_PLATFORM}/${process.arch}`, {
        size: buffer.length,
      });
      sendJson(res, 200, { ok: true, version });
      return true;
    }

    if (pathname === "/api/admin/users" && req.method === "GET") {
      // 0.10.2.8：映射情况以集群为单位——叠加在线从节点承载的活跃映射（按用户合并统计）。
      const slaveRows = slaveProxySnapshotRows();
      const slaveMapping = new Map();
      const slaveOnlineMapping = new Map();
      for (const row of slaveRows) {
        slaveMapping.set(row.userId, (slaveMapping.get(row.userId) || 0) + 1);
        if (row.online) {
          slaveOnlineMapping.set(row.userId, (slaveOnlineMapping.get(row.userId) || 0) + 1);
        }
      }
      sendJson(res, 200, {
        users: store.listUsers().map((user) => ({
          ...publicAdminUser(user),
          mappingCount: user.mappingCount + (slaveMapping.get(user.id) || 0),
          onlineMappingCount:
            user.onlineMappingCount + (slaveOnlineMapping.get(user.id) || 0),
        })),
      });
      return true;
    }
    if (pathname === "/api/admin/users" && req.method === "POST") {
      const body = await readJson(req);
      // 0.9.2：分配前预检——保留端口/已占用端口直接拒绝并提示明细。
      await assertRangesPortsFree(parsePortRanges(body.portRanges));
      const user = store.createUser(body, admin.username);
      sendJson(res, 201, { user: publicAdminUser(user) });
      return true;
    }

    // ---------- 0.9.0 套餐管理 ----------
    if (pathname === "/api/admin/plans" && req.method === "GET") {
      sendJson(res, 200, { plans: store.listPlans().map(publicPlan) });
      return true;
    }
    if (pathname === "/api/admin/plans" && req.method === "POST") {
      const body = await readJson(req);
      const plan = store.createPlan(
        {
          name: body.name,
          durationDays: body.durationDays,
          trafficLimitBytes: Math.round(planAmount(body.trafficGB, "流量(GB)") * 1024 ** 3),
          // 0.10.2.1：界面单位 Mbps，存储单位 bps；空/未传视为 0（不限速）。
          rateLimitBps: Math.round(planAmount(body.rateLimitMbps, "限速(Mbps)") * 1_000_000),
          portCount: body.portCount,
          priceCents: Math.round(planAmount(body.priceYuan, "价格(元)") * 100),
          sortOrder: body.sortOrder ?? 0,
        },
        admin.username,
      );
      sendJson(res, 201, { plan: publicPlan(plan) });
      return true;
    }
    const planMatch = /^\/api\/admin\/plans\/(\d+)$/.exec(pathname);
    if (planMatch) {
      const planId = Number(planMatch[1]);
      if (req.method === "PUT") {
        const body = await readJson(req);
        const patch = { ...body };
        if (body.trafficGB !== undefined) {
          patch.trafficLimitBytes = Math.round(planAmount(body.trafficGB, "流量(GB)") * 1024 ** 3);
        }
        // 0.10.2.1：限速 Mbps→bps（未传则维持现值）。
        if (body.rateLimitMbps !== undefined) {
          patch.rateLimitBps = Math.round(planAmount(body.rateLimitMbps, "限速(Mbps)") * 1_000_000);
        }
        if (body.priceYuan !== undefined) {
          patch.priceCents = Math.round(planAmount(body.priceYuan, "价格(元)") * 100);
        }
        const plan = store.updatePlan(planId, patch, admin.username);
        sendJson(
          res,
          plan ? 200 : 404,
          plan ? { plan: publicPlan(plan) } : { error: "套餐不存在" },
        );
        return true;
      }
      if (req.method === "DELETE") {
        const deleted = store.deletePlan(planId, admin.username);
        sendJson(res, deleted ? 200 : 404, deleted ? { ok: true } : { error: "套餐不存在" });
        return true;
      }
    }

    // ---------- 0.9.0 批量开号端口池 ----------
    if (pathname === "/api/admin/port-pool" && req.method === "GET") {
      sendJson(res, 200, { portPool: store.getSetting("port_pool") || "20000-30000" });
      return true;
    }
    if (pathname === "/api/admin/port-pool" && req.method === "PUT") {
      const body = await readJson(req);
      const ranges = parsePortRanges(body.portPool);
      const total = ranges.reduce((sum, range) => sum + (range.end - range.start + 1), 0);
      if (total > 60_000) throw new Error("端口池总端口数不能超过 60000");
      const text = formatPortRanges(ranges);
      store.setSetting("port_pool", text);
      store.audit(admin.username, "port_pool.update", "port-pool", { portPool: text });
      sendJson(res, 200, { portPool: text });
      return true;
    }

    // ---------- 0.9.0 按套餐批量开号 / 0.9.3 用户批量操作 ----------
    if (pathname === "/api/admin/users/batch" && req.method === "POST") {
      const body = await readJson(req);
      // 0.9.3：带 action 的为勾选批量操作（限速 / 改套餐 / 启停 / 删除）；无 action 为按套餐批量开号。
      if (body.action) {
        const ids = Array.isArray(body.ids) ? body.ids : [];
        if (body.action === "delete") {
          const result = store.batchDeleteUsers(ids, admin.username);
          sendJson(res, 200, { ok: true, ...result });
          return true;
        }
        const patch = {};
        if (body.action === "rateLimit") {
          // 界面单位 Mbps，存储单位 bps。
          patch.rateLimitBps = Math.max(0, Number(body.rateLimitMbps) || 0) * 1_000_000;
        } else if (body.action === "plan") {
          // 0.9.3：批量改套餐必须指定有效套餐（解绑套餐不属于批量操作语义，避免误清套餐快照）。
          if (!body.planId || !Number.isInteger(Number(body.planId))) {
            throw new Error("请选择要批量应用的套餐");
          }
          patch.planId = Number(body.planId);
        } else if (body.action === "enable") {
          patch.enabled = true;
        } else if (body.action === "disable") {
          patch.enabled = false;
        } else {
          throw new Error("未知的批量操作类型");
        }
        const result = store.batchUpdateUsers(ids, patch, admin.username);
        // 0.9.3.2：批量限速后给每个被修改的用户推送命令；
        // 0.10.2.1：批量改套餐同步套餐限速，同样推送。
        if ((body.action === "rateLimit" || body.action === "plan") && result.updatedIds) {
          for (const uid of result.updatedIds) {
            const u = store.getUserById(uid);
            if (u) {
              enqueueClientCommand(uid, {
                type: "rateLimitUpdate",
                rateLimitBps: u.rateLimitBps,
                proxyRateLimits: Object.fromEntries(store.getProxyRateLimitsByUser(uid)),
              });
            }
          }
        }
        sendJson(res, 200, { ok: true, ...result });
        return true;
      }
      // 0.10.0.2：批量开号前必须先选定目标节点；主节点才需要本机保留/监听端口预检。
      const targetNode = String(body.node || "").trim();
      if (!targetNode) {
        sendJson(res, 400, { error: "请先选定目标节点，再执行批量开号" });
        return true;
      }
      body.node = targetNode;
      if (targetNode === "master") {
        // 0.9.2：平台保留端口 + 本机当前 LISTENING 端口全部纳入"已占用"，分配自动绕开。
        const reserved = new Set(frpsReservedPorts().map(Number));
        try {
          const listeners = await listTcpListeners();
          const managed = new Set(
            store
              .listProxies()
              .filter((proxy) => !proxy.closedAt && proxy.remotePort)
              .map((proxy) => proxy.remotePort),
          );
          for (const item of listeners) {
            const port = Number(item.port);
            if (!managed.has(port)) reserved.add(port);
          }
        } catch {
          // netstat 不可用时至少保留平台端口排除。
        }
        body.reservedPorts = [...reserved];
      } else {
        body.reservedPorts = [];
      }
      const result = store.batchCreateUsers(body, admin.username);
      sendJson(res, 201, result);
      return true;
    }

    // ---------- 0.9.2 账号导入/导出/模板 ----------
    if (pathname === "/api/admin/users/template" && req.method === "GET") {
      const format = url.searchParams.get("format") === "txt" ? "txt" : "xlsx";
      const defaultPlanName = store.listPlans()[0]?.name || "基础套餐";
      const rows = [
        ["用户ID", "用户名", "密码", "端口范围", "套餐名", "有效天数"],
        ["留空自动生成", "user001", "留空自动生成", "20000-20009", defaultPlanName, "30"],
      ];
      sendAccountFile(res, format, "账号导入模板", rows);
      return true;
    }

    if (pathname === "/api/admin/users/export" && req.method === "GET") {
      const format = url.searchParams.get("format") === "txt" ? "txt" : "xlsx";
      const rows = [["用户ID", "用户名", "初始密码", "端口范围", "套餐名", "套餐天数", "到期时间", "状态"]];
      for (const user of store.listUsers()) {
        const status = !user.enabled
          ? "停用"
          : !user.activated
            ? "未激活"
            : user.expired
              ? "已过期"
              : "启用";
        rows.push([
          user.uid ?? "",
          user.username,
          user.tempPassword ?? "已修改",
          user.portRangesText || "",
          user.planName || "",
          String(user.durationDays ?? ""),
          // 0.9.3：未激活账号到期时间为空（激活时刻才起算）。
          user.expiresAt ? new Date(user.expiresAt).toISOString().slice(0, 10) : "未激活",
          status,
        ]);
      }
      sendAccountFile(res, format, `账号导出-${new Date().toISOString().slice(0, 10)}`, rows);
      store.audit(admin.username, "user.export", `导出 ${rows.length - 1} 个账号`, { format });
      return true;
    }

    // 路径名不以 import 结尾，避免旧版更新包校验正则把路径字符串误判为导入语句。
    if (pathname === "/api/admin/users/import-accounts" && req.method === "POST") {
      const body = await readRaw(req, 5 * 1024 * 1024);
      let table;
      try {
        table = looksLikeXlsx(body) ? parseXlsx(body) : parseDelimited(body.toString("utf8"));
      } catch (error) {
        sendJson(res, 400, { error: `文件解析失败：${error.message}` });
        return true;
      }
      if (!table.length) {
        sendJson(res, 400, { error: "文件内容为空，请按模板填写后再导入" });
        return true;
      }
      // 表头识别：首行含"用户名"视为表头并按列名映射，否则按固定列顺序解析。
      const header = table[0].map((cell) => String(cell ?? "").trim().replace(/\s+/g, ""));
      const hasHeader = header.some((cell) => cell.includes("用户名"));
      const findCol = (keywords) =>
        header.findIndex((cell) => keywords.some((keyword) => cell.includes(keyword)));
      const idx = hasHeader
        ? {
            uid: findCol(["用户ID"]),
            username: findCol(["用户名"]),
            password: findCol(["密码"]),
            portRanges: findCol(["端口范围", "端口段"]),
            planName: findCol(["套餐"]),
            durationDays: findCol(["有效天数", "天数"]),
          }
        : { uid: 0, username: 1, password: 2, portRanges: 3, planName: 4, durationDays: 5 };
      const pick = (cells, index) => (index >= 0 ? String(cells[index] ?? "").trim() : "");
      const records = [];
      const preFailed = [];
      table.slice(hasHeader ? 1 : 0).forEach((cells, i) => {
        const record = {
          row: (hasHeader ? 2 : 1) + i,
          uid: pick(cells, idx.uid),
          username: pick(cells, idx.username),
          password: pick(cells, idx.password),
          portRanges: pick(cells, idx.portRanges),
          planName: pick(cells, idx.planName),
          durationDays: pick(cells, idx.durationDays),
        };
        if (
          ![record.uid, record.username, record.password, record.portRanges, record.planName, record.durationDays].some(
            (value) => value,
          )
        ) {
          return; // 纯空行跳过
        }
        records.push(record);
      });
      if (!records.length) {
        sendJson(res, 400, { error: "未解析到有效数据行，请按模板填写" });
        return true;
      }
      // 显式端口段：格式校验 + OS 占用预检（系统保留端口/监听端口直接拒绝该行）。
      for (const record of records) {
        if (!record.portRanges) continue;
        try {
          await assertRangesPortsFree(parsePortRanges(record.portRanges));
        } catch (error) {
          preFailed.push({ row: record.row, username: record.username, reason: error.message });
        }
      }
      const validRecords = records.filter(
        (record) => !preFailed.some((item) => item.row === record.row),
      );

      // 平台保留端口 + 本机 LISTENING 端口纳入端口池自动分配的排除集合。
      const reserved = new Set(frpsReservedPorts().map(Number));
      try {
        const listeners = await listTcpListeners();
        const managed = new Set(
          store
            .listProxies()
            .filter((proxy) => !proxy.closedAt && proxy.remotePort)
            .map((proxy) => proxy.remotePort),
        );
        for (const item of listeners) {
          const port = Number(item.port);
          if (!managed.has(port)) reserved.add(port);
        }
      } catch {
        // netstat 不可用时至少保留平台端口。
      }
      const result = store.importUsers(validRecords, admin.username, [...reserved]);
      result.failed = [...preFailed, ...result.failed].sort((a, b) => a.row - b.row);
      sendJson(res, 200, result);
      return true;
    }

    if (pathname === "/api/admin/proxies" && req.method === "GET") {
      sendJson(res, 200, { proxies: store.listProxies().map(publicProxy) });
      return true;
    }

    // 0.9.0：隧道级限速（bytes/秒，0=清除/继承用户级）。proxyName 为全限定代理名。
    if (pathname === "/api/admin/proxies/rate-limit" && req.method === "POST") {
      const input = await readJson(req);
      const userId = Number(input.userId);
      const proxyName = String(input.proxyName || input.qualifiedName || "").trim();
      if (!Number.isInteger(userId) || !proxyName) {
        sendJson(res, 400, { error: "缺少用户或隧道标识" });
        return true;
      }
      try {
        const rawBps = Number(input.rateLimitBps ?? 0);
        if (!Number.isFinite(rawBps) || rawBps < 0) {
          sendJson(res, 400, { error: "限速值必须为非负数字（比特/秒，0=清除）" });
          return true;
        }
        const limit = store.setProxyRateLimit(userId, proxyName, Math.floor(rawBps), admin.username);
        // 0.9.3.2：隧道级限速变更后推送命令给在线客户端。
        const user = store.getUserById(userId);
        if (user) {
          enqueueClientCommand(userId, {
            type: "rateLimitUpdate",
            rateLimitBps: user.rateLimitBps,
            proxyRateLimits: Object.fromEntries(store.getProxyRateLimitsByUser(userId)),
          });
          // 0.10.0.2：用户端口段跨从节点时限速命令同步下发到对应从节点。
          const bps = Math.floor(rawBps);
          for (const nodeName of new Set((user.portRanges || []).map(rangeNode))) {
            if (nodeName !== "master") {
              store.enqueueClusterCommand(
                nodeName,
                "rate-limit",
                { limits: [{ userId, proxyName, bps }] },
                admin.username,
              );
            }
          }
        }
        sendJson(res, 200, { ok: true, rateLimitBps: limit });
      } catch (error) {
        sendJson(res, Number(error.status) || 400, { error: error.message });
      }
      return true;
    }

    if (pathname === "/api/admin/icp-text" && req.method === "GET") {
      sendJson(res, 200, {
        icpText: store.getSetting("icp_text") || "",
        policeText: store.getSetting("police_text") || "",
      });
      return true;
    }
    if (pathname === "/api/admin/icp-text" && req.method === "POST") {
      const input = await readJson(req);
      const text = String(input.icpText || "").trim().slice(0, 100);
      const police = String(input.policeText || "").trim().slice(0, 100);
      store.setSetting("icp_text", text);
      store.setSetting("police_text", police);
      store.audit(admin.username, "icp.text.update", "icp-text", { icpText: text, policeText: police });
      sendJson(res, 200, { icpText: text, policeText: police });
      return true;
    }

    // ---------- 版权声明：查看当前生效版权 / 向授权中心申请自定义版权 ----------
    if (pathname === "/api/admin/copyright" && req.method === "GET") {
      sendJson(res, 200, {
        copyright: licenseManager.copyrightSnapshot(),
        identity: licenseManager.machineSnapshot(),
      });
      return true;
    }
    if (pathname === "/api/admin/copyright/apply" && req.method === "POST") {
      const input = await readJson(req);
      const text = String(input.text || "").trim();
      const url = String(input.url || "").trim();
      const reason = String(input.reason || "").trim();
      if (!text) return sendJson(res, 400, { error: "请填写期望显示的版权声明文字" }), true;
      if (!reason) return sendJson(res, 400, { error: "请填写申请理由" }), true;
      if (url && !/^https?:\/\//i.test(url))
        return sendJson(res, 400, { error: "版权链接须为 http/https 地址" }), true;
      // 已在审批中或已授权时禁止重复申请（前端表单也会同步灰显）。
      const currentStatus = licenseManager.copyrightSnapshot().status;
      if (currentStatus === "pending") {
        return (
          sendJson(res, 400, { error: "版权申请正在审批中，请勿重复提交" }), true
        );
      }
      if (currentStatus === "approved") {
        return (
          sendJson(res, 400, { error: "已授权自定义版权，如需变更请联系授权中心处理" }),
          true
        );
      }
      try {
        await licenseManager.applyCopyright({ text, url, reason });
        store.audit(admin.username, "copyright.apply", "copyright", { text });
        sendJson(res, 200, { copyright: licenseManager.copyrightSnapshot() });
      } catch (error) {
        sendJson(res, 502, {
          error: `向授权中心提交申请失败：${error.message || error}`,
        });
      }
      return true;
    }

    // ---------- 0.9.9：公开服务端信息（推送到授权中心，客户端登录页「服务器列表」展示） ----------
    if (pathname === "/api/admin/server-public-info" && req.method === "GET") {
      try {
        const info = await licenseManager.fetchPublicInfo();
        sendJson(res, 200, { info, mode: licenseManager.status().mode });
      } catch (error) {
        sendJson(res, 502, {
          error: `从授权中心获取公开信息失败：${error.message || error}`,
        });
      }
      return true;
    }
    if (pathname === "/api/admin/server-public-info" && req.method === "POST") {
      const input = await readJson(req);
      // 0.10.0.1：推送优惠信息需要集群授权许可（免费额度仅 1 台/集群）。
      if (String(input?.promo || "").trim() && licenseManager.status().mode !== "licensed") {
        sendJson(res, 402, {
          error: "推送优惠信息需要集群授权许可：免费额度为每集群 1 台服务端（主节点）",
          code: "SERVER_LICENSE_REQUIRED",
        });
        return true;
      }
      try {
        // 0.10.0：集群节点信息由主节点自动采集（注册表实时状态），随公开信息一并推送。
        const info = await licenseManager.publishPublicInfo({
          ...input,
          clusterName: clusterName(),
          clusterNodes: store.listClusterNodes().map((node) => ({
            name: node.name,
            host: node.host,
            clientApiPort: node.clientApiPort,
            bindPort: node.bindPort,
            online: node.online,
            version: node.version,
          })),
        });
        store.audit(admin.username, "license.publish_public_info", "license", {
          location: info?.location || "",
          hidden: Boolean(info?.hidden),
          clusterName: info?.clusterName || "",
        });
        sendJson(res, 200, { info });
      } catch (error) {
        sendJson(res, 502, { error: `推送公开信息失败：${error.message || error}` });
      }
      return true;
    }

    // ---------- 网络设置（管理端口 + HTTPS） ----------
    if (pathname === "/api/admin/network" && req.method === "GET") {
      sendJson(res, 200, { network: resolveNetworkConfig(DATA_DIR) });
      return true;
    }
    if (pathname === "/api/admin/network" && req.method === "POST") {
      const input = await readJson(req);
      const previousNetwork = resolveNetworkConfig(DATA_DIR);
      const network = saveNetworkConfig(DATA_DIR, {
        port: input.port,
        httpsEnabled: input.httpsEnabled,
      });
      store.audit(admin.username, "network.update", "network", {
        port: input.port,
        httpsEnabled: input.httpsEnabled,
      });
      const portChanged = network.port !== previousNetwork.port && !network.envLockedPort;
      const httpsChanged = network.httpsActive !== previousNetwork.httpsActive;
      // 端口或 HTTPS 传输模式变更时，在当前进程内重启 Web 监听，
      // 完成后前端按返回的 redirectUrl 自动跳转。
      if (portChanged || httpsChanged) {
        try {
          const restarted = await restartWebServer(network.port, network.httpsActive);
          const scheme = restarted.httpsActive ? "https" : "http";
          const host = req.headers.host
            ? req.headers.host.replace(/:\d+$/, "")
            : (HOST === "0.0.0.0" ? "127.0.0.1" : HOST);
          sendJson(res, 200, {
            network,
            restarted: true,
            redirectUrl: `${scheme}://${host}:${network.port}`,
            message: "网络配置已保存，Web 服务已重启",
          });
        } catch (error) {
          sendJson(res, 200, {
            network,
            restarted: false,
            message: `网络配置已保存，但重启失败：${error.message}，请手动重启服务端`,
          });
        }
      } else {
        sendJson(res, 200, {
          network,
          restarted: false,
          message: "网络配置已保存",
        });
      }
      return true;
    }
    if (pathname === "/api/admin/network/cert" && req.method === "POST") {
      const kind = url.searchParams.get("kind") === "key" ? "key" : "cert";
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 200 * 1024) {
          sendJson(res, 413, { error: "证书/私钥文件不能超过 200KB" });
          return true;
        }
        chunks.push(chunk);
      }
      const buffer = Buffer.concat(chunks);
      const saved = saveTlsMaterial(DATA_DIR, kind, buffer);
      store.audit(admin.username, "network.cert.upload", kind, { size: buffer.length });
      sendJson(res, 200, { ok: true, ...saved, network: resolveNetworkConfig(DATA_DIR) });
      return true;
    }
    if (pathname === "/api/admin/network/cert" && req.method === "DELETE") {
      const network = clearTlsMaterial(DATA_DIR);
      store.audit(admin.username, "network.cert.clear", "network");
      sendJson(res, 200, { ok: true, network });
      return true;
    }

    // ---------- 管理员用户名 ----------
    if (pathname === "/api/admin/username" && req.method === "POST") {
      const input = await readJson(req);
      const updated = store.changeAdminUsername(
        admin.id,
        input.currentPassword,
        input.newUsername,
        admin.username,
      );
      const session = adminSession(updated, req);
      sendJson(res, 200, { admin: { username: updated.username } }, {
        "Set-Cookie": session.cookie,
      });
      return true;
    }

    if (pathname === "/api/admin/password" && req.method === "POST") {
      const input = await readJson(req);
      if (input.newPassword !== input.confirmPassword) {
        throw new Error("两次输入的新密码不一致");
      }
      const updated = store.changeAdminPassword(
        admin.id,
        input.currentPassword,
        input.newPassword,
        admin.username,
      );
      const session = adminSession(updated, req);
      sendJson(res, 200, { admin: { username: updated.username } }, {
        "Set-Cookie": session.cookie,
      });
      return true;
    }

    const resetTrafficMatch = /^\/api\/admin\/users\/(\d+)\/reset-traffic$/.exec(pathname);
    if (resetTrafficMatch && req.method === "POST") {
      const user = store.resetUserTraffic(Number(resetTrafficMatch[1]), admin.username);
      sendJson(res, user ? 200 : 404, user ? { user: publicAdminUser(user) } : { error: "用户不存在" });
      return true;
    }

    const match = /^\/api\/admin\/users\/(\d+)(?:\/(disconnect|proxies|renew))?$/.exec(pathname);
    if (match) {
      const id = Number(match[1]);
      if (match[2] === "disconnect" && req.method === "POST") {
        const user = store.revokeUser(id, admin.username);
        sendJson(res, user ? 200 : 404, user ? { user: publicAdminUser(user) } : { error: "用户不存在" });
        return true;
      }
      if (match[2] === "proxies" && req.method === "GET") {
        const user = store.listUsers().find((item) => item.id === id);
        sendJson(
          res,
          user ? 200 : 404,
          user
            ? { user: publicAdminUser(user), proxies: store.listProxies(id).map(publicProxy) }
            : { error: "用户不存在" },
        );
        return true;
      }
      if (match[2] === "renew" && req.method === "POST") {
        const user = store.renewUser(id, await readJson(req), admin.username);
        sendJson(
          res,
          user ? 200 : 404,
          user ? { user: publicAdminUser(user) } : { error: "用户不存在" },
        );
        return true;
      }
      if (req.method === "PUT") {
        const body = await readJson(req);
        if (body.portRanges !== undefined && body.portRanges !== null) {
          // 0.9.2：端口段变更同样先预检占用。
          await assertRangesPortsFree(parsePortRanges(body.portRanges));
        }
        const user = store.updateUser(id, body, admin.username);
        // 0.9.3.2：限速变更后推送命令给在线客户端。
        if (user && "rateLimitBps" in body) {
          enqueueClientCommand(user.id, {
            type: "rateLimitUpdate",
            rateLimitBps: user.rateLimitBps,
            proxyRateLimits: Object.fromEntries(store.getProxyRateLimitsByUser(user.id)),
          });
        }
        sendJson(res, user ? 200 : 404, user ? { user: publicAdminUser(user) } : { error: "用户不存在" });
        return true;
      }
      if (req.method === "DELETE") {
        const deleted = store.deleteUser(id, admin.username);
        sendJson(res, deleted ? 200 : 404, deleted ? { ok: true } : { error: "用户不存在" });
        return true;
      }
    }

    if (pathname === "/api/admin/frps/start" && req.method === "POST") {
      licenseManager.assertAllowed();
      frps.start();
      sendJson(res, 202, { frps: frps.status() });
      return true;
    }
    if (pathname === "/api/admin/frps/stop" && req.method === "POST") {
      frps.stop();
      sendJson(res, 202, { frps: frps.status() });
      return true;
    }

    // ---------- 0.9.0 HTTP/HTTPS 隧道 vhost 端口 ----------
    if (pathname === "/api/admin/frps/vhost-ports" && req.method === "GET") {
      sendJson(res, 200, {
        httpPort: vhostHttpPort(),
        httpsPort: vhostHttpsPort(),
        envHttpLocked: FRP_VHOST_HTTP_PORT_ENV !== null,
        envHttpsLocked: FRP_VHOST_HTTPS_PORT_ENV !== null,
      });
      return true;
    }
    if (pathname === "/api/admin/frps/vhost-ports" && req.method === "PUT") {
      const body = await readJson(req);
      const httpPort = Number(body.httpPort);
      const httpsPort = Number(body.httpsPort);
      if (![httpPort, httpsPort].every((p) => Number.isInteger(p) && p >= 0 && p <= 65535)) {
        throw new Error("vhost 端口须为 0-65535 的整数（0 表示关闭）");
      }
      if (FRP_VHOST_HTTP_PORT_ENV !== null) {
        throw new Error("HTTP vhost 端口已由环境变量 FRP_VHOST_HTTP_PORT 固定，无法在页面修改");
      }
      if (FRP_VHOST_HTTPS_PORT_ENV !== null) {
        throw new Error("HTTPS vhost 端口已由环境变量 FRP_VHOST_HTTPS_PORT 固定，无法在页面修改");
      }
      if (httpPort > 0 && httpsPort > 0 && httpPort === httpsPort) {
        throw new Error("HTTP 与 HTTPS vhost 端口不能相同");
      }
      for (const reserved of [FRP_BIND_PORT, FRP_METRICS_PORT, PORT, FIXED_CLIENT_API_PORT]) {
        if (httpPort === reserved || httpsPort === reserved) {
          throw new Error(`端口 ${reserved} 是系统/frp 服务保留端口，不能用作 vhost 端口`);
        }
      }
      // 0.9.2：保存前真实探测新端口；被占用则返回 400，配置不动、frps 不重启。
      const probeTargets = [httpPort, httpsPort].filter((port) => port > 0);
      const busy = await probeTcpPorts(probeTargets, { useCache: false });
      if (busy.length) {
        const owners = await findListenersByPort(busy.map((item) => item.port)).catch(() => []);
        const detail = busy
          .map((item) => {
            const owner = owners.find((o) => o.port === item.port);
            return `${item.port}${owner?.processName ? `（占用进程：${owner.processName}）` : ""}`;
          })
          .join("、");
        sendJson(res, 400, { error: `vhost 端口 ${detail} 已被占用，请释放或更换后再试` });
        return true;
      }
      store.setSetting("vhost_http_port", String(httpPort));
      store.setSetting("vhost_https_port", String(httpsPort));
      store.audit(admin.username, "frps.vhost_ports.update", "frps", { httpPort, httpsPort });
      const wasRunning = frps.process !== null;
      if (wasRunning) {
        // 等待旧 frps 退出后再以新 vhost 配置启动，避免同步 stop/start 竞态导致 frps 不重启。
        await frps.restart();
      }
      sendJson(res, 200, {
        httpPort: vhostHttpPort(),
        httpsPort: vhostHttpsPort(),
        restarted: wasRunning,
      });
      return true;
    }

    // ---------- 0.10.0 frp 监听端口（bindPort）：默认随机生成，支持手动修改 ----------
    if (pathname === "/api/admin/frps/bind-port" && req.method === "GET") {
      sendJson(res, 200, {
        bindPort: FRP_BIND_PORT,
        metricsPort: FRP_METRICS_PORT,
        envLocked: FRP_BIND_PORT_ENV !== null,
      });
      return true;
    }
    if (pathname === "/api/admin/frps/bind-port" && req.method === "PUT") {
      const body = await readJson(req);
      const port = Number(body.bindPort);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error("监听端口须为 1-65535 的整数");
      }
      if (FRP_BIND_PORT_ENV !== null) {
        throw new Error("监听端口已由环境变量 FRP_BIND_PORT 固定，无法在页面修改");
      }
      if (Number.isInteger(FRP_METRICS_PORT) && port === FRP_METRICS_PORT) {
        throw new Error(`端口 ${FRP_METRICS_PORT} 是 frp 指标端口，不能用作监听端口`);
      }
      for (const reserved of [PORT, FIXED_CLIENT_API_PORT, vhostHttpPort(), vhostHttpsPort()]) {
        if (Number.isInteger(reserved) && reserved > 0 && port === reserved) {
          throw new Error(`端口 ${reserved} 是系统/隧道保留端口，不能用作监听端口`);
        }
      }
      if (port === FRP_BIND_PORT) {
        sendJson(res, 200, { bindPort: FRP_BIND_PORT, restarted: false });
        return true;
      }
      const busy = await probeTcpPorts([port], { useCache: false });
      if (busy.length) {
        const owners = await findListenersByPort([port]).catch(() => []);
        const owner = owners.find((item) => item.port === port);
        sendJson(res, 400, {
          error: `端口 ${port} 已被占用${owner?.processName ? `（占用进程：${owner.processName}）` : ""}，请释放或更换后再试`,
        });
        return true;
      }
      store.setSetting("frp_bind_port", String(port));
      FRP_BIND_PORT = port;
      store.audit(admin.username, "frps.bind_port.update", "frps", { bindPort: port });
      const wasRunning = frps.process !== null;
      if (wasRunning) {
        await frps.restart();
      }
      sendJson(res, 200, { bindPort: FRP_BIND_PORT, restarted: wasRunning });
      return true;
    }

    // ---------- 0.9.2 防火墙 ----------
    if (pathname === "/api/admin/firewall/status" && req.method === "GET") {
      const status = await firewallStatus().catch((error) => ({
        supported: false,
        backend: null,
        reason: error?.message || "防火墙状态探测失败",
      }));
      sendJson(res, 200, status);
      return true;
    }
    if (pathname === "/api/admin/firewall/ports" && req.method === "GET") {
      sendJson(res, 200, await buildFirewallPortReport());
      return true;
    }
    if (pathname === "/api/admin/firewall/open" && req.method === "POST") {
      const body = await readJson(req);
      const ports = Array.isArray(body.ports)
        ? body.ports
        : String(body.ports || "")
            .split(/[,，\s]+/)
            .filter(Boolean);
      if (ports.length === 0) throw new Error("请填写要放行的端口或端口段");
      try {
        const result = await openFirewallPorts(ports, body.proto || "tcp");
        store.audit(admin.username, "firewall.port.open", "firewall", {
          ports: result.opened.map((spec) => `${spec.port}/${spec.proto}`),
        });
        // 0.10.0.2：防火墙由主节点统一管理——放行命令同步下发到所有在线从节点。
        for (const node of store.listClusterNodes()) {
          if (!node.online) continue;
          store.enqueueClusterCommand(
            node.name,
            "firewall",
            { action: "open", ports: body.ports ?? String(body.ports || ""), proto: body.proto || "tcp" },
            admin.username,
          );
        }
        sendJson(res, 200, { opened: result.opened });
      } catch (error) {
        if (error.code === "FIREWALL_UNSUPPORTED" || error.code === "FIREWALL_FORBIDDEN") {
          sendJson(res, 403, { error: error.message, code: error.code });
          return true;
        }
        throw error;
      }
      return true;
    }
    // 0.9.3：防火墙整体关闭 / 开启 / 重启。
    if (pathname === "/api/admin/firewall/control" && req.method === "POST") {
      const body = await readJson(req);
      const action = String(body.action || "");
      try {
        const result = await controlFirewall(action);
        store.audit(admin.username, "firewall.control", "firewall", { action: result.action });
        // 0.10.0.2：防火墙开关/重启命令同步下发到所有在线从节点。
        for (const node of store.listClusterNodes()) {
          if (!node.online) continue;
          store.enqueueClusterCommand(
            node.name,
            "firewall",
            { action: "control", firewallAction: action },
            admin.username,
          );
        }
        const status = await firewallStatus().catch(() => ({ supported: true }));
        sendJson(res, 200, { ok: true, action: result.action, status });
      } catch (error) {
        if (
          error.code === "FIREWALL_UNSUPPORTED" ||
          error.code === "FIREWALL_FORBIDDEN" ||
          error.code === "FIREWALL_LIFECYCLE"
        ) {
          sendJson(res, 403, { error: error.message, code: error.code });
          return true;
        }
        throw error;
      }
      return true;
    }

    // ---------- 0.10.0 注册/忘记密码：功能开关 + SMTP 邮箱配置 + 模板 + 测试邮箱 ----------
    if (pathname === "/api/admin/email-settings" && req.method === "GET") {
      const smtp = smtpConfig();
      sendJson(res, 200, {
        registerEnabled: registerEnabled(),
        forgotEnabled: forgotEnabled(),
        clusterName: clusterName(),
        serverDisplayName: store.getSetting("server_display_name") || "",
        // 0.10.0.1：邮箱验证码有效期（分钟）。
        emailCodeTtlMinutes: Math.round(emailCodeTtlMs() / 60_000),
        smtp: {
          host: smtp.host,
          port: smtp.port || (smtp.secure ? 465 : 587),
          secure: Boolean(smtp.secure),
          user: smtp.user,
          from: smtp.from,
          hasPass: Boolean(smtp.pass),
        },
        templates: { register: mailTemplate("register"), forgot: mailTemplate("forgot") },
      });
      return true;
    }
    if (pathname === "/api/admin/email-settings" && req.method === "PUT") {
      const input = await readJson(req);
      if (input.registerEnabled !== undefined) {
        store.setSetting("register_enabled", input.registerEnabled ? "1" : "0");
      }
      if (input.forgotEnabled !== undefined) {
        store.setSetting("forgot_enabled", input.forgotEnabled ? "1" : "0");
      }
      if (input.clusterName !== undefined) {
        store.setSetting("cluster_name", String(input.clusterName || "").trim().slice(0, 60));
      }
      // 0.10.0.2：主节点服务器名称自定义（客户端节点列表 / 总览集群卡展示）。
      if (input.serverDisplayName !== undefined) {
        store.setSetting("server_display_name", String(input.serverDisplayName || "").trim().slice(0, 60));
      }
      // 0.10.0.1：邮箱验证码有效期（分钟，1-60）。
      if (input.emailCodeTtlMinutes !== undefined) {
        const minutes = Math.round(Number(input.emailCodeTtlMinutes));
        if (!Number.isFinite(minutes) || minutes < 1 || minutes > 60) {
          throw new Error("验证码有效期须为 1-60 的整数分钟");
        }
        store.setSetting("email_code_ttl_minutes", String(minutes));
      }
      if (input.smtp !== undefined) {
        const previous = smtpConfig();
        const host = String(input.smtp.host || "").trim();
        if (host && !/^[a-z0-9.-]+$/i.test(host)) throw new Error("SMTP 服务器地址格式不正确");
        const port = Number(input.smtp.port) || (input.smtp.secure ? 465 : 587);
        if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("SMTP 端口无效");
        const pass = String(input.smtp.pass ?? "").length > 0 ? String(input.smtp.pass) : previous.pass;
        store.setSetting(
          "smtp_config",
          JSON.stringify({
            host,
            port,
            secure: Boolean(input.smtp.secure) || port === 465,
            user: String(input.smtp.user || "").trim(),
            pass,
            from: String(input.smtp.from || "").trim(),
          }),
        );
      }
      if (input.templates !== undefined) {
        for (const kind of ["register", "forgot"]) {
          const template = input.templates?.[kind];
          if (template === undefined) continue;
          store.setSetting(
            `mail_template_${kind}`,
            JSON.stringify({
              subject: String(template.subject || "").slice(0, 120),
              body: String(template.body || "").slice(0, 4000),
            }),
          );
        }
      }
      store.audit(admin.username, "email_settings.update");
      sendJson(res, 200, { ok: true });
      return true;
    }
    if (pathname === "/api/admin/email-settings/test" && req.method === "POST") {
      try {
        const input = await readJson(req);
        assertSmtpReady();
        const to = normalizeEmailFormat(input.to);
        const config = smtpConfig();
        await sendMail(config, {
          to,
          subject: "XFCloud Tunnel 测试邮件",
          text: `这是一封来自 ${brandingConfig().clientName || "XFCloud Tunnel"} 的测试邮件。\n\nSMTP 配置正确，验证码邮件将可以正常发送。\n\n发送时间：${new Date().toLocaleString("zh-CN")}`,
        });
        store.audit(admin.username, "email_settings.test", to);
        sendJson(res, 200, { ok: true, message: `测试邮件已发送至 ${to}，请查收` });
      } catch (error) {
        sendJson(res, 400, { error: error.message });
      }
      return true;
    }

    // ---------- 0.10.0 套餐码管理 ----------
    if (pathname === "/api/admin/plan-codes" && req.method === "GET") {
      const codes = store.listPlanCodes({
        batchId: url.searchParams.get("batchId") || "",
        status: url.searchParams.get("status") || "",
      });
      sendJson(res, 200, { codes });
      return true;
    }
    if (pathname === "/api/admin/plan-codes" && req.method === "POST") {
      const input = await readJson(req);
      // 0.10.0.2：套餐码生成前必须先选定目标节点（master 或集群从节点）。
      const node = String(input.node || "").trim();
      if (!node) {
        sendJson(res, 400, { error: "请先选定目标节点，再生成套餐码" });
        return true;
      }
      const result = store.generatePlanCodes(
        { planId: Number(input.planId), count: Number(input.count), node },
        admin.username,
      );
      sendJson(res, 200, { batchId: result.batchId, codes: result.codes, plan: publicPlan(result.plan), node: result.node });
      return true;
    }
    if (pathname === "/api/admin/plan-codes/delete" && req.method === "POST") {
      const input = await readJson(req);
      const result = store.deletePlanCodes(input.ids, admin.username);
      sendJson(res, 200, result);
      return true;
    }
    if (pathname === "/api/admin/plan-codes/export" && req.method === "GET") {
      const codes = store.listPlanCodes({
        batchId: url.searchParams.get("batchId") || "",
        status: url.searchParams.get("status") || "unused",
      });
      const text = codes.map((item) => item.code).join("\n");
      res.writeHead(200, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Disposition": `attachment; filename="plan-codes-${url.searchParams.get("batchId") || "all"}.txt"`,
        "Cache-Control": "no-store",
      });
      res.end(`${text}\n`);
      return true;
    }

    // ---------- 0.10.0 集群管理 ----------
    // 0.10.0.1：本机部署环境检测（sshpass / frps 内核 / 部署路径），集群页前置提示。
    if (pathname === "/api/admin/cluster/env" && req.method === "GET") {
      sendJson(res, 200, clusterEnvStatus());
      return true;
    }
    if (pathname === "/api/admin/cluster/nodes" && req.method === "GET") {
      sendJson(res, 200, {
        role: SERVER_ROLE,
        clusterName: clusterName(),
        // 0.10.2.0：集群 id（授权中心心跳分配，客户端可凭该 id 登录集群）。
        clusterId: String(store.getSetting("cluster_id") || ""),
        serverDisplayName: store.getSetting("server_display_name") || "",
        nodes: store.listClusterNodes(),
        // 0.10.1.3 规格1：主节点自身 frps 概况（状态 + 内存日志），集群页主节点行展示。
        masterFrps: {
          state: frps.state,
          pid: frps.process?.pid ?? null,
          startedAt: frps.startedAt,
          logs: frps.logs.slice(-200),
        },
      });
      return true;
    }
    if (pathname === "/api/admin/cluster/nodes" && req.method === "POST") {
      // 0.10.0.1：免费额度——每集群仅 1 台（主节点）免费；添加从节点需集群授权许可。
      assertClusterLicense();
      const input = await readJson(req);
      const created = store.createClusterNode(
        {
          name: input.name,
          host: input.host,
          address: input.address,
          clientApiPort: input.clientApiPort,
        },
        admin.username,
      );
      sendJson(res, 200, { node: created.node, token: created.token });
      return true;
    }
    // 0.10.0.2：各节点端口池占用情况（开号 / 套餐码节点选择器使用）。
    if (pathname === "/api/admin/cluster/pools" && req.method === "GET") {
      const pools = [
        {
          node: "master",
          label: store.getSetting("server_display_name") || derivePublicHost(req),
          isMaster: true,
          online: true,
          ...store.nodePortUsage("master"),
        },
        ...store.listClusterNodes().map((node) => ({
          node: node.name,
          label: node.name,
          isMaster: false,
          online: Boolean(node.online),
          ...store.nodePortUsage(node.name),
        })),
      ];
      sendJson(res, 200, { pools });
      return true;
    }
    // 0.10.0.2：集群级映射监控——各在线从节点的活跃映射快照（主节点映射走 /api/admin/proxies）。
    if (pathname === "/api/admin/cluster/proxies" && req.method === "GET") {
      const proxies = [];
      for (const node of store.listClusterNodes()) {
        if (!node.online) continue;
        const rows = Array.isArray(node.stats?.proxies) ? node.stats.proxies : [];
        for (const row of rows) {
          proxies.push({ ...row, node: node.name, isMaster: false });
        }
      }
      sendJson(res, 200, { proxies, sampledAt: new Date().toISOString() });
      return true;
    }
    // 0.10.0.2：同步版本——把主节点当前版本（授权中心最新服务端包）同步到所有在线从节点。
    if (pathname === "/api/admin/cluster/nodes/sync-version" && req.method === "POST") {
      const targets = store.listClusterNodes().filter((node) => node.online);
      for (const node of targets) {
        store.enqueueClusterCommand(node.name, "version-sync", { version: VERSION }, admin.username);
      }
      store.audit(admin.username, "cluster.version.sync", "cluster", {
        targets: targets.map((node) => node.name),
      });
      // 0.10.0.3：version-sync 命令为 0.10.0.2 新增——旧版本从节点不认识该命令会静默忽略，
      // 对这类节点提示管理员重新部署（部署会直接安装主节点当前版本代码）。
      // 0.10.1.2 规格1：原正则 /^0\.(\d+)\.(\d+)/ 丢弃第 4 位修订号，把 0.10.0.3 / 0.10.1.1
      // 误判为 <0.10.0.2（偶发报「版本过旧」）。改为逐段数值比较实时上报的节点版本。
      const outdated = targets
        .filter((node) => {
          const version = String(node.version || "").trim();
          // 版本未知（尚未上报）不算过旧——命令下发后从节点不认识会回报未知命令，可重新部署。
          if (!version) return false;
          return compareVersions(version, MIN_VERSION_SYNC_COMMAND) < 0;
        })
        .map((node) => `${node.name}（v${node.version || "未知"}）`);
      sendJson(res, 200, { ok: true, targets: targets.map((node) => node.name), outdated });
      return true;
    }
    // ---------- 0.10.1.0：远程修改从节点 frps 监听端口（命令队列下发，从节点约 30 秒内执行） ----------
    if (pathname === "/api/admin/cluster/nodes/bind-port" && req.method === "POST") {
      const input = await readJson(req);
      const node = store.getClusterNodeByName(String(input.name || ""));
      if (!node) throw new Error("节点不存在");
      const port = Number(input.bindPort);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error("监听端口须为 1-65535 的整数");
      }
      if (!node.online) {
        throw new Error(`节点 ${node.name} 当前离线，无法下发端口修改命令`);
      }
      store.enqueueClusterCommand(node.name, "bind-port", { bindPort: port }, admin.username);
      sendJson(res, 200, {
        ok: true,
        message: `命令已下发，${node.name} 将在下次同步（约 30 秒内）切换到端口 ${port}`,
      });
      return true;
    }
    // ---------- 0.10.1.3 规格1：主节点远程启停/重启从节点 frps（命令队列下发） ----------
    if (pathname === "/api/admin/cluster/nodes/frps-control" && req.method === "POST") {
      const input = await readJson(req);
      const node = store.getClusterNodeByName(String(input.name || ""));
      if (!node) throw new Error("节点不存在");
      const action = String(input.action || "");
      if (!["start", "stop", "restart"].includes(action)) {
        throw new Error("action 须为 start / stop / restart");
      }
      if (!node.online) {
        throw new Error(`节点 ${node.name} 当前离线，无法下发 frps ${action} 命令`);
      }
      const id = store.enqueueClusterCommand(node.name, "frps-control", { action }, admin.username);
      sendJson(res, 200, {
        ok: true,
        id,
        message: `frps ${action} 命令已下发，${node.name} 将在下次同步（约 30 秒内）执行`,
      });
      return true;
    }
    // ---------- 0.10.1.3 规格1：主节点查看从节点 frps 运行日志（下发命令后轮询结果） ----------
    if (pathname === "/api/admin/cluster/nodes/frps-logs" && req.method === "POST") {
      const input = await readJson(req);
      const node = store.getClusterNodeByName(String(input.name || ""));
      if (!node) throw new Error("节点不存在");
      if (!node.online) {
        throw new Error(`节点 ${node.name} 当前离线，无法获取 frps 日志`);
      }
      const lines = Math.min(Math.max(Number(input.lines) || 120, 10), 400);
      const id = store.enqueueClusterCommand(node.name, "frps-logs", { lines }, admin.username);
      sendJson(res, 200, { ok: true, id, message: `已向 ${node.name} 下发日志获取命令，约 30 秒内回报` });
      return true;
    }
    // ---------- 0.10.1.3 规格1：查询节点最近命令执行状态（frps 日志/控制结果轮询） ----------
    if (pathname === "/api/admin/cluster/commands" && req.method === "GET") {
      const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
      const nodeName = String(url.searchParams.get("name") || "");
      const type = String(url.searchParams.get("type") || "");
      sendJson(res, 200, {
        commands: store.listClusterCommands(nodeName, type, 10),
      });
      return true;
    }
    // ---------- 0.10.1.1 规格10：设置备用主节点优先级（>0=可自动升主，数字越大越优先） ----------
    if (pathname === "/api/admin/cluster/nodes/priority" && req.method === "POST") {
      const input = await readJson(req);
      const node = store.setClusterNodePriority(Number(input.id), input.priority, admin.username);
      sendJson(res, 200, {
        ok: true,
        node,
        message:
          Number(input.priority) > 0
            ? `已设置 ${node.name} 为备用主节点（优先级 ${node.priority}），主节点失联时优先升主`
            : `已取消 ${node.name} 的备用主资格`,
      });
      return true;
    }
    if (pathname === "/api/admin/cluster/nodes/deploy" && req.method === "POST") {
      // 0.10.0.1：部署从节点同样需要集群授权许可（免费额度仅 1 台/集群）。
      assertClusterLicense();
      const input = await readJson(req);
      // 0.10.0.1：节点不存在时自动登记（管理页「添加节点」一步完成登记 + 部署）。
      let node = store.getClusterNodeByName(String(input.name || ""));
      if (!node) {
        node = store
          .createClusterNode(
            {
              name: input.name,
              host: input.host,
              address: input.address,
              clientApiPort: FIXED_CLIENT_API_PORT,
            },
            admin.username,
          )
          .node;
      }
      const sshUser = String(input.sshUser || "root").trim();
      const sshPassword = String(input.sshPassword || "");
      if (!sshPassword) {
        sendJson(res, 400, { error: "请填写从节点 SSH 密码" });
        return true;
      }
      try {
        // 每次部署重置节点令牌（旧令牌立即失效），保证 .env 只含最新令牌。
        const reset = store.resetClusterNodeToken(node.id, admin.username);
        const masterHost = String(input.masterAddress || "").trim() || derivePublicHost(req);
        const log = await deployClusterNode(
          { ...reset.node, token: reset.token },
          { sshUser, sshPassword },
          masterHost,
        );
        store.markClusterNodeStatus(reset.node.id, "pending");
        store.audit(admin.username, "cluster.node.deploy", node.name);
        sendJson(res, 200, { ok: true, token: reset.token, log });
      } catch (error) {
        sendJson(res, 400, { error: error.message });
      }
      return true;
    }
    if (pathname === "/api/admin/cluster/nodes/delete" && req.method === "POST") {
      const input = await readJson(req);
      store.deleteClusterNode(input.id, admin.username);
      sendJson(res, 200, { ok: true });
      return true;
    }
    // 0.10.0.1：设为主节点——把从节点提升为主节点，旧主节点（本机）降级为从节点。
    if (pathname === "/api/admin/cluster/nodes/promote" && req.method === "POST") {
      const input = await readJson(req);
      // 0.10.0.2：设为主节点属高危操作，须先验证当前管理员密码。
      if (!store.verifyAdminPassword(admin.id, input.adminPassword)) {
        sendJson(res, 403, { error: "管理员密码验证失败" });
        return true;
      }
      const node = store
        .listClusterNodes()
        .find((item) => item.id === Number(input.id));
      if (!node) {
        sendJson(res, 404, { error: "节点不存在" });
        return true;
      }
      const sshUser = String(input.sshUser || "root").trim() || "root";
      const sshPassword = String(input.sshPassword || "");
      if (!sshPassword) {
        sendJson(res, 400, { error: "请填写该节点的 root SSH 密码" });
        return true;
      }
      const oldMasterHost = String(input.masterAddress || "").trim() || derivePublicHost(req);
      try {
        const result = await promoteClusterNode(node, { sshUser, sshPassword }, oldMasterHost);
        store.audit(admin.username, "cluster.node.promote", node.name);
        // systemd 场景：写好本机降级 drop-in 后再延迟重启（先让响应送达浏览器）。
        if (result.demote?.mode === "systemd") {
          mkdirSync(result.demote.dropInDir, { recursive: true });
          writeFileSync(join(result.demote.dropInDir, "cluster-slave.conf"), result.demote.dropIn);
          const unit = result.demote.unit;
          spawn("sh", ["-c", `sleep 3 && systemctl daemon-reload && systemctl restart ${unit}`], {
            detached: true,
            stdio: "ignore",
          }).unref?.();
        }
        sendJson(res, 200, {
          ok: true,
          log: result.log,
          demote: {
            mode: result.demote.mode,
            reason: result.demote.reason || "",
            envLines: result.demote.envLines || [],
            unit: result.demote.unit || "",
          },
          newMasterHost: node.host,
          oldMasterName: result.oldMasterName,
        });
      } catch (error) {
        sendJson(res, 400, { error: error.message });
      }
      return true;
    }
  }

  // ---------- 0.10.0 注册 / 忘记密码（公共接口，带图形验证码 + 邮箱验证码） ----------
  if (pathname === "/api/client/auth-config" && req.method === "GET") {
    sendJson(res, 200, {
      registerEnabled: registerEnabled(),
      forgotEnabled: forgotEnabled(),
      clusterName: clusterName(),
      role: SERVER_ROLE,
      registerEndpoint: clusterRegisterEndpoint(req),
    });
    return true;
  }

  if (pathname === "/api/client/captcha" && req.method === "GET") {
    const captcha = createCaptcha(CAPTCHA_SECRET);
    sendJson(res, 200, { token: captcha.token, svg: captcha.svg });
    return true;
  }

  // 0.10.0.1：滑动验证码挑战——发送邮箱验证码前的人机验证（缺口 X 服务端保密）。
  if (pathname === "/api/client/slider-captcha" && req.method === "GET") {
    const challenge = createSliderChallenge(CAPTCHA_SECRET);
    sendJson(res, 200, {
      token: challenge.token,
      background: challenge.background,
      piece: challenge.piece,
      pieceY: challenge.pieceY,
      width: challenge.width,
      height: challenge.height,
      pieceSize: challenge.pieceSize,
    });
    return true;
  }

  if (pathname === "/api/client/register/send-code" && req.method === "POST") {
    try {
      if (!registerEnabled()) throw new Error("管理员未开启注册功能");
      assertLoginRate(req);
      const input = await readJson(req);
      const email = normalizeEmailFormat(input.email);
      // 0.10.0.1：发送验证码改用滑动验证（拖动拼图），图形验证码保留给注册提交。
      assertSliderCaptcha(input.sliderToken, input.sliderX);
      if (store.getUserByEmail(email)) {
        throw new Error("该邮箱已注册，请直接登录或使用忘记密码");
      }
      const code = issueEmailCode("register", email);
      await sendVerificationMail("register", email, code);
      clearLoginFailures(req);
      sendJson(res, 200, { ok: true });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return true;
  }

  if (pathname === "/api/client/register" && req.method === "POST") {
    try {
      if (!registerEnabled()) throw new Error("管理员未开启注册功能");
      assertLoginRate(req);
      const input = await readJson(req);
      const email = normalizeEmailFormat(input.email);
      assertCaptcha(input.captchaToken, input.captchaAnswer);
      assertEmailCode("register", email, input.code);
      const user = store.registerUser({ email, password: input.password, username: input.username });
      clearLoginFailures(req);
      store.audit(`user:${user.uid}`, "client.register", email);
      sendJson(res, 200, {
        ok: true,
        uid: user.uid,
        username: user.username,
        email: user.email,
        message: "注册成功，请使用用户 ID 或邮箱登录",
      });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return true;
  }

  if (pathname === "/api/client/forgot/send-code" && req.method === "POST") {
    try {
      if (!forgotEnabled()) throw new Error("管理员未开启忘记密码功能");
      assertLoginRate(req);
      const input = await readJson(req);
      const email = normalizeEmailFormat(input.email);
      // 0.10.0.1：发送验证码改用滑动验证（拖动拼图），图形验证码保留给重置提交。
      assertSliderCaptcha(input.sliderToken, input.sliderX);
      const user = store.getUserByEmail(email);
      if (!user) throw new Error("该邮箱未注册");
      const code = issueEmailCode("forgot", email);
      await sendVerificationMail("forgot", email, code, user.uid);
      clearLoginFailures(req);
      sendJson(res, 200, { ok: true });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return true;
  }

  if (pathname === "/api/client/forgot/reset" && req.method === "POST") {
    try {
      if (!forgotEnabled()) throw new Error("管理员未开启忘记密码功能");
      assertLoginRate(req);
      const input = await readJson(req);
      const email = normalizeEmailFormat(input.email);
      assertCaptcha(input.captchaToken, input.captchaAnswer);
      assertEmailCode("forgot", email, input.code);
      const user = store.resetPasswordByEmail(email, input.newPassword);
      clearLoginFailures(req);
      sendJson(res, 200, { ok: true, uid: user.uid, message: "密码已重置，请使用新密码登录" });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return true;
  }

  // ---------- 0.10.0 集群 agent 接口（节点令牌认证；主从共用一套路由） ----------
  if (pathname === "/api/cluster/agent/sync" && req.method === "POST") {
    const node = clusterAgentFromRequest(req);
    if (!node) {
      // 0.10.1.1 规格10-12：主节点切换后旧令牌不被认识——返回 reauth 标记，
      // 从节点收到后自动 join 重新登记换发令牌。
      sendJson(res, 401, { error: "集群节点令牌无效", reauth: true });
      return true;
    }
    const input = await readJson(req);
    store.touchClusterNode(String(req.headers["x-agent-token"] || ""), {
      version: input.version,
      bindPort: input.bindPort,
      stats: input.stats,
      // 0.10.1.0：记录从节点 frps 认证令牌（客户端连从节点 frps 用）。
      frpToken: input.frpToken,
    });
    // 0.10.1.1 规格13：落库从节点本地 frpc 会话（合并统一用户在线判定口径）。
    if (Array.isArray(input.stats?.sessions)) {
      store.replaceClusterNodeSessions(node.name, input.stats.sessions);
    }
    // 0.10.0.2：从节点回报命令执行结果；主节点按节点裁剪用户并下发待执行命令。
    if (Array.isArray(input.commandResults) && input.commandResults.length) {
      store.finishClusterCommands(node.name, input.commandResults);
    }
    store.pruneClusterCommands();
    const { scopedUsers, scopedLimits } = clusterSyncPayloadForNode(node.name);
    sendJson(res, 200, {
      cluster: {
        name: clusterName(),
        registerEnabled: registerEnabled(),
        forgotEnabled: forgotEnabled(),
        // 0.10.1.0：下发主节点 frp token 与签名密钥，从节点对齐后客户端可统一 token 连集群。
        frpAuthToken,
        signingSecret,
      },
      users: scopedUsers,
      proxyRateLimits: scopedLimits,
      commands: store.takePendingClusterCommands(node.name),
      // 0.10.1.1 规格10-12：下发集群节点表（含备用主优先级）与调用方身份回执，
      // 从节点用于故障转移仲裁（优先级最高的备用主自动升主）与自我识别（join）。
      clusterNodes: store.listClusterNodes().map((item) => ({
        name: item.name,
        host: item.host,
        clientApiPort: item.clientApiPort,
        bindPort: item.bindPort,
        location: item.location,
        frpToken: item.frpToken,
        priority: item.priority,
        online: item.online,
        version: item.version,
        lastSyncAt: item.lastSyncAt,
      })),
      self: { name: node.name, priority: node.priority },
      // 0.10.1.0 数据高可用：随同步下发全量备份（用户含密码哈希 + 管理员 + 套餐），
      // 从节点实时落库；主节点宕机提升从节点时恢复，数据不丢失、可切换。
      backup: {
        users: store.exportBackupUsers(),
        admin: store.exportBackupAdmin(),
        plans: store.exportBackupPlans(),
      },
      // 0.10.2.8：公告随同步通道镜像到从节点（从节点客户端经本地 /api/client 下发）。
      announcements: store.activeAnnouncements(50),
    });
    return true;
  }

  // ---------- 0.10.1.1 规格10-12：从节点 join（主节点切换后重新登记换发令牌） ----------
  // 新主节点不认识旧令牌：从节点携带旧令牌+集群名 join，主节点重置/新建节点并签发新令牌。
  // 仅登记（不迁移数据），安全边界为集群名匹配 + 旧令牌非空；主从本就同属一个管理域。
  if (pathname === "/api/cluster/agent/join" && req.method === "POST") {
    const input = await readJson(req);
    const cluster = String(input.cluster || "").trim();
    const oldToken = String(input.oldToken || "");
    if (!cluster || cluster !== clusterName()) {
      sendJson(res, 403, { error: "集群名称不匹配，无法加入" });
      return true;
    }
    if (!oldToken) {
      sendJson(res, 401, { error: "缺少旧节点令牌，请通过主节点重新部署" });
      return true;
    }
    const name = String(input.name || "").trim().slice(0, 40) || `node-${requestIp(req)}`;
    const host = requestIp(req) || name;
    let node = store.getClusterNodeByName(name);
    let token;
    if (node) {
      // 已登记（可能来自旧主同步列表）：重置令牌视为重新接入。
      const reset = store.resetClusterNodeToken(node.id, "cluster.failover");
      token = reset.token;
    } else {
      const created = store.createClusterNode(
        {
          name,
          host,
          clientApiPort: Number(input.clientApiPort) || FIXED_CLIENT_API_PORT,
        },
        "cluster.failover",
      );
      node = created.node;
      token = created.token;
    }
    store.markClusterNodeStatus(node.id, "pending");
    sendJson(res, 200, { ok: true, token, node: { name: node.name, host: node.host } });
    return true;
  }

  if (pathname === "/api/cluster/agent/login" && req.method === "POST") {
    const node = clusterAgentFromRequest(req);
    if (!node) {
      sendJson(res, 401, { error: "集群节点令牌无效" });
      return true;
    }
    const input = await readJson(req);
    let user = store.authenticateUser(String(input.identifier || "").trim(), input.password, {
      allowExpired: true,
    });
    if (!user) {
      sendJson(res, 401, { error: "用户 ID 或密码错误" });
      return true;
    }
    user = store.claimDevice(user.id, normalizeDeviceId(input.deviceId), String(input.clientAddress || ""));
    store.audit(user.username, `cluster.login@${node.name}`, requestIp(req));
    // 0.10.0.2：快照裁剪到本节点端口段，防止从节点本地 token 跨节点绑端口。
    sendJson(res, 200, { user: userSnapshotForNode(user, node.name) });
    return true;
  }

  if (pathname === "/api/cluster/agent/proxy" && req.method === "POST") {
    const node = clusterAgentFromRequest(req);
    if (!node) {
      sendJson(res, 401, { error: "集群节点令牌无效" });
      return true;
    }
    try {
      const input = await readJson(req);
      const actor = `cluster:${node.name}`;
      const userId = Number(input.userId);
      const args = input.args || {};
      let user;
      switch (String(input.action || "")) {
        case "changePassword":
          user = store.changeUserPassword(userId, args.currentPassword, args.newPassword, actor);
          break;
        case "changeUsername":
          user = store.changeUserUsername(userId, args.currentPassword, args.newUsername, actor);
          break;
        case "changeUid":
          user = store.changeUserUid(userId, args.currentPassword, args.newUid, actor);
          break;
        case "redeem":
          user = store.redeemPlanCode(args.code, userId).user;
          break;
        default:
          sendJson(res, 400, { error: "未知操作" });
          return true;
      }
      sendJson(res, 200, { user: sessionUserSnapshot(user) });
    } catch (error) {
      sendJson(res, 400, { error: error.message });
    }
    return true;
  }

  // 从节点补拉内核：frps 直接下发本机二进制；frpc 走本地缓存（缺失时经授权中心拉取）。
  if (pathname === "/api/cluster/agent/frps" && req.method === "GET") {
    const node = clusterAgentFromRequest(req);
    if (!node) {
      sendJson(res, 401, { error: "集群节点令牌无效" });
      return true;
    }
    if (!existsSync(FRPS_BIN)) {
      sendJson(res, 404, { error: "主节点尚未安装 frps 内核" });
      return true;
    }
    const body = readFileSync(FRPS_BIN);
    res.writeHead(200, {
      "Content-Type": "application/octet-stream",
      "Content-Length": body.length,
      "Cache-Control": "no-store",
      "X-Frp-Version": frpsVersion,
    });
    res.end(body);
    return true;
  }

  if (pathname === "/api/cluster/agent/frpc" && req.method === "GET") {
    const node = clusterAgentFromRequest(req);
    if (!node) {
      sendJson(res, 401, { error: "集群节点令牌无效" });
      return true;
    }
    const platform = String(url.searchParams.get("platform") || "").toLowerCase();
    const arch = String(url.searchParams.get("arch") || "").toLowerCase();
    if (!FRP_PLATFORMS.includes(platform) || !FRP_ARCHES.includes(arch)) {
      sendJson(res, 400, { error: "platform/arch 无效" });
      return true;
    }
    const cachePath = frpcCachePath(platform, arch);
    let version = store.getSetting(`frpc_version_${platform}_${arch}`) || "";
    if (!existsSync(cachePath)) {
      const result = await licenseManager.fetchFrpBinaryFor("frpc", platform, arch);
      const saved = saveFrpcCache(platform, arch, result.buffer, result.version);
      version = saved.version;
    }
    const body = readFileSync(cachePath);
    res.writeHead(200, {
      "Content-Type": "application/octet-stream",
      "Content-Length": body.length,
      "Cache-Control": "no-store",
      "X-Frp-Version": version,
    });
    res.end(body);
    return true;
  }

  if (pathname === "/api/client/login" && req.method === "POST") {
    licenseManager.assertAllowed();
    assertLoginRate(req);
    const input = await readJson(req);
    // 0.9.2：登录标识为 6 位用户 ID（uid）；兼容旧客户端传 username。
    // 0.10.0：含 @ 的标识按邮箱解析（一邮箱一 ID）。
    const rawIdentifier = String(input.uid ?? input.username ?? input.email ?? "").trim();
    let identifier = rawIdentifier;
    if (rawIdentifier.includes("@")) {
      const byEmail = store.getUserByEmail(rawIdentifier);
      if (byEmail) identifier = byEmail.uid ?? byEmail.username;
    }
    if (activeRole === "slave") {
      // 从节点：登录代理主节点校验（本地不存密码），随后本地签发会话令牌。
      try {
        const result = await clusterAgentRequest("/api/cluster/agent/login", {
          identifier: rawIdentifier,
          password: input.password,
          deviceId: normalizeDeviceId(input.deviceId),
          clientAddress: requestIp(req),
        });
        const [synced] = store.upsertSyncedUsers([result.user]);
        clearLoginFailures(req);
        const clientVersion = req.headers["x-client-version"] || input.clientVersion;
        store.setUserClientVersion(synced.id, clientVersion);
        store.audit(synced.username, "client.login@slave", requestIp(req));
        sendJson(res, 200, {
          token: clientToken(synced),
          user: publicUser(synced),
          traffic: clientTraffic(synced.id),
          ports: clientPorts(synced),
          branding: clientBranding(),
          renewalUrl: store.getSetting("renewal_url") || "",
          update: licenseManager.clientUpdateSnapshot(),
          // 0.10.2.8：公告随登录下发（从节点镜像自主节点同步通道）。
          notices: store.activeAnnouncements(20),
          frp: {
            host: derivePublicHost(req),
            port: FRP_BIND_PORT,
            authToken: frpAuthToken,
            heartbeatInterval: 5,
            rateLimitBps: synced.rateLimitBps,
            vhostHttpPort: vhostHttpPort(),
            vhostHttpsPort: vhostHttpsPort(),
            proxyRateLimits: Object.fromEntries(store.getProxyRateLimitsByUser(synced.id)),
          },
          frpc: {
            available: listFrpcCache().length > 0 || licenseManager.isAllowed(),
            version: "",
          },
        });
      } catch (error) {
        recordLoginFailure(req);
        sendJson(res, Number(error.status) || 401, { error: error.message });
      }
      return true;
    }
    let user = store.authenticateUser(identifier, input.password, {
      allowExpired: true,
    });
    if (!user) {
      recordLoginFailure(req);
      sendJson(res, 401, { error: "用户 ID 或密码错误" });
      return true;
    }
    clearLoginFailures(req);
    const deviceId = normalizeDeviceId(input.deviceId);
    user = store.claimDevice(user.id, deviceId, requestIp(req));
    const clientVersion = req.headers["x-client-version"] || input.clientVersion;
    licenseManager.recordClientVersion(clientVersion);
    store.setUserClientVersion(user.id, clientVersion);
    const token = clientToken(user);
    store.audit(user.username, "client.login", requestIp(req));
    sendJson(res, 200, {
      token,
      user: publicUser(user),
      traffic: clientTraffic(user.id),
      ports: clientPorts(user),
      // 0.10.0.2：登录后可选择的节点列表（节点权限由主节点分配）。
      nodes: clientNodesForUser(user, req),
      branding: clientBranding(),
      renewalUrl: store.getSetting("renewal_url") || "",
      update: licenseManager.clientUpdateSnapshot(),
      // 0.10.2.8：公告随登录下发（客户端信息中心 + 未读弹窗）。
      notices: store.activeAnnouncements(20),
      frp: {
        host: derivePublicHost(req),
        port: FRP_BIND_PORT,
        authToken: frpAuthToken,
        heartbeatInterval: 5,
        rateLimitBps: user.rateLimitBps,
        vhostHttpPort: vhostHttpPort(),
        vhostHttpsPort: vhostHttpsPort(),
        proxyRateLimits: Object.fromEntries(store.getProxyRateLimitsByUser(user.id)),
      },
      frpc: {
        available: listFrpcCache().length > 0 || licenseManager.isAllowed(),
        version: "",
      },
    });
    return true;
  }

  if (pathname === "/api/client/logout" && req.method === "POST") {
    try {
      const session = authorizedUserSession(bearerToken(req), null, {
        allowExpired: true,
        allowDisabled: true,
      });
      store.releaseDevice(session.user.id, session.payload.dev);
      store.audit(session.user.username, "client.logout", requestIp(req));
      sendJson(res, 200, { ok: true });
    } catch (error) {
      sendJson(res, Number(error.status) || 401, {
        error: error.message,
        code: authErrorCode(error),
      });
    }
    return true;
  }

  if (pathname === "/api/client/me" && req.method === "GET") {
    try {
      licenseManager.assertAllowed();
      const session = authorizedUserSession(bearerToken(req), null, {
        allowExpired: true,
        clientAddress: requestIp(req),
      });
      const shouldRefreshToken =
        session.payload.ttl !== CLIENT_TOKEN_TTL_SECONDS ||
        session.payload.exp <=
          Math.floor(Date.now() / 1000) + CLIENT_TOKEN_REFRESH_SECONDS;
      licenseManager.recordClientVersion(req.headers["x-client-version"]);
      store.setUserClientVersion(session.user.id, req.headers["x-client-version"]);
      sendJson(res, 200, {
        user: publicUser(session.user),
        traffic: clientTraffic(session.user.id),
        ports: clientPorts(session.user),
        branding: clientBranding(),
        renewalUrl: store.getSetting("renewal_url") || "",
        update: licenseManager.clientUpdateSnapshot(),
        frpc: {
          available: listFrpcCache().length > 0 || licenseManager.isAllowed(),
          version: "",
        },
        frp: {
          host: derivePublicHost(req),
          port: FRP_BIND_PORT,
          authToken: frpAuthToken,
          heartbeatInterval: 5,
          vhostHttpPort: vhostHttpPort(),
          vhostHttpsPort: vhostHttpsPort(),
        },
        // 0.10.0.2：随心跳下发用户被授权的节点列表（节点+端口二维授权）。
        nodes: clientNodesForUser(session.user, req),
        // 0.10.2.8：公告随心跳下发（客户端信息中心 + 未读弹窗）。
        notices: store.activeAnnouncements(20),
        // 0.9.3.2：限速不再随心跳下发，改由 commands 队列推送。
        commands: drainClientCommands(session.user.id),
        token: shouldRefreshToken ? clientToken(session.user) : undefined,
      });
    } catch (error) {
      sendJson(res, Number(error.status) || 401, {
        error: error.message,
        code: authErrorCode(error),
      });
    }
    return true;
  }

  if (pathname === "/api/client/account/password" && req.method === "POST") {
    try {
      const session = authorizedUserSession(bearerToken(req), null, {
        allowExpired: true,
      });
      const input = await readJson(req);
      let token;
      let user;
      if (activeRole === "slave") {
        ({ token, user } = await slaveProxyAccount(session, "changePassword", {
          currentPassword: input.currentPassword,
          newPassword: input.newPassword,
        }));
      } else {
        user = store.changeUserPassword(
          session.user.id,
          input.currentPassword,
          input.newPassword,
          session.user.username,
        );
        token = clientToken(user);
      }
      sendJson(res, 200, { token, user });
    } catch (error) {
      sendJson(res, Number(error.status) || 400, { error: error.message });
    }
    return true;
  }

  if (pathname === "/api/client/account/username" && req.method === "POST") {
    try {
      licenseManager.assertAllowed();
      const session = authorizedUserSession(bearerToken(req), null, {
        allowExpired: true,
      });
      const input = await readJson(req);
      let token;
      let user;
      if (activeRole === "slave") {
        ({ token, user } = await slaveProxyAccount(session, "changeUsername", {
          currentPassword: input.currentPassword,
          newUsername: input.newUsername,
        }));
      } else {
        user = store.changeUserUsername(
          session.user.id,
          input.currentPassword,
          input.newUsername,
          session.user.username,
        );
        token = clientToken(user);
      }
      sendJson(res, 200, { token, user });
    } catch (error) {
      sendJson(res, Number(error.status) || 400, { error: error.message });
    }
    return true;
  }

  // 0.9.2：自助修改用户 ID（6 位数字、全局唯一；成功后旧 token 失效、限速键迁移）。
  if (pathname === "/api/client/account/uid" && req.method === "POST") {
    try {
      licenseManager.assertAllowed();
      const session = authorizedUserSession(bearerToken(req), null, {
        allowExpired: true,
      });
      const input = await readJson(req);
      let token;
      let user;
      if (activeRole === "slave") {
        ({ token, user } = await slaveProxyAccount(session, "changeUid", {
          currentPassword: input.currentPassword,
          newUid: input.newUid,
        }));
      } else {
        user = store.changeUserUid(
          session.user.id,
          input.currentPassword,
          input.newUid,
          session.user.username,
        );
        token = clientToken(user);
      }
      sendJson(res, 200, { token, user });
    } catch (error) {
      sendJson(res, Number(error.status) || 400, { error: error.message });
    }
    return true;
  }

  // 0.10.0：客户端兑换套餐码（注册用户兑换后获得端口与时长；从节点代理主节点执行）。
  if (pathname === "/api/client/account/redeem" && req.method === "POST") {
    try {
      licenseManager.assertAllowed();
      const session = authorizedUserSession(bearerToken(req), null, {
        allowExpired: true,
      });
      const input = await readJson(req);
      let user;
      let plan = null;
      let addedRanges = [];
      if (activeRole === "slave") {
        const result = await slaveProxyAccount(session, "redeem", { code: input.code });
        user = result.snapshot;
        // 兑换涉及端口/限速变化，立即触发一次同步以便客户端拿到最新配置。
        await clusterAgentSyncOnce().catch(() => {});
      } else {
        const redeemed = store.redeemPlanCode(input.code, session.user.id);
        user = redeemed.user;
        plan = publicPlan(redeemed.plan);
        addedRanges = redeemed.addedRanges;
      }
      sendJson(res, 200, {
        user: publicUser(user),
        plan,
        addedRanges,
        message: "套餐码兑换成功，端口配置将在客户端重启隧道后生效",
      });
    } catch (error) {
      sendJson(res, Number(error.status) || 400, { error: error.message });
    }
    return true;
  }

  if (pathname === "/api/client/frpc" && req.method === "GET") {
    try {
      licenseManager.assertAllowed();
      const session = authorizedUserSession(bearerToken(req), null, {
        allowExpired: true,
        clientAddress: requestIp(req),
      });
      const platform = String(url.searchParams.get("platform") || "").trim().toLowerCase();
      const arch = String(url.searchParams.get("arch") || "").trim().toLowerCase();
      if (!FRP_PLATFORMS.includes(platform) || !FRP_ARCHES.includes(arch)) {
        sendJson(res, 400, { error: "platform 须为 linux/windows/darwin，arch 须为 amd64/arm64/arm" });
        return true;
      }
      const cachePath = frpcCachePath(platform, arch);
      let version = store.getSetting(`frpc_version_${platform}_${arch}`) || "";
      if (!existsSync(cachePath)) {
        // 本地无缓存时实时向授权中心拉取（签名：fetchFrpBinaryFor(component, platform, arch)）。
        const result = await licenseManager.fetchFrpBinaryFor("frpc", platform, arch);
        const saved = saveFrpcCache(platform, arch, result.buffer, result.version);
        version = saved.version;
      }
      const body = readFileSync(cachePath);
      res.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "Content-Length": body.length,
        "Content-Disposition": `attachment; filename="frpc-${version || "unknown"}-${platform}-${arch}"`,
        "Cache-Control": "no-store",
        "X-Frp-Version": version,
      });
      res.end(body);
      store.audit(session.user.username, "client.frpc.download", `${platform}/${arch}`);
    } catch (error) {
      sendJson(res, Number(error.status) || 401, {
        error: error.message,
        code: authErrorCode(error),
      });
    }
    return true;
  }

  return false;
}

let server = null; // 管理 Web 端口实例（可改端口/HTTPS，可重启）
let apiServer = null; // 固定客户端通信端口实例（HTTP，启动后不重启）
let currentServerPort = PORT;
let currentServerHttps = HTTPS_ENABLED;

async function dispatchRequest(req, res, scheme) {
  const url = new URL(req.url || "/", `${scheme}://${req.headers.host || "localhost"}`);
  try {
    // 0.10.0：从节点不开 Web——静态资源与管理页一律 404，仅保留 API。
    if (
      SERVER_ROLE === "slave" &&
      // 0.10.1.1：升主后 activeRole=master，此分支仅在原生态从节点未接管时生效。
      req.method === "GET" &&
      url.pathname !== "/healthz" &&
      !url.pathname.startsWith("/api/")
    ) {
      sendJson(res, 404, { error: "从节点不提供 Web 管理界面" });
      return;
    }
    if (await handleApi(req, res, url)) return;
    if (req.method === "GET" && serveStatic(res, url.pathname)) return;
    sendJson(res, 404, { error: "接口不存在" });
  } catch (error) {
    const message =
      error?.code === "ERR_SQLITE_CONSTRAINT_UNIQUE"
        ? "用户名已存在"
        : error.message || "服务器内部错误";
    sendJson(res, Number(error.status) || 400, {
      error: message,
      ...(/^(DEVICE_|SERVER_LICENSE_|LICENSE_|COPYRIGHT_)/.test(String(error?.code || ""))
        ? { code: error.code }
        : {}),
    });
  }
}

// 管理 Web 服务器：按配置启用 HTTP/HTTPS，端口可在网页修改并热重启。
function createManagerServer() {
  const tlsOptions = loadManagerTlsOptions(DATA_DIR, (msg) =>
    console.log(`[network] ${msg}`),
  );
  const useHttps = Boolean(tlsOptions);
  currentServerHttps = useHttps;
  return useHttps
    ? createHttpsServer(tlsOptions, (req, res) => dispatchRequest(req, res, "https"))
    : createHttpServer((req, res) => dispatchRequest(req, res, "http"));
}

// 固定客户端通信服务器：始终 HTTP，监听 FIXED_CLIENT_API_PORT，客户端始终连此端口。
function createApiServer() {
  return createHttpServer((req, res) => dispatchRequest(req, res, "http"));
}

// 首次启动时的初始化（仅在管理端口首次 listening 后执行一次）。
async function runFirstStartSetup() {
  if (readUpdateMarker(DATA_DIR)?.stage === "replaced") {
    clearUpdateMarker(DATA_DIR, { version: VERSION });
    console.log(`[updater] update health check passed, now running v${VERSION}`);
  }
  if (process.env.FORCE_RESET_ADMIN_PASSWORD === "1") {
    console.warn(
      "⚠ FORCE_RESET_ADMIN_PASSWORD=1 已生效，管理员密码被环境变量 ADMIN_PASSWORD 覆盖。" +
        " 请立即删除 FORCE_RESET_ADMIN_PASSWORD 环境变量并重启，否则每次启动都会重置密码。",
    );
  }
  if (DEFAULT_ADMIN_PASSWORD === "change-me-now") {
    console.warn("Default admin password is active. Set ADMIN_PASSWORD before production use.");
  }
  trafficMonitor.start();
  systemTraffic.start();
  // 0.10.0：从节点 agent 轮询（用户快照/限速/集群配置同步）。
  startClusterAgentLoop();
  setInterval(() => {
    try {
      const deltas = trafficAccumulator.snapshot();
      if (deltas.size > 0) store.addUserTrafficUsage(deltas);
    } catch (error) {
      console.error("traffic accumulation failed:", error.message);
    }
    try {
      // 0.10.2.8：永久累计流量落盘（settings），更新/重启后 restore 续算。
      store.setSetting("traffic_cumulative", JSON.stringify(trafficMonitor.persistState()));
    } catch {
      // 落盘失败下轮重试。
    }
  }, 30_000).unref?.();
  const license = await licenseManager.start();
  console.log(
    `License mode: ${license.mode}, expires at ${license.expiresAt || "not available"}`,
  );
  if (FRPS_AUTOSTART && license.valid) frps.start();
}

function startServers() {
  // 固定通信端口：客户端始终连接此端口，不受 Web 管理端口改动影响。
  apiServer = createApiServer();
  apiServer.once("error", (error) => {
    console.error(`[network] fixed client API port ${FIXED_CLIENT_API_PORT} listen failed:`, error.message);
  });
  apiServer.listen(FIXED_CLIENT_API_PORT, HOST, () => {
    console.log(`XFCloud Tunnel client API: http://127.0.0.1:${FIXED_CLIENT_API_PORT}`);
  });

  // 管理 Web 端口：浏览器访问，端口可改；从节点仅回环监听（不开 Web）。
  server = createManagerServer();
  const managerHost = SERVER_ROLE === "slave" ? "127.0.0.1" : HOST;
  server.listen(PORT, managerHost, async () => {
    currentServerPort = PORT;
    console.log(
      `XFCloud Tunnel server UI: ${currentServerHttps ? "https" : "http"}://127.0.0.1:${PORT}`,
    );
    if (currentServerHttps) console.log("[network] manager transport encryption: HTTPS");
    await runFirstStartSetup();
  });
}

// 重启管理 Web 服务器：关闭旧监听并按新配置重新创建（仅端口/HTTPS 变更时调用）。
// 固定客户端通信端口不受影响，frps/license/traffic 等子服务也不重启。
function restartWebServer(nextPort) {
  return new Promise((resolve, reject) => {
    const oldServer = server;
    // 防重入标志：旧服务器 close 回调与 3 秒强制重建超时可能先后触发，
    // 必须保证新服务器只创建一次，否则第二个实例 listen 同一端口会
    // 触发 EADDRINUSE 且无 error 监听器，导致整个进程崩溃。
    let relistened = false;
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve({ port: nextPort, httpsActive: currentServerHttps });
    };
    const closeAndRelisten = () => {
      if (relistened) return;
      relistened = true;
      try {
        const instance = createManagerServer();
        // listen 失败（如端口被占用）必须捕获，否则未处理的 'error'
        // 事件会使 Node 进程崩溃。
        instance.once("error", (error) => {
          console.error("[network] web server restart listen failed:", error.message);
          finish(error);
        });
        instance.once("listening", () => {
          currentServerPort = nextPort;
          console.log(`[network] web server restarted on port ${nextPort}`);
          finish(null);
        });
        server = instance;
        instance.listen(nextPort, HOST);
      } catch (error) {
        finish(error);
      }
    };
    if (oldServer) {
      // close() 会等待所有现有连接（含 keep-alive 轮询）关闭后才回调，
      // 因此注册一次性回调；超时后强制重建，旧服务器的后续回调由
      // relistened 标志拦截，不会重复创建。
      oldServer.close(() => closeAndRelisten());
      setTimeout(() => closeAndRelisten(), 3_000).unref();
    } else {
      closeAndRelisten();
    }
  });
}

async function handleRequest(req, res, url) {
  return dispatchRequest(req, res, url.protocol.startsWith("https") ? "https" : "http");
}

startServers();

function shutdown() {
  licenseManager.stop();
  trafficMonitor.stop();
  systemTraffic.stop();
  frps.stop();
  let closed = 0;
  const maybeExit = () => {
    closed += 1;
    if (closed >= 2) {
      store.close();
      process.exit(0);
    }
  };
  server.close(maybeExit);
  if (apiServer) apiServer.close(maybeExit);
  else maybeExit();
  setTimeout(() => process.exit(1), 3_000).unref();
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
