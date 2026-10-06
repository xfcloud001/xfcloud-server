import {
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";
import { chmodSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const USERNAME_PATTERN = /^[A-Za-z0-9_.-]{3,32}$/;
const DEVICE_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// 客户端 ↔ 服务端管理 API 的固定通信端口。
// 与可在网页修改的 Web 管理端口（默认 8080）分离：该端口不可更改、不可通过
// 界面配置，保证服务端无论怎样修改 Web 管理端口，客户端始终能连上通信端口。
// 客户端登录只需填写 IP/域名，通信端口由此常量固定，不暴露给用户。
export const FIXED_CLIENT_API_PORT = 9400;

// 版权声明兜底文案：未连接服务端的全新客户端展示该默认声明（与授权中心全局默认一致）；
// 连接服务端后改由服务端下发的版权（服务端内容同样源自授权中心）覆盖。
export const DEFAULT_COPYRIGHT_TEXT = "XFCloud Tunnel";

// 0.10.2.6：逐段数值比较版本号——仅 latest 高于 current 时返回 true（相等/更低返回 false）。
// 客户端/服务端对授权中心的 hasUpdate 判定做本地兜底，避免"已是最新仍提示更新"。
export function versionNewer(latest, current) {
  const toParts = (value) =>
    String(value || "")
      .split(".")
      .map((part) => Number.parseInt(part, 10) || 0);
  const left = toParts(latest);
  const right = toParts(current);
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const diff = (left[index] || 0) - (right[index] || 0);
    if (diff !== 0) return diff > 0;
  }
  return false;
}

// 0.10.2.6：清洗服务端下发的更新信息。旧版服务端（<0.10.2.3）会把「服务端自身
// vs 授权中心」的更新结果原样下发给客户端，客户端版本不低于服务端时就会出现
// "当前 vX，最新 vX"的假横幅（如飞牛上客户端 0.10.2.4 连旧服务端 0.10.2.2）。
// 以本机 currentVersion 重新判定 hasUpdate：仅 latestVersion 严格更高时才提示。
export function sanitizeUpdateInfo(info, currentVersion) {
  if (!info) return null;
  return {
    ...info,
    hasUpdate: Boolean(info.hasUpdate) && versionNewer(info.latestVersion, currentVersion),
    currentVersion,
  };
}

export function normalizeUsername(value) {
  const username = String(value ?? "").trim();
  if (!USERNAME_PATTERN.test(username)) {
    throw new Error("用户名须为 3-32 位字母、数字、点、下划线或短横线");
  }
  return username;
}

export function normalizeDeviceId(value) {
  const deviceId = String(value ?? "").trim().toLowerCase();
  if (!DEVICE_ID_PATTERN.test(deviceId)) {
    throw new Error("设备标识无效");
  }
  return deviceId;
}

export function validatePassword(value) {
  const password = String(value ?? "");
  if (password.length < 8 || password.length > 128) {
    throw new Error("密码长度须为 8-128 位");
  }
  return password;
}

// 0.10.0.2：端口段支持节点维度（二维授权 = 节点 + 端口）。
// 文本格式：`20000-20100`（主节点）或 `节点名:20000-20100`（从节点）；
// 数组格式：{start, end, node?}。未带节点的段一律归属主节点（master），兼容旧数据。
export function normalizeRangeNode(value, defaultNode = "master") {
  const node = String(value ?? "").trim();
  if (!node) return defaultNode;
  if (node.length > 40) throw new Error("端口段节点名过长（≤40 字符）");
  return node;
}

export function rangeNode(range) {
  return normalizeRangeNode(range?.node);
}

export function parsePortRanges(value, { defaultNode = "master" } = {}) {
  // 0.10.1.0：`0` 表示该用户无端口（不分配任何端口段），空数组不报错。
  if (!Array.isArray(value) && String(value ?? "").trim() === "0") {
    return [];
  }
  const parsePart = (part, nodeHint) => {
    const match = /^(?:([^:：]{1,40})[:：])?(\d{1,5})(?:-(\d{1,5}))?$/.exec(String(part).trim());
    if (!match) {
      throw new Error(`端口段格式无效: ${part}`);
    }
    const start = Number(match[2]);
    const end = Number(match[3] ?? match[2]);
    if (start < 1 || end > 65535 || start > end) {
      throw new Error(`端口段超出范围: ${part}`);
    }
    const node = normalizeRangeNode(nodeHint ?? match[1], defaultNode);
    return node === "master" ? { start, end } : { start, end, node };
  };

  const ranges = (
    Array.isArray(value)
      ? value.map((item) =>
          parsePart(
            `${item.start}-${item.end}`,
            typeof item === "object" && item !== null ? item.node : undefined,
          ),
        )
      : String(value ?? "")
          .split(/[,，\s]+/)
          .filter(Boolean)
          .map((part) => parsePart(part))
  ).sort((a, b) => rangeNode(a).localeCompare(rangeNode(b)) || a.start - b.start || a.end - b.end);

  if (ranges.length === 0) {
    throw new Error("至少分配一个端口或端口段");
  }

  // 相邻段合并：仅同节点（不同节点端口互相独立，可重叠）。
  return ranges.reduce((result, range) => {
    const previous = result.at(-1);
    if (
      previous &&
      rangeNode(previous) === rangeNode(range) &&
      range.start <= previous.end + 1
    ) {
      previous.end = Math.max(previous.end, range.end);
    } else {
      result.push({ ...range });
    }
    return result;
  }, []);
}

export function formatPortRanges(ranges) {
  return ranges
    .map(({ start, end, node }) => {
      const label = start === end ? String(start) : `${start}-${end}`;
      const scope = normalizeRangeNode(node);
      return scope === "master" ? label : `${scope}:${label}`;
    })
    .join(", ");
}

export function isPortAllowed(port, ranges) {
  const value = Number(port);
  return (
    Number.isInteger(value) &&
    ranges.some(({ start, end }) => value >= start && value <= end)
  );
}

export function findRangeConflict(candidate, assignments) {
  for (const assigned of assignments) {
    for (const left of candidate) {
      for (const right of assigned.ranges) {
        // 0.10.0.2：不同节点的端口池互相独立，仅同节点段才判冲突。
        if (rangeNode(left) !== rangeNode(right)) continue;
        if (left.start <= right.end && right.start <= left.end) {
          return {
            username: assigned.username,
            node: rangeNode(right),
            start: Math.max(left.start, right.start),
            end: Math.min(left.end, right.end),
          };
        }
      }
    }
  }
  return null;
}

export function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = scryptSync(validatePassword(password), salt, 64);
  return `scrypt:${salt.toString("base64url")}:${derived.toString("base64url")}`;
}

export function verifyPassword(password, encoded) {
  try {
    const [algorithm, saltText, hashText] = String(encoded).split(":");
    if (algorithm !== "scrypt" || !saltText || !hashText) return false;
    const expected = Buffer.from(hashText, "base64url");
    const actual = scryptSync(String(password), Buffer.from(saltText, "base64url"), expected.length);
    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function encodeJson(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

export function signToken(payload, secret) {
  const header = encodeJson({ alg: "HS256", typ: "JWT" });
  const body = encodeJson(payload);
  const signature = createHmac("sha256", secret)
    .update(`${header}.${body}`)
    .digest("base64url");
  return `${header}.${body}.${signature}`;
}

export function verifyToken(token, secret, expectedType) {
  const parts = String(token ?? "").split(".");
  if (parts.length !== 3) throw new Error("令牌格式无效");

  const expected = createHmac("sha256", secret)
    .update(`${parts[0]}.${parts[1]}`)
    .digest();
  const provided = Buffer.from(parts[2], "base64url");
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    throw new Error("令牌签名无效");
  }

  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  if (expectedType && payload.type !== expectedType) throw new Error("令牌类型无效");
  if (!Number.isFinite(payload.exp) || payload.exp * 1000 <= Date.now()) {
    throw new Error("令牌已过期");
  }
  return payload;
}

export function randomSecret(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

export function isExpired(isoDate, now = Date.now()) {
  const timestamp = Date.parse(isoDate);
  return !Number.isFinite(timestamp) || timestamp <= now;
}

export function escapeToml(value) {
  return JSON.stringify(String(value));
}

export function sanitizeProxyName(value) {
  const name = String(value ?? "").trim();
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(name)) {
    throw new Error("代理名称须为 1-32 位字母、数字、下划线或短横线");
  }
  return name;
}

const DOMAIN_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * 规范化 HTTP/HTTPS 隧道的自定义域名（frp customDomains）：
 * 接受数组或逗号/分号/空白分隔字符串；统一转小写、去尾部点、去重；
 * 逐项校验域名格式（须为完整域名，非法项抛出错误）。
 */
export function normalizeDomains(value) {
  const raw = Array.isArray(value)
    ? value
    : typeof value === "string"
      ? value.split(/[\s,;]+/)
      : [];
  const seen = new Set();
  const result = [];
  for (const item of raw) {
    const domain = String(item ?? "").trim().toLowerCase().replace(/\.+$/, "");
    if (!domain) continue;
    if (domain.length > 253) {
      throw new Error(`域名格式不合法: ${domain}`);
    }
    const labels = domain.split(".");
    if (!labels.every((label) => DOMAIN_LABEL.test(label))) {
      throw new Error(`域名格式不合法: ${domain}`);
    }
    if (!seen.has(domain)) {
      seen.add(domain);
      result.push(domain);
    }
  }
  return result;
}

export function requestIp(req) {
  const forwarded = req?.headers?.["x-forwarded-for"];
  return String(forwarded || req?.socket?.remoteAddress || "")
    .split(",")[0]
    .trim()
    .replace(/^::ffff:/, "");
}

/**
 * 登录尝试限流器：按 IP 记录失败次数，窗口内超限抛出 429。
 * 成功后清空该 IP 计数；内部定期清理过期条目，避免 Map 无限增长。
 */
export class LoginRateLimiter {
  constructor({ maxAttempts = 8, windowMs = 5 * 60_000 } = {}) {
    this.maxAttempts = maxAttempts;
    this.windowMs = windowMs;
    this.attempts = new Map();
    this.cleanupTimer = setInterval(() => this.cleanup(), windowMs);
    this.cleanupTimer.unref?.();
  }

  prune(key, now = Date.now()) {
    const recent = (this.attempts.get(key) || []).filter((time) => now - time < this.windowMs);
    if (recent.length > 0) this.attempts.set(key, recent);
    else this.attempts.delete(key);
    return recent;
  }

  assert(key, message) {
    const recent = this.prune(key);
    if (recent.length >= this.maxAttempts) {
      const error = new Error(message || "登录尝试过多，请 5 分钟后再试");
      error.status = 429;
      throw error;
    }
  }

  failure(key) {
    const recent = this.prune(key);
    recent.push(Date.now());
    this.attempts.set(key, recent);
  }

  clear(key) {
    this.attempts.delete(key);
  }

  cleanup() {
    const now = Date.now();
    for (const key of [...this.attempts.keys()]) this.prune(key, now);
  }
}

// ---------- 服务运行时引导 ----------
// 在每个应用启动时调用：
// 1. 修复部署包在 Windows 打包/传输后丢失的 Linux 脚本可执行权限；
// 2. 写入 data/service.pid，使 service.sh 与在线更新重启后的新进程可被识别。
export function setupServiceRuntime(rootDir) {
  try {
    for (const name of ["service.sh", "start.sh"]) {
      const file = join(rootDir, name);
      if (existsSync(file)) {
        try {
          chmodSync(file, 0o755);
        } catch {
          // Windows 下 chmod 近乎空操作，忽略。
        }
      }
    }
    const dataDir = join(rootDir, "data");
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(join(dataDir, "service.pid"), String(process.pid));
  } catch {
    // 引导失败不影响主流程。
  }
}
