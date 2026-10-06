import { createHash, randomInt } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import {
  findRangeConflict,
  formatPortRanges,
  hashPassword,
  isExpired,
  normalizeUsername,
  parsePortRanges,
  randomSecret,
  rangeNode,
  validatePassword,
  verifyPassword,
} from "../shared/core.js";

function nowISO() {
  return new Date().toISOString();
}

const DEVICE_LEASE_MS = 30_000;

function normalizeRenewalDays(value) {
  const days = Number(value);
  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    throw new Error("续费天数须为 1-3650 天");
  }
  return days;
}

function normalizeNote(value, label = "备注") {
  const note = String(value ?? "").trim();
  if (note.length > 200) throw new Error(`${label}不能超过 200 个字符`);
  return note;
}

function parseUser(row) {
  if (!row) return null;
  const ranges = JSON.parse(row.port_ranges);
  return {
    id: row.id,
    uid: row.uid ?? null,
    username: row.username,
    tempPassword: row.temp_password ?? null,
    portRanges: ranges,
    portRangesText: formatPortRanges(ranges),
    // 0.9.3：expires_at 为 NULL 表示未激活（激活时才起算套餐时长），不算到期。
    expiresAt: row.expires_at ?? null,
    activatedAt: row.activated_at ?? null,
    activated: Boolean(row.activated_at),
    durationDays: Number(row.duration_days || 30),
    httpAllowed: Boolean(row.http_allowed),
    enabled: Boolean(row.enabled),
    tokenVersion: row.token_version,
    deviceId: row.active_device_id ?? null,
    deviceAddress: row.device_address ?? null,
    deviceLastSeen: row.device_last_seen ?? null,
    deviceOnline:
      Boolean(row.active_device_id) &&
      Boolean(row.device_last_seen) &&
      Date.parse(row.device_last_seen) >= Date.now() - DEVICE_LEASE_MS,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    online: Boolean(row.online),
    lastSeen: row.last_seen ?? null,
    expired: row.expires_at ? isExpired(row.expires_at) : false,
    mappingCount: Number(row.mapping_count || 0),
    onlineMappingCount: Number(row.online_mapping_count || 0),
    rateLimitBps: Number(row.rate_limit_bps || 0),
    trafficLimitBytes: Number(row.traffic_limit_bytes || 0),
    trafficUsedBytes: Number(row.traffic_used_bytes || 0),
    mustChangePassword: Boolean(row.must_change_password),
    email: row.email ?? null,
    emailVerified: Boolean(row.email_verified),
    planId: row.plan_id ?? null,
    planName: row.plan_name ?? null,
    clientVersion: row.client_version ?? null,
  };
}

// 0.10.2.8：公告行解析。
function parseAnnouncement(row) {
  if (!row) return null;
  return {
    id: Number(row.id),
    title: row.title,
    content: row.content,
    level: row.level || "info",
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function parseAdmin(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    tokenVersion: row.token_version,
  };
}

function parseProxy(row) {
  const sessionLastSeen = row.last_seen ?? null;
  const online =
    !row.closed_at &&
    !row.session_closed_at &&
    Boolean(row.user_enabled) &&
    !isExpired(row.user_expires_at) &&
    Boolean(sessionLastSeen) &&
    Date.parse(sessionLastSeen) >= Date.now() - 30_000;
  let domains = [];
  try {
    const parsed = JSON.parse(row.custom_domains || "[]");
    if (Array.isArray(parsed)) domains = parsed.filter((item) => typeof item === "string");
  } catch {
    domains = [];
  }
  return {
    id: row.id,
    userId: row.user_id,
    username: row.username,
    uid: row.uid ?? null,
    name: row.proxy_name,
    type: row.proxy_type,
    remotePort: row.remote_port ? Number(row.remote_port) : null,
    domains,
    rateLimitBps: Number(row.proxy_rate_limit_bps || 0),
    clientAddress: row.client_address ?? null,
    online,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    closedAt: row.closed_at ?? null,
    lastSeen: row.closed_at ?? sessionLastSeen ?? row.updated_at,
  };
}

function parsePlan(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    durationDays: Number(row.duration_days),
    trafficLimitBytes: Number(row.traffic_limit_bytes || 0),
    rateLimitBps: Number(row.rate_limit_bps || 0),
    portCount: Number(row.port_count),
    priceCents: Number(row.price_cents || 0),
    sortOrder: Number(row.sort_order || 0),
    userCount: Number(row.user_count || 0),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// 0.9.0 预设套餐：价格单位为分；traffic_limit_bytes 为 0 表示不限流量。
const DEFAULT_PLANS = [
  { name: "试用套餐", durationDays: 3, trafficGB: 20, portCount: 5, priceCents: 100 },
  { name: "月抛套餐", durationDays: 30, trafficGB: 100, portCount: 5, priceCents: 660 },
  { name: "月卡套餐（推荐·不限量）", durationDays: 30, trafficGB: 0, portCount: 8, priceCents: 990 },
  { name: "月卡套餐 12 口", durationDays: 30, trafficGB: 0, portCount: 12, priceCents: 1590 },
  { name: "季卡套餐", durationDays: 90, trafficGB: 0, portCount: 8, priceCents: 2690 },
  { name: "年卡套餐", durationDays: 365, trafficGB: 0, portCount: 10, priceCents: 8800 },
];

function normalizePlanName(value) {
  const name = String(value ?? "").trim();
  if (!name) throw new Error("套餐名称不能为空");
  if (name.length > 40) throw new Error("套餐名称不能超过 40 个字符");
  return name;
}

// 套餐输入归一化；内部统一使用字节（0=不限）与分。
function normalizePlanInput(input, { partial = false } = {}) {
  const data = {};
  if (!partial || input.name !== undefined) data.name = normalizePlanName(input.name);
  if (!partial || input.durationDays !== undefined) {
    const days = Number(input.durationDays);
    if (!Number.isInteger(days) || days < 1 || days > 3650) {
      throw new Error("套餐时长须为 1-3650 天");
    }
    data.durationDays = days;
  }
  if (!partial || input.trafficLimitBytes !== undefined) {
    const bytes = Number(input.trafficLimitBytes);
    if (!Number.isInteger(bytes) || bytes < 0) {
      throw new Error("流量限额须为非负整数字节数（0 表示不限）");
    }
    data.trafficLimitBytes = bytes;
  }
  // 0.10.2.1：套餐限速（bps，0=不限速）；与隧道级限速共用 100 Gbps 上限。
  if (!partial || input.rateLimitBps !== undefined) {
    const bps = Number(input.rateLimitBps || 0);
    if (!Number.isInteger(bps) || bps < 0 || bps > 100_000_000_000) {
      throw new Error("套餐限速须为 0-100000000000 的整数比特/秒（0 表示不限速）");
    }
    data.rateLimitBps = bps;
  }
  if (!partial || input.portCount !== undefined) {
    const count = Number(input.portCount);
    if (!Number.isInteger(count) || count < 1 || count > 500) {
      throw new Error("套餐端口数须为 1-500");
    }
    data.portCount = count;
  }
  if (!partial || input.priceCents !== undefined) {
    const cents = Number(input.priceCents);
    if (!Number.isInteger(cents) || cents < 0 || cents > 10_000_000) {
      throw new Error("套餐价格须为 0-100000 元");
    }
    data.priceCents = cents;
  }
  if (!partial || input.sortOrder !== undefined) {
    data.sortOrder = Number.isFinite(Number(input.sortOrder)) ? Number(input.sortOrder) : 0;
  }
  return data;
}

// 0.9.0 批量开号：密码字符集剔除易混字符（0/O/1/l）；用户名后缀仅小写字母数字。
const BATCH_PASSWORD_CHARS = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
const BATCH_USERNAME_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789";

function randomText(chars, length) {
  let out = "";
  for (let i = 0; i < length; i += 1) {
    out += chars[randomInt(chars.length)];
  }
  return out;
}

export class Store {
  constructor(filename, adminUser, adminPassword) {
    this.db = new DatabaseSync(filename);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;

      CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        token_version INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        uid TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL COLLATE BINARY,
        password_hash TEXT NOT NULL,
        port_ranges TEXT NOT NULL,
        -- 0.9.3：expires_at 可空（NULL=未激活，激活时按 activated_at + duration_days 计算）。
        expires_at TEXT,
        activated_at TEXT,
        duration_days INTEGER NOT NULL DEFAULT 30,
        http_allowed INTEGER NOT NULL DEFAULT 0,
        enabled INTEGER NOT NULL DEFAULT 1,
        token_version INTEGER NOT NULL DEFAULT 1,
        active_device_id TEXT,
        device_address TEXT,
        device_last_seen TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        temp_password TEXT
      );

      CREATE TABLE IF NOT EXISTS frp_sessions (
        run_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        client_address TEXT,
        connected_at TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        closed_at TEXT
      );

      CREATE TABLE IF NOT EXISTS frp_proxies (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        run_id TEXT NOT NULL,
        proxy_name TEXT NOT NULL,
        proxy_type TEXT NOT NULL,
        remote_port INTEGER NOT NULL DEFAULT 0,
        custom_domains TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        closed_at TEXT,
        UNIQUE(user_id, proxy_name)
      );

      CREATE TABLE IF NOT EXISTS plans (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        duration_days INTEGER NOT NULL,
        traffic_limit_bytes INTEGER NOT NULL DEFAULT 0,
        rate_limit_bps INTEGER NOT NULL DEFAULT 0,
        port_count INTEGER NOT NULL,
        price_cents INTEGER NOT NULL DEFAULT 0,
        sort_order INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS proxy_rate_limits (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        proxy_name TEXT NOT NULL,
        rate_limit_bps INTEGER NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(user_id, proxy_name)
      );

      -- 0.10.0：套餐码（批量生成 → 客户端兑换绑定套餐）。
      CREATE TABLE IF NOT EXISTS plan_codes (
        id INTEGER PRIMARY KEY,
        code TEXT NOT NULL UNIQUE,
        plan_id INTEGER NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
        batch_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'unused',
        used_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        used_at TEXT,
        created_at TEXT NOT NULL,
        created_by TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_plan_codes_batch ON plan_codes(batch_id);

      -- 0.10.0：集群从节点（主节点注册表；从节点经 agent 轮询接入）。
      CREATE TABLE IF NOT EXISTS cluster_nodes (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        host TEXT NOT NULL,
        address TEXT NOT NULL,
        client_api_port INTEGER NOT NULL DEFAULT 9400,
        token_hash TEXT NOT NULL,
        bind_port INTEGER,
        status TEXT NOT NULL DEFAULT 'pending',
        last_sync_at TEXT,
        version TEXT,
        stats TEXT,
        priority INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT,
        detail TEXT,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      -- 0.10.0.2：主→从命令队列（限速 / 防火墙 / 版本同步等经同步通道下发）。
      CREATE TABLE IF NOT EXISTS cluster_commands (
        id INTEGER PRIMARY KEY,
        node_name TEXT NOT NULL,
        type TEXT NOT NULL,
        payload TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        result TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_cluster_commands_node
        ON cluster_commands(node_name, status);

      -- 0.10.1.0 数据高可用：从节点实时备份主节点全量数据（用户含密码哈希 + 管理员 + 套餐），
      -- 主节点宕机提升从节点为主节点时恢复，实现数据不丢失、可切换。
      CREATE TABLE IF NOT EXISTS backup_users (
        uid TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        payload TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS backup_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      -- 0.10.1.1 规格13：从节点本地 frpc 会话上报（统一用户在线判定口径：
      -- 用户管理在线 = 主节点 frp_sessions ∪ 各从节点上报会话，30 秒心跳为准）。
      CREATE TABLE IF NOT EXISTS cluster_sessions (
        node_name TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        last_seen TEXT NOT NULL,
        PRIMARY KEY (node_name, user_id)
      );

      -- 0.10.2.8：公告（管理台发布 → 客户端信息中心）；synced=1 表示从节点镜像自主节点。
      CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        level TEXT NOT NULL DEFAULT 'info',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        synced INTEGER NOT NULL DEFAULT 0
      );

      CREATE INDEX IF NOT EXISTS idx_sessions_user_seen
        ON frp_sessions(user_id, last_seen);
      CREATE INDEX IF NOT EXISTS idx_proxies_user_updated
        ON frp_proxies(user_id, updated_at);
    `);

    // 0.10.0.2：集群节点位置（登录页/授权中心展示）与套餐码目标节点。
    const clusterNodeColumns = this.db.prepare("PRAGMA table_info(cluster_nodes)").all();
    if (!clusterNodeColumns.some((column) => column.name === "location")) {
      this.db.exec("ALTER TABLE cluster_nodes ADD COLUMN location TEXT");
    }
    // 0.10.1.0：从节点 frps 认证令牌（sync 上报；客户端连从节点 frps 需与该节点一致）。
    if (!clusterNodeColumns.some((column) => column.name === "frp_token")) {
      this.db.exec("ALTER TABLE cluster_nodes ADD COLUMN frp_token TEXT");
    }
    // 0.10.1.1 规格10：备用主节点优先级（>0=可自动升主，数字越大越优先；0=不参与）。
    if (!clusterNodeColumns.some((column) => column.name === "priority")) {
      this.db.exec("ALTER TABLE cluster_nodes ADD COLUMN priority INTEGER NOT NULL DEFAULT 0");
    }
    const planCodeColumns = this.db.prepare("PRAGMA table_info(plan_codes)").all();
    if (!planCodeColumns.some((column) => column.name === "node_name")) {
      this.db.exec("ALTER TABLE plan_codes ADD COLUMN node_name TEXT NOT NULL DEFAULT 'master'");
    }
    // 0.10.2.1：套餐级带宽限速（bps，0=不限速）；老库补列。
    const planColumns = this.db.prepare("PRAGMA table_info(plans)").all();
    if (!planColumns.some((column) => column.name === "rate_limit_bps")) {
      this.db.exec("ALTER TABLE plans ADD COLUMN rate_limit_bps INTEGER NOT NULL DEFAULT 0");
    }

    const adminColumns = this.db.prepare("PRAGMA table_info(admins)").all();
    if (!adminColumns.some((column) => column.name === "token_version")) {
      this.db.exec("ALTER TABLE admins ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1");
    }
    const userColumns = this.db.prepare("PRAGMA table_info(users)").all();
    if (!userColumns.some((column) => column.name === "active_device_id")) {
      this.db.exec("ALTER TABLE users ADD COLUMN active_device_id TEXT");
    }
    if (!userColumns.some((column) => column.name === "device_address")) {
      this.db.exec("ALTER TABLE users ADD COLUMN device_address TEXT");
    }
    if (!userColumns.some((column) => column.name === "device_last_seen")) {
      this.db.exec("ALTER TABLE users ADD COLUMN device_last_seen TEXT");
    }
    if (!userColumns.some((column) => column.name === "rate_limit_bps")) {
      this.db.exec("ALTER TABLE users ADD COLUMN rate_limit_bps INTEGER NOT NULL DEFAULT 0");
    }
    if (!userColumns.some((column) => column.name === "traffic_limit_bytes")) {
      this.db.exec("ALTER TABLE users ADD COLUMN traffic_limit_bytes INTEGER NOT NULL DEFAULT 0");
    }
    if (!userColumns.some((column) => column.name === "traffic_used_bytes")) {
      this.db.exec("ALTER TABLE users ADD COLUMN traffic_used_bytes INTEGER NOT NULL DEFAULT 0");
    }
    if (!userColumns.some((column) => column.name === "must_change_password")) {
      this.db.exec("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0");
    }
    if (!userColumns.some((column) => column.name === "plan_id")) {
      this.db.exec("ALTER TABLE users ADD COLUMN plan_id INTEGER");
    }
    if (!userColumns.some((column) => column.name === "plan_name")) {
      this.db.exec("ALTER TABLE users ADD COLUMN plan_name TEXT");
    }
    if (!userColumns.some((column) => column.name === "client_version")) {
      this.db.exec("ALTER TABLE users ADD COLUMN client_version TEXT");
    }
    // 0.9.2：用户 ID（uid，6 位数字）与初始密码（temp_password，改密后清空）。
    if (!userColumns.some((column) => column.name === "uid")) {
      this.db.exec("ALTER TABLE users ADD COLUMN uid TEXT");
    }
    if (!userColumns.some((column) => column.name === "temp_password")) {
      this.db.exec("ALTER TABLE users ADD COLUMN temp_password TEXT");
    }
    // 0.10.0：邮箱（注册绑定，一个邮箱一个 ID）与邮箱验证标记。
    if (!userColumns.some((column) => column.name === "email")) {
      this.db.exec("ALTER TABLE users ADD COLUMN email TEXT");
    }
    if (!userColumns.some((column) => column.name === "email_verified")) {
      this.db.exec("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0");
    }
    this.backfillUids();
    // username 允许重名（uid 为唯一登录标识）：重建 users 表去掉 username 唯一约束。
    this.rebuildUsersTableIfUsernameUnique();
    // 0.9.2 一次性数据迁移：限速单位字节/秒→比特/秒（×8）；限速键前缀用户名→uid。
    if (!this.getSetting("migration_092_done")) {
      this.db.exec("UPDATE users SET rate_limit_bps = rate_limit_bps * 8 WHERE rate_limit_bps > 0");
      this.db.exec(
        "UPDATE proxy_rate_limits SET rate_limit_bps = rate_limit_bps * 8 WHERE rate_limit_bps > 0",
      );
      for (const row of this.db.prepare("SELECT id, uid, username FROM users").all()) {
        this.migrateRateLimitPrefix(row.id, `${row.username}-`, `${row.uid}-`);
      }
      this.setSetting("migration_092_done", "1");
    }
    // 0.9.3：激活起算套餐模型（activated_at / duration_days）与 HTTP/HTTPS 授权列（http_allowed）。
    if (!userColumns.some((column) => column.name === "activated_at")) {
      this.db.exec("ALTER TABLE users ADD COLUMN activated_at TEXT");
    }
    if (!userColumns.some((column) => column.name === "duration_days")) {
      this.db.exec("ALTER TABLE users ADD COLUMN duration_days INTEGER NOT NULL DEFAULT 30");
    }
    if (!userColumns.some((column) => column.name === "http_allowed")) {
      this.db.exec("ALTER TABLE users ADD COLUMN http_allowed INTEGER NOT NULL DEFAULT 0");
    }
    // expires_at 需由 NOT NULL 放宽为可空（NULL=未激活）：重建表（新库已是可空，自动跳过）。
    this.rebuildUsersTableFor093();
    if (!this.getSetting("migration_093_done")) {
      const planDays = new Map(
        this.listPlans().map((plan) => [Number(plan.id), Number(plan.durationDays)]),
      );
      const setDays = this.db.prepare("UPDATE users SET duration_days = ? WHERE id = ?");
      const activateBackfill = this.db
        .prepare("UPDATE users SET duration_days = ?, activated_at = ? WHERE id = ? AND activated_at IS NULL");
      const resetUnactivated = this.db
        .prepare("UPDATE users SET duration_days = ?, activated_at = NULL, expires_at = NULL WHERE id = ?");
      for (const row of this.db
        .prepare("SELECT id, plan_id, must_change_password, created_at FROM users")
        .all()) {
        const days = (row.plan_id && planDays.get(Number(row.plan_id))) || 30;
        if (Number(row.must_change_password) === 0) {
          // 已激活老用户：回填激活时间（取创建时间），到期时间保持不变。
          activateBackfill.run(days, row.created_at, row.id);
        } else {
          // 未激活老用户：旧到期时间作废，改由激活时刻起算。
          resetUnactivated.run(days, row.id);
        }
        setDays.run(days, row.id);
      }
      // 历史曾建立 http/https 隧道的用户自动授权，避免升级后业务中断。
      this.db.exec(
        `UPDATE users SET http_allowed = 1
         WHERE id IN (SELECT DISTINCT user_id FROM frp_proxies WHERE proxy_type IN ('http', 'https'))`,
      );
      this.setSetting("migration_093_done", "1");
    }
    const proxyColumns = this.db.prepare("PRAGMA table_info(frp_proxies)").all();
    if (!proxyColumns.some((column) => column.name === "custom_domains")) {
      this.db.exec("ALTER TABLE frp_proxies ADD COLUMN custom_domains TEXT");
    }

    const adminCount = this.db.prepare("SELECT COUNT(*) AS count FROM admins").get().count;
    if (adminCount === 0) {
      this.db
        .prepare("INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)")
        .run(normalizeUsername(adminUser), hashPassword(adminPassword), nowISO());
    } else if (process.env.FORCE_RESET_ADMIN_PASSWORD === "1") {
      const password = validatePassword(adminPassword);
      const existing = this.db
        .prepare("SELECT id, password_hash FROM admins WHERE username = ?")
        .get(normalizeUsername(adminUser));
      if (existing) {
        this.db
          .prepare(
            "UPDATE admins SET password_hash = ?, token_version = token_version + 1 WHERE id = ?",
          )
          .run(hashPassword(password), existing.id);
      } else {
        const firstAdmin = this.db.prepare("SELECT id FROM admins ORDER BY id ASC LIMIT 1").get();
        if (firstAdmin) {
          this.db
            .prepare(
              "UPDATE admins SET username = ?, password_hash = ?, token_version = token_version + 1 WHERE id = ?",
            )
            .run(normalizeUsername(adminUser), hashPassword(password), firstAdmin.id);
        }
      }
    }

    // 0.9.0：首次启动种子预设套餐与默认端口池（已有数据不覆盖）。
    this.seedPlans();
    this.getOrCreateSetting("port_pool", () => "20000-30000");
  }

  close() {
    this.db.close();
  }

  // 0.9.0：plans 表为空时种子 6 个预设套餐（已有数据不覆盖）。
  seedPlans() {
    const count = this.db.prepare("SELECT COUNT(*) AS count FROM plans").get().count;
    if (count > 0) return;
    const now = nowISO();
    const stmt = this.db.prepare(`
      INSERT INTO plans (
        name, duration_days, traffic_limit_bytes, port_count, price_cents,
        sort_order, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    DEFAULT_PLANS.forEach((plan, index) => {
      stmt.run(
        plan.name,
        plan.durationDays,
        plan.trafficGB * 1024 ** 3,
        plan.portCount,
        plan.priceCents,
        index,
        now,
        now,
      );
    });
  }

  getOrCreateSetting(key, factory = () => randomSecret()) {
    const existing = this.db.prepare("SELECT value FROM settings WHERE key = ?").get(key);
    if (existing) return existing.value;
    const value = factory();
    this.db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)").run(key, value);
    return value;
  }

  getSetting(key) {
    return this.db.prepare("SELECT value FROM settings WHERE key = ?").get(key)?.value ?? null;
  }

  setSetting(key, value) {
    this.db
      .prepare(`
        INSERT INTO settings (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
      `)
      .run(String(key), String(value));
  }

  deleteSetting(key) {
    this.db.prepare("DELETE FROM settings WHERE key = ?").run(String(key));
  }

  // 0.9.2：6 位数字用户 ID（uid）——登录与 frp 身份标识，全局唯一。
  static normalizeUid(value) {
    const uid = String(value ?? "").trim();
    if (!/^\d{6}$/.test(uid)) throw new Error("用户 ID 必须是 6 位数字（100000-999999）");
    return uid;
  }

  generateUid() {
    const exists = this.db.prepare("SELECT 1 FROM users WHERE uid = ?");
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const candidate = String(randomInt(100000, 1000000));
      if (!exists.get(candidate)) return candidate;
    }
    throw new Error("用户 ID 生成冲突过多，请重试");
  }

  // 存量用户回填 uid（随机 6 位，内存集合查重避免事务内反复查询）。
  backfillUids() {
    const rows = this.db.prepare("SELECT id FROM users WHERE uid IS NULL OR uid = ''").all();
    if (rows.length === 0) return;
    const used = new Set(
      this.db
        .prepare("SELECT uid FROM users WHERE uid IS NOT NULL AND uid != ''")
        .all()
        .map((row) => row.uid),
    );
    const update = this.db.prepare("UPDATE users SET uid = ? WHERE id = ?");
    for (const row of rows) {
      let candidate = null;
      for (let attempt = 0; attempt < 200; attempt += 1) {
        const value = String(randomInt(100000, 1000000));
        if (!used.has(value)) {
          candidate = value;
          break;
        }
      }
      if (!candidate) throw new Error("用户 ID 生成冲突过多，请重试");
      used.add(candidate);
      update.run(candidate, row.id);
    }
  }

  // 旧库 users.username 带 UNIQUE 约束：重建表去除（uid 已回填，新表 uid NOT NULL UNIQUE）。
  rebuildUsersTableIfUsernameUnique() {
    const indexes = this.db.prepare("PRAGMA index_list('users')").all();
    const usernameUnique = indexes.some((index) => {
      if (!index.unique) return false;
      const info = this.db.prepare(`PRAGMA index_info('${index.name}')`).all();
      return info.some((column) => column.name === "username");
    });
    if (!usernameUnique) return;
    this.db.exec("PRAGMA foreign_keys = OFF");
    try {
      this.db.exec(`
        CREATE TABLE users_new (
          id INTEGER PRIMARY KEY,
          uid TEXT NOT NULL UNIQUE,
          username TEXT NOT NULL COLLATE BINARY,
          password_hash TEXT NOT NULL,
          port_ranges TEXT NOT NULL,
          expires_at TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1,
          token_version INTEGER NOT NULL DEFAULT 1,
          active_device_id TEXT,
          device_address TEXT,
          device_last_seen TEXT,
          rate_limit_bps INTEGER NOT NULL DEFAULT 0,
          traffic_limit_bytes INTEGER NOT NULL DEFAULT 0,
          traffic_used_bytes INTEGER NOT NULL DEFAULT 0,
          must_change_password INTEGER NOT NULL DEFAULT 0,
          plan_id INTEGER,
          plan_name TEXT,
          client_version TEXT,
          temp_password TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        INSERT INTO users_new (
          id, uid, username, password_hash, port_ranges, expires_at, enabled,
          token_version, active_device_id, device_address, device_last_seen,
          rate_limit_bps, traffic_limit_bytes, traffic_used_bytes,
          must_change_password, plan_id, plan_name, client_version,
          temp_password, created_at, updated_at
        )
        SELECT
          id, uid, username, password_hash, port_ranges, expires_at, enabled,
          token_version, active_device_id, device_address, device_last_seen,
          rate_limit_bps, traffic_limit_bytes, traffic_used_bytes,
          must_change_password, plan_id, plan_name, client_version,
          temp_password, created_at, updated_at
        FROM users;
        DROP TABLE users;
        ALTER TABLE users_new RENAME TO users;
      `);
    } finally {
      this.db.exec("PRAGMA foreign_keys = ON");
    }
  }

  // 0.9.3：重建 users 表以放宽 expires_at 为可空并纳入新列（activated_at/duration_days/http_allowed）。
  // 新库（CREATE TABLE 已是新结构）检测到 expires_at 可空即跳过。
  rebuildUsersTableFor093() {
    const columns = this.db.prepare("PRAGMA table_info('users')").all();
    const expiresCol = columns.find((column) => column.name === "expires_at");
    if (expiresCol && !expiresCol.notnull) return;
    this.db.exec("PRAGMA foreign_keys = OFF");
    try {
      this.db.exec(`
        CREATE TABLE users_new (
          id INTEGER PRIMARY KEY,
          uid TEXT NOT NULL UNIQUE,
          username TEXT NOT NULL COLLATE BINARY,
          password_hash TEXT NOT NULL,
          port_ranges TEXT NOT NULL,
          expires_at TEXT,
          activated_at TEXT,
          duration_days INTEGER NOT NULL DEFAULT 30,
          http_allowed INTEGER NOT NULL DEFAULT 0,
          enabled INTEGER NOT NULL DEFAULT 1,
          token_version INTEGER NOT NULL DEFAULT 1,
          active_device_id TEXT,
          device_address TEXT,
          device_last_seen TEXT,
          rate_limit_bps INTEGER NOT NULL DEFAULT 0,
          traffic_limit_bytes INTEGER NOT NULL DEFAULT 0,
          traffic_used_bytes INTEGER NOT NULL DEFAULT 0,
          must_change_password INTEGER NOT NULL DEFAULT 0,
          plan_id INTEGER,
          plan_name TEXT,
          client_version TEXT,
          temp_password TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        INSERT INTO users_new (
          id, uid, username, password_hash, port_ranges, expires_at, activated_at,
          duration_days, http_allowed, enabled, token_version, active_device_id,
          device_address, device_last_seen, rate_limit_bps, traffic_limit_bytes,
          traffic_used_bytes, must_change_password, plan_id, plan_name, client_version,
          temp_password, created_at, updated_at
        )
        SELECT
          id, uid, username, password_hash, port_ranges, expires_at, activated_at,
          duration_days, http_allowed, enabled, token_version, active_device_id,
          device_address, device_last_seen, rate_limit_bps, traffic_limit_bytes,
          traffic_used_bytes, must_change_password, plan_id, plan_name, client_version,
          temp_password, created_at, updated_at
        FROM users;
        DROP TABLE users;
        ALTER TABLE users_new RENAME TO users;
      `);
    } finally {
      this.db.exec("PRAGMA foreign_keys = ON");
    }
  }

  // 迁移某用户隧道限速行的全限定名前缀（改 uid 或数据迁移用）。
  migrateRateLimitPrefix(userId, oldPrefix, newPrefix) {
    if (oldPrefix === newPrefix) return;
    const rows = this.db
      .prepare("SELECT proxy_name, rate_limit_bps FROM proxy_rate_limits WHERE user_id = ?")
      .all(Number(userId));
    for (const item of rows) {
      if (!String(item.proxy_name).startsWith(oldPrefix)) continue;
      const newName = newPrefix + String(item.proxy_name).slice(oldPrefix.length);
      this.db
        .prepare("DELETE FROM proxy_rate_limits WHERE user_id = ? AND proxy_name = ?")
        .run(Number(userId), item.proxy_name);
      this.db
        .prepare(
          `INSERT INTO proxy_rate_limits (user_id, proxy_name, rate_limit_bps, updated_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(user_id, proxy_name) DO UPDATE SET
             rate_limit_bps = excluded.rate_limit_bps,
             updated_at = excluded.updated_at`,
        )
        .run(Number(userId), newName, item.rate_limit_bps, nowISO());
    }
  }

  authenticateAdmin(username, password) {
    const row = this.db.prepare("SELECT * FROM admins WHERE username = ?").get(String(username));
    return row && verifyPassword(password, row.password_hash) ? parseAdmin(row) : null;
  }

  getAdminById(id) {
    return parseAdmin(this.db.prepare("SELECT * FROM admins WHERE id = ?").get(Number(id)));
  }

  // 0.10.0.2：敏感集群操作（设为主节点）前的管理员密码校验。
  verifyAdminPassword(id, password) {
    const row = this.db.prepare("SELECT * FROM admins WHERE id = ?").get(Number(id));
    return Boolean(row) && verifyPassword(String(password ?? ""), row.password_hash);
  }

  changeAdminPassword(id, currentPassword, newPassword, actor) {
    const row = this.db.prepare("SELECT * FROM admins WHERE id = ?").get(Number(id));
    if (!row || !verifyPassword(currentPassword, row.password_hash)) {
      throw new Error("当前密码错误");
    }
    const password = validatePassword(newPassword);
    if (verifyPassword(password, row.password_hash)) {
      throw new Error("新密码不能与当前密码相同");
    }
    this.db
      .prepare(`
        UPDATE admins
        SET password_hash = ?, token_version = token_version + 1
        WHERE id = ?
      `)
      .run(hashPassword(password), row.id);
    this.audit(actor, "admin.password", row.username);
    return this.getAdminById(row.id);
  }

  changeAdminUsername(id, currentPassword, newUsername, actor) {
    const row = this.db.prepare("SELECT * FROM admins WHERE id = ?").get(Number(id));
    if (!row || !verifyPassword(currentPassword, row.password_hash)) {
      throw new Error("当前密码错误");
    }
    const username = normalizeUsername(newUsername);
    if (username === row.username) {
      throw new Error("新用户名与当前用户名相同");
    }
    const conflict = this.db
      .prepare("SELECT id FROM admins WHERE username = ? AND id != ?")
      .get(username, row.id);
    if (conflict) throw new Error("用户名已被占用");
    this.db
      .prepare("UPDATE admins SET username = ?, token_version = token_version + 1 WHERE id = ?")
      .run(username, row.id);
    this.audit(actor, "admin.username", username, { previous: row.username });
    return this.getAdminById(row.id);
  }

  // 0.9.2：登录标识为 6 位 uid；过渡期兼容旧用户名（6 位数字优先按 uid 查）。
  authenticateUser(identifier, password, { allowExpired = false } = {}) {
    const key = String(identifier ?? "").trim();
    let row = null;
    // 0.10.0：支持邮箱登录（注册用户绑定邮箱；主节点与从节点 agent 代理登录共用此入口）。
    if (key.includes("@")) {
      const byEmail = this.getUserByEmail(key);
      if (byEmail) {
        row = this.db.prepare("SELECT * FROM users WHERE id = ?").get(byEmail.id);
      }
    }
    if (!row && /^\d{6}$/.test(key)) {
      row = this.db.prepare("SELECT * FROM users WHERE uid = ?").get(key);
    }
    if (!row) {
      row = this.db.prepare("SELECT * FROM users WHERE username = ?").get(key);
    }
    if (!row || !verifyPassword(password, row.password_hash)) return null;
    const user = parseUser(row);
    if (!user.enabled) throw new Error("账号已停用");
    if (user.expired && !allowExpired) throw new Error("账号已到期");
    // 0.9.3：管理员未强制改密的账号（must_change_password=0 且未激活）首次登录即激活，
    // 激活时刻起算套餐时长；强制改密的账号在改密完成时激活（见 changeUserPassword）。
    if (!user.activatedAt && !user.mustChangePassword) {
      return this.activateUser(user.id, user.username);
    }
    return user;
  }

  // 0.9.3：激活账号——expires_at 以激活时刻为起点 + duration_days 天；已激活则原样返回。
  activateUser(id, actor) {
    const row = this.db.prepare("SELECT * FROM users WHERE id = ?").get(Number(id));
    if (!row) throw new Error("用户不存在");
    if (row.activated_at) return this.getUserById(row.id);
    const days = Number(row.duration_days || 30);
    const now = nowISO();
    const expiresAt = new Date(Date.now() + days * 86_400_000).toISOString();
    this.db
      .prepare("UPDATE users SET activated_at = ?, expires_at = ?, updated_at = ? WHERE id = ?")
      .run(now, expiresAt, now, row.id);
    this.audit(actor ?? row.username, "user.activate", row.username, {
      durationDays: days,
      expiresAt,
    });
    return this.getUserById(row.id);
  }

  claimDevice(userId, deviceId, clientAddress = null) {
    const now = nowISO();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const row = this.db
        .prepare(`
          SELECT active_device_id, device_last_seen
          FROM users
          WHERE id = ?
        `)
        .get(Number(userId));
      if (!row) {
        this.db.exec("ROLLBACK");
        return null;
      }

      const otherDeviceActive =
        row.active_device_id &&
        row.active_device_id !== deviceId &&
        row.device_last_seen &&
        Date.parse(row.device_last_seen) >= Date.now() - DEVICE_LEASE_MS;
      if (otherDeviceActive) {
        const error = new Error("该账号已在另一台设备登录");
        error.code = "DEVICE_IN_USE";
        error.status = 409;
        throw error;
      }

      const replacingDevice =
        Boolean(row.active_device_id) && row.active_device_id !== deviceId;
      if (replacingDevice) this.closeUserActivity(userId);
      this.db
        .prepare(`
          UPDATE users
          SET active_device_id = ?,
              device_address = ?,
              device_last_seen = ?,
              token_version = token_version + ?,
              updated_at = ?
          WHERE id = ?
        `)
        .run(
          deviceId,
          clientAddress || null,
          now,
          replacingDevice ? 1 : 0,
          now,
          Number(userId),
        );
      this.db.exec("COMMIT");
    } catch (error) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // The transaction may already have been closed by SQLite.
      }
      throw error;
    }
    return this.getUserById(userId);
  }

  touchDevice(userId, deviceId, clientAddress = null) {
    const result = this.db
      .prepare(`
        UPDATE users
        SET device_last_seen = ?,
            device_address = COALESCE(?, device_address)
        WHERE id = ? AND active_device_id = ?
      `)
      .run(nowISO(), clientAddress || null, Number(userId), deviceId);
    return result.changes > 0;
  }

  releaseDevice(userId, deviceId) {
    const result = this.db
      .prepare(`
        UPDATE users
        SET active_device_id = NULL,
            device_address = NULL,
            device_last_seen = NULL,
            token_version = token_version + 1,
            updated_at = ?
        WHERE id = ? AND active_device_id = ?
      `)
      .run(nowISO(), Number(userId), deviceId);
    if (result.changes > 0) this.closeUserActivity(userId);
    return result.changes > 0;
  }

  // 0.9.0：记录客户端版本（心跳/登录上报）；空值不覆盖。
  setUserClientVersion(id, version) {
    const text = String(version ?? "").trim();
    if (!text) return false;
    const result = this.db
      .prepare("UPDATE users SET client_version = ? WHERE id = ?")
      .run(text.slice(0, 50), Number(id));
    return result.changes > 0;
  }

  getUserById(id) {
    return parseUser(this.db.prepare("SELECT * FROM users WHERE id = ?").get(Number(id)));
  }

  getUserByUsername(username) {
    return parseUser(this.db.prepare("SELECT * FROM users WHERE username = ?").get(String(username)));
  }

  getUserByUid(uid) {
    return parseUser(this.db.prepare("SELECT * FROM users WHERE uid = ?").get(String(uid)));
  }

  listUsers() {
    const onlineAfter = new Date(Date.now() - 30_000).toISOString();
    const users = this.db
      .prepare(`
        SELECT u.*,
          MAX(CASE WHEN s.closed_at IS NULL THEN s.last_seen END) AS last_seen,
          CASE
            WHEN MAX(CASE WHEN s.closed_at IS NULL THEN s.last_seen END) >= ? THEN 1
            ELSE 0
          END AS online,
          COUNT(DISTINCT p.id) AS mapping_count,
          COUNT(DISTINCT CASE
            WHEN p.closed_at IS NULL
              AND ps.closed_at IS NULL
              AND ps.last_seen >= ?
              AND u.enabled = 1
              AND u.expires_at > ?
            THEN p.id
          END) AS online_mapping_count
        FROM users u
        LEFT JOIN frp_sessions s ON s.user_id = u.id
        LEFT JOIN frp_proxies p ON p.user_id = u.id
        LEFT JOIN frp_sessions ps ON ps.run_id = p.run_id
        GROUP BY u.id
        ORDER BY u.created_at DESC
      `)
      .all(onlineAfter, onlineAfter, nowISO())
      .map(parseUser);
    // 0.10.1.1 规格13：统一在线判定口径——用户可能经从节点 frpc 接入（主节点无本地会话），
    // 在线 = 主节点会话 ∪ 从节点上报会话（cluster_sessions，30 秒心跳为准）。
    const slaveSessions = this.clusterSessionLatestByUser();
    if (slaveSessions.size) {
      for (const user of users) {
        const slaveSeen = slaveSessions.get(user.id);
        if (!slaveSeen) continue;
        if (!user.lastSeen || slaveSeen > user.lastSeen) user.lastSeen = slaveSeen;
        if (slaveSeen >= onlineAfter) user.online = true;
      }
    }
    return users;
  }

  listProxies(userId = null) {
    return this.db
      .prepare(`
        SELECT
          p.*,
          u.username,
          u.uid,
          u.enabled AS user_enabled,
          u.expires_at AS user_expires_at,
          s.client_address,
          s.last_seen,
          s.closed_at AS session_closed_at,
          prl.rate_limit_bps AS proxy_rate_limit_bps
        FROM frp_proxies p
        JOIN users u ON u.id = p.user_id
        LEFT JOIN frp_sessions s ON s.run_id = p.run_id
        LEFT JOIN proxy_rate_limits prl
          ON prl.user_id = p.user_id AND prl.proxy_name = p.proxy_name
        WHERE (? IS NULL OR p.user_id = ?)
        ORDER BY
          CASE WHEN p.closed_at IS NULL THEN 0 ELSE 1 END,
          p.updated_at DESC
      `)
      .all(userId, userId)
      .map(parseProxy);
  }

  // 0.10.0.2：端口段引用的从节点必须真实存在（主节点免检）。
  assertRangeNodes(ranges) {
    const names = new Set(ranges.map(rangeNode).filter((name) => name !== "master"));
    for (const name of names) {
      if (!this.getClusterNodeByName(name)) {
        throw new Error(`节点 ${name} 不存在，无法授权该节点的端口`);
      }
    }
  }

  validateRanges(portRanges, excludedUserId = null) {
    const ranges = parsePortRanges(portRanges);
    this.assertRangeNodes(ranges);
    const assignments = this.db
      .prepare("SELECT id, username, port_ranges FROM users WHERE id != COALESCE(?, -1)")
      .all(excludedUserId)
      .map((row) => ({
        username: row.username,
        ranges: JSON.parse(row.port_ranges),
      }));
    const conflict = findRangeConflict(ranges, assignments);
    if (conflict) {
      const ports =
        conflict.start === conflict.end
          ? conflict.start
          : `${conflict.start}-${conflict.end}`;
      const scope = conflict.node !== "master" ? `节点 ${conflict.node} 的` : "";
      throw new Error(`${scope}端口 ${ports} 已分配给用户 ${conflict.username}`);
    }
    return ranges;
  }

  // 0.10.0.2：节点端口池占用统计（用于开号/批量生成选择器与集群监控）。
  nodePortUsage(node) {
    const poolRanges = parsePortRanges(this.getSetting("port_pool") || "20000-30000");
    const used = new Set();
    for (const row of this.db.prepare("SELECT port_ranges FROM users").all()) {
      for (const range of JSON.parse(row.port_ranges)) {
        if (rangeNode(range) !== node) continue;
        for (let port = Number(range.start); port <= Number(range.end); port += 1) used.add(port);
      }
    }
    const total = poolRanges.reduce((sum, range) => sum + (range.end - range.start + 1), 0);
    return { used: used.size, total };
  }

  // 0.9.3：套餐天数归一化（1-3650 天）。
  static normalizeDurationDays(value) {
    const days = Number.parseInt(Number(value), 10);
    if (!Number.isInteger(days) || days < 1 || days > 3650) {
      throw new Error("有效天数须为 1-3650 的整数");
    }
    return days;
  }

  createUser(input, actor) {
    const username = normalizeUsername(input.username);
    // 0.9.2：密码留空则自动生成（创建后在用户列表可见，用户改密后不可再查看）。
    const password = input.password && String(input.password).trim()
      ? validatePassword(input.password)
      : randomText(BATCH_PASSWORD_CHARS, 10);
    // 0.9.2：uid 可由管理员指定（6 位数字、唯一）；留空自动随机生成并查重。
    let uid;
    if (input.uid !== undefined && input.uid !== null && String(input.uid).trim() !== "") {
      uid = Store.normalizeUid(input.uid);
      if (this.getUserByUid(uid)) throw new Error("用户 ID 已存在，请更换后重试");
    } else {
      uid = this.generateUid();
    }
    const ranges = this.validateRanges(input.portRanges);
    let planId = null;
    let planName = null;
    let planDuration = null;
    let planTraffic = null;
    let planRateLimit = null;
    if (input.planId) {
      const plan = this.getPlan(input.planId);
      if (!plan) throw new Error("套餐不存在");
      planId = plan.id;
      planName = plan.name;
      planDuration = plan.durationDays;
      planTraffic = plan.trafficLimitBytes;
      planRateLimit = plan.rateLimitBps;
    }
    // 0.9.3：有效期改为套餐天数，激活（首次改密/首次登录）时刻才起算；创建时 expires_at 为 NULL。
    const durationDays = Store.normalizeDurationDays(
      input.durationDays !== undefined && input.durationDays !== null && String(input.durationDays).trim() !== ""
        ? input.durationDays
        : (planDuration ?? 30),
    );
    // 0.10.2.1：未显式传限速时取套餐限速（0=不限速）；显式传值（管理端弹窗）以传值为准。
    const rateLimitBps =
      input.rateLimitBps === undefined
        ? Math.max(0, Number(planRateLimit) || 0)
        : Math.max(0, Number(input.rateLimitBps) || 0);
    const trafficLimitBytes = Math.max(
      0,
      input.trafficLimitBytes !== undefined && input.trafficLimitBytes !== null
        ? Number(input.trafficLimitBytes) || 0
        : (planTraffic ?? 0),
    );
    // 0.9.3：新账号默认强制首登改密（= 未激活）；管理员显式关闭时首次登录补记激活。
    const mustChangePassword = input.mustChangePassword === undefined ? true : Boolean(input.mustChangePassword);
    const httpAllowed = Boolean(input.httpAllowed);

    const now = nowISO();
    const result = this.db
      .prepare(`
        INSERT INTO users (
          uid, username, password_hash, port_ranges, expires_at, activated_at,
          duration_days, http_allowed, enabled, token_version, rate_limit_bps,
          traffic_limit_bytes, must_change_password, plan_id, plan_name,
          temp_password, created_at, updated_at
        ) VALUES (?, ?, ?, ?, NULL, NULL, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        uid,
        username,
        hashPassword(password),
        JSON.stringify(ranges),
        durationDays,
        httpAllowed ? 1 : 0,
        input.enabled === false ? 0 : 1,
        rateLimitBps,
        trafficLimitBytes,
        mustChangePassword ? 1 : 0,
        planId,
        planName,
        password,
        now,
        now,
      );
    this.audit(actor, "user.create", username, {
      uid,
      portRanges: ranges,
      durationDays,
      httpAllowed,
      rateLimitBps,
      trafficLimitBytes,
      mustChangePassword,
      planId,
      planName,
    });
    return this.getUserById(Number(result.lastInsertRowid));
  }

  updateUser(id, input, actor) {
    const current = this.getUserById(id);
    if (!current) return null;

    const username = normalizeUsername(input.username ?? current.username);
    // 0.9.2：uid 为登录标识，可改但必须全局唯一；用户名允许重名。
    let uid = current.uid;
    let uidChanged = false;
    if (input.uid !== undefined && input.uid !== null && String(input.uid).trim() !== "") {
      uid = Store.normalizeUid(input.uid);
      if (uid !== current.uid) {
        const conflict = this.db
          .prepare("SELECT 1 FROM users WHERE uid = ? AND id != ?")
          .get(uid, current.id);
        if (conflict) throw new Error("用户 ID 已存在，请更换后重试");
        uidChanged = true;
      }
    }
    const ranges = this.validateRanges(input.portRanges ?? current.portRanges, current.id);
    // 0.10.1.0：管理员可在用户编辑中直接修改到期时间——传有效日期即更新；传空串清除
    // 到期限制（已激活账号 expires_at 为 NULL 视为永不过期）；不传（undefined）维持现值。
    let expiresAtValue = current.expiresAt;
    if (input.expiresAt !== undefined && input.expiresAt !== null) {
      const raw = String(input.expiresAt).trim();
      if (raw === "") {
        expiresAtValue = null;
      } else {
        const parsed = new Date(raw);
        if (!Number.isFinite(parsed.getTime())) throw new Error("到期时间无效");
        expiresAtValue = parsed.toISOString();
      }
    }
    // 0.9.3：套餐天数只允许在未激活时修改；已激活账号的有效期只能通过续费调整。
    const isActivated = Boolean(current.activatedAt);
    const durationDaysInputProvided =
      input.durationDays !== undefined &&
      input.durationDays !== null &&
      String(input.durationDays).trim() !== "";
    if (durationDaysInputProvided && isActivated) {
      const requested = Store.normalizeDurationDays(input.durationDays);
      if (requested !== current.durationDays) {
        throw new Error("账号已激活，套餐天数不可直接修改；如需调整有效期请使用续费功能");
      }
    }
    let durationDays = durationDaysInputProvided
      ? Store.normalizeDurationDays(input.durationDays)
      : current.durationDays;
    const httpAllowed = input.httpAllowed === undefined ? current.httpAllowed : Boolean(input.httpAllowed);
    const enabled = input.enabled === undefined ? current.enabled : Boolean(input.enabled);
    let rateLimitBps = input.rateLimitBps === undefined ? current.rateLimitBps : Math.max(0, Number(input.rateLimitBps) || 0);
    let trafficLimitBytes = input.trafficLimitBytes === undefined ? current.trafficLimitBytes : Math.max(0, Number(input.trafficLimitBytes) || 0);
    const passwordChanged = Boolean(input.password);
    // 管理员重置密码：默认要求下次登录改密，并记录为新的初始密码（改密前可查看）。
    const mustChangePassword =
      input.mustChangePassword === undefined
        ? passwordChanged || current.mustChangePassword
        : Boolean(input.mustChangePassword);
    let planId = current.planId;
    let planName = current.planName;
    if (input.planId !== undefined) {
      if (input.planId) {
        const plan = this.getPlan(input.planId);
        if (!plan) throw new Error("套餐不存在");
        planId = plan.id;
        planName = plan.name;
        // 0.9.3：与批量改套餐保持一致——切换套餐同步流量配额；
        // 未激活账号同步套餐天数（已激活账号天数/到期不受影响，续费另算）。
        // 0.10.2.1：未显式传限速时同步套餐限速（显式传值以传值为准）。
        if (input.trafficLimitBytes === undefined) {
          trafficLimitBytes = plan.trafficLimitBytes;
        }
        if (input.rateLimitBps === undefined) {
          rateLimitBps = plan.rateLimitBps;
        }
        if (!durationDaysInputProvided && !isActivated) {
          durationDays = plan.durationDays;
        }
      } else {
        planId = null;
        planName = null;
      }
    }
    const portGrantChanged =
      JSON.stringify(ranges) !== JSON.stringify(current.portRanges);
    const tokenVersion =
      current.tokenVersion +
      (passwordChanged || uidChanged || portGrantChanged ? 1 : 0);
    const passwordHash = passwordChanged
      ? hashPassword(validatePassword(input.password))
      : this.db.prepare("SELECT password_hash FROM users WHERE id = ?").get(current.id).password_hash;
    const tempPassword = passwordChanged ? validatePassword(input.password) : current.tempPassword;

    this.db
      .prepare(`
        UPDATE users SET
          uid = ?, username = ?, password_hash = ?, port_ranges = ?, expires_at = ?,
          duration_days = ?, http_allowed = ?,
          enabled = ?, token_version = ?, rate_limit_bps = ?, traffic_limit_bytes = ?,
          must_change_password = ?, plan_id = ?, plan_name = ?, temp_password = ?,
          updated_at = ?
        WHERE id = ?
      `)
      .run(
        uid,
        username,
        passwordHash,
        JSON.stringify(ranges),
        expiresAtValue,
        durationDays,
        httpAllowed ? 1 : 0,
        enabled ? 1 : 0,
        tokenVersion,
        rateLimitBps,
        trafficLimitBytes,
        mustChangePassword ? 1 : 0,
        planId,
        planName,
        tempPassword,
        nowISO(),
        current.id,
      );
    if (uidChanged) {
      // frp 身份随 uid 变化：限速全限定名前缀迁移。
      this.migrateRateLimitPrefix(current.id, `${current.uid}-`, `${uid}-`);
    }
    if (
      passwordChanged ||
      uidChanged ||
      portGrantChanged ||
      !enabled ||
      current.expired ||
      (Boolean(expiresAtValue) && isExpired(expiresAtValue))
    ) {
      this.closeUserActivity(current.id);
    }
    this.audit(actor, "user.update", username, {
      uid,
      uidChanged,
      portRanges: ranges,
      durationDays,
      httpAllowed,
      enabled,
      passwordChanged,
      rateLimitBps,
      trafficLimitBytes,
      mustChangePassword,
      planId,
      planName,
    });
    return this.getUserById(current.id);
  }

  deleteUser(id, actor) {
    const user = this.getUserById(id);
    if (!user) return false;
    this.db.prepare("DELETE FROM users WHERE id = ?").run(user.id);
    this.audit(actor, "user.delete", user.username);
    return true;
  }

  // 0.9.3：批量更新用户（限速 bps；支持套餐/套餐天数/启停/HTTP 授权）。
  batchUpdateUsers(ids, patch, actor) {
    const userIds = [
      ...new Set(
        (Array.isArray(ids) ? ids : [])
          .map(Number)
          .filter((id) => Number.isInteger(id) && id > 0),
      ),
    ];
    if (userIds.length === 0) throw new Error("未选择任何用户");
    if (userIds.length > 500) throw new Error("单次批量操作不能超过 500 个用户");
    const sets = [];
    const params = [];
    const auditPatch = {};
    if (patch.rateLimitBps !== undefined) {
      const bps = Math.max(0, Number(patch.rateLimitBps) || 0);
      sets.push("rate_limit_bps = ?");
      params.push(bps);
      auditPatch.rateLimitBps = bps;
    }
    if (patch.enabled !== undefined) {
      sets.push("enabled = ?");
      params.push(patch.enabled ? 1 : 0);
      auditPatch.enabled = Boolean(patch.enabled);
    }
    if (patch.httpAllowed !== undefined) {
      sets.push("http_allowed = ?");
      params.push(patch.httpAllowed ? 1 : 0);
      auditPatch.httpAllowed = Boolean(patch.httpAllowed);
    }
    // 0.9.3：套餐天数只对「未激活」账号可改（激活后到期时间已起算，改天数不影响有效期）；
    // 这类字段走独立 UPDATE 并附加 activated_at IS NULL 条件。
    const inactiveSets = [];
    const inactiveParams = [];
    if (patch.durationDays !== undefined && patch.planId === undefined) {
      const days = Store.normalizeDurationDays(patch.durationDays);
      inactiveSets.push("duration_days = ?");
      inactiveParams.push(days);
      auditPatch.durationDays = days;
    }
    if (patch.planId !== undefined) {
      if (patch.planId) {
        const plan = this.getPlan(patch.planId);
        if (!plan) throw new Error("套餐不存在");
        // 套餐快照、流量配额与限速对全部选中用户生效（0.10.2.1：同步套餐限速）。
        sets.push("plan_id = ?", "plan_name = ?", "traffic_limit_bytes = ?", "rate_limit_bps = ?");
        params.push(plan.id, plan.name, plan.trafficLimitBytes, plan.rateLimitBps);
        // 套餐天数仅同步给未激活账号（已激活账号续费请走续费流程）。
        inactiveSets.push("duration_days = ?");
        inactiveParams.push(plan.durationDays);
        auditPatch.planId = plan.id;
        auditPatch.planName = plan.name;
      } else {
        sets.push("plan_id = ?", "plan_name = ?");
        params.push(null, null);
        auditPatch.planId = null;
      }
    }
    if (sets.length === 0 && inactiveSets.length === 0) {
      throw new Error("未指定任何批量修改项");
    }
    const placeholders = userIds.map(() => "?").join(",");
    const existing = this.db
      .prepare(`SELECT id, uid FROM users WHERE id IN (${placeholders})`)
      .all(...userIds);
    const existingIds = existing.map((row) => row.id);
    const existingPlaceholders = existingIds.map(() => "?").join(",");
    const stamp = nowISO();
    if (sets.length > 0) {
      sets.push("updated_at = ?");
      params.push(stamp);
      this.db
        .prepare(
          `UPDATE users SET ${sets.join(", ")} WHERE id IN (${existingPlaceholders})`,
        )
        .run(...params, ...existingIds);
    }
    if (inactiveSets.length > 0) {
      inactiveSets.push("updated_at = ?");
      inactiveParams.push(stamp);
      this.db
        .prepare(
          `UPDATE users SET ${inactiveSets.join(", ")} WHERE id IN (${existingPlaceholders}) AND activated_at IS NULL`,
        )
        .run(...inactiveParams, ...existingIds);
    }
    // 批量停用需关闭在线会话与隧道。
    if (patch.enabled === false) {
      for (const row of existing) this.closeUserActivity(row.id);
    }
    const found = new Set(existingIds);
    const failed = userIds
      .filter((id) => !found.has(id))
      .map((id) => ({ id, reason: "用户不存在" }));
    this.audit(actor, "user.batch_update", `${existing.length} 个用户`, {
      // 0.9.3：审计记录 6 位用户 ID（uid）而非数据库自增 id，便于运营追溯。
      uids: existing.map((row) => row.uid),
      count: existing.length,
      failed,
      ...auditPatch,
    });
    return { updated: existing.length, failed, updatedIds: existingIds };
  }

  // 0.9.3：批量删除用户。
  batchDeleteUsers(ids, actor) {
    const userIds = [
      ...new Set(
        (Array.isArray(ids) ? ids : [])
          .map(Number)
          .filter((id) => Number.isInteger(id) && id > 0),
      ),
    ];
    if (userIds.length === 0) throw new Error("未选择任何用户");
    if (userIds.length > 500) throw new Error("单次批量操作不能超过 500 个用户");
    const placeholders = userIds.map(() => "?").join(",");
    const existing = this.db
      .prepare(`SELECT id, uid FROM users WHERE id IN (${placeholders})`)
      .all(...userIds);
    const existingIds = existing.map((row) => row.id);
    for (const row of existing) this.closeUserActivity(row.id);
    if (existingIds.length) {
      const existingPlaceholders = existingIds.map(() => "?").join(",");
      this.db
        .prepare(`DELETE FROM users WHERE id IN (${existingPlaceholders})`)
        .run(...existingIds);
    }
    const found = new Set(existingIds);
    const failed = userIds
      .filter((id) => !found.has(id))
      .map((id) => ({ id, reason: "用户不存在" }));
    this.audit(actor, "user.batch_delete", `${existing.length} 个用户`, {
      uids: existing.map((row) => row.uid),
      count: existing.length,
      failed,
    });
    return { deleted: existing.length, failed };
  }

  addUserTrafficUsage(deltas) {
    if (!deltas || deltas.size === 0) return;
    const now = nowISO();
    const stmt = this.db.prepare(
      "UPDATE users SET traffic_used_bytes = traffic_used_bytes + ?, updated_at = ? WHERE id = ?",
    );
    for (const [userId, delta] of deltas) {
      const bytes = Number(delta.incomingBytes) + Number(delta.outgoingBytes);
      if (bytes > 0) stmt.run(bytes, now, Number(userId));
    }
  }

  resetUserTraffic(id, actor) {
    const user = this.getUserById(id);
    if (!user) return null;
    this.db
      .prepare("UPDATE users SET traffic_used_bytes = 0, updated_at = ? WHERE id = ?")
      .run(nowISO(), user.id);
    this.audit(actor, "user.reset_traffic", user.username);
    return this.getUserById(user.id);
  }

  revokeUser(id, actor) {
    const user = this.getUserById(id);
    if (!user) return null;
    this.db
      .prepare(`
        UPDATE users
        SET token_version = token_version + 1,
            active_device_id = NULL,
            device_address = NULL,
            device_last_seen = NULL,
            updated_at = ?
        WHERE id = ?
      `)
      .run(nowISO(), user.id);
    this.closeUserActivity(user.id);
    this.audit(actor, "user.disconnect", user.username);
    return this.getUserById(user.id);
  }

  renewUser(id, input, actor) {
    const user = this.getUserById(id);
    if (!user) return null;
    const days = normalizeRenewalDays(input.days);
    const note = normalizeNote(input.note);
    const now = nowISO();
    let resultExpiresAt = null;
    if (!user.activatedAt) {
      // 0.9.3：未激活账号续费只累加套餐天数（封顶 3650 天），激活时刻才起算。
      const totalDays = Math.min(3650, user.durationDays + days);
      this.db
        .prepare("UPDATE users SET duration_days = ?, updated_at = ? WHERE id = ?")
        .run(totalDays, now, user.id);
      this.audit(actor, "user.renew", user.username, { days, totalDays, unactivated: true, note });
      return this.getUserById(user.id);
    }
    const base = Math.max(Date.now(), Date.parse(user.expiresAt));
    resultExpiresAt = new Date(base + days * 86_400_000).toISOString();
    this.db
      .prepare("UPDATE users SET expires_at = ?, updated_at = ? WHERE id = ?")
      .run(resultExpiresAt, now, user.id);
    this.audit(actor, "user.renew", user.username, { days, resultExpiresAt, note });
    return this.getUserById(user.id);
  }

  // ---------- 0.10.0：套餐码 ----------
  #normalizeEmail(value) {
    const email = String(value ?? "").trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) throw new Error("邮箱格式不正确");
    return email;
  }

  generatePlanCodes(input, actor) {
    const plan = this.getPlan(input.planId);
    if (!plan) throw new Error("套餐不存在");
    const count = Number(input.count);
    if (!Number.isInteger(count) || count < 1 || count > 500) {
      throw new Error("生成数量须为 1-500");
    }
    // 0.10.0.2：套餐码必须绑定目标节点（master 或从节点名），兑换时按该节点端口池分配。
    const node = String(input.node || "").trim() || "master";
    if (node !== "master" && !this.getClusterNodeByName(node)) {
      throw new Error(`目标节点 ${node} 不存在，请先选定有效节点`);
    }
    // 16 位复杂字符（去除易混淆的 0/O/1/l/I）。
    const charset = "23456789ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz";
    const batchId = `batch-${Date.now().toString(36)}-${randomInt(1000, 10000)}`;
    const used = new Set(
      this.db.prepare("SELECT code FROM plan_codes").all().map((row) => row.code),
    );
    const codes = [];
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const stmt = this.db.prepare(
        "INSERT INTO plan_codes (code, plan_id, batch_id, status, node_name, created_at, created_by) VALUES (?, ?, ?, 'unused', ?, ?, ?)",
      );
      while (codes.length < count) {
        let code = "";
        for (let i = 0; i < 16; i += 1) code += charset[randomInt(charset.length)];
        if (used.has(code)) continue;
        used.add(code);
        stmt.run(code, plan.id, batchId, node, nowISO(), actor);
        codes.push(code);
      }
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
    this.audit(actor, "plan_code.generate", plan.name, { count, batchId, node });
    return { batchId, codes, plan, node };
  }

  listPlanCodes(filter = {}) {
    const clauses = [];
    const params = [];
    if (filter.batchId) {
      clauses.push("batch_id = ?");
      params.push(String(filter.batchId));
    }
    if (filter.status) {
      clauses.push("status = ?");
      params.push(String(filter.status));
    }
    const rows = this.db
      .prepare(
        `SELECT pc.*, p.name AS plan_name, u.username AS used_by_name
         FROM plan_codes pc
         LEFT JOIN plans p ON p.id = pc.plan_id
         LEFT JOIN users u ON u.id = pc.used_by
         ${clauses.length ? `WHERE ${clauses.join(" AND ")}` : ""}
         ORDER BY pc.id DESC
         LIMIT 2000`,
      )
      .all(...params);
    return rows.map((row) => ({
      id: row.id,
      code: row.code,
      planId: row.plan_id,
      planName: row.plan_name,
      batchId: row.batch_id,
      status: row.status,
      nodeName: row.node_name || "master",
      usedByName: row.used_by_name ?? null,
      usedAt: row.used_at ?? null,
      createdAt: row.created_at,
    }));
  }

  deletePlanCodes(ids, actor) {
    const targets = (Array.isArray(ids) ? ids : []).map(Number).filter(Number.isInteger);
    if (targets.length === 0) throw new Error("请选择要删除的套餐码");
    const placeholders = targets.map(() => "?").join(",");
    const deletable = this.db
      .prepare(`SELECT id, status FROM plan_codes WHERE id IN (${placeholders})`)
      .all(...targets)
      .filter((row) => row.status !== "used");
    const alreadyUsed = targets.length - deletable.length;
    const info = this.db
      .prepare(`DELETE FROM plan_codes WHERE id IN (${deletable.map(() => "?").join(",")})`)
      .run(...deletable.map((row) => row.id));
    this.audit(actor, "plan_code.delete", "plan_codes", { count: info.changes });
    return { deleted: info.changes, skippedUsed: alreadyUsed };
  }

  // 兑换套餐码：绑定套餐（时长/端口/流量），未激活用户激活起算，已激活顺延，过期重新起算。
  redeemPlanCode(code, userId) {
    const normalized = String(code ?? "").trim();
    if (!normalized) throw new Error("请填写套餐码");
    const row = this.db.prepare("SELECT * FROM plan_codes WHERE code = ?").get(normalized);
    if (!row) throw new Error("套餐码不存在，请核对后重试");
    if (row.status === "used") throw new Error("该套餐码已被使用");
    if (row.status !== "unused") throw new Error("该套餐码已失效");
    const plan = this.getPlan(row.plan_id);
    if (!plan) throw new Error("套餐码对应的套餐已下架，请联系管理员");
    const user = this.getUserById(userId);
    if (!user) throw new Error("用户不存在");

    const now = nowISO();
    const days = Number(plan.durationDays) || 0;
    // 端口：从端口池分配 plan.portCount 个连续空闲端口，追加到用户授权段。
    // 0.10.0.2：套餐码绑定目标节点，按该节点的端口池独立分配。
    const codeNode = String(row.node_name || "").trim() || "master";
    let addedRanges = [];
    if (plan.portCount > 0) {
      const poolRanges = parsePortRanges(this.getSetting("port_pool") || "20000-30000");
      const occupied = new Set();
      for (const item of this.db.prepare("SELECT port_ranges FROM users").all()) {
        for (const range of JSON.parse(item.port_ranges)) {
          if (rangeNode(range) !== codeNode) continue;
          for (let port = Number(range.start); port <= Number(range.end); port += 1) {
            occupied.add(port);
          }
        }
      }
      for (const range of user.portRanges) {
        if (rangeNode(range) !== codeNode) continue;
        for (let port = Number(range.start); port <= Number(range.end); port += 1) {
          occupied.add(port);
        }
      }
      const findRun = (need) => {
        for (const range of poolRanges) {
          let runStart = null;
          for (let port = range.start; port <= range.end; port += 1) {
            if (!occupied.has(port)) {
              if (runStart === null) runStart = port;
              if (port - runStart + 1 >= need) return { start: runStart, end: runStart + need - 1 };
            } else {
              runStart = null;
            }
          }
        }
        return null;
      };
      const run = findRun(plan.portCount);
      if (!run) throw new Error("端口池空闲端口不足，无法分配该套餐端口数，请联系管理员");
      addedRanges = [codeNode === "master" ? run : { ...run, node: codeNode }];
    }

    const nextRanges = [...user.portRanges, ...addedRanges];
    let activatedAt = user.activatedAt;
    let expiresAt = user.expiresAt;
    let durationDays = user.durationDays;
    if (!user.activatedAt) {
      // 未激活（含纯注册用户）：兑换后天数暂存，激活时刻起算（与续费语义一致）。
      durationDays = Math.min(3650, user.durationDays + days);
    } else if (user.expired || !user.expiresAt) {
      activatedAt = now;
      expiresAt = new Date(Date.now() + days * 86_400_000).toISOString();
    } else {
      const base = Math.max(Date.now(), Date.parse(user.expiresAt));
      expiresAt = new Date(base + days * 86_400_000).toISOString();
    }
    const trafficLimit =
      plan.trafficLimitBytes > 0
        ? Number(user.trafficLimitBytes || 0) + Number(plan.trafficLimitBytes)
        : user.trafficLimitBytes;
    // 0.10.2.1：套餐带限速（>0）时直接应用到用户；不限速（0）保持用户现有限速不变。
    const rateLimitBps =
      plan.rateLimitBps > 0 ? Number(plan.rateLimitBps) : Number(user.rateLimitBps || 0);
    this.db
      .prepare(
        `UPDATE users SET port_ranges = ?, activated_at = ?, expires_at = ?, duration_days = ?,
         traffic_limit_bytes = ?, rate_limit_bps = ?, plan_id = ?, plan_name = ?, updated_at = ? WHERE id = ?`,
      )
      .run(
        JSON.stringify(nextRanges),
        activatedAt,
        expiresAt,
        durationDays,
        trafficLimit,
        rateLimitBps,
        plan.id,
        plan.name,
        now,
        user.id,
      );
    this.db
      .prepare("UPDATE plan_codes SET status = 'used', used_by = ?, used_at = ? WHERE id = ?")
      .run(user.id, now, row.id);
    this.audit(`user:${user.uid}`, "plan_code.redeem", plan.name, { code: normalized });
    return { user: this.getUserById(user.id), plan, addedRanges };
  }

  // ---------- 0.10.0：注册（邮箱绑定，一邮箱一 ID） ----------
  getUserByEmail(email) {
    const normalized = this.#normalizeEmail(email);
    const row = this.db.prepare("SELECT * FROM users WHERE email = ?").get(normalized);
    return row ? parseUser(row) : null;
  }

  registerUser({ email, password, username }) {
    const normalizedEmail = this.#normalizeEmail(email);
    if (this.getUserByEmail(normalizedEmail)) {
      throw new Error("该邮箱已注册，请直接登录或找回密码");
    }
    const validPassword = validatePassword(password);
    const usedUids = new Set(this.db.prepare("SELECT uid FROM users").all().map((row) => row.uid));
    let uid = null;
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const candidate = String(randomInt(100000, 1000000));
      if (!usedUids.has(candidate)) {
        uid = candidate;
        break;
      }
    }
    if (!uid) throw new Error("用户 ID 生成冲突过多，请重试");
    const name = normalizeUsername(String(username || "").trim() || normalizedEmail.split("@")[0]);
    const now = nowISO();
    // 注册即激活（activated_at=now）；无套餐（duration_days=0、expires_at=NULL）、无端口，
    // 兑换套餐码后获得端口与时长。
    this.db
      .prepare(
        `INSERT INTO users (
          uid, username, password_hash, port_ranges, expires_at, activated_at, duration_days,
          http_allowed, enabled, token_version, email, email_verified, must_change_password,
          created_at, updated_at
        ) VALUES (?, ?, ?, '[]', NULL, ?, 0, 0, 1, 1, ?, 1, 0, ?, ?)`,
      )
      .run(uid, name, hashPassword(validPassword), now, normalizedEmail, now, now);
    this.audit(`user:${uid}`, "user.register", normalizedEmail);
    const user = this.getUserByEmail(normalizedEmail);
    return { ...user, uid };
  }

  // 邮箱找回密码：重置并踢下线（token_version+1），清除未激活标记（重置即可直接登录）。
  resetPasswordByEmail(email, newPassword) {
    const normalizedEmail = this.#normalizeEmail(email);
    const user = this.getUserByEmail(normalizedEmail);
    if (!user) throw new Error("该邮箱未注册");
    const validPassword = validatePassword(newPassword);
    this.db
      .prepare(
        `UPDATE users SET password_hash = ?, must_change_password = 0, temp_password = NULL,
         token_version = token_version + 1, active_device_id = NULL, device_address = NULL,
         device_last_seen = NULL, updated_at = ? WHERE id = ?`,
      )
      .run(hashPassword(validPassword), nowISO(), user.id);
    this.closeUserActivity(user.id);
    this.audit(`user:${user.uid}`, "user.reset_password_by_email", normalizedEmail);
    return this.getUserById(user.id);
  }

  // ---------- 0.10.0：集群节点注册表 ----------
  createClusterNode(input, actor) {
    const name = String(input.name || "").trim().slice(0, 40);
    const host = String(input.host || "").trim();
    if (!name) throw new Error("节点名称不能为空");
    if (!/^(?:\d{1,3}(?:\.\d{1,3}){3}|[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+)$/i.test(host)) {
      throw new Error("节点地址须为合法 IP 或域名");
    }
    if (this.db.prepare("SELECT id FROM cluster_nodes WHERE name = ?").get(name)) {
      throw new Error(`节点名称 ${name} 已存在`);
    }
    const token = `xfnode-${randomSecret(24)}`;
    const address = String(input.address || "").trim() || host;
    const clientApiPort = Number(input.clientApiPort) || 9400;
    const location = String(input.location || "").trim().slice(0, 64) || null;
    // 0.10.1.1 规格10：备用主节点优先级（>0=可自动升主）。
    const priority = Math.max(0, Math.min(1000, Math.floor(Number(input.priority) || 0)));
    const now = nowISO();
    this.db
      .prepare(
        `INSERT INTO cluster_nodes (name, host, address, client_api_port, token_hash, location, priority, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
      )
      .run(name, host, address, clientApiPort, createHash("sha256").update(token).digest("hex"), location, priority, now, now);
    this.audit(actor, "cluster.node.create", name, { host, address, location });
    return { node: this.getClusterNodeByName(name), token };
  }

  #parseClusterNode(row) {
    if (!row) return null;
    let stats = null;
    try {
      stats = row.stats ? JSON.parse(row.stats) : null;
    } catch {
      stats = null;
    }
    const online =
      row.status === "online" &&
      Boolean(row.last_sync_at) &&
      Date.now() - Date.parse(row.last_sync_at) < 90_000;
    return {
      id: row.id,
      name: row.name,
      host: row.host,
      address: row.address,
      clientApiPort: Number(row.client_api_port),
      bindPort: row.bind_port ?? null,
      location: row.location ?? null,
      // 0.10.1.0：从节点 frps 的 auth.token（sync 上报），主节点转发给客户端连从节点用。
      frpToken: row.frp_token ?? null,
      // 0.10.1.1 规格10：备用主节点优先级（>0=可自动升主，数字越大越优先）。
      priority: Number(row.priority || 0),
      status: row.status,
      online,
      lastSyncAt: row.last_sync_at ?? null,
      version: row.version ?? null,
      stats: stats ?? null,
      createdAt: row.created_at,
    };
  }

  listClusterNodes() {
    return this.db
      .prepare("SELECT * FROM cluster_nodes ORDER BY id ASC")
      .all()
      .map((row) => this.#parseClusterNode(row));
  }

  getClusterNodeByName(name) {
    return this.#parseClusterNode(
      this.db.prepare("SELECT * FROM cluster_nodes WHERE name = ?").get(String(name)),
    );
  }

  getClusterNodeByToken(token) {
    const hash = createHash("sha256").update(String(token || "")).digest("hex");
    return this.#parseClusterNode(
      this.db.prepare("SELECT * FROM cluster_nodes WHERE token_hash = ?").get(hash),
    );
  }

  deleteClusterNode(id, actor) {
    const row = this.db.prepare("SELECT * FROM cluster_nodes WHERE id = ?").get(Number(id));
    if (!row) throw new Error("节点不存在");
    this.db.prepare("DELETE FROM cluster_nodes WHERE id = ?").run(row.id);
    this.audit(actor, "cluster.node.delete", row.name);
    return true;
  }

  // 从节点同步：刷新状态/版本/统计，返回主节点下发的同步载荷（由路由层构造）。
  touchClusterNode(token, { version, bindPort, stats, frpToken }) {
    const node = this.getClusterNodeByToken(token);
    if (!node) throw new Error("集群节点令牌无效");
    this.db
      .prepare(
        "UPDATE cluster_nodes SET status = 'online', last_sync_at = ?, version = ?, bind_port = ?, stats = ?, frp_token = ?, updated_at = ? WHERE id = ?",
      )
      .run(
        nowISO(),
        String(version || ""),
        bindPort ?? null,
        JSON.stringify(stats || {}),
        // 0.10.1.0：记录从节点 frps auth.token（客户端连从节点 frps 用）。
        String(frpToken || "") || null,
        nowISO(),
        node.id,
      );
    return this.getClusterNodeByName(node.name);
  }

  markClusterNodeStatus(id, status) {
    this.db
      .prepare("UPDATE cluster_nodes SET status = ?, updated_at = ? WHERE id = ?")
      .run(String(status), nowISO(), Number(id));
  }

  // 0.10.1.1 规格10：设置从节点备用主优先级（>0=可自动升主，数字越大越优先）。
  setClusterNodePriority(id, priority, actor) {
    const node = this.getClusterNodeById(Number(id));
    if (!node) throw new Error("节点不存在");
    const value = Math.max(0, Math.min(1000, Math.floor(Number(priority) || 0)));
    this.db
      .prepare("UPDATE cluster_nodes SET priority = ?, updated_at = ? WHERE id = ?")
      .run(value, nowISO(), node.id);
    this.audit(actor, "cluster.node.priority", node.name, { priority: value });
    return this.getClusterNodeById(node.id);
  }

  getClusterNodeById(id) {
    return this.#parseClusterNode(
      this.db.prepare("SELECT * FROM cluster_nodes WHERE id = ?").get(Number(id)),
    );
  }

  // ---------- 0.10.1.1 规格13：从节点会话上报（统一用户在线判定口径） ----------
  // 从节点每轮 sync 上报本地 frpc 会话（user_id → 最新 last_seen），主节点落库。
  replaceClusterNodeSessions(nodeName, sessions) {
    const node = String(nodeName || "").slice(0, 40);
    if (!node) return;
    const rows = (Array.isArray(sessions) ? sessions : [])
      .map((item) => ({ userId: Number(item?.userId), lastSeen: String(item?.lastSeen || "") }))
      .filter((item) => Number.isInteger(item.userId) && item.userId > 0 && item.lastSeen)
      .slice(0, 2000);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM cluster_sessions WHERE node_name = ?").run(node);
      const stmt = this.db.prepare(
        "INSERT OR REPLACE INTO cluster_sessions (node_name, user_id, last_seen) VALUES (?, ?, ?)",
      );
      for (const row of rows) stmt.run(node, row.userId, row.lastSeen);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  // 用户 ID → 从节点会话最新 last_seen（listUsers 在线口径合并用）。
  clusterSessionLatestByUser() {
    const rows = this.db
      .prepare("SELECT user_id, MAX(last_seen) AS last_seen FROM cluster_sessions GROUP BY user_id")
      .all();
    const map = new Map();
    for (const row of rows) map.set(Number(row.user_id), row.last_seen);
    return map;
  }

  // 0.10.1.2 规格7：「使用从节点 IP 登录」的用户在线情况。
  // 按用户 × 节点展开从节点会话（30 秒心跳口径），附用户名/UID，在线 = 心跳在 30 秒内。
  slaveLoginUsers() {
    const onlineAfter = new Date(Date.now() - 30_000).toISOString();
    const rows = this.db
      .prepare(
        `SELECT cs.node_name AS node, cs.user_id AS userId, cs.last_seen AS lastSeen,
                u.username AS username, u.uid AS uid, u.enabled AS enabled
         FROM cluster_sessions cs
         LEFT JOIN users u ON u.id = cs.user_id
         ORDER BY cs.last_seen DESC`,
      )
      .all();
    return rows
      .map((row) => ({
        userId: Number(row.userId),
        username: row.username || `用户#${row.userId}`,
        uid: row.uid ?? null,
        node: row.node,
        lastSeen: row.lastSeen,
        online: Boolean(row.lastSeen && row.lastSeen >= onlineAfter),
        enabled: row.enabled === null ? null : Boolean(row.enabled),
      }))
      .slice(0, 200);
  }

  // 0.10.1.1 规格13：本地未关闭 frpc 会话按用户汇总（从节点上报主节点，统一在线口径）。
  userSessionSummary() {
    return this.db
      .prepare(
        `SELECT user_id, MAX(last_seen) AS last_seen FROM frp_sessions
         WHERE closed_at IS NULL AND user_id IS NOT NULL GROUP BY user_id`,
      )
      .all()
      .map((row) => ({ userId: Number(row.user_id), lastSeen: row.last_seen }));
  }

  // ---------- 0.10.2.8：公告（管理员 → 客户端信息中心） ----------
  // 主节点管理台发布，随客户端登录/心跳下发；从节点经集群同步通道镜像主节点公告。
  listAnnouncements() {
    return this.db
      .prepare("SELECT * FROM announcements ORDER BY id DESC")
      .all()
      .map(parseAnnouncement);
  }

  activeAnnouncements(limit = 20) {
    const safe = Math.min(Math.max(Number(limit) || 20, 1), 100);
    return this.db
      .prepare("SELECT * FROM announcements ORDER BY id DESC LIMIT ?")
      .all(safe)
      .map(parseAnnouncement);
  }

  createAnnouncement(input, actor) {
    const title = String(input?.title || "").trim().slice(0, 80);
    const content = String(input?.content || "").trim().slice(0, 4000);
    const level = ["info", "warn"].includes(String(input?.level)) ? String(input.level) : "info";
    if (!title) throw new Error("公告标题不能为空");
    if (!content) throw new Error("公告内容不能为空");
    const now = nowISO();
    this.db
      .prepare(
        "INSERT INTO announcements (title, content, level, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
      )
      .run(title, content, level, now, now);
    const row = this.db.prepare("SELECT * FROM announcements ORDER BY id DESC LIMIT 1").get();
    this.audit(actor, "announcement.create", title);
    return parseAnnouncement(row);
  }

  deleteAnnouncement(id, actor) {
    const row = this.db.prepare("SELECT * FROM announcements WHERE id = ?").get(Number(id));
    if (!row) return false;
    this.db.prepare("DELETE FROM announcements WHERE id = ?").run(Number(id));
    this.audit(actor, "announcement.delete", row.title);
    return true;
  }

  // 从节点：镜像主节点公告（全量替换，主节点删除后从节点同步消失）。
  replaceSyncedAnnouncements(list) {
    const items = (Array.isArray(list) ? list : []).slice(0, 100);
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.exec("DELETE FROM announcements WHERE synced = 1");
      const insert = this.db.prepare(
        "INSERT INTO announcements (title, content, level, created_at, updated_at, synced) VALUES (?, ?, ?, ?, ?, 1)",
      );
      // 传入列表为最新在前（主节点 ORDER BY id DESC）；逆序插入使最新一条在本库获得最大 id，
      // 保证从节点 listAnnouncements（id DESC）的展示顺序与主节点一致。
      for (const item of [...items].reverse()) {
        const title = String(item?.title || "").trim().slice(0, 80);
        const content = String(item?.content || "").trim().slice(0, 4000);
        if (!title || !content) continue;
        insert.run(
          title,
          content,
          ["info", "warn"].includes(String(item?.level)) ? String(item.level) : "info",
          String(item?.createdAt || nowISO()),
          String(item?.createdAt || nowISO()),
        );
      }
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  // 0.10.1.1 规格10-12：从节点合并主节点下发的集群节点表（含备用主优先级）。
  // 保留本地既有行 token_hash（自我识别/降级后验签需要），新节点插入空 hash。
  upsertSyncedClusterNodes(nodes) {
    const list = (Array.isArray(nodes) ? nodes : []).slice(0, 100);
    if (!list.length) return;
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const byName = new Map(
        this.db.prepare("SELECT name FROM cluster_nodes").all().map((row) => [row.name, true]),
      );
      const insert = this.db.prepare(`
        INSERT INTO cluster_nodes (
          name, host, address, client_api_port, token_hash, bind_port, location,
          frp_token, priority, status, last_sync_at, version, created_at, updated_at
        ) VALUES (?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      const update = this.db.prepare(`
        UPDATE cluster_nodes SET host = ?, address = ?, client_api_port = ?, bind_port = ?,
          location = ?, frp_token = ?, priority = ?, status = ?, last_sync_at = ?, version = ?, updated_at = ?
        WHERE name = ?
      `);
      const now = nowISO();
      for (const node of list) {
        const name = String(node?.name || "").trim().slice(0, 40);
        const host = String(node?.host || "").trim();
        if (!name || !host) continue;
        const clientApiPort = Number(node?.clientApiPort) || 9400;
        const bindPort = Number.isInteger(node?.bindPort) ? node.bindPort : null;
        const location = String(node?.location || "").slice(0, 64) || null;
        const frpToken = String(node?.frpToken || "") || null;
        const priority = Math.max(0, Math.min(1000, Math.floor(Number(node?.priority) || 0)));
        const status = node?.online ? "online" : "offline";
        const lastSyncAt = String(node?.lastSyncAt || "") || null;
        const version = String(node?.version || "") || null;
        if (byName.has(name)) {
          update.run(host, host, clientApiPort, bindPort, location, frpToken, priority, status, lastSyncAt, version, now, name);
        } else {
          insert.run(name, host, host, clientApiPort, bindPort, location, frpToken, priority, status, lastSyncAt, version, now, now);
        }
      }
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  // 重新部署/重新生成节点令牌（令牌仅创建与重置时明文返回一次）。
  resetClusterNodeToken(id, actor) {
    const row = this.db.prepare("SELECT * FROM cluster_nodes WHERE id = ?").get(Number(id));
    if (!row) throw new Error("节点不存在");
    const token = `xfnode-${randomSecret(24)}`;
    this.db
      .prepare("UPDATE cluster_nodes SET token_hash = ?, status = 'pending', updated_at = ? WHERE id = ?")
      .run(createHash("sha256").update(token).digest("hex"), nowISO(), row.id);
    this.audit(actor, "cluster.node.reset_token", row.name);
    return { node: this.getClusterNodeByName(row.name), token };
  }

  // 0.10.0.2：节点位置（客户端登录页集群主机行 / 授权中心展示）。
  updateClusterNodeLocation(id, location, actor) {
    const row = this.db.prepare("SELECT * FROM cluster_nodes WHERE id = ?").get(Number(id));
    if (!row) throw new Error("节点不存在");
    const value = String(location || "").trim().slice(0, 64) || null;
    this.db
      .prepare("UPDATE cluster_nodes SET location = ?, updated_at = ? WHERE id = ?")
      .run(value, nowISO(), row.id);
    this.audit(actor, "cluster.node.location", row.name, { location: value });
    return this.getClusterNodeByName(row.name);
  }

  // ---------- 0.10.0.2：主→从命令队列 ----------
  // 从节点每 30 秒拉取一次同步载荷；主节点把限速/防火墙/版本同步等操作写入队列，
  // 随同步响应下发，从节点执行后在下次同步回报结果。
  enqueueClusterCommand(nodeName, type, payload, actor) {
    const node = this.getClusterNodeByName(String(nodeName || ""));
    if (!node) throw new Error(`集群节点 ${nodeName} 不存在`);
    const now = nowISO();
    const result = this.db
      .prepare(
        "INSERT INTO cluster_commands (node_name, type, payload, status, created_at, updated_at) VALUES (?, ?, ?, 'pending', ?, ?)",
      )
      .run(node.name, String(type), JSON.stringify(payload ?? {}), now, now);
    this.audit(actor, "cluster.command.enqueue", node.name, { type, id: Number(result.lastInsertRowid) });
    return Number(result.lastInsertRowid);
  }

  takePendingClusterCommands(nodeName) {
    return this.db
      .prepare(
        "SELECT id, type, payload FROM cluster_commands WHERE node_name = ? AND status = 'pending' ORDER BY id ASC LIMIT 20",
      )
      .all(String(nodeName))
      .map((row) => {
        let payload = {};
        try {
          payload = row.payload ? JSON.parse(row.payload) : {};
        } catch {
          payload = {};
        }
        return { id: row.id, type: row.type, payload };
      });
  }

  finishClusterCommands(nodeName, results) {
    const list = Array.isArray(results) ? results : [];
    for (const item of list) {
      const id = Number(item.id);
      if (!Number.isInteger(id)) continue;
      const status = item.ok === false ? "failed" : "done";
      this.db
        .prepare("UPDATE cluster_commands SET status = ?, result = ?, updated_at = ? WHERE id = ? AND node_name = ?")
        // 0.10.1.3 规格1：frps-logs 结果为多行日志，上限放宽到 20k（原 500 会截断日志）。
        .run(status, String(item.result || item.error || "").slice(0, 20000), nowISO(), id, String(nodeName));
    }
  }

  // 0.10.1.3 规格1：查询节点最近的命令执行状态（管理台轮询 frps 日志 / 控制结果）。
  listClusterCommands(nodeName, type = "", limit = 10) {
    const rows = this.db
      .prepare(
        "SELECT id, type, status, result, created_at, updated_at FROM cluster_commands WHERE node_name = ? AND type = ? ORDER BY id DESC LIMIT ?",
      )
      .all(String(nodeName || ""), String(type || ""), Math.min(Math.max(Number(limit) || 10, 1), 50));
    return rows;
  }

  // 命令结果留档 24 小时后清理（排队时顺带做一次扫除）。
  pruneClusterCommands() {
    this.db
      .prepare("DELETE FROM cluster_commands WHERE status != 'pending' AND updated_at < ?")
      .run(new Date(Date.now() - 86_400_000).toISOString());
  }

  // 从节点用户快照落库：仅覆盖主节点权威字段，本地统计（流量用量/映射计数/设备心跳）保持本地。
  // password_hash 仅在插入时置空串（从节点登录走主节点代理校验，本地不验密）。
  upsertSyncedUsers(users) {
    const list = Array.isArray(users) ? users : [];
    if (list.length === 0) return [];
    const now = nowISO();
    const result = [];
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const stmt = this.db.prepare(`
        INSERT INTO users (
          id, uid, username, password_hash, port_ranges, expires_at, activated_at, duration_days,
          http_allowed, enabled, token_version, active_device_id, rate_limit_bps,
          traffic_limit_bytes, must_change_password, email, email_verified, plan_id, plan_name,
          created_at, updated_at
        ) VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
          uid = excluded.uid,
          username = excluded.username,
          port_ranges = excluded.port_ranges,
          expires_at = excluded.expires_at,
          activated_at = excluded.activated_at,
          duration_days = excluded.duration_days,
          http_allowed = excluded.http_allowed,
          enabled = excluded.enabled,
          token_version = excluded.token_version,
          active_device_id = excluded.active_device_id,
          rate_limit_bps = excluded.rate_limit_bps,
          traffic_limit_bytes = excluded.traffic_limit_bytes,
          must_change_password = excluded.must_change_password,
          email = excluded.email,
          email_verified = excluded.email_verified,
          plan_id = excluded.plan_id,
          plan_name = excluded.plan_name,
          updated_at = excluded.updated_at
      `);
      for (const item of list) {
        if (!item || !Number.isInteger(Number(item.id))) continue;
        const ranges = Array.isArray(item.portRanges)
          ? item.portRanges
          : parsePortRanges(String(item.portRangesText || ""));
        stmt.run(
          Number(item.id),
          String(item.uid ?? ""),
          String(item.username ?? ""),
          JSON.stringify(ranges),
          item.expiresAt ?? null,
          item.activatedAt ?? null,
          Number(item.durationDays) || 0,
          item.httpAllowed ? 1 : 0,
          item.enabled === false ? 0 : 1,
          Number(item.tokenVersion) || 1,
          item.deviceId ?? null,
          Number(item.rateLimitBps) || 0,
          Number(item.trafficLimitBytes) || 0,
          item.mustChangePassword ? 1 : 0,
          item.email ?? null,
          item.emailVerified ? 1 : 0,
          item.planId ?? null,
          item.planName ?? null,
          String(item.createdAt || now),
          now,
        );
        const row = this.db.prepare("SELECT * FROM users WHERE id = ?").get(Number(item.id));
        if (row) result.push(parseUser(row));
      }
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
    return result;
  }

  // ---------- 0.10.1.0 数据高可用：主节点数据从节点实时备份 ----------
  // 主节点导出：全量用户（含密码哈希；仅经 agent 令牌认证的同步通道下发）。
  exportBackupUsers() {
    return this.db
      .prepare("SELECT * FROM users ORDER BY id ASC")
      .all()
      .map((row) => ({ ...parseUser(row), passwordHash: row.password_hash ?? "" }));
  }

  exportBackupAdmin() {
    const row = this.db
      .prepare("SELECT username, password_hash FROM admins ORDER BY id ASC LIMIT 1")
      .get();
    return row ? { username: row.username, passwordHash: row.password_hash } : null;
  }

  exportBackupPlans() {
    return this.listPlans().map((plan) => ({
      name: plan.name,
      durationDays: plan.durationDays,
      trafficLimitBytes: plan.trafficLimitBytes,
      rateLimitBps: plan.rateLimitBps,
      portCount: plan.portCount,
      priceCents: plan.priceCents,
      sortOrder: plan.sortOrder,
    }));
  }

  // 从节点保存备份快照（整体替换；每轮同步调用，保证实时性）。
  saveBackupSnapshot({ users, admin, plans } = {}) {
    const list = Array.isArray(users) ? users.filter((item) => item?.uid) : [];
    const now = nowISO();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.exec("DELETE FROM backup_users");
      const stmt = this.db.prepare(
        "INSERT INTO backup_users (uid, user_id, username, password_hash, payload, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
      );
      for (const item of list) {
        stmt.run(
          String(item.uid),
          Number(item.id) || 0,
          String(item.username ?? ""),
          String(item.passwordHash ?? ""),
          JSON.stringify(item),
          now,
        );
      }
      const metaStmt = this.db.prepare(
        "INSERT INTO backup_meta (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
      );
      metaStmt.run("admin", JSON.stringify(admin ?? null), now);
      metaStmt.run("plans", JSON.stringify(Array.isArray(plans) ? plans : []), now);
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
    return list.length;
  }

  // 提升为主节点（角色切回 master）后的启动恢复：把备份合并进本地权威表并清空备份。
  // 用户恢复走 upsertSyncedUsers（保留本地流量统计，自管事务），再回填密码哈希；管理员/套餐按备份覆盖。
  // 幂等：中途失败备份未清空，下次启动重新恢复。
  restoreBackupSnapshot() {
    const rows = this.db.prepare("SELECT payload, password_hash FROM backup_users ORDER BY user_id ASC").all();
    const adminRaw = this.db.prepare("SELECT value FROM backup_meta WHERE key = 'admin'").get();
    const plansRaw = this.db.prepare("SELECT value FROM backup_meta WHERE key = 'plans'").get();
    if (!rows.length && !adminRaw) return null;
    const payloads = rows
      .map((row) => {
        try {
          return JSON.parse(row.payload);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
    // 1) 用户快照合并 + 密码哈希回填（从节点平时不存哈希，切换后需本地验密）。
    if (payloads.length) {
      this.upsertSyncedUsers(payloads);
      this.db.exec("BEGIN IMMEDIATE");
      try {
        const hashStmt = this.db.prepare("UPDATE users SET password_hash = ? WHERE uid = ?");
        for (const row of rows) {
          const uid = String(JSON.parse(row.payload)?.uid ?? "");
          if (uid) hashStmt.run(String(row.password_hash ?? ""), uid);
        }
        this.db.exec("COMMIT");
      } catch (error) {
        this.db.exec("ROLLBACK");
        throw error;
      }
    }
    // 2) 管理员凭据 + 套餐恢复，成功后清空备份。
    this.db.exec("BEGIN IMMEDIATE");
    try {
      if (adminRaw) {
        const admin = JSON.parse(adminRaw.value);
        if (admin?.username && admin?.passwordHash) {
          const existing = this.db.prepare("SELECT id FROM admins ORDER BY id ASC LIMIT 1").get();
          if (existing) {
            this.db
              .prepare("UPDATE admins SET username = ?, password_hash = ?, token_version = token_version + 1 WHERE id = ?")
              .run(normalizeUsername(admin.username), admin.passwordHash, existing.id);
          } else {
            this.db
              .prepare("INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)")
              .run(normalizeUsername(admin.username), admin.passwordHash, nowISO());
          }
        }
      }
      if (plansRaw) {
        const plans = JSON.parse(plansRaw.value);
        if (Array.isArray(plans) && plans.length) {
          const stmt = this.db.prepare(`
            INSERT INTO plans (name, duration_days, traffic_limit_bytes, rate_limit_bps, port_count, price_cents, sort_order, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
              duration_days = excluded.duration_days,
              traffic_limit_bytes = excluded.traffic_limit_bytes,
              rate_limit_bps = excluded.rate_limit_bps,
              port_count = excluded.port_count,
              price_cents = excluded.price_cents,
              sort_order = excluded.sort_order,
              updated_at = excluded.updated_at
          `);
          const now = nowISO();
          for (const plan of plans) {
            if (!plan?.name) continue;
            stmt.run(
              String(plan.name),
              Number(plan.durationDays) || 30,
              Number(plan.trafficLimitBytes) || 0,
              Number(plan.rateLimitBps) || 0,
              Number(plan.portCount) || 1,
              Number(plan.priceCents) || 0,
              Number(plan.sortOrder) || 0,
              now,
              now,
            );
          }
        }
      }
      this.db.exec("DELETE FROM backup_users");
      this.db.exec("DELETE FROM backup_meta");
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
    return { users: payloads.length, admin: Boolean(adminRaw), plans: Boolean(plansRaw) };
  }

  hasBackupSnapshot() {
    const row = this.db.prepare("SELECT COUNT(*) AS count FROM backup_users").get();
    return Number(row.count) > 0;
  }

  // 从节点全量重建端口级限速表（主节点为准；每轮同步整体覆盖）。
  replaceAllProxyRateLimits(entries) {
    const list = Array.isArray(entries) ? entries : [];
    const now = nowISO();
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.exec("DELETE FROM proxy_rate_limits");
      const stmt = this.db.prepare(
        "INSERT OR IGNORE INTO proxy_rate_limits (user_id, proxy_name, rate_limit_bps, updated_at) VALUES (?, ?, ?, ?)",
      );
      for (const item of list) {
        const bps = Number(item.rateLimitBps) || 0;
        if (bps > 0) stmt.run(Number(item.userId), String(item.proxyName), bps, now);
      }
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }

  // 0.9.0：客户端自助改密（首次激活同样走此接口）。
  // 校验当前密码 → 新密码规则 → 不得与旧密码相同；清除 must_change_password 并使旧 token 失效。
  changeUserPassword(id, currentPassword, newPassword, actor) {
    const row = this.db.prepare("SELECT * FROM users WHERE id = ?").get(Number(id));
    if (!row) throw new Error("用户不存在");
    if (!verifyPassword(currentPassword, row.password_hash)) {
      throw new Error("当前密码错误");
    }
    const password = validatePassword(newPassword);
    if (verifyPassword(password, row.password_hash)) {
      throw new Error("新密码不能与当前密码相同");
    }
    const now = nowISO();
    // 0.9.3：改密完成即激活——首次改密写入 activated_at，并以该时刻起算套餐时长。
    const activating = !row.activated_at;
    if (activating) {
      const days = Number(row.duration_days || 30);
      const expiresAt = new Date(Date.now() + days * 86_400_000).toISOString();
      this.db
        .prepare(`
          UPDATE users
          SET password_hash = ?, must_change_password = 0, temp_password = NULL,
              activated_at = ?, expires_at = ?,
              token_version = token_version + 1, updated_at = ?
          WHERE id = ?
        `)
        .run(hashPassword(password), now, expiresAt, now, row.id);
      this.audit(actor, "user.activate", row.username, { durationDays: days, expiresAt, via: "password" });
    } else {
      this.db
        .prepare(`
          UPDATE users
          SET password_hash = ?, must_change_password = 0, temp_password = NULL,
              token_version = token_version + 1, updated_at = ?
          WHERE id = ?
        `)
        .run(hashPassword(password), now, row.id);
    }
    this.audit(actor, "user.password", row.username, { activating });
    return this.getUserById(row.id);
  }

  // 0.9.2：客户端自助改用户 ID（登录标识，6 位数字，全局唯一）。
  // 校验当前密码 → 格式/查重 → 迁移限速键前缀 → 旧会话失效，客户端以新 uid 重启 frpc。
  changeUserUid(id, currentPassword, newUid, actor) {
    const row = this.db.prepare("SELECT * FROM users WHERE id = ?").get(Number(id));
    if (!row) throw new Error("用户不存在");
    if (!verifyPassword(currentPassword, row.password_hash)) {
      throw new Error("当前密码错误");
    }
    const uid = Store.normalizeUid(newUid);
    if (uid === row.uid) throw new Error("新用户 ID 与当前 ID 相同");
    const conflict = this.db
      .prepare("SELECT 1 FROM users WHERE uid = ? AND id != ?")
      .get(uid, row.id);
    if (conflict) throw new Error("用户 ID 已存在，请更换后重试");
    this.db
      .prepare(
        "UPDATE users SET uid = ?, token_version = token_version + 1, updated_at = ? WHERE id = ?",
      )
      .run(uid, nowISO(), row.id);
    this.migrateRateLimitPrefix(row.id, `${row.uid}-`, `${uid}-`);
    this.closeUserActivity(row.id);
    this.audit(actor, "user.uid", uid, { previous: row.uid });
    return this.getUserById(row.id);
  }

  // 0.9.2：用户名仅用于展示，允许重名、不影响 frp 身份，改名不再踢下线/迁移限速键。
  changeUserUsername(id, currentPassword, newUsername, actor) {
    const row = this.db.prepare("SELECT * FROM users WHERE id = ?").get(Number(id));
    if (!row) throw new Error("用户不存在");
    if (!verifyPassword(currentPassword, row.password_hash)) {
      throw new Error("当前密码错误");
    }
    const username = normalizeUsername(newUsername);
    if (username === row.username) {
      throw new Error("新用户名与当前用户名相同");
    }
    this.db
      .prepare("UPDATE users SET username = ?, updated_at = ? WHERE id = ?")
      .run(username, nowISO(), row.id);
    this.audit(actor, "user.username", username, { previous: row.username });
    return this.getUserById(row.id);
  }

  // 0.9.0：套餐管理（价格单位分，流量 0=不限）。
  listPlans() {
    return this.db
      .prepare(`
        SELECT p.*,
          (SELECT COUNT(*) FROM users u WHERE u.plan_id = p.id) AS user_count
        FROM plans p
        ORDER BY p.sort_order ASC, p.id ASC
      `)
      .all()
      .map(parsePlan);
  }

  getPlan(id) {
    return parsePlan(
      this.db
        .prepare(`
          SELECT p.*,
            (SELECT COUNT(*) FROM users u WHERE u.plan_id = p.id) AS user_count
          FROM plans p
          WHERE p.id = ?
        `)
        .get(Number(id)),
    );
  }

  createPlan(input, actor) {
    const data = normalizePlanInput(input);
    const conflict = this.db.prepare("SELECT id FROM plans WHERE name = ?").get(data.name);
    if (conflict) throw new Error("套餐名称已存在");
    const now = nowISO();
    const result = this.db
      .prepare(`
        INSERT INTO plans (
          name, duration_days, traffic_limit_bytes, rate_limit_bps, port_count,
          price_cents, sort_order, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .run(
        data.name,
        data.durationDays,
        data.trafficLimitBytes,
        data.rateLimitBps || 0,
        data.portCount,
        data.priceCents,
        data.sortOrder,
        now,
        now,
      );
    this.audit(actor, "plan.create", data.name, data);
    return this.getPlan(Number(result.lastInsertRowid));
  }

  updatePlan(id, input, actor) {
    const current = this.getPlan(id);
    if (!current) return null;
    const data = normalizePlanInput(input, { partial: true });
    if (data.name && data.name !== current.name) {
      const conflict = this.db
        .prepare("SELECT id FROM plans WHERE name = ? AND id != ?")
        .get(data.name, current.id);
      if (conflict) throw new Error("套餐名称已存在");
    }
    const next = {
      name: data.name ?? current.name,
      durationDays: data.durationDays ?? current.durationDays,
      trafficLimitBytes: data.trafficLimitBytes ?? current.trafficLimitBytes,
      rateLimitBps: data.rateLimitBps ?? current.rateLimitBps,
      portCount: data.portCount ?? current.portCount,
      priceCents: data.priceCents ?? current.priceCents,
      sortOrder: data.sortOrder ?? current.sortOrder,
    };
    this.db
      .prepare(`
        UPDATE plans SET
          name = ?, duration_days = ?, traffic_limit_bytes = ?, rate_limit_bps = ?,
          port_count = ?, price_cents = ?, sort_order = ?, updated_at = ?
        WHERE id = ?
      `)
      .run(
        next.name,
        next.durationDays,
        next.trafficLimitBytes,
        next.rateLimitBps,
        next.portCount,
        next.priceCents,
        next.sortOrder,
        nowISO(),
        current.id,
      );
    // 套餐改名时级联同步 users 表冗余列 plan_name，避免用户列表显示旧名。
    if (data.name && data.name !== current.name) {
      this.db
        .prepare("UPDATE users SET plan_name = ? WHERE plan_id = ?")
        .run(next.name, current.id);
    }
    this.audit(actor, "plan.update", next.name, next);
    return this.getPlan(current.id);
  }

  countUsersByPlan(id) {
    return this.db
      .prepare("SELECT COUNT(*) AS count FROM users WHERE plan_id = ?")
      .get(Number(id)).count;
  }

  deletePlan(id, actor) {
    const plan = this.getPlan(id);
    if (!plan) return false;
    const used = this.countUsersByPlan(plan.id);
    if (used > 0) {
      const error = new Error(
        `该套餐已被 ${used} 个账号引用，无法删除（可编辑调整或先迁移账号）`,
      );
      error.status = 409;
      throw error;
    }
    this.db.prepare("DELETE FROM plans WHERE id = ?").run(plan.id);
    this.audit(actor, "plan.delete", plan.name);
    return true;
  }

  // 0.9.0：按套餐批量开号（单事务，失败整体回滚）。
  // 端口池内取连续空闲段分配；用户名 = 前缀 + 6 位随机；密码 10 位随机；
  // 首登强制改密；写入套餐快照；明文密码仅在返回值中出现一次。
  // 0.10.0.2：必须先选定目标节点（master 或集群从节点名），各节点端口池互相独立。
  batchCreateUsers(input, actor) {
    const plan = this.getPlan(input.planId);
    if (!plan) throw new Error("套餐不存在");
    const count = Number(input.count);
    if (!Number.isInteger(count) || count < 1 || count > 200) {
      throw new Error("批量开号数量须为 1-200");
    }
    const prefix = String(input.prefix ?? "").trim().toLowerCase();
    if (!/^[a-z0-9]{1,20}$/.test(prefix)) {
      throw new Error("用户名前缀须为 1-20 位字母或数字");
    }
    const node = String(input.node || "").trim() || "master";
    if (node !== "master" && !this.getClusterNodeByName(node)) {
      throw new Error(`目标节点 ${node} 不存在，请先选定有效节点`);
    }

    const poolRanges = parsePortRanges(this.getSetting("port_pool") || "20000-30000");

    this.db.exec("BEGIN IMMEDIATE");
    try {
      // 已占用端口 = 所有用户在该节点上的端口段并集（0.10.0.2 起按节点独立计算）。
      const occupied = new Set();
      for (const row of this.db.prepare("SELECT port_ranges FROM users").all()) {
        for (const range of JSON.parse(row.port_ranges)) {
          if (rangeNode(range) !== node) continue;
          for (let port = Number(range.start); port <= Number(range.end); port += 1) {
            occupied.add(port);
          }
        }
      }
      // 0.9.2：平台保留端口与本机 LISTENING 端口（由路由层探测传入）同样跳过。
      // 仅对主节点生效——保留/监听端口探测的是主节点本机。
      if (node === "master") {
        for (const port of Array.isArray(input.reservedPorts) ? input.reservedPorts : []) {
          const value = Number(port);
          if (Number.isInteger(value) && value >= 1 && value <= 65535) occupied.add(value);
        }
      }

      const findContiguousRun = (need) => {
        for (const range of poolRanges) {
          let runStart = null;
          for (let port = range.start; port <= range.end; port += 1) {
            if (!occupied.has(port)) {
              if (runStart === null) runStart = port;
              if (port - runStart + 1 >= need) {
                return { start: runStart, end: runStart + need - 1 };
              }
            } else {
              runStart = null;
            }
          }
        }
        return null;
      };

      const countFreePorts = () => {
        let free = 0;
        for (const range of poolRanges) {
          for (let port = range.start; port <= range.end; port += 1) {
            if (!occupied.has(port)) free += 1;
          }
        }
        return free;
      };

      // 0.9.3：批量开号同样未激活（expires_at=NULL），套餐时长激活时起算。
      const created = [];
      // 0.9.2：用户名允许重名（仍随机生成便于辨识）；uid 必须全局唯一。
      const usedUids = new Set(
        this.db.prepare("SELECT uid FROM users").all().map((row) => row.uid),
      );
      const generateBatchUid = () => {
        for (let attempt = 0; attempt < 200; attempt += 1) {
          const candidate = String(randomInt(100000, 1000000));
          if (!usedUids.has(candidate)) {
            usedUids.add(candidate);
            return candidate;
          }
        }
        throw new Error("用户 ID 生成冲突过多，请重试");
      };
      const insertStmt = this.db.prepare(`
        INSERT INTO users (
          uid, username, password_hash, port_ranges, expires_at, activated_at,
          duration_days, http_allowed, enabled, token_version, rate_limit_bps,
          traffic_limit_bytes, must_change_password, plan_id, plan_name,
          temp_password, created_at, updated_at
        ) VALUES (?, ?, ?, ?, NULL, NULL, ?, 0, 1, 1, ?, ?, 1, ?, ?, ?, ?, ?)
      `);

      for (let i = 0; i < count; i += 1) {
        const run = findContiguousRun(plan.portCount);
        if (!run) {
          throw new Error(
            `端口池仅剩 ${countFreePorts()} 个空闲端口，无法再为「${plan.name}」分配连续 ${plan.portCount} 个端口；本次操作已全部回滚`,
          );
        }
        for (let port = run.start; port <= run.end; port += 1) occupied.add(port);

        const username = `${prefix}${randomText(BATCH_USERNAME_CHARS, 6)}`;
        const uid = generateBatchUid();
        const password = randomText(BATCH_PASSWORD_CHARS, 10);
        const ranges = node === "master" ? [{ start: run.start, end: run.end }] : [{ start: run.start, end: run.end, node }];
        const now = nowISO();
        insertStmt.run(
          uid,
          username,
          hashPassword(password),
          JSON.stringify(ranges),
          plan.durationDays,
          // 0.10.2.1：批量开号按套餐限速（0=不限速）。
          plan.rateLimitBps || 0,
          plan.trafficLimitBytes,
          plan.id,
          plan.name,
          password,
          now,
          now,
        );
        created.push({
          uid,
          username,
          password,
          planName: plan.name,
          durationDays: plan.durationDays,
          expiresAt: null,
          portRangesText: formatPortRanges(ranges),
        });
      }

      this.audit(actor, "user.batch_create", `${prefix}*`, {
        count,
        planId: plan.id,
        planName: plan.name,
        uids: created.map((item) => item.uid),
        usernames: created.map((item) => item.username),
      });
      this.db.exec("COMMIT");
      return { users: created, plan: { id: plan.id, name: plan.name } };
    } catch (error) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        // 事务可能已被 SQLite 关闭。
      }
      throw error;
    }
  }

  // 0.9.2：按行导入账号（xlsx/txt 解析在路由层完成）。
  // 每行独立事务：成功提交、失败回滚并汇总到 failed（不影响其他行）。
  // rows: [{ row, uid, username, password, portRanges, planName, durationDays }]
  // reservedPorts：平台保留 + 本机 LISTENING 端口（路由探测传入），端口池自动分配时避开。
  importUsers(rows, actor, reservedPorts = []) {
    const plans = this.listPlans();
    const defaultPlan = plans[0] || null;
    const poolRanges = parsePortRanges(this.getSetting("port_pool") || "20000-30000");
    const reserved = new Set(
      (Array.isArray(reservedPorts) ? reservedPorts : [])
        .map(Number)
        .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535),
    );

    const buildOccupied = () => {
      const occupied = new Set(reserved);
      for (const row of this.db.prepare("SELECT port_ranges FROM users").all()) {
        for (const range of JSON.parse(row.port_ranges)) {
          for (let port = Number(range.start); port <= Number(range.end); port += 1) {
            occupied.add(port);
          }
        }
      }
      return occupied;
    };

    const created = [];
    const failed = [];
    const usedUids = new Set(this.db.prepare("SELECT uid FROM users").all().map((row) => row.uid));

    for (const item of rows) {
      try {
        this.db.exec("BEGIN IMMEDIATE");
        let committed = false;
        try {
          const username = normalizeUsername(item.username);

          // 套餐：显式名称精确匹配；留空用默认套餐（排序第一）。
          let plan = null;
          const planName = String(item.planName ?? "").trim();
          if (planName) {
            plan = plans.find((candidate) => candidate.name === planName);
            if (!plan) throw new Error(`套餐「${planName}」不存在`);
          } else {
            plan = defaultPlan;
            if (!plan) throw new Error("未指定套餐且系统中没有默认套餐");
          }
          // 0.9.3：导入行只确定套餐天数；账号未激活，到期时间激活时才起算。
          const daysParsed = Number.parseInt(String(item.durationDays ?? "").trim(), 10);
          const durationDays = Store.normalizeDurationDays(
            Number.isInteger(daysParsed) && daysParsed > 0 ? daysParsed : plan.durationDays,
          );

          // 端口：显式端口段直接使用（createUser.validateRanges 负责与已有用户查重）；
          // 留空则从端口池按套餐端口数分配连续段（避开保留端口/监听端口/已分配端口）。
          let rangesText = String(item.portRanges ?? "").trim();
          if (!rangesText) {
            const occupied = buildOccupied();
            let run = null;
            for (const range of poolRanges) {
              let runStart = null;
              for (let port = range.start; port <= range.end; port += 1) {
                if (!occupied.has(port)) {
                  if (runStart === null) runStart = port;
                  if (port - runStart + 1 >= plan.portCount) {
                    run = { start: runStart, end: runStart + plan.portCount - 1 };
                    break;
                  }
                } else {
                  runStart = null;
                }
              }
              if (run) break;
            }
            if (!run) {
              throw new Error(`端口池空闲端口不足，无法为套餐「${plan.name}」分配 ${plan.portCount} 个连续端口`);
            }
            rangesText = formatPortRanges([run]);
          }

          // uid：显式指定须 6 位数字且唯一；留空自动随机生成并查重。
          let uid = null;
          const uidRaw = String(item.uid ?? "").trim();
          if (uidRaw) {
            uid = Store.normalizeUid(uidRaw);
            if (usedUids.has(uid)) throw new Error("用户 ID 已存在，请更换后重试");
          } else {
            for (let attempt = 0; attempt < 200; attempt += 1) {
              const candidate = String(randomInt(100000, 1000000));
              if (!usedUids.has(candidate)) {
                uid = candidate;
                break;
              }
            }
            if (!uid) throw new Error("用户 ID 生成冲突过多，请重试");
          }

          const password = String(item.password ?? "").trim()
            ? validatePassword(item.password)
            : randomText(BATCH_PASSWORD_CHARS, 10);

          const user = this.createUser(
            {
              uid,
              username,
              password,
              portRanges: rangesText,
              durationDays,
              enabled: true,
              mustChangePassword: true,
              planId: plan.id,
              rateLimitBps: 0,
              trafficLimitBytes: plan.trafficLimitBytes,
            },
            actor,
          );
          usedUids.add(uid);
          this.db.exec("COMMIT");
          committed = true;
          created.push({
            uid: user.uid,
            username: user.username,
            password,
            planName: plan.name,
            durationDays,
            expiresAt: null,
            portRangesText: formatPortRanges(parsePortRanges(rangesText)),
          });
        } finally {
          if (!committed) {
            try {
              this.db.exec("ROLLBACK");
            } catch {
              // 事务可能已关闭。
            }
          }
        }
      } catch (error) {
        failed.push({
          row: item.row,
          username: String(item.username ?? "").trim(),
          reason: error.message,
        });
      }
    }

    // 动作名不以 import 结尾，避免旧版更新包校验正则把该字符串误判为导入语句。
    this.audit(actor, "user.import_accounts", `成功 ${created.length} / 失败 ${failed.length}`, {
      createdCount: created.length,
      failedCount: failed.length,
      uids: created.map((item) => item.uid),
    });
    return { created, failed };
  }

  // 0.9.0：隧道级限速（bps，0/空=清除）；proxy_name 为全限定代理名。
  setProxyRateLimit(userId, proxyName, bps, actor) {
    const user = this.getUserById(userId);
    if (!user) throw new Error("用户不存在");
    const name = String(proxyName ?? "").trim();
    if (!name) throw new Error("隧道名称不能为空");
    const raw = Number(bps);
    if (!Number.isFinite(raw) || raw < 0) throw new Error("限速值必须为非负数字（比特/秒，0=清除）");
    const limit = Math.floor(raw);
    if (limit > 100_000_000_000) throw new Error("限速值超出允许范围");
    if (limit === 0) {
      this.db
        .prepare("DELETE FROM proxy_rate_limits WHERE user_id = ? AND proxy_name = ?")
        .run(user.id, name);
    } else {
      const now = nowISO();
      this.db
        .prepare(`
          INSERT INTO proxy_rate_limits (user_id, proxy_name, rate_limit_bps, updated_at)
          VALUES (?, ?, ?, ?)
          ON CONFLICT(user_id, proxy_name) DO UPDATE SET
            rate_limit_bps = excluded.rate_limit_bps,
            updated_at = excluded.updated_at
        `)
        .run(user.id, name, limit, now);
    }
    this.audit(actor, "proxy.rate_limit", `${user.username}/${name}`, { rateLimitBps: limit });
    return limit;
  }

  listProxyRateLimits() {
    return this.db
      .prepare(`
        SELECT user_id, proxy_name, rate_limit_bps, updated_at
        FROM proxy_rate_limits
        ORDER BY updated_at DESC
      `)
      .all()
      .map((row) => ({
        userId: row.user_id,
        proxyName: row.proxy_name,
        rateLimitBps: Number(row.rate_limit_bps) || 0,
        updatedAt: row.updated_at,
      }));
  }

  getProxyRateLimitsByUser(userId) {
    const rows = this.db
      .prepare("SELECT proxy_name, rate_limit_bps FROM proxy_rate_limits WHERE user_id = ?")
      .all(Number(userId));
    const map = new Map();
    for (const row of rows) {
      const bps = Number(row.rate_limit_bps) || 0;
      if (bps > 0) map.set(row.proxy_name, bps);
    }
    return map;
  }

  touchSession(runId, userId, clientAddress = null) {
    if (!runId) return;
    const now = nowISO();
    this.db
      .prepare(`
        INSERT INTO frp_sessions (
          run_id, user_id, client_address, connected_at, last_seen, closed_at
        ) VALUES (?, ?, ?, ?, ?, NULL)
        ON CONFLICT(run_id) DO UPDATE SET
          user_id = excluded.user_id,
          client_address = COALESCE(excluded.client_address, frp_sessions.client_address),
          last_seen = excluded.last_seen,
          closed_at = NULL
      `)
      .run(runId, userId, clientAddress, now, now);
  }

  closeSession(runId) {
    if (!runId) return;
    const now = nowISO();
    this.db
      .prepare("UPDATE frp_sessions SET closed_at = ?, last_seen = ? WHERE run_id = ?")
      .run(now, now, runId);
    this.db
      .prepare("UPDATE frp_proxies SET closed_at = ?, updated_at = ? WHERE run_id = ?")
      .run(now, now, runId);
  }

  touchProxy(runId, userId, input) {
    if (!runId || !input.name) return;
    const now = nowISO();
    const domains = Array.isArray(input.domains)
      ? JSON.stringify(input.domains.map((item) => String(item)).filter(Boolean))
      : "[]";
    this.db
      .prepare(`
        INSERT INTO frp_proxies (
          user_id, run_id, proxy_name, proxy_type, remote_port, custom_domains,
          created_at, updated_at, closed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
        ON CONFLICT(user_id, proxy_name) DO UPDATE SET
          run_id = excluded.run_id,
          proxy_type = excluded.proxy_type,
          remote_port = excluded.remote_port,
          custom_domains = excluded.custom_domains,
          updated_at = excluded.updated_at,
          closed_at = NULL
      `)
      .run(
        Number(userId),
        String(runId),
        String(input.name),
        String(input.type),
        Number(input.remotePort) || 0,
        domains,
        now,
        now,
      );
  }

  closeProxy(runId, proxyName) {
    if (!runId || !proxyName) return;
    const now = nowISO();
    this.db
      .prepare(`
        UPDATE frp_proxies
        SET closed_at = ?, updated_at = ?
        WHERE run_id = ? AND proxy_name = ?
      `)
      .run(now, now, String(runId), String(proxyName));
  }

  closeUserActivity(userId) {
    const now = nowISO();
    this.db
      .prepare(`
        UPDATE frp_sessions
        SET closed_at = ?, last_seen = ?
        WHERE user_id = ? AND closed_at IS NULL
      `)
      .run(now, now, Number(userId));
    this.db
      .prepare(`
        UPDATE frp_proxies
        SET closed_at = ?, updated_at = ?
        WHERE user_id = ? AND closed_at IS NULL
      `)
      .run(now, now, Number(userId));
  }

  closeAllActivity() {
    const now = nowISO();
    this.db
      .prepare(`
        UPDATE frp_sessions
        SET closed_at = ?, last_seen = ?
        WHERE closed_at IS NULL
      `)
      .run(now, now);
    this.db
      .prepare(`
        UPDATE frp_proxies
        SET closed_at = ?, updated_at = ?
        WHERE closed_at IS NULL
      `)
      .run(now, now);
  }

  stats() {
    const users = this.listUsers();
    const proxies = this.listProxies();
    const ranges = users.flatMap((user) => user.portRanges);
    const allocatedPorts = ranges.reduce((sum, range) => sum + range.end - range.start + 1, 0);
    // 0.10.2.8：统计全面以集群为单位——映射数 / 在线映射含在线从节点承载的部分
    // （从节点活跃映射快照随同步上报，与本机 frp_proxies 无重叠，不重复计数）。
    let mappings = proxies.length;
    let onlineMappings = proxies.filter((proxy) => proxy.online).length;
    const onlineAfter = new Date(Date.now() - 30_000).toISOString();
    const slaveSessionUserIds = new Set(
      this.db
        .prepare("SELECT user_id FROM cluster_sessions WHERE last_seen >= ?")
        .all(onlineAfter)
        .map((row) => Number(row.user_id)),
    );
    for (const node of this.listClusterNodes()) {
      if (!node.online) continue;
      const rows = Array.isArray(node.stats?.proxies) ? node.stats.proxies : [];
      mappings += rows.length;
      onlineMappings += rows.filter((row) => row.online).length;
    }
    return {
      users: users.length,
      active: users.filter((user) => user.enabled && !user.expired).length,
      // 0.9.0：在线口径统一为 30 秒心跳租约（deviceOnline），与 overview.onlineUsers 一致。
      // 0.10.2.8：clusterOnline = 主节点客户端在线 ∪ 从节点 frpc 接入在线（并集，按用户去重）。
      online: users.filter((user) => user.deviceOnline && user.enabled && !user.expired).length,
      clusterOnline: new Set([
        ...users
          .filter((user) => user.deviceOnline && user.enabled && !user.expired)
          .map((user) => user.id),
        ...slaveSessionUserIds,
      ]).size,
      allocatedPorts,
      mappings,
      onlineMappings,
    };
  }

  listAudit(limit = 50) {
    return this.db
      .prepare("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?")
      .all(Math.min(Math.max(Number(limit) || 50, 1), 200))
      .map((row) => ({
        id: row.id,
        actor: row.actor,
        action: row.action,
        target: row.target,
        detail: row.detail ? JSON.parse(row.detail) : null,
        createdAt: row.created_at,
      }));
  }

  audit(actor, action, target = null, detail = null) {
    this.db
      .prepare(`
        INSERT INTO audit_logs (actor, action, target, detail, created_at)
        VALUES (?, ?, ?, ?, ?)
      `)
      .run(actor, action, target, detail ? JSON.stringify(detail) : null, nowISO());
  }
}
