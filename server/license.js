import { createHash, randomUUID } from "node:crypto";
import { hostname, networkInterfaces } from "node:os";
import {
  licenseKeyPreview,
  normalizeLicenseKey,
  publicKeyFingerprint,
  verifyLicenseLease,
} from "../shared/license.js";
import { versionNewer } from "../shared/core.js";
import { VERSION } from "../shared/version.js";
import { frpReleaseTarget } from "../shared/platform.js";

const TRIAL_DAYS = 30;
const ANNOUNCEMENTS_INTERVAL_MS = 5 * 60_000;
const ANNOUNCEMENTS_MAX = 20;
const ANNOUNCEMENT_LEVELS = ["info", "success", "warning", "danger"];
const HEARTBEAT_INTERVAL_MS = 5 * 60_000;

// 0.10.2.6：versionNewer 移至 shared/core.js 统一维护（逐段数值比较，相等/更低均无更新）。
// 综合"授权中心判定"与"本地版本比较"：两者都认为有更高版本时才提示更新。
function confirmedHasUpdate(data, currentVersion) {
  const latestVersion = String(data?.latestVersion || "").trim();
  return Boolean(data?.hasUpdate) && latestVersion !== "" && versionNewer(latestVersion, currentVersion);
}

// 取首个对外网卡的 MAC（用于机器指纹与授权中心身份登记）。
function primaryMacAddress() {
  for (const list of Object.values(networkInterfaces())) {
    for (const item of list || []) {
      if (item && !item.internal && item.mac && item.mac !== "00:00:00:00:00:00") {
        return item.mac;
      }
    }
  }
  return "";
}

// 机器指纹：平台 + MAC（无外置网卡时回退主机名）。
// 授权中心按该指纹记账免费试用，重装/更换 installationId 不会重置。
function machineFingerprint() {
  const seed = `${process.platform}|${primaryMacAddress() || hostname()}`;
  return createHash("sha256").update(seed).digest("hex").slice(0, 40);
}

function normalizeServerUrl(value) {
  const text = String(value || "https://key.xfhub.top").trim().replace(/\/+$/, "");
  const url = new URL(text);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("LICENSE_SERVER_URL 仅支持 http 或 https");
  }
  return url.toString().replace(/\/$/, "");
}

function normalizePublicKey(value) {
  const text = String(value || "").trim();
  if (!text) return null;
  if (text.includes("BEGIN PUBLIC KEY")) return text.replaceAll("\\n", "\n");
  try {
    const decoded = Buffer.from(text, "base64").toString("utf8").trim();
    return decoded.includes("BEGIN PUBLIC KEY") ? decoded : text;
  } catch {
    return text;
  }
}

function requestError(message, status = 503, code = "LICENSE_SERVER_ERROR") {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  return error;
}

export class LicenseManager {
  constructor({
    store,
    serverUrl,
    publicKey = "",
    intervalMs = 10 * 60_000,
    fetchImpl = fetch,
    now = () => Date.now(),
    onStatusChange = () => {},
    onMasterConflict = () => {},
  }) {
    this.store = store;
    this.serverUrl = normalizeServerUrl(serverUrl);
    this.configuredPublicKey = normalizePublicKey(publicKey);
    this.intervalMs = Math.max(60_000, Number(intervalMs) || 10 * 60_000);
    this.fetchImpl = fetchImpl;
    this.now = now;
    this.onStatusChange = onStatusChange;
    // 0.10.1.1 规格10-12：主节点高可用仲裁——心跳认领冲突（更新鲜的主存在）时回调降级。
    this.onMasterConflict = onMasterConflict;
    this.timer = null;
    this.localTimer = null;
    this.refreshing = null;
    this.installationId = store.getOrCreateSetting(
      "license_installation_id",
      () => randomUUID(),
    );
    this.fingerprint = machineFingerprint();
    this.blockedReason = store.getSetting("license_blocked_reason") || "";
    this.trialStartedAt = store.getOrCreateSetting(
      "license_trial_started_at",
      () => new Date(this.now()).toISOString(),
    );
    this.state = this.evaluateLocal();
    this.announcements = [];
    this.announcementsSyncedAt = null;
    this.announcementsError = null;
    this.announcementsTimer = null;
    this.purchaseUrl = "";
    this.updateInfo = null;
    this.updateTimer = null;
    this.clientUpdateInfo = null;
    this.clientUpdateTimer = null;
    this.heartbeatInfo = null;
    this.heartbeatTimer = null;
    // 0.10.2.9：心跳失败自愈——启动竞态（服务端先于授权中心就绪）下按退避重试，避免等满 5 分钟。
    this.heartbeatRetryTimer = null;
    this.heartbeatRetryDelay = 0;
    // 0.10.1.1 规格10-12：主节点认领标记（心跳携带 isMaster；从节点升主后置 true）。
    this.announceMaster = false;
  }

  storedPublicKey() {
    return this.configuredPublicKey || this.store.getSetting("license_public_key");
  }

  evaluateLocal(error = null) {
    const now = this.now();
    const licenseKey = this.store.getSetting("license_key");

    // 授权中心封禁优先：命中 IP/IP+MAC 封禁后拒绝服务，直到解除封禁。
    if (this.blockedReason) {
      return {
        valid: false,
        mode: "blocked",
        installationId: this.installationId,
        fingerprint: this.fingerprint,
        trialStartedAt: this.trialStartedAt,
        expiresAt: null,
        leaseExpiresAt: null,
        customer: "",
        plan: "",
        keyPreview: licenseKey ? licenseKeyPreview(licenseKey) : null,
        lastCheckedAt: this.store.getSetting("license_last_checked_at"),
        online: false,
        error: this.blockedReason,
      };
    }

    const lease = this.store.getSetting("license_lease");
    const publicKey = this.storedPublicKey();
    if (licenseKey && lease && publicKey) {
      try {
        const payload = verifyLicenseLease(lease, publicKey, {
          installationId: this.installationId,
          now,
        });
        return {
          valid: true,
          mode: "licensed",
          installationId: this.installationId,
          trialStartedAt: this.trialStartedAt,
          expiresAt: payload.licenseExpiresAt,
          leaseExpiresAt: new Date(payload.exp * 1000).toISOString(),
          customer: payload.customer || "",
          plan: payload.plan || "commercial",
          keyPreview: licenseKeyPreview(licenseKey),
          lastCheckedAt: this.store.getSetting("license_last_checked_at"),
          online: !error,
          error: error?.message || null,
        };
      } catch (verifyError) {
        error = error || verifyError;
      }
    }

    if (licenseKey) {
      return {
        valid: false,
        mode: "invalid",
        installationId: this.installationId,
        trialStartedAt: this.trialStartedAt,
        expiresAt: null,
        leaseExpiresAt: null,
        customer: "",
        plan: "",
        keyPreview: licenseKeyPreview(licenseKey),
        lastCheckedAt: this.store.getSetting("license_last_checked_at"),
        online: false,
        error: error?.message || "许可密钥尚未完成在线验证",
      };
    }

    // 0.10.0.1：免费额度——单集群 1 台服务端（主节点）永久免费，无需密钥、不再到期降级。
    return {
      valid: true,
      mode: "free",
      installationId: this.installationId,
      trialStartedAt: this.trialStartedAt,
      expiresAt: null,
      leaseExpiresAt: null,
      customer: "",
      plan: "free",
      keyPreview: null,
      lastCheckedAt: null,
      online: false,
      error: null,
    };
  }

  status() {
    const current =
      this.state?.mode === "invalid" || this.state?.mode === "blocked"
        ? this.state
        : this.evaluateLocal(
            this.state?.mode === "licensed" && this.state.error
              ? new Error(this.state.error)
              : null,
          );
    return {
      ...current,
      remainingSeconds: current.expiresAt
        ? Math.max(0, Math.floor((Date.parse(current.expiresAt) - this.now()) / 1000))
        : 0,
      purchaseUrl: this.purchaseUrl || "",
      publicKeyFingerprint: this.storedPublicKey()
        ? publicKeyFingerprint(this.storedPublicKey())
        : null,
      trialDays: TRIAL_DAYS,
      heartbeat: this.heartbeatInfo ? { ...this.heartbeatInfo } : null,
    };
  }

  isAllowed() {
    return this.status().valid;
  }

  assertAllowed() {
    const status = this.status();
    if (status.valid) return status;
    throw requestError(
      status.error || "服务端许可无效，请联系管理员",
      402,
      "SERVER_LICENSE_REQUIRED",
    );
  }

  setState(next) {
    const previous = this.state;
    this.state = next;
    if (
      !previous ||
      previous.valid !== next.valid ||
      previous.mode !== next.mode ||
      previous.expiresAt !== next.expiresAt
    ) {
      this.onStatusChange(next, previous);
    }
    return this.status();
  }

  async request(path, body = null) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10_000);
    try {
      const response = await this.fetchImpl(`${this.serverUrl}${path}`, {
        method: body ? "POST" : "GET",
        signal: controller.signal,
        headers: body ? { "Content-Type": "application/json" } : {},
        body: body ? JSON.stringify(body) : undefined,
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw requestError(
          data.error || `授权中心返回 ${response.status}`,
          response.status,
          data.code || "LICENSE_REJECTED",
        );
      }
      return data;
    } catch (error) {
      if (error.name === "AbortError") {
        throw requestError("连接授权中心超时");
      }
      if (error.code) throw error;
      throw requestError(`无法连接授权中心：${error.message}`);
    } finally {
      clearTimeout(timeout);
    }
  }

  async trustedPublicKey() {
    const existing = this.storedPublicKey();
    if (existing) return existing;
    const data = await this.request("/api/public-key");
    const publicKey = normalizePublicKey(data.publicKey);
    if (!publicKey) throw requestError("授权中心未提供有效公钥");
    this.store.setSetting("license_public_key", publicKey);
    return publicKey;
  }

  persistLease(key, lease, payload) {
    const checkedAt = new Date(this.now()).toISOString();
    this.store.setSetting("license_key", key);
    this.store.setSetting("license_lease", lease);
    this.store.setSetting("license_last_checked_at", checkedAt);
    return this.setState({
      valid: true,
      mode: "licensed",
      installationId: this.installationId,
      trialStartedAt: this.trialStartedAt,
      expiresAt: payload.licenseExpiresAt,
      leaseExpiresAt: new Date(payload.exp * 1000).toISOString(),
      customer: payload.customer || "",
      plan: payload.plan || "commercial",
      keyPreview: licenseKeyPreview(key),
      lastCheckedAt: checkedAt,
      online: true,
      error: null,
    });
  }

  async activate(value) {
    const key = normalizeLicenseKey(value);
    const publicKey = await this.trustedPublicKey();
    const data = await this.request("/api/v1/licenses/activate", {
      licenseKey: key,
      installationId: this.installationId,
    });
    const payload = verifyLicenseLease(data.lease, publicKey, {
      installationId: this.installationId,
      now: this.now(),
    });
    const result = this.persistLease(key, data.lease, payload);
    // 0.10.2.9：激活成功立即上报心跳——授权中心即时登记节点（source=auto），
    // 避免「公开信息推送」等依赖心跳登记的操作在激活后仍报「尚未登记」。
    await this.reportHeartbeat().catch(() => {});
    return result;
  }

  async refresh() {
    if (this.refreshing) return this.refreshing;
    this.refreshing = this.refreshInternal().finally(() => {
      this.refreshing = null;
    });
    return this.refreshing;
  }

  async refreshInternal() {
    const key = this.store.getSetting("license_key");
    if (!key) return this.setState(this.evaluateLocal());
    try {
      const publicKey = await this.trustedPublicKey();
      const data = await this.request("/api/v1/licenses/validate", {
        licenseKey: key,
        installationId: this.installationId,
      });
      const payload = verifyLicenseLease(data.lease, publicKey, {
        installationId: this.installationId,
        now: this.now(),
      });
      return this.persistLease(key, data.lease, payload);
    } catch (error) {
      if (
        ["LICENSE_REVOKED", "LICENSE_EXPIRED", "LICENSE_NOT_FOUND", "LICENSE_BOUND"].includes(
          error.code,
        )
      ) {
        this.store.deleteSetting("license_lease");
      }
      return this.setState(this.evaluateLocal(error));
    }
  }

  remove() {
    this.store.deleteSetting("license_key");
    this.store.deleteSetting("license_lease");
    this.store.deleteSetting("license_last_checked_at");
    return this.setState(this.evaluateLocal());
  }

  // 心跳上报的身份信息：授权中心据此记录部署节点并按机器指纹记账试用。
  machineSnapshot() {
    return {
      installationId: this.installationId,
      fingerprint: this.fingerprint,
      hostname: hostname(),
      mac: primaryMacAddress(),
      platform: process.platform,
      arch: process.arch,
      version: VERSION,
      mode: this.state?.mode || "free",
      licensePreview: this.state?.keyPreview || "",
    };
  }

  // 0.10.0.1：集群从节点快照（主节点注册表），随心跳上报给授权中心集群视图。
  // 0.10.0.2：携带节点位置（客户端登录页集群主机行展示）。
  clusterNodesSnapshot() {
    try {
      return (this.store.listClusterNodes() || []).map((node) => ({
        name: String(node.name || "").slice(0, 40),
        host: String(node.host || "").slice(0, 80),
        location: String(node.location || "").slice(0, 64),
        clientApiPort: Number(node.clientApiPort) || 9400,
        online: Boolean(node.online),
        version: String(node.version || "").slice(0, 32),
        lastSyncAt: String(node.lastSyncAt || "").slice(0, 40),
      }));
    } catch {
      return [];
    }
  }

  async reportHeartbeat() {
    let data;
    try {
      data = await this.request("/api/v1/servers/heartbeat", {
        ...this.machineSnapshot(),
        // 0.10.0.1：心跳携带集群名称与从节点列表，授权中心可查看每个集群的节点构成。
        clusterName: String(this.store.getSetting("cluster_name") || "").trim().slice(0, 60),
        clusterNodes: this.clusterNodesSnapshot(),
        // 0.10.1.1 规格10-12：主节点身份认领——授权中心记录集群当前主节点（供客户端拉取新主 IP）。
        isMaster: Boolean(this.announceMaster),
      });
    } catch (error) {
      this.heartbeatInfo = {
        ...(this.heartbeatInfo || {}),
        blocked: Boolean(this.blockedReason),
        error: error.message,
        syncedAt: this.heartbeatInfo?.syncedAt || null,
      };
      this.scheduleHeartbeatRetry();
      return this.heartbeatInfo;
    }
    // 心跳成功：取消待执行的重试并恢复常规节奏。
    if (this.heartbeatRetryTimer) {
      clearTimeout(this.heartbeatRetryTimer);
      this.heartbeatRetryTimer = null;
    }
    this.heartbeatRetryDelay = 0;

    // 0.10.1.1 规格10-12：认领冲突——授权中心存在更新鲜的其他主节点认领（旧主回归场景），
    // 回调宿主自动降级为从节点并跟随新主。
    if (data.masterConflict && data.masterAddress) {
      try {
        this.onMasterConflict(String(data.masterAddress));
      } catch (error) {
        console.error(`[license] master conflict handler failed: ${error.message}`);
      }
    }

    // 0.10.2.0 集群 id 登录：落库授权中心分配的集群短 id（集群管理页展示，客户端可凭 id 登录）。
    if (data.clusterId) {
      const clusterId = String(data.clusterId).slice(0, 16);
      if (clusterId !== this.store.getSetting("cluster_id")) {
        this.store.setSetting("cluster_id", clusterId);
      }
    }

    if (data.blocked) {
      const reason = String(data.reason || "该服务端已被授权中心封禁").slice(0, 300);
      if (reason !== this.blockedReason) {
        this.blockedReason = reason;
        this.store.setSetting("license_blocked_reason", reason);
        this.setState(this.evaluateLocal());
      }
    } else if (this.blockedReason) {
      // 封禁已解除，恢复正常评估。
      this.blockedReason = "";
      this.store.deleteSetting("license_blocked_reason");
      this.setState(this.evaluateLocal());
    }

    // 试用模式下以授权中心按指纹记账的试用起点为准，重装不会重置。
    if (!this.store.getSetting("license_key") && data.trialStartedAt) {
      const centerStart = String(data.trialStartedAt);
      if (centerStart !== this.trialStartedAt) {
        this.trialStartedAt = centerStart;
        this.store.setSetting("license_trial_started_at", centerStart);
        this.setState(this.evaluateLocal());
      }
    }

    // 授权中心在心跳响应中下发该服务端当前应显示的版权声明（全局默认或已授权自定义）。
    if (data.copyright && typeof data.copyright === "object") {
      this.store.setSetting(
        "copyright_info",
        JSON.stringify({
          text: String(data.copyright.text || "").slice(0, 200),
          url: String(data.copyright.url || "").slice(0, 300),
          source: data.copyright.source === "custom" ? "custom" : "default",
          status: String(data.copyright.status || "none"),
          rejectReason: String(data.copyright.rejectReason || "").slice(0, 500),
          syncedAt: new Date(this.now()).toISOString(),
        }),
      );
    }

    this.heartbeatInfo = {
      blocked: Boolean(data.blocked),
      trialStartedAt: data.trialStartedAt || null,
      trialExpiresAt: data.trialExpiresAt || null,
      remainingSeconds: Number(data.remainingSeconds) || 0,
      syncedAt: new Date(this.now()).toISOString(),
      error: null,
    };
    return this.heartbeatInfo;
  }

  // 0.10.2.9：心跳失败后退避重试（15s → 30s → … → 封顶 5 分钟），成功后由 reportHeartbeat 复位。
  scheduleHeartbeatRetry() {
    if (this.heartbeatRetryTimer) return;
    this.heartbeatRetryDelay = Math.min(
      this.heartbeatRetryDelay ? this.heartbeatRetryDelay * 2 : 15_000,
      HEARTBEAT_INTERVAL_MS,
    );
    this.heartbeatRetryTimer = setTimeout(() => {
      this.heartbeatRetryTimer = null;
      this.reportHeartbeat().catch(() => {});
    }, this.heartbeatRetryDelay);
    this.heartbeatRetryTimer.unref?.();
  }

  // 当前生效版权快照（由授权中心下发，服务端/客户端统一展示）。
  copyrightSnapshot() {
    const raw = this.store.getSetting("copyright_info");
    if (!raw) {
      return { text: "", url: "", source: "default", status: "none", rejectReason: "", syncedAt: null };
    }
    try {
      const parsed = JSON.parse(raw);
      return {
        text: String(parsed.text || ""),
        url: String(parsed.url || ""),
        source: parsed.source === "custom" ? "custom" : "default",
        status: String(parsed.status || "none"),
        rejectReason: String(parsed.rejectReason || "").slice(0, 500),
        syncedAt: parsed.syncedAt || null,
      };
    } catch {
      return { text: "", url: "", source: "default", status: "none", rejectReason: "", syncedAt: null };
    }
  }

  // 主动拉取版权（申请提交后可立即刷新）。携带指纹以便重装后仍能匹配授权。
  async syncCopyright() {
    const qs = new URLSearchParams({
      installationId: this.installationId,
      fingerprint: this.fingerprint || "",
    });
    const data = await this.request(`/api/v1/copyright?${qs.toString()}`);
    if (data.copyright && typeof data.copyright === "object") {
      this.store.setSetting(
        "copyright_info",
        JSON.stringify({
          text: String(data.copyright.text || "").slice(0, 200),
          url: String(data.copyright.url || "").slice(0, 300),
          source: data.copyright.source === "custom" ? "custom" : "default",
          status: String(data.copyright.status || "none"),
          rejectReason: String(data.copyright.rejectReason || "").slice(0, 500),
          syncedAt: new Date(this.now()).toISOString(),
        }),
      );
    }
    return this.copyrightSnapshot();
  }

  // 向授权中心申请自定义版权：携带理由与服务端身份信息。
  async applyCopyright({ text, url, reason }) {
    const body = {
      ...this.machineSnapshot(),
      ip: "",
      text: String(text || "").trim(),
      url: String(url || "").trim(),
      reason: String(reason || "").trim(),
    };
    const data = await this.request("/api/v1/copyright/apply", body);
    await this.syncCopyright().catch(() => {});
    return data;
  }

  // ---------- 0.9.9：公开服务端信息（推送到授权中心，客户端登录页「服务器列表」展示） ----------
  // 0.10.0：扩展集群字段——clusterName/clusterNodes 由主节点自动采集推送。
  normalizePublicInfo(info) {
    if (!info || typeof info !== "object") return null;
    let clusterNodes = [];
    if (Array.isArray(info.clusterNodes)) {
      clusterNodes = info.clusterNodes
        .slice(0, 50)
        .map((node) => ({
          name: String(node?.name || "").slice(0, 40),
          host: String(node?.host || "").slice(0, 80),
          clientApiPort: Number(node?.clientApiPort) || 9400,
          bindPort: Number(node?.bindPort) || 0,
          online: Boolean(node?.online),
          version: String(node?.version || "").slice(0, 32),
        }))
        .filter((node) => node.name && node.host);
    }
    return {
      ip: String(info.ip || ""),
      hostname: String(info.hostname || ""),
      location: String(info.location || ""),
      promo: String(info.promo || ""),
      hidden: Boolean(info.hidden),
      online: Boolean(info.online),
      licensed: Boolean(info.licensed),
      clusterName: String(info.clusterName || "").slice(0, 60),
      clusterNodes,
    };
  }

  // 读取本服务端在授权中心登记的公开信息（IP/名称来自心跳登记）。
  async fetchPublicInfo() {
    const data = await this.request(
      `/api/v1/servers/public-info?installationId=${encodeURIComponent(
        this.installationId,
      )}&fingerprint=${encodeURIComponent(this.fingerprint || "")}`,
    );
    return this.normalizePublicInfo(data.info);
  }

  // 推送公开信息：位置/优惠文案/是否隐藏 + 0.10.0 集群名称与节点列表，字段与客户端登录页展示一致。
  async publishPublicInfo({ location, promo, hidden, clusterName, clusterNodes }) {
    const data = await this.request("/api/v1/servers/public-info", {
      ...this.machineSnapshot(),
      ip: "",
      location: String(location || "").trim(),
      promo: String(promo || "").trim(),
      hidden: Boolean(hidden),
      clusterName: String(clusterName || "").trim(),
      clusterNodes: Array.isArray(clusterNodes) ? clusterNodes : [],
    });
    return this.normalizePublicInfo(data.info);
  }

  normalizeAnnouncements(list) {
    if (!Array.isArray(list)) return [];
    return list.slice(0, ANNOUNCEMENTS_MAX).map((item) => ({
      id: Number(item?.id) || 0,
      title: String(item?.title || "").slice(0, 200),
      body: String(item?.body || "").slice(0, 8000),
      level: ANNOUNCEMENT_LEVELS.includes(item?.level) ? item.level : "info",
      updatedAt: String(item?.updatedAt || ""),
    }));
  }

  announcementsSnapshot() {
    return {
      announcements: this.announcements,
      syncedAt: this.announcementsSyncedAt,
      error: this.announcementsError,
    };
  }

  async syncAnnouncements() {
    try {
      const data = await this.request("/api/v1/announcements");
      this.announcements = this.normalizeAnnouncements(data.announcements);
      this.announcementsSyncedAt = new Date(this.now()).toISOString();
      this.announcementsError = null;
      this.purchaseUrl = String(data.purchaseUrl || "").slice(0, 500);
    } catch (error) {
      this.announcementsError = error.message;
    }
    return this.announcementsSnapshot();
  }

  async checkUpdates() {
    try {
      const data = await this.request(
        `/api/v1/updates/latest?role=server&version=${encodeURIComponent(VERSION)}`,
      );
      this.updateInfo = {
        hasUpdate: confirmedHasUpdate(data, VERSION),
        latestVersion: String(data.latestVersion || "").slice(0, 32),
        currentVersion: VERSION,
        downloadUrl: data.downloadUrl
          ? `${this.serverUrl}${String(data.downloadUrl).slice(0, 500)}`
          : "",
        changelog: String(data.changelog || "").slice(0, 8000),
        publishedAt: String(data.publishedAt || "").slice(0, 40),
        urgency: String(data.urgency || "normal").slice(0, 16),
        checkedAt: new Date(this.now()).toISOString(),
      };
    } catch (error) {
      this.updateInfo = {
        hasUpdate: false,
        latestVersion: "",
        currentVersion: VERSION,
        checkedAt: new Date(this.now()).toISOString(),
        error: error.message,
      };
    }
    return this.updateInfoSnapshot();
  }

  async checkClientUpdates() {
    const clientVersion = this.lastClientVersion || VERSION;
    try {
      const data = await this.request(
        `/api/v1/updates/latest?role=client&version=${encodeURIComponent(clientVersion)}`,
      );
      this.clientUpdateInfo = {
        hasUpdate: confirmedHasUpdate(data, clientVersion),
        latestVersion: String(data.latestVersion || "").slice(0, 32),
        currentVersion: clientVersion,
        downloadUrl: data.downloadUrl
          ? `${this.serverUrl}${String(data.downloadUrl).slice(0, 500)}`
          : "",
        changelog: String(data.changelog || "").slice(0, 8000),
        publishedAt: String(data.publishedAt || "").slice(0, 40),
        urgency: String(data.urgency || "normal").slice(0, 16),
        checkedAt: new Date(this.now()).toISOString(),
      };
    } catch (error) {
      this.clientUpdateInfo = {
        hasUpdate: false,
        latestVersion: "",
        currentVersion: clientVersion,
        checkedAt: new Date(this.now()).toISOString(),
        error: error.message,
      };
    }
    return this.clientUpdateSnapshot();
  }

  recordClientVersion(version) {
    const v = String(version || "").trim().slice(0, 32);
    if (!/^\d+\.\d+\.\d+/.test(v) || v === this.lastClientVersion) return;
    this.lastClientVersion = v;
    this.checkClientUpdates().catch(() => {});
  }

  updateInfoSnapshot() {
    return this.updateInfo
      ? { ...this.updateInfo }
      : { hasUpdate: false, currentVersion: VERSION, checkedAt: null };
  }

  clientUpdateSnapshot() {
    return this.clientUpdateInfo
      ? { ...this.clientUpdateInfo }
      : { hasUpdate: false, currentVersion: VERSION, checkedAt: null };
  }

  /**
   * 从授权中心下载指定组件（frps/frpc）的最新二进制。
   * 返回 { version, buffer, checksum, filename, platform, arch }。
   */
  async fetchFrpBinary(component) {
    const target = frpReleaseTarget();
    return this.fetchFrpBinaryFor(component, target.platform, target.architecture);
  }

  async fetchFrpBinaryFor(component, platform, arch) {
    const info = await this.request(
      `/api/v1/frp/latest?component=${encodeURIComponent(component)}&platform=${encodeURIComponent(platform)}&arch=${encodeURIComponent(arch)}`,
    );
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 120_000);
    try {
      const response = await this.fetchImpl(`${this.serverUrl}${info.downloadUrl}`, {
        signal: controller.signal,
      });
      if (!response.ok) {
        throw requestError(`下载 FRP 二进制失败: HTTP ${response.status}`, response.status);
      }
      const buffer = Buffer.from(await response.arrayBuffer());
      const checksum = response.headers.get("x-content-sha256") || "";
      return {
        version: info.version,
        buffer,
        checksum,
        filename: info.filename,
        platform,
        arch,
      };
    } catch (error) {
      if (error.name === "AbortError") {
        throw requestError("下载 FRP 二进制超时", 504, "FRP_DOWNLOAD_TIMEOUT");
      }
      throw error;
    } finally {
      clearTimeout(timeout);
    }
  }

  async start() {
    await this.refresh();
    await this.syncAnnouncements();
    await this.checkUpdates();
    await this.checkClientUpdates();
    await this.reportHeartbeat().catch(() => {});
    this.timer = setInterval(() => this.refresh(), this.intervalMs);
    this.timer.unref?.();
    this.localTimer = setInterval(() => {
      const error = this.state?.error ? new Error(this.state.error) : null;
      this.setState(this.evaluateLocal(error));
    }, 60_000);
    this.localTimer.unref?.();
    this.announcementsTimer = setInterval(() => {
      this.syncAnnouncements().catch(() => {});
    }, ANNOUNCEMENTS_INTERVAL_MS);
    this.announcementsTimer.unref?.();
    this.updateTimer = setInterval(() => this.checkUpdates().catch(() => {}), 10 * 60_000);
    this.updateTimer.unref?.();
    this.clientUpdateTimer = setInterval(() => this.checkClientUpdates().catch(() => {}), 10 * 60_000);
    this.clientUpdateTimer.unref?.();
    this.heartbeatTimer = setInterval(() => this.reportHeartbeat().catch(() => {}), HEARTBEAT_INTERVAL_MS);
    this.heartbeatTimer.unref?.();
    return this.status();
  }

  stop() {
    clearInterval(this.timer);
    clearInterval(this.localTimer);
    clearInterval(this.announcementsTimer);
    clearInterval(this.updateTimer);
    clearInterval(this.clientUpdateTimer);
    clearInterval(this.heartbeatTimer);
    if (this.heartbeatRetryTimer) {
      clearTimeout(this.heartbeatRetryTimer);
      this.heartbeatRetryTimer = null;
    }
    this.heartbeatRetryDelay = 0;
    this.timer = null;
    this.localTimer = null;
    this.announcementsTimer = null;
    this.updateTimer = null;
    this.clientUpdateTimer = null;
    this.heartbeatTimer = null;
  }
}
