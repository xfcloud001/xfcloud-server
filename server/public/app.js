const state = {
  users: [],
  proxies: [],
  overview: null,
  plans: [],
  plansLoaded: false,
  planCodes: [],
  planCodesLoaded: false,
  portPool: "",
  batchResult: [],
  clusterPools: [],
  userRangesByNode: {},
  activeView: "overview",
  mappingFilter: "all",
  mappingNode: "all",
  clusterProxies: [],
  settingsTab: "branding",
  refreshing: false,
  mappingRefreshMs: 10_000,
  mappingTimer: null,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

/**
 * 安全写入 DOM 属性：选择器找不到元素时不抛错。
 * 用于避免 UI 重构后"Cannot set properties of null (setting 'xxx')"类崩溃。
 */
function setProp(selector, property, value) {
  const el = $(selector);
  if (el == null) return;
  el[property] = value;
}
/** 安全读取 DOM 属性，找不到返回 undefined。 */
function getProp(selector, property) {
  const el = $(selector);
  return el == null ? undefined : el[property];
}

function icons() {
  window.lucide?.createIcons();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.error || `请求失败 (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return data;
}

function toast(message, error = false) {
  const element = document.createElement("div");
  element.className = `toast${error ? " error" : ""}`;
  element.textContent = message;
  const stack = $("#toastStack");
  if (stack) stack.append(element);
  setTimeout(() => element.remove(), 3_200);
}

function formatDate(value, fallback = "-") {
  if (!value) return fallback;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return fallback;
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  }).format(date);
}

function formatRelative(value) {
  if (!value) return "-";
  const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(value)) / 1000));
  if (seconds < 10) return "刚刚";
  if (seconds < 60) return `${seconds} 秒前`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  return formatDate(value);
}

function formatRemaining(seconds) {
  const total = Math.max(0, Number(seconds) || 0);
  const days = Math.floor(total / 86_400);
  const hours = Math.floor((total % 86_400) / 3_600);
  return days > 0 ? `${days} 天 ${hours} 小时` : `${hours} 小时`;
}

function formatBytes(value) {
  const bytes = Math.max(0, Number(value) || 0);
  const units = ["B", "KB", "MB", "GB", "TB"];
  let amount = bytes;
  let unitIndex = 0;
  while (amount >= 1024 && unitIndex < units.length - 1) {
    amount /= 1024;
    unitIndex += 1;
  }
  const digits = unitIndex === 0 || amount >= 100 ? 0 : amount >= 10 ? 1 : 2;
  return `${amount.toFixed(digits)} ${units[unitIndex]}`;
}

function trafficMarkup(traffic) {
  if (!traffic?.available) {
    const label = traffic?.error ? "采集异常" : "等待采样";
    return `<span class="traffic-unavailable">${label}</span>`;
  }
  if (!traffic.hasMetrics) {
    return '<span class="traffic-unavailable" title="frps 尚未结算该映射的连接流量">暂无已结算流量</span>';
  }
  const title = `累计入站 ${formatBytes(traffic.incomingBytes)}，累计出站 ${formatBytes(
    traffic.outgoingBytes,
  )}`;
  return `
    <div class="traffic-rates" title="${escapeHtml(title)}">
      <span class="traffic-rate incoming">
        <span>入站</span>
        <strong>${escapeHtml(formatBytes(traffic.incomingBytesPerSecond))}/s</strong>
      </span>
      <span class="traffic-rate outgoing">
        <span>出站</span>
        <strong>${escapeHtml(formatBytes(traffic.outgoingBytesPerSecond))}/s</strong>
      </span>
    </div>
  `;
}

function toLocalInput(value) {
  const date = value ? new Date(value) : new Date(Date.now() + 30 * 24 * 60 * 60_000);
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

function userStatus(user) {
  if (!user.enabled) return { label: "已停用", className: "danger" };
  // 0.9.3：未完成首次登录/改密的账号处于未激活状态（套餐时长尚未起算）。
  if (!user.activated) return { label: "未激活", className: "info" };
  if (user.expired) return { label: "已到期", className: "warning" };
  // 在线口径与总览一致：30 秒心跳租约（deviceOnline）。
  if (user.deviceOnline) return { label: "在线", className: "success" };
  return { label: "离线", className: "" };
}

function processStatus(status) {
  const map = {
    running: ["运行中", "success"],
    starting: ["启动中", "info"],
    missing: ["缺少程序", "warning"],
    "license-required": ["许可受限", "danger"],
    error: ["异常", "danger"],
    stopped: ["已停止", ""],
  };
  return map[status] || ["未知", ""];
}

const announceLevels = {
  info: ["通知", "info"],
  success: ["正常", "success"],
  warning: ["警告", "warning"],
  danger: ["紧急", "danger"],
};

function renderAnnouncements(data) {
  const container = $("#announceList");
  const meta = $("#announceMeta");
  const snapshot = data.announcements || {};
  const list = snapshot.announcements || [];
  if (!list.length) {
    container.innerHTML = `<p class="announce-empty">${
      snapshot.error
        ? `暂无公告：${escapeHtml(snapshot.error)}`
        : "暂无公告，授权中心发布后将自动显示。"
    }</p>`;
  } else {
    container.innerHTML = list
      .map((item) => {
        const [label, className] = announceLevels[item.level] || ["通知", "info"];
        return `
          <article class="announce-item">
            <header>
              <span class="badge ${className}">${label}</span>
              <strong>${escapeHtml(item.title)}</strong>
              <time>${escapeHtml(formatDate(item.updatedAt))}</time>
            </header>
            ${item.body ? `<p>${escapeHtml(item.body)}</p>` : ""}
          </article>
        `;
      })
      .join("");
  }
  const parts = [];
  if (snapshot.syncedAt) parts.push(`同步于 ${formatDate(snapshot.syncedAt)}`);
  if (snapshot.error) parts.push(`同步失败：${snapshot.error}`);
  meta.textContent = list.length
    ? `${list.length} 条公告 · ${parts.join(" · ")}`
    : parts.join(" · ");
}

function showLogin() {
  $("#loginView")?.classList.remove("hidden");
  $("#appView")?.classList.add("hidden");
}

function showApp() {
  $("#loginView")?.classList.add("hidden");
  $("#appView")?.classList.remove("hidden");
}

// 0.10.2.8：集群用户——原「在线用户」与「从节点登录用户」两面板合并为一个以集群为单位的
// 用户列表：主节点客户端在线 ∪ 从节点 frpc 接入在线，按用户去重（nodes 为登录节点列表）。
function renderClusterUsers(clusterUsers) {
  const rows = $("#clusterUsersRows");
  if (!rows) return;
  const list = Array.isArray(clusterUsers) ? clusterUsers : [];
  setProp("#clusterUsersCount", "textContent", `${list.length} 人在线`);
  const empty = $("#clusterUsersEmpty");
  if (empty) empty.classList.toggle("hidden", list.length !== 0);
  rows.innerHTML = list
    .map(
      (u) => `
      <tr>
        <td>
          <div class="user-cell compact">
            <span class="avatar">${escapeHtml(String(u.username).slice(0, 2))}</span>
            <strong>${escapeHtml(u.username)}</strong>
          </div>
        </td>
        <td class="mono">${escapeHtml(u.uid != null ? String(u.uid) : "-")}</td>
        <td>${(u.nodes || [])
          .map(
            (node) =>
              `<span class="badge ${node === "master" ? "master" : ""}">${escapeHtml(node === "master" ? "主节点" : node)}</span>`,
          )
          .join(" ")}</td>
        <td class="mono">${escapeHtml(u.deviceAddress || "-")}</td>
        <td title="${escapeHtml(formatDate(u.lastSeen))}">${escapeHtml(formatRelative(u.lastSeen))}</td>
        <td><span class="badge ${u.onlineMappingCount > 0 ? "success" : ""}">${u.onlineMappingCount || 0}</span></td>
        <td class="mono">${escapeHtml(u.clientVersion || "-")}</td>
        <td title="${escapeHtml(formatDate(u.expiresAt))}">${escapeHtml(formatRelative(u.expiresAt))}</td>
      </tr>
    `,
    )
    .join("");
  icons();
}

// 0.10.2.8：服务端运行提醒列表 + 侧边栏未读徽标（数据来自 /api/admin/overview 的 messages 快照）。
function renderServerMessages(snapshot) {
  const list = Array.isArray(snapshot?.list) ? snapshot.list : [];
  const unread = Number(snapshot?.unread) || 0;
  const badge = $("#serverMessagesBadge");
  if (badge) {
    badge.textContent = unread > 99 ? "99+" : String(unread);
    badge.classList.toggle("hidden", unread === 0);
  }
  setProp("#serverMessageMeta", "textContent", list.length ? `${list.length} 条` : "");
  const wrap = $("#serverMessageList");
  if (wrap) {
    wrap.innerHTML = list.length
      ? list
          .map(
            (item) => `
          <article class="message-item ${item.level === "warn" ? "warn" : "error"}">
            <div class="message-item-head">
              <span class="message-level">${escapeHtml(item.level === "warn" ? "警告" : "错误")}</span>
              <time class="mono">${escapeHtml(formatDate(item.createdAt))}</time>
            </div>
            <p>${escapeHtml(item.text)}</p>
          </article>`,
          )
          .join("")
      : '<p class="empty">暂无运行提醒</p>';
  }
}

// 0.10.2.8：公告管理列表（发布/删除入口在消息中心页）。
function renderAnnouncementManage(announcements) {
  const wrap = $("#announcementManageList");
  if (!wrap) return;
  const list = Array.isArray(announcements) ? announcements : [];
  wrap.innerHTML = list.length
    ? list
        .map(
          (item) => `
        <article class="message-item ${item.level === "warn" ? "warn" : "info"}">
          <div class="message-item-head">
            <span class="message-level">${escapeHtml(item.level === "warn" ? "重要" : "公告")} · ${escapeHtml(formatDate(item.createdAt))}</span>
            <button
              class="button ghost icon-only"
              type="button"
              data-announcement-delete="${Number(item.id)}"
              title="删除公告"
              aria-label="删除公告"
            >
              <i data-lucide="trash-2" class="icon"></i>
            </button>
          </div>
          <h3>${escapeHtml(item.title)}</h3>
          <p>${escapeHtml(item.content)}</p>
        </article>`,
        )
        .join("")
    : '<p class="empty">暂无公告</p>';
  icons();
}

async function loadAnnouncements() {
  try {
    const data = await api("/api/admin/announcements");
    renderAnnouncementManage(data.announcements);
  } catch (error) {
    if (error.status === 401) {
      showLogin();
      return;
    }
    toast(error.message, true);
  }
}

async function markServerMessagesRead() {
  try {
    const data = await api("/api/admin/messages/read", { method: "POST" });
    renderServerMessages(data.messages);
  } catch (error) {
    if (error.status === 401) showLogin();
  }
}

// 0.10.1.2 规格8：节点流量统计——默认合计（主节点+从节点求和），点击展开各节点明细。
function renderNodeTraffic(cluster) {
  const summary = $("#nodeTrafficSummary");
  if (!summary) return;
  const nodes = [];
  if (cluster?.master) {
    nodes.push({
      name: cluster.master.label || "主节点",
      role: '<span class="badge master">主节点</span>',
      host: cluster.master.host || "-",
      status: '<span class="badge success">在线</span>',
      traffic: cluster.master.traffic || {},
    });
  }
  for (const node of cluster?.nodes || []) {
    nodes.push({
      name: node.label || node.name,
      role: '<span class="badge">从节点</span>',
      host: node.host || "-",
      status: node.online
        ? '<span class="badge success">在线</span>'
        : '<span class="badge danger">离线</span>',
      traffic: node.traffic || {},
    });
  }
  const sum = (field) =>
    nodes.reduce((total, node) => total + (Number(node.traffic?.[field]) || 0), 0);
  setProp("#nodeTrafficInRate", "textContent", `${escapeHtml(formatBytes(sum("totalIncomingRate")))}/s`);
  setProp("#nodeTrafficOutRate", "textContent", `${escapeHtml(formatBytes(sum("totalOutgoingRate")))}/s`);
  setProp("#nodeTrafficInTotal", "textContent", escapeHtml(formatBytes(sum("totalIncomingBytes"))));
  setProp("#nodeTrafficOutTotal", "textContent", escapeHtml(formatBytes(sum("totalOutgoingBytes"))));
  $("#nodeTrafficRows").innerHTML = nodes
    .map(
      (node) => `
      <tr>
        <td>${escapeHtml(node.name)}</td>
        <td>${node.role}</td>
        <td class="mono">${escapeHtml(node.host)}</td>
        <td>${node.status}</td>
        <td class="mono">${node.traffic?.totalIncomingRate == null ? "-" : `${escapeHtml(formatBytes(node.traffic.totalIncomingRate))}/s`}</td>
        <td class="mono">${node.traffic?.totalOutgoingRate == null ? "-" : `${escapeHtml(formatBytes(node.traffic.totalOutgoingRate))}/s`}</td>
        <td class="mono">${node.traffic?.totalIncomingBytes == null ? "-" : escapeHtml(formatBytes(node.traffic.totalIncomingBytes))}</td>
        <td class="mono">${node.traffic?.totalOutgoingBytes == null ? "-" : escapeHtml(formatBytes(node.traffic.totalOutgoingBytes))}</td>
      </tr>
    `,
    )
    .join("");
}

// 规格8：合计卡点击展开 / 收起各节点明细。
function toggleNodeTrafficDetail() {
  const detail = $("#nodeTrafficDetail");
  const summary = $("#nodeTrafficSummary");
  const hint = $("#nodeTrafficToggleHint");
  if (!detail || !summary) return;
  const expanded = detail.classList.toggle("hidden") === false;
  summary.setAttribute("aria-expanded", String(expanded));
  if (hint) hint.textContent = expanded ? "收起明细 ▴" : "展开明细 ▾";
}

$("#nodeTrafficSummary")?.addEventListener("click", toggleNodeTrafficDetail);
$("#nodeTrafficSummary")?.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    toggleNodeTrafficDetail();
  }
});

// 0.10.0.2：总览页集群总览卡——主节点 + 从节点的流量 / 端口池 / 用户概况。
function renderClusterOverview(cluster) {
  const rows = $("#clusterOverviewRows");
  if (!rows) return;
  const nodes = [];
  if (cluster?.master) {
    const master = cluster.master;
    const traffic = master.traffic || {};
    nodes.push({
      name: master.label || "主节点",
      role: '<span class="badge master">主节点</span>',
      host: master.host || "-",
      status: '<span class="badge success">在线</span>',
      version: master.version ? `v${master.version}` : "-",
      workload: `${master.userCount ?? 0} 用户 · ${master.proxyCount ?? 0} 映射`,
      ports: `${master.ports?.used ?? 0}/${master.ports?.total ?? 0}`,
      inRate: traffic.totalIncomingRate,
      outRate: traffic.totalOutgoingRate,
      inTotal: traffic.totalIncomingBytes,
      outTotal: traffic.totalOutgoingBytes,
    });
  }
  for (const node of cluster?.nodes || []) {
    const traffic = node.traffic || {};
    nodes.push({
      name: node.label || node.name,
      role: '<span class="badge">从节点</span>',
      host: node.host || "-",
      status: node.online
        ? '<span class="badge success">在线</span>'
        : '<span class="badge danger">离线</span>',
      version: node.version ? `v${node.version}` : "-",
      workload:
        node.userCount == null
          ? "-"
          : `${node.userCount} 用户 · ${node.proxyCount ?? 0} 映射`,
      ports: `${node.ports?.used ?? 0}/${node.ports?.total ?? 0}`,
      inRate: traffic.totalIncomingRate,
      outRate: traffic.totalOutgoingRate,
      inTotal: traffic.totalIncomingBytes,
      outTotal: traffic.totalOutgoingBytes,
    });
  }
  setProp("#clusterOverviewEmpty", "hidden", nodes.length > 1);
  setProp(
    "#clusterOverviewBadge",
    "textContent",
    cluster?.name ? `${cluster.name} · ${nodes.length} 台节点` : "",
  );
  rows.innerHTML = nodes
    .map(
      (node) => `
      <tr>
        <td>${escapeHtml(node.name)}</td>
        <td>${node.role}</td>
        <td class="mono">${escapeHtml(node.host)}</td>
        <td>${node.status}</td>
        <td class="mono">${escapeHtml(node.version)}</td>
        <td>${escapeHtml(node.workload)}</td>
        <td class="mono">${escapeHtml(node.ports)}</td>
        <td class="mono">${node.inRate == null ? "-" : `${escapeHtml(formatBytes(node.inRate))}/s`}</td>
        <td class="mono">${node.outRate == null ? "-" : `${escapeHtml(formatBytes(node.outRate))}/s`}</td>
        <td class="mono">${node.inTotal == null ? "-" : escapeHtml(formatBytes(node.inTotal))}</td>
        <td class="mono">${node.outTotal == null ? "-" : escapeHtml(formatBytes(node.outTotal))}</td>
      </tr>`,
    )
    .join("");
}

function renderOverview() {
  const data = state.overview;
  if (!data) return;
  setProp("#adminName", "textContent", data.admin.username);
  setProp("#overviewTime", "textContent", `更新于 ${formatDate(new Date().toISOString())}`);
  renderAnnouncements(data);
  setProp("#statUsers", "textContent", data.stats.users);
  setProp("#statActive", "textContent", data.stats.active);
  setProp("#statOnline", "textContent", data.stats.online);
  setProp("#statPorts", "textContent", data.stats.allocatedPorts.toLocaleString("zh-CN"));
  setProp("#statMappings", "textContent", data.stats.onlineMappings);
  setProp("#statMappingsMeta", "textContent", `共 ${data.stats.mappings} 条映射`);
  renderClusterUsers(data.clusterUsers || []);
  // 0.10.2.8：运行提醒（frps 报错等）+ 侧边栏未读徽标。
  renderServerMessages(data.messages);
  renderClusterOverview(data.cluster);
  // 0.10.1.2 规格8：节点流量合计 + 展开明细。
  renderNodeTraffic(data.cluster);
  const notice = $("#licenseNotice");
  if (notice) {
    notice.classList.toggle(
      "hidden",
      data.license.mode === "licensed" || data.license.mode === "free",
    );
    if (data.license.mode === "free") {
      notice.textContent =
        "当前为免费额度：单集群 1 台服务端（主节点）永久免费，添加从节点需购买集群授权许可。";
    } else if (!data.license.valid) {
      notice.textContent = data.license.error || "服务端许可无效，frps 已停止。";
    }
  }

  const [label, className] = processStatus(data.frps.state);
  setProp("#frpsBadge", "className", `badge ${className}`.trim());
  setProp("#frpsBadge", "textContent", label);
  setProp("#frpsPort", "textContent", data.frps.bindPort);
  setProp("#frpsVersion", "textContent", data.frps.version || "未知");
  setProp("#frpsPid", "textContent", data.frps.pid || "-");
  setProp("#frpsStarted", "textContent", formatDate(data.frps.startedAt));
  const traffic = data.frps.traffic;
  setProp(
    "#trafficStatus",
    "textContent",
    traffic.available
      ? `正常 · ${traffic.seriesCount} 个指标`
      : traffic.error
        ? "异常"
        : "等待采样",
  );
  setProp("#trafficStatus", "title", traffic.error || "");
  setProp("#frpsLogs", "textContent", data.frps.logs.join("\n") || "暂无日志");

  const t = data.traffic;
  const sys = t?.system;
  if (sys && sys.available) {
    setProp("#systemIncomingRate", "textContent", `${formatBytes(sys.incomingBytesPerSecond)}/s`);
    setProp("#systemOutgoingRate", "textContent", `${formatBytes(sys.outgoingBytesPerSecond)}/s`);
  } else {
    setProp("#systemIncomingRate", "textContent", "-");
    setProp("#systemOutgoingRate", "textContent", "-");
  }
  if (t && t.available) {
    setProp(
      "#trafficMeta",
      "textContent",
      `${t.activeProxies} 个映射有流量数据 · 采样于 ${formatDate(t.sampledAt)}`,
    );
    setProp("#trafficIncomingTotal", "textContent", formatBytes(t.totalIncomingBytes));
    setProp("#trafficOutgoingTotal", "textContent", formatBytes(t.totalOutgoingBytes));
  } else {
    setProp("#trafficMeta", "textContent", t?.error ? "采集异常" : "等待采样");
    setProp("#trafficIncomingTotal", "textContent", "-");
    setProp("#trafficOutgoingTotal", "textContent", "-");
  }

  const userList = $("#trafficUserList");
  const trafficUsers = t?.users || [];
  if (t && t.available && trafficUsers.length > 0) {
    userList.innerHTML = trafficUsers.slice(0, 10).map((u) => `
      <article class="traffic-user-item">
        <span class="avatar">${escapeHtml(u.username.slice(0, 2))}</span>
        <div class="traffic-user-info">
          <strong>${escapeHtml(u.username)}</strong>
          <span class="traffic-user-rates">
            入站 ${escapeHtml(formatBytes(u.incomingRate))}/s ·
            出站 ${escapeHtml(formatBytes(u.outgoingRate))}/s
          </span>
        </div>
        <div class="traffic-user-totals" title="本次运行周期累计">
          <span>累计 ${escapeHtml(formatBytes(u.incomingBytes + u.outgoingBytes))}</span>
        </div>
      </article>
    `).join("");
  } else {
    userList.innerHTML = '<p class="empty">暂无流量数据</p>';
  }

  const actionLabels = {
    "user.create": "创建用户",
    "user.update": "更新用户",
    "user.delete": "删除用户",
    "user.disconnect": "强制下线",
    "user.renew": "管理员续费",
    "client.login": "客户端登录",
    "client.logout": "客户端退出",
    "admin.password": "修改管理员密码",
    "license.activate": "激活许可密钥",
    "license.refresh": "验证许可密钥",
    "license.remove": "移除许可密钥",
    "icp.text.update": "更新备案信息",
    "renewal.url.update": "更新续费地址",
    "branding.update": "更新品牌设置",
  };
  $("#auditList").innerHTML =
    data.recentAudit
      .map(
        (item) => `
          <article class="audit-item">
            <strong>${escapeHtml(actionLabels[item.action] || item.action)} · ${escapeHtml(item.target || "-")}</strong>
            <p>${escapeHtml(item.actor)} · ${escapeHtml(formatDate(item.createdAt))}</p>
          </article>
        `,
      )
      .join("") || '<div class="empty">暂无操作记录</div>';
}

function renderLicense() {
  const license = state.overview?.license;
  if (!license) return;
  const modes = {
    free: ["免费额度", "success"],
    trial: ["免费试用", "warning"],
    licensed: ["已授权", "success"],
    expired: ["试用已结束", "danger"],
    invalid: ["授权无效", "danger"],
    blocked: ["已封禁", "danger"],
  };
  const [label, className] = modes[license.mode] || ["未知", ""];
  setProp("#licenseBadge", "className", `badge ${className}`.trim());
  setProp("#licenseBadge", "textContent", label);
  setProp(
    "#licenseStatusText",
    "textContent",
    license.error ||
      (license.mode === "licensed"
        ? `${license.customer || "商业授权"} · ${license.plan}`
        : license.mode === "free"
          ? "免费额度：单集群 1 台服务端（主节点）"
          : "许可未激活"),
  );
  setProp("#licenseMode", "textContent", label);
  setProp("#licenseExpiresAt", "textContent", formatDate(license.expiresAt));
  setProp("#licenseRemaining", "textContent", formatRemaining(license.remainingSeconds));
  setProp("#licenseInstallationId", "textContent", license.installationId);
  setProp("#licenseLastChecked", "textContent", formatDate(license.lastCheckedAt));
  setProp(
    "#licenseKeyPreview",
    "textContent",
    license.keyPreview ? `当前密钥 ${license.keyPreview}` : "当前未设置密钥",
  );
  const removeBtn = $("#removeLicenseButton");
  if (removeBtn) removeBtn.classList.toggle("hidden", !license.keyPreview);
  setProp("#refreshLicenseButton", "disabled", !license.keyPreview);
  const purchaseButton = $("#purchaseUrlButton");
  if (purchaseButton) {
    if (license.purchaseUrl) {
      purchaseButton.href = license.purchaseUrl;
      purchaseButton.hidden = false;
    } else {
      purchaseButton.hidden = true;
    }
  }
}

function renderUpdate() {
  const u = state.overview?.update;
  const currentVersion = state.overview?.currentVersion || "-";
  setProp("#updateCurrentVersion", "textContent", currentVersion);
  if (!u || !u.checkedAt) {
    setProp("#updateBadge", "textContent", "未知");
    setProp("#updateBadge", "className", "badge");
    setProp("#updateLatestVersion", "textContent", "-");
    setProp("#updatePublishedAt", "textContent", "-");
    setProp("#updateUrgency", "textContent", "-");
    setProp("#updateChangelogWrap", "hidden", true);
    setProp("#applyUpdateButton", "hidden", true);
    setProp("#updateError", "textContent", u?.error || "");
    return;
  }
  setProp("#updateLatestVersion", "textContent", u.latestVersion || "-");
  setProp("#updatePublishedAt", "textContent", formatDate(u.publishedAt));
  setProp("#updateUrgency", "textContent", u.urgency || "-");
  setProp("#updateBadge", "className", `badge ${u.hasUpdate ? "warning" : "success"}`.trim());
  setProp("#updateBadge", "textContent", u.hasUpdate ? "有更新" : "已是最新");
  setProp("#updateChangelog", "textContent", u.changelog || "");
  setProp("#updateChangelogWrap", "hidden", !u.changelog);
  setProp("#applyUpdateButton", "hidden", !u.hasUpdate);
  setProp("#updateError", "textContent", u.error || "");
}

function renderUsers() {
  const query = (getProp("#userSearch", "value") || "").trim().toLowerCase();
  const users = state.users
    .filter((user) =>
      `${user.username} ${user.uid || ""} ${user.portRangesText} ${user.deviceAddress || ""}`
        .toLowerCase()
        .includes(query),
    )
    // 0.10.1.5：在线用户置顶（设备心跳 30 秒租约口径，与状态徽标一致），组内保持原有顺序。
    .sort((a, b) => Number(Boolean(b.deviceOnline)) - Number(Boolean(a.deviceOnline)));
  setProp("#userCount", "textContent", `${state.users.length} 名用户`);
  const empty = $("#usersEmpty");
  if (empty) empty.classList.toggle("hidden", users.length !== 0);
  $("#userRows").innerHTML = users
    .map((user) => {
      const status = userStatus(user);
      return `
        <tr>
          <td class="check-cell">
            <input type="checkbox" class="user-check" data-id="${user.id}" aria-label="选择 ${escapeHtml(user.username)}" />
          </td>
          <td>
            <div class="user-cell">
              <span class="avatar">${escapeHtml(user.username.slice(0, 2))}</span>
              <div>
                <strong>${escapeHtml(user.username)}</strong>
                <small title="当前登录设备">
                  ${user.deviceOnline ? escapeHtml(user.deviceAddress || "已登录") : "无活跃设备"}
                </small>
                ${
                  user.planName
                    ? `<small class="user-plan-tag"><i data-lucide="package" class="icon"></i> ${escapeHtml(user.planName)}</small>`
                    : ""
                }
                ${
                  user.httpAllowed
                    ? `<small class="user-plan-tag" title="已授权 HTTP/HTTPS 隧道"><i data-lucide="globe" class="icon"></i> HTTP/HTTPS</small>`
                    : ""
                }
              </div>
            </div>
          </td>
          <td>
            <div class="uid-cell">
              <strong class="mono">${escapeHtml(user.uid || "-")}</strong>
              ${
                user.uid
                  ? `<button class="button ghost icon-only tiny" type="button" data-copy="${escapeHtml(user.uid)}" title="复制用户 ID">
                      <i data-lucide="copy" class="icon"></i>
                    </button>`
                  : ""
              }
            </div>
          </td>
          <td>
            ${
              user.tempPassword
                ? `<div class="uid-cell">
                    <span class="mono" data-password-mask title="点击显示初始密码">••••••••</span>
                    <button class="button ghost icon-only tiny" type="button" data-copy="${escapeHtml(user.tempPassword)}" title="复制初始密码">
                      <i data-lucide="copy" class="icon"></i>
                    </button>
                  </div>
                  <small><span class="badge warning">待改密</span></small>`
                : '<small class="muted">已修改</small>'
            }
          </td>
          <td><span class="badge ${status.className}">${status.label}</span></td>
          <td>
            <button
              class="mapping-summary"
              data-user-action="mappings"
              data-id="${user.id}"
              title="查看 ${escapeHtml(user.username)} 的映射"
            >
              <strong>${user.onlineMappingCount}</strong> / ${user.mappingCount}
            </button>
          </td>
          <td>
            ${user.trafficLimitBytes > 0
              ? (() => {
                  const pct = user.trafficLimitBytes > 0
                    ? Math.min(100, (user.trafficUsedBytes / user.trafficLimitBytes) * 100) : 0;
                  const barClass = pct >= 100 ? "danger" : pct >= 80 ? "warning" : "";
                  return `<div class="usage-cell">
                    <span>${escapeHtml(formatBytes(user.trafficUsedBytes))} / ${escapeHtml(formatBytes(user.trafficLimitBytes))}</span>
                    <div class="usage-bar"><div class="usage-fill ${barClass}" style="width:${pct}%"></div></div>
                  </div>`;
                })()
              : `<span class="muted">${escapeHtml(formatBytes(user.trafficUsedBytes))}</span>`
            }
          </td>
          <td>
            <div class="port-list">
              ${user.portRanges.length
                ? user.portRanges
                    .map(
                      (range) =>
                        `<span class="port-chip">${range.start === range.end ? range.start : `${range.start}-${range.end}`}</span>`,
                    )
                    .join("")
                : `<span class="badge info">无端口</span>`}
            </div>
          </td>
          <td title="${user.activated ? "" : `未激活；激活后起算 ${user.durationDays} 天`}">
            ${user.activated
              ? escapeHtml(formatDate(user.expiresAt))
              : `<span class="badge info">未激活 · ${user.durationDays}天</span>`}
          </td>
          <td>${escapeHtml(formatDate(user.lastSeen))}</td>
          <td>
            <div class="row-actions">
              <button class="button ghost icon-only" data-user-action="renew" data-id="${user.id}" title="续费">
                <i data-lucide="calendar-plus" class="icon"></i>
              </button>
              <button class="button ghost icon-only" data-user-action="edit" data-id="${user.id}" title="编辑">
                <i data-lucide="pencil" class="icon"></i>
              </button>
              <button class="button ghost icon-only" data-user-action="disconnect" data-id="${user.id}" title="强制下线">
                <i data-lucide="unplug" class="icon"></i>
              </button>
              <button class="button ghost icon-only" data-user-action="reset-traffic" data-id="${user.id}" title="重置流量">
                <i data-lucide="rotate-ccw" class="icon"></i>
              </button>
              <button
                class="button ghost icon-only"
                data-user-action="revoke-ports"
                data-id="${user.id}"
                title="${user.portRanges?.length ? "收回全部端口并取消节点关联" : "当前无已分配端口"}"
              >
                <i data-lucide="eraser" class="icon"></i>
              </button>
              <button class="button ghost icon-only" data-user-action="delete" data-id="${user.id}" title="删除">
                <i data-lucide="trash-2" class="icon"></i>
              </button>
            </div>
          </td>
        </tr>
      `;
    })
    .join("");
  icons();
  syncUserCheckboxes();
}

// 0.9.3：用户多选与批量操作（限速 / 改套餐 / 启停 / 删除）。
const selectedUserIds = new Set();
let usersBatchAction = null;

function syncUserCheckboxes() {
  const boxes = $$(".user-check");
  let allChecked = boxes.length > 0;
  for (const box of boxes) {
    const on = selectedUserIds.has(Number(box.dataset.id));
    box.checked = on;
    if (!on) allChecked = false;
  }
  const checkAll = $("#userCheckAll");
  if (checkAll) checkAll.checked = allChecked;
  const bar = $("#batchBar");
  if (bar) bar.classList.toggle("hidden", selectedUserIds.size === 0);
  setProp("#batchSelectedCount", "textContent", `已选 ${selectedUserIds.size} 人`);
}

function openUsersBatchDialog(action) {
  usersBatchAction = action;
  const titles = { rateLimit: "批量限速", plan: "批量改套餐" };
  setProp("#usersBatchDialogTitle", "textContent", titles[action] || "批量操作");
  setProp(
    "#usersBatchSummary",
    "textContent",
    `将对已选的 ${selectedUserIds.size} 个用户执行「${titles[action]}」。`,
  );
  $("#usersBatchFieldRate")?.classList.toggle("hidden", action !== "rateLimit");
  $("#usersBatchFieldPlan")?.classList.toggle("hidden", action !== "plan");
  if (action === "plan") {
    const select = $("#usersBatchPlanSelect");
    if (select) {
      select.innerHTML = state.plans
        .map(
          (plan) =>
            `<option value="${plan.id}">${escapeHtml(plan.name)}（${plan.durationDays}天 / ${
              plan.trafficLimitBytes > 0 ? `${plan.trafficGB}GB / ` : "不限流量 / "
            }${plan.rateLimitBps > 0 ? `限${Math.round(plan.rateLimitMbps)}M / ` : ""}${plan.portCount}口）</option>`,
        )
        .join("");
    }
  }
  setProp("#usersBatchFormError", "textContent", "");
  $("#usersBatchDialog")?.showModal();
}

async function postUsersBatch(body) {
  try {
    const result = await api("/api/admin/users/batch", {
      method: "POST",
      body: JSON.stringify({ ids: [...selectedUserIds], ...body }),
    });
    const count = result.updated ?? result.deleted ?? selectedUserIds.size;
    toast(`批量操作完成，共影响 ${count} 个用户`);
    selectedUserIds.clear();
    $("#usersBatchDialog")?.close();
    await refresh();
  } catch (error) {
    setProp("#usersBatchFormError", "textContent", error.message);
  }
}

async function runUsersBatchAction(action) {
  if (selectedUserIds.size === 0) {
    toast("请先勾选用户");
    return;
  }
  if (action === "rateLimit" || action === "plan") {
    openUsersBatchDialog(action);
    return;
  }
  if (action === "enable") {
    if (!confirm(`确认批量启用已选的 ${selectedUserIds.size} 个用户？`)) return;
    await postUsersBatch({ action: "enable" });
    return;
  }
  if (action === "disable") {
    if (!confirm(`确认批量停用已选的 ${selectedUserIds.size} 个用户？在线连接将被断开。`)) return;
    await postUsersBatch({ action: "disable" });
    return;
  }
  if (action === "delete") {
    if (!confirm(`确认批量删除已选的 ${selectedUserIds.size} 个用户？此操作无法撤销。`)) return;
    await postUsersBatch({ action: "delete" });
  }
}

async function submitUsersBatch(event) {
  event.preventDefault();
  const body = { action: usersBatchAction };
  if (usersBatchAction === "rateLimit") {
    body.rateLimitMbps = Number(getProp("#usersBatchRateMbps", "value") || 0);
  }
  if (usersBatchAction === "plan") {
    body.planId = Number(getProp("#usersBatchPlanSelect", "value") || 0) || null;
  }
  await postUsersBatch(body);
}

// 0.9.2：用户表复制用户 ID / 初始密码、点击掩码显示初始密码。
async function copyText(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`已复制${label}`);
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    document.body.append(area);
    area.select();
    document.execCommand("copy");
    area.remove();
    toast(`已复制${label}`);
  }
}

$("#userRows")?.addEventListener("click", (event) => {
  const copyButton = event.target.closest("[data-copy]");
  if (copyButton) {
    void copyText(copyButton.dataset.copy, copyButton.title || "内容");
    return;
  }
  const mask = event.target.closest("[data-password-mask]");
  if (mask) {
    const user = state.users.find(
      (item) => item.tempPassword && mask.parentElement?.querySelector("[data-copy]")?.dataset.copy === item.tempPassword,
    );
    if (user?.tempPassword) {
      mask.textContent = user.tempPassword;
      mask.title = "初始密码（用户改密后将不可查看）";
    }
  }
});

// 0.10.0.2：映射监控节点筛选（全部 / 主节点 / 各从节点）。
function renderMappingNodeFilter() {
  const wrap = $("#mappingNodeFilters");
  if (!wrap) return;
  const nodes = [
    { id: "all", label: "全节点" },
    { id: "master", label: "主节点" },
  ];
  for (const node of state.overview?.cluster?.nodes || []) {
    nodes.push({ id: node.name, label: node.name });
  }
  const current = state.mappingNode || "all";
  wrap.innerHTML = nodes
    .map(
      (node) =>
        `<button type="button" data-mapping-node="${escapeHtml(node.id)}" aria-pressed="${node.id === current}">${escapeHtml(node.label)}</button>`,
    )
    .join("");
}

function renderMappings() {
  const query = (getProp("#mappingSearch", "value") || "").trim().toLowerCase();
  const nodeFilter = state.mappingNode || "all";
  // 0.10.0.2：集群维度——主节点实时映射 + 各在线从节点的映射快照合并展示。
  const merged = [
    ...state.proxies.map((proxy) => ({ ...proxy, node: "master", isMaster: true })),
    ...state.clusterProxies,
  ];
  const proxies = merged.filter((proxy) => {
    const domainsText = (proxy.domains || []).join(" ");
    const matchesQuery =
      `${proxy.username} ${proxy.name} ${proxy.remotePort ?? ""} ${proxy.type} ${domainsText} ${proxy.node || ""}`
        .toLowerCase()
        .includes(query);
    const matchesStatus =
      state.mappingFilter === "all" ||
      (state.mappingFilter === "online" && proxy.online) ||
      (state.mappingFilter === "offline" && !proxy.online);
    const matchesNode =
      nodeFilter === "all" ||
      (nodeFilter === "master" ? proxy.node === "master" : proxy.node === nodeFilter);
    return matchesQuery && matchesStatus && matchesNode;
  });
  // 0.10.1.0：在线节点/隧道排在前面；同组内主节点优先，再按最近活跃时间倒序。
  proxies.sort((a, b) => {
    if (Boolean(a.online) !== Boolean(b.online)) return a.online ? -1 : 1;
    const aMaster = a.node === "master" ? 0 : 1;
    const bMaster = b.node === "master" ? 0 : 1;
    if (aMaster !== bMaster) return aMaster - bMaster;
    return new Date(b.lastSeen || 0) - new Date(a.lastSeen || 0);
  });

  setProp(
    "#mappingCount",
    "textContent",
    proxies.length === merged.length
      ? `${merged.length} 条映射`
      : `${proxies.length} / ${merged.length} 条`,
  );
  setProp("#mappingUpdatedAt", "textContent", `更新于 ${formatDate(new Date().toISOString())}`);
  const mapEmpty = $("#mappingsEmpty");
  if (mapEmpty) mapEmpty.classList.toggle("hidden", proxies.length !== 0);
  $("#mappingRows").innerHTML = proxies
    .map((proxy) => {
      const isHttp = proxy.type === "http" || proxy.type === "https";
      const domains = Array.isArray(proxy.domains) ? proxy.domains : [];
      const accessCell = isHttp
        ? `<div class="domain-cell">${
            domains.length
              ? domains
                  .map((d) => `<span class="port-chip" title="${escapeHtml(proxy.type + "://" + d)}">${escapeHtml(d)}</span>`)
                  .join("")
              : `<span class="muted">-</span>`
          }</div>`
        : `<span class="port-chip">${proxy.remotePort ?? "-"}</span>`;
      const limitMbps = Math.round((proxy.rateLimitBps || 0) / 1_000_000);
      const limitCell = `<button
          type="button"
          class="button tiny ${proxy.rateLimitBps ? "warning" : "ghost"}"
          data-rate-limit="${escapeHtml(proxy.qualifiedName || proxy.name)}"
          data-user-id="${proxy.userId}"
          title="设置隧道限速">
          <i data-lucide="gauge" class="icon"></i>
          ${proxy.rateLimitBps ? `${limitMbps} Mbps` : "限速"}
        </button>`;
      return `
        <tr>
          <td>
            <div class="user-cell compact">
              <span class="avatar">${escapeHtml(proxy.username.slice(0, 2))}</span>
              <strong>${escapeHtml(proxy.username)}</strong>
            </div>
          </td>
          <td>
            <strong>${escapeHtml(proxy.name)}</strong>
          </td>
          <td>${
            proxy.isMaster || proxy.node === "master"
              ? '<span class="badge master">主节点</span>'
              : `<span class="port-chip" title="从节点映射">${escapeHtml(proxy.node || "-")}</span>`
          }</td>
          <td><span class="protocol-label">${escapeHtml(proxy.type.toUpperCase())}</span></td>
          <td>${accessCell}</td>
          <td class="traffic-cell">${trafficMarkup(proxy.traffic)}</td>
          <td class="mono">${escapeHtml(proxy.clientAddress || "-")}</td>
          <td>
            <span class="badge ${proxy.online ? "success" : ""}">
              ${proxy.online ? "在线" : "离线"}
            </span>
          </td>
          <td>${limitCell}</td>
          <td title="${escapeHtml(formatDate(proxy.lastSeen))}">
            ${escapeHtml(formatRelative(proxy.lastSeen))}
          </td>
        </tr>
      `;
    })
    .join("");
  icons();
}

async function refresh() {
  if (state.refreshing) return;
  state.refreshing = true;
  try {
    const [overview, users, plans] = await Promise.all([
      api("/api/admin/overview"),
      api("/api/admin/users"),
      api("/api/admin/plans"),
    ]);
    state.overview = overview;
    state.users = users.users;
    state.plans = plans.plans;
    state.plansLoaded = true;
    renderOverview();
    renderLicense();
    renderUpdate();
    renderUsers();
    renderMappingNodeFilter();
    renderMappings();
    renderSlavePorts();
    renderPlans();
    showApp();
  } catch (error) {
    if (error.status === 401) {
      showLogin();
      return;
    }
    toast(error.message, true);
  } finally {
    state.refreshing = false;
  }
}

async function refreshMappings() {
  try {
    // 0.10.0.2：并行拉取主节点映射与各在线从节点的映射快照。
    const [data, cluster] = await Promise.all([
      api("/api/admin/proxies"),
      api("/api/admin/cluster/proxies").catch(() => ({ proxies: [] })),
    ]);
    state.proxies = data.proxies;
    state.clusterProxies = cluster.proxies || [];
    renderMappingNodeFilter();
    renderMappings();
  } catch (error) {
    if (error.status === 401) { showLogin(); return; }
  }
}

function startMappingTimer() {
  if (state.mappingTimer) clearInterval(state.mappingTimer);
  state.mappingTimer = setInterval(() => {
    if (!document.hidden && !$("#appView").classList.contains("hidden")) {
      refreshMappings();
    }
  }, state.mappingRefreshMs);
}

function switchSettingsTab(tab) {
  state.settingsTab = tab;
  $$("[data-settings-tab]").forEach((button) =>
    button.setAttribute("aria-pressed", String(button.dataset.settingsTab === tab)),
  );
  $$(".settings-pane").forEach((pane) => pane.classList.add("hidden"));
  const pane = $(`#settingsPane${tab.charAt(0).toUpperCase()}${tab.slice(1)}`);
  if (pane) pane.classList.remove("hidden");
  if (tab === "branding") void loadBrandingForm();
  if (tab === "license") renderLicense();
  if (tab === "update") renderUpdate();
  if (tab === "network") void loadNetwork();
  if (tab === "account") void loadAccount();
  if (tab === "icp") {
    void loadIcpForm();
    void loadCopyrightForm();
  }
  if (tab === "renewal") void loadRenewalUrl();
  if (tab === "publicinfo") void loadPublicInfo();
  if (tab === "register") void loadEmailSettings();
}

function switchView(view) {
  state.activeView = view;
  $$(".page-view").forEach((element) => element.classList.add("hidden"));
  $(`#${view}View`)?.classList.remove("hidden");
  $$(".nav-button").forEach((button) =>
    button.classList.toggle("active", button.dataset.view === view),
  );
  if (view === "settings") {
    switchSettingsTab(state.settingsTab || "branding");
    renderLicense();
    renderUpdate();
  }
  if (view === "frp") void loadFrpcCache();
  if (view === "plans") {
    void loadPlans();
    void loadPlanCodes();
  }
  if (view === "cluster") void loadCluster();
  if (view === "runtime") {
    void loadVhostPorts();
    void loadBindPort();
    renderSlavePorts();
  }
  // 0.10.2.8：消息中心——进入即清除未读徽标，并加载公告管理列表。
  if (view === "messages") {
    void markServerMessagesRead();
    void loadAnnouncements();
  }
  if (view === "firewall") void loadFirewall();
}

const DEFAULT_BRAND_NAME = "XFCloud Tunnel";
const pendingLogo = { site: undefined, client: undefined };

function setFavicon(href) {
  let link = document.querySelector('link[rel="icon"]');
  if (!link) {
    link = document.createElement("link");
    link.rel = "icon";
    document.head.appendChild(link);
  }
  link.href = href;
}

function applySiteBranding(branding) {
  const customName = branding?.siteName?.trim();
  const brandName = customName || DEFAULT_BRAND_NAME;
  document.title = customName ? `${customName} 服务端` : "XFCloud Tunnel 服务端";
  $$(".brand-name").forEach((element) => {
    element.textContent = brandName;
  });
  // 备案旁版权声明：由授权中心统一下发（全局默认或已授权的自定义版权）。
  const cpText = (branding?.copyright?.text || "").trim() || brandName;
  const cpUrl = (branding?.copyright?.url || "").trim();
  $$(".footer-brand").forEach((element) => {
    element.textContent = cpText;
    if (element.tagName === "A") {
      if (cpUrl) {
        element.href = cpUrl;
        element.target = "_blank";
        element.rel = "noopener noreferrer";
        element.classList.add("is-link");
      } else {
        element.removeAttribute("href");
        element.removeAttribute("target");
        element.classList.remove("is-link");
      }
    }
  });
  $$(".brand-symbol").forEach((symbol) => {
    if (branding?.siteLogoUrl) {
      symbol.innerHTML = `<img src="${escapeHtml(branding.siteLogoUrl)}" alt="" />`;
    } else {
      symbol.innerHTML = '<i data-lucide="waypoints"></i>';
      icons();
    }
  });
  const icpText = (branding?.icp || "").trim();
  $$("[data-icp-link]").forEach((link) => {
    if (icpText) {
      link.textContent = icpText;
      link.classList.remove("hidden");
    } else {
      link.classList.add("hidden");
    }
  });
  const policeText = (branding?.police || "").trim();
  $$("[data-police-link]").forEach((link) => {
    if (policeText) {
      link.textContent = policeText;
      link.classList.remove("hidden");
    } else {
      link.classList.add("hidden");
    }
  });
  setFavicon(branding?.siteLogoUrl || "/favicon.svg");
}

async function loadPublicBranding() {
  try {
    const data = await api("/api/public/branding");
    applySiteBranding(data);
  } catch {
    // 品牌信息加载失败时保持默认外观。
  }
}

function updateLogoPreview(kind, url) {
  const preview = $(`#${kind}LogoPreview`);
  const placeholder = $(`#${kind}LogoPlaceholder`);
  const removeButton = $(`#${kind}LogoRemove`);
  if (url) {
    if (preview) {
      preview.src = url;
      preview.classList.remove("hidden");
    }
    placeholder?.classList.add("hidden");
    if (removeButton) removeButton.hidden = false;
  } else {
    if (preview) {
      preview.removeAttribute("src");
      preview.classList.add("hidden");
    }
    placeholder?.classList.remove("hidden");
    if (removeButton) removeButton.hidden = true;
  }
}

async function loadBrandingForm() {
  try {
    const { branding } = await api("/api/admin/branding");
    setProp("#siteName", "value", branding.siteName || "");
    setProp("#clientName", "value", branding.clientName || "");
    updateLogoPreview("site", branding.siteLogoUrl);
    updateLogoPreview("client", branding.clientLogoUrl);
    pendingLogo.site = undefined;
    pendingLogo.client = undefined;
  } catch (error) {
    if (error.status !== 401) toast(error.message, true);
  }
}

async function loadRenewalUrl() {
  try {
    const { renewalUrl } = await api("/api/admin/renewal-url");
    setProp("#renewalUrlInput", "value", renewalUrl || "");
    setProp("#renewalUrlError", "textContent", "");
  } catch (error) {
    if (error.status !== 401) toast(error.message, true);
  }
}

async function loadIcpForm() {
  try {
    const data = await api("/api/admin/icp-text");
    setProp("#icpText", "value", data.icpText || "");
    setProp("#policeText", "value", data.policeText || "");
    setProp("#icpFormError", "textContent", "");
  } catch (error) {
    if (error.status !== 401) toast(error.message, true);
  }
}

const COPYRIGHT_SOURCE_LABEL = {
  custom: "已授权自定义",
  default: "授权中心默认",
  none: "默认",
  pending: "申请待审批",
  rejected: "申请已驳回",
  revoked: "授权已回收",
};

async function loadCopyrightForm() {
  try {
    const data = await api("/api/admin/copyright");
    const cp = data.copyright || {};
    setProp("#copyrightCurrentText", "textContent", cp.text || "XFCloud Tunnel");
    const source = $("#copyrightSource");
    if (source) {
      const labelKey = cp.status === "approved" ? "custom" : cp.status || "default";
      source.textContent = COPYRIGHT_SOURCE_LABEL[labelKey] || COPYRIGHT_SOURCE_LABEL.default;
      source.dataset.status = cp.status || "none";
    }
    // 驳回时展示授权中心填写的驳回原因，提示管理员修改后可重新申请。
    const rejectBox = $("#copyrightRejectReason");
    if (rejectBox) {
      if (cp.status === "rejected" && cp.rejectReason) {
        rejectBox.textContent = `版权申请被驳回：${cp.rejectReason}。可修改申请内容后重新提交。`;
        rejectBox.classList.remove("hidden");
      } else {
        rejectBox.textContent = "";
        rejectBox.classList.add("hidden");
      }
    }
    // 审批中 / 已授权：灰显申请表单并提示，避免重复提交；驳回/回收后自动恢复可申请。
    const form = $("#copyrightForm");
    if (form) {
      const locked = cp.status === "pending" || cp.status === "approved";
      form.querySelectorAll("input, textarea, button").forEach((element) => {
        element.disabled = locked;
      });
      const notice =
        cp.status === "pending"
          ? "版权申请正在审批中，审批结果将自动同步到本服务端及客户端，请勿重复提交。"
          : cp.status === "approved"
            ? "当前已授权自定义版权，如需变更或取消请联系授权中心处理。"
            : "";
      setProp("#copyrightFormMsg", "textContent", notice);
    }
    setProp("#copyrightFormError", "textContent", "");
  } catch (error) {
    if (error.status !== 401) toast(error.message, true);
  }
}

// ---------- 0.9.9：信息公开（推送到授权中心，客户端登录页「服务器列表」展示） ----------
async function loadPublicInfo() {
  try {
    const data = await api("/api/admin/server-public-info");
    const info = data.info;
    const badge = $("#publicInfoBadge");
    if (badge) {
      badge.textContent =
        data.mode === "licensed"
          ? "已激活许可"
          : data.mode === "free"
            ? "免费额度（单集群）"
            : "未激活许可";
    }
    if (info) {
      setProp("#publicInfoIp", "textContent", info.ip || "-");
      setProp("#publicInfoHostname", "textContent", info.hostname || "-");
      setProp("#publicInfoOnline", "textContent", info.online ? "在线" : "离线/未上报");
      setProp("#publicInfoLocation", "value", info.location || "");
      setProp("#publicInfoPromo", "value", info.promo || "");
      const hiddenBox = $("#publicInfoHidden");
      if (hiddenBox) hiddenBox.checked = Boolean(info.hidden);
      if (data.mode === "free") {
        setProp(
          "#publicInfoMsg",
          "textContent",
          "当前为免费额度（单集群 1 台）：公开信息与优惠信息可正常推送；添加从节点需购买集群授权许可。",
        );
      } else if (data.mode !== "licensed") {
        setProp(
          "#publicInfoMsg",
          "textContent",
          "服务端尚未激活许可：当前修改无法推送，激活许可后才能公开到客户端服务端列表。",
        );
      } else {
        setProp("#publicInfoMsg", "textContent", "");
      }
    }
    setProp("#publicInfoError", "textContent", "");
  } catch (error) {
    if (error.status !== 401) setProp("#publicInfoError", "textContent", error.message);
  }
}

$("#publicInfoForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setProp("#publicInfoError", "textContent", "");
  setProp("#publicInfoMsg", "textContent", "");
  try {
    const data = await api("/api/admin/server-public-info", {
      location: $("#publicInfoLocation")?.value || "",
      promo: $("#publicInfoPromo")?.value || "",
      hidden: Boolean($("#publicInfoHidden")?.checked),
    });
    setProp(
      "#publicInfoMsg",
      "textContent",
      data.info?.hidden
        ? "已推送到授权中心：本服务器当前在客户端「服务器列表」中隐藏。"
        : "已推送到授权中心：客户端登录页左侧「服务器列表」已同步展示本服务器信息。",
    );
  } catch (error) {
    setProp("#publicInfoError", "textContent", error.message);
  }
});

$("#publicInfoRefresh")?.addEventListener("click", () => void loadPublicInfo());

// ---------- 0.10.0 注册与邮箱：开关 / SMTP / 测试邮箱 / 邮件模板 ----------
async function loadEmailSettings() {
  try {
    const data = await api("/api/admin/email-settings");
    setProp("#registerEnabledInput", "checked", Boolean(data.registerEnabled));
    setProp("#forgotEnabledInput", "checked", Boolean(data.forgotEnabled));
    setProp(
      "#emailCodeTtlInput",
      "value",
      String(data.emailCodeTtlMinutes ?? 10),
    );
    const smtp = data.smtp || {};
    setProp("#smtpHost", "value", smtp.host || "");
    setProp("#smtpPort", "value", smtp.port ? String(smtp.port) : "");
    setProp("#smtpUser", "value", smtp.user || "");
    setProp("#smtpFrom", "value", smtp.from || "");
    setProp("#smtpSecure", "checked", Boolean(smtp.secure));
    setProp("#smtpPass", "value", "");
    setProp("#smtpPassHint", "textContent", smtp.hasPass ? "已配置授权码（留空不修改）" : "尚未配置授权码");
    const badge = $("#smtpStateBadge");
    if (badge) {
      const ready = Boolean(smtp.host && smtp.user && smtp.hasPass);
      badge.textContent = ready ? "已配置" : "未配置";
      badge.classList.toggle("success", ready);
    }
    const templates = data.templates || {};
    setProp("#mailRegisterSubject", "value", templates.register?.subject || "");
    setProp("#mailRegisterBody", "value", templates.register?.body || "");
    setProp("#mailForgotSubject", "value", templates.forgot?.subject || "");
    setProp("#mailForgotBody", "value", templates.forgot?.body || "");
    setProp("#registerToggleError", "textContent", "");
    setProp("#smtpFormError", "textContent", "");
    setProp("#smtpFormMsg", "textContent", "");
    setProp("#mailTemplateError", "textContent", "");
    setProp("#mailTemplateMsg", "textContent", "");
  } catch (error) {
    if (error.status !== 401) toast(error.message, true);
  }
}

$("#registerToggleForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setProp("#registerToggleError", "textContent", "");
  try {
    await api("/api/admin/email-settings", {
      method: "PUT",
      body: JSON.stringify({
        registerEnabled: Boolean($("#registerEnabledInput")?.checked),
        forgotEnabled: Boolean($("#forgotEnabledInput")?.checked),
        emailCodeTtlMinutes: Number(getProp("#emailCodeTtlInput", "value")) || 10,
      }),
    });
    toast("功能开关已保存，客户端登录页即时生效");
  } catch (error) {
    setProp("#registerToggleError", "textContent", error.message);
  }
});

$("#smtpForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setProp("#smtpFormError", "textContent", "");
  setProp("#smtpFormMsg", "textContent", "");
  try {
    await api("/api/admin/email-settings", {
      method: "PUT",
      body: JSON.stringify({
        smtp: {
          host: (getProp("#smtpHost", "value") || "").trim(),
          port: Number(getProp("#smtpPort", "value")) || undefined,
          secure: Boolean($("#smtpSecure")?.checked),
          user: (getProp("#smtpUser", "value") || "").trim(),
          pass: getProp("#smtpPass", "value") || "",
          from: (getProp("#smtpFrom", "value") || "").trim(),
        },
      }),
    });
    setProp("#smtpFormMsg", "textContent", "SMTP 配置已保存；可用下方「发送测试邮件」验证");
    toast("SMTP 配置已保存");
    await loadEmailSettings();
  } catch (error) {
    setProp("#smtpFormError", "textContent", error.message);
  }
});

$("#smtpTestForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setProp("#smtpFormError", "textContent", "");
  const button = $("#smtpTestButton");
  if (button) button.disabled = true;
  try {
    const data = await api("/api/admin/email-settings/test", {
      method: "POST",
      body: JSON.stringify({ to: (getProp("#smtpTestTo", "value") || "").trim() }),
    });
    toast(data.message || "测试邮件已发送");
    setProp("#smtpFormMsg", "textContent", data.message || "测试邮件已发送，请查收");
  } catch (error) {
    setProp("#smtpFormError", "textContent", error.message);
  } finally {
    if (button) button.disabled = false;
  }
});

$("#mailTemplateForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setProp("#mailTemplateError", "textContent", "");
  setProp("#mailTemplateMsg", "textContent", "");
  try {
    await api("/api/admin/email-settings", {
      method: "PUT",
      body: JSON.stringify({
        templates: {
          register: {
            subject: getProp("#mailRegisterSubject", "value") || "",
            body: getProp("#mailRegisterBody", "value") || "",
          },
          forgot: {
            subject: getProp("#mailForgotSubject", "value") || "",
            body: getProp("#mailForgotBody", "value") || "",
          },
        },
      }),
    });
    setProp("#mailTemplateMsg", "textContent", "邮件模板已保存，占位符将在发送时替换为实际值");
    toast("邮件模板已保存");
  } catch (error) {
    setProp("#mailTemplateError", "textContent", error.message);
  }
});


function frpMessage(text, isError) {
  const msg = $("#frpMessage");
  msg.textContent = text || "";
  msg.classList.toggle("error-text", Boolean(isError));
}

async function loadFrpcCache() {
  const body = $("#frpcCacheBody");
  try {
    const data = await api("/api/admin/frp");
    const items = data.frpcCache || [];
    if (!items.length) {
      body.innerHTML = '<tr><td colspan="6" class="muted">暂无缓存，可从授权中心预拉取或手动上传</td></tr>';
    } else {
      body.innerHTML = items
        .map(
          (item) => `
        <tr>
          <td>${escapeHtml(item.platform)}</td>
          <td class="mono">${escapeHtml(item.arch)}</td>
          <td>${item.version ? "v" + escapeHtml(item.version) : '<span class="muted">未知</span>'}</td>
          <td>${formatBytes(item.fileSize)}</td>
          <td>${item.cachedAt ? new Date(item.cachedAt).toLocaleString() : "-"}</td>
          <td>
            <button class="button ghost danger" type="button" data-frpc-delete="${escapeHtml(item.platform)}/${escapeHtml(item.arch)}">
              <i data-lucide="trash-2" class="icon"></i> 删除
            </button>
          </td>
        </tr>`,
        )
        .join("");
      icons();
    }
    frpMessage("");
  } catch (error) {
    if (error.status !== 401) {
      body.innerHTML = '<tr><td colspan="6" class="muted">加载失败</td></tr>';
      frpMessage(error.message, true);
    }
  }
}

async function fetchFrpc() {
  const btn = $("#fetchFrpcButton");
  const platform = $("#frpcFetchPlatform").value;
  const arch = $("#frpcFetchArch").value;
  frpMessage("");
  btn.disabled = true;
  btn.textContent = "正在拉取...";
  try {
    const data = await api("/api/admin/frp/frpc/fetch", {
      method: "POST",
      body: JSON.stringify({ platform, arch }),
    });
    const item = data.item || {};
    frpMessage(`已缓存 frpc ${platform}/${arch}${item.version ? " v" + item.version : ""}（${formatBytes(item.fileSize)}）`, false);
    await loadFrpcCache();
  } catch (error) {
    frpMessage(error.message, true);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="download-cloud" class="icon"></i> 拉取并缓存';
    icons();
  }
}

async function uploadFrpc(file) {
  const platform = $("#frpcUploadPlatform").value;
  const arch = $("#frpcUploadArch").value;
  const btn = $("#uploadFrpcButton");
  frpMessage("");
  btn.disabled = true;
  btn.textContent = "上传中...";
  try {
    const resp = await fetch(
      `/api/admin/frp/frpc/upload?platform=${encodeURIComponent(platform)}&arch=${encodeURIComponent(arch)}`,
      {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/octet-stream" },
        body: file,
      },
    );
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || `上传失败（HTTP ${resp.status}）`);
    const item = data.item || {};
    frpMessage(`已上传 frpc ${platform}/${arch}（${formatBytes(item.fileSize)}）`, false);
    await loadFrpcCache();
  } catch (error) {
    frpMessage(error.message, true);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i data-lucide="upload" class="icon"></i> 选择文件上传';
    icons();
  }
}

async function deleteFrpcCache(platform, arch) {
  if (!confirm(`确认删除缓存的 frpc ${platform}/${arch}？客户端下次拉取时会重新从授权中心下载。`)) return;
  try {
    await api(`/api/admin/frp/frpc/${platform}/${arch}`, { method: "DELETE" });
    frpMessage(`已删除 frpc ${platform}/${arch}`, false);
    await loadFrpcCache();
  } catch (error) {
    frpMessage(error.message, true);
  }
}

// ---------- 网络设置（管理端口 + HTTPS） ----------
function renderNetwork(network) {
  setProp("#networkPort", "value", network.port ?? "");
  setProp(
    "#networkPortHint",
    "textContent",
    network.envLockedPort
      ? "端口由环境变量 MANAGER_PORT 固定，无法在此修改"
      : "保存后重启服务端生效，默认 8080",
  );
  $("#networkPort").disabled = Boolean(network.envLockedPort);
  $("#networkHttps").checked = Boolean(network.httpsEnabled);
  setProp(
    "#networkHttpsState",
    "textContent",
    network.httpsActive
      ? "HTTPS 已启用（重启后生效于当前会话前请勿关闭原入口）"
      : network.httpsEnabled && !network.certReady
        ? "已开启但证书缺失，实际仍为 HTTP"
        : "未启用（HTTP）",
  );
  setProp("#networkCertState", "textContent", network.certReady ? "已上传" : "未上传");
  setProp("#networkCertBadge", "className", `badge ${network.certReady ? "success" : ""}`.trim());
  setProp("#networkCertBadge", "textContent", network.certReady ? "已就绪" : "未上传");
}

async function loadNetwork() {
  try {
    const data = await api("/api/admin/network");
    renderNetwork(data.network);
  } catch (error) {
    toast(error.message, true);
  }
}

async function uploadNetworkCert(kind, file) {
  try {
    const resp = await fetch(`/api/admin/network/cert?kind=${kind}`, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/octet-stream" },
      body: file,
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || `上传失败（HTTP ${resp.status}）`);
    toast(`${kind === "cert" ? "证书" : "私钥"}已上传`);
    renderNetwork(data.network);
  } catch (error) {
    toast(error.message, true);
  }
}

// ---------- 账号（管理员用户名） ----------
async function loadAccount() {
  setProp("#adminUsernameNow", "value", state.overview?.admin?.username || "-");
  setProp("#usernameFormError", "textContent", "");
}

function bindLogoPicker(kind) {
  const chooseBtn = $(`#${kind}LogoChoose`);
  const fileInput = $(`#${kind}LogoFile`);
  const removeBtn = $(`#${kind}LogoRemove`);
  chooseBtn?.addEventListener("click", () => fileInput?.click());
  fileInput?.addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > 800_000) {
      toast("Logo 需小于 800KB", true);
      event.target.value = "";
      return;
    }
    const dataUrl = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(new Error("图片读取失败"));
      reader.readAsDataURL(file);
    });
    pendingLogo[kind] = dataUrl;
    updateLogoPreview(kind, dataUrl);
  });
  removeBtn?.addEventListener("click", () => {
    pendingLogo[kind] = "";
    if (fileInput) fileInput.value = "";
    updateLogoPreview(kind, null);
  });
}

function bindBrandingForm(kind, nameField, errorId) {
  const form = $(`#${kind}BrandingForm`);
  form?.addEventListener("submit", async (event) => {
    event.preventDefault();
    setProp(`#${errorId}`, "textContent", "");
    try {
      const payload = { [nameField]: getProp(`#${nameField}`, "value") ?? "" };
      if (pendingLogo[kind] !== undefined) payload[`${kind}Logo`] = pendingLogo[kind];
      const { branding } = await api("/api/admin/branding", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      pendingLogo[kind] = undefined;
      updateLogoPreview(kind, branding[`${kind}LogoUrl`]);
      if (kind === "site") applySiteBranding(branding);
      toast(kind === "site" ? "控制台品牌已保存" : "客户端品牌已保存，在线客户端数秒内自动生效");
    } catch (error) {
      setProp(`#${errorId}`, "textContent", error.message);
    }
  });
}

// ---------- 0.10.0.2 二维授权：节点端口池加载与节点选择器 ----------
async function loadClusterPools() {
  try {
    const data = await api("/api/admin/cluster/pools");
    state.clusterPools = data.pools || [];
  } catch {
    state.clusterPools = [{ node: "master", label: "主节点", isMaster: true, online: true, used: 0, total: 0 }];
  }
  return state.clusterPools;
}

// required=true 时首项为空（「请先选定目标节点」），用于开号/套餐码；用户对话框默认选中指定节点。
function fillNodeSelect(select, { required = false, selected = "" } = {}) {
  if (!select) return;
  const pools = state.clusterPools.length
    ? state.clusterPools
    : [{ node: "master", label: "主节点", isMaster: true, used: 0, total: 0 }];
  const options = pools.map((pool) => {
    const name = pool.isMaster ? `主节点${pool.label ? `（${pool.label}）` : ""}` : pool.node;
    const usage = Number.isFinite(pool.total) && pool.total > 0 ? ` · 已用 ${pool.used}/${pool.total}` : "";
    return `<option value="${escapeHtml(pool.node)}">${escapeHtml(name + usage)}</option>`;
  });
  select.innerHTML = required ? `<option value="">请先选定目标节点</option>${options.join("")}` : options.join("");
  select.value = required ? selected || "" : selected || "master";
}

function nodePortPoolHint(node) {
  const pool = (state.clusterPools || []).find((item) => item.node === node);
  if (!pool) return "多个端口段用逗号分隔";
  return `${pool.isMaster ? "主节点" : node} 端口池已用 ${pool.used}/${pool.total}；多个端口段用逗号分隔`;
}

// 组装用户端口段文本：master 节点用纯端口段，从节点带 `节点名:` 前缀（服务端 parsePortRanges 支持）。
// 0.10.1.2 规格3：当前节点选择无效（未加载/已删除）时返回 null 并由 saveUser 明确报错终止，
// 禁止把输入回填到主节点（旧行为 `|| "master"` 会把从节点端口静默写到主节点）。
// 0.10.1.5：填 0 或留空 = 收回该节点全部端口并取消关联（该节点不可再使用）；
// 全部节点均被收回时返回 "0"（服务端按无端口处理，tokenVersion 自增踢下线）。
function buildUserRangesPayload() {
  const select = $("#userNodeSelect");
  const node = (select?.value || "").trim();
  if (!node || !select?.querySelector(`option[value="${CSS.escape(node)}"]`)) {
    return null;
  }
  // 0.10.1.3 规格2：当前编辑节点（dataset.currentNode）必须与下拉实际选中值一致，
  // 否则输入会被记到错误节点名下（曾把从节点端口写进主节点）——不一致时拒绝保存。
  if (select.dataset.currentNode && select.dataset.currentNode !== node) {
    return null;
  }
  const map = state.userRangesByNode || {};
  const raw = (getProp("#portRanges", "value") || "").trim();
  if (!raw || raw === "0") {
    delete map[node];
  } else {
    map[node] = raw;
  }
  state.userRangesByNode = map;
  const parts = [];
  for (const [name, text] of Object.entries(map)) {
    const clean = String(text || "").trim();
    if (!clean || clean === "0") continue;
    parts.push(name === "master" ? clean : `${name}:${clean}`);
  }
  return parts.length ? parts.join(", ") : "0";
}

// 0.10.1.5：收回当前节点端口并取消关联（清空输入 + 从暂存移除，保存后生效）。
$("#revokeNodePorts")?.addEventListener("click", () => {
  const select = $("#userNodeSelect");
  const node = select?.value || "master";
  const map = state.userRangesByNode || {};
  delete map[node];
  state.userRangesByNode = map;
  setProp("#portRanges", "value", "");
  const remaining = Object.values(map).filter((text) => String(text || "").trim());
  setProp(
    "#portRangesHint",
    "textContent",
    `已收回 ${node === "master" ? "主节点" : node} 的端口，保存后取消关联（该节点不可再使用）${
      remaining.length ? `；仍保留 ${remaining.length} 个节点` : "；保存后该用户将无任何可用节点"
    }`,
  );
});

// 0.10.1.5：收回全部端口——清空所有节点关联，保存后该用户无法使用任何节点。
$("#revokeAllPorts")?.addEventListener("click", () => {
  state.userRangesByNode = {};
  setProp("#portRanges", "value", "");
  setProp("#portRangesHint", "textContent", "已收回全部节点端口，保存后该用户将无法使用任何节点");
});

// 切换授权节点：暂存当前输入到原节点，载入目标节点已有的端口段。
$("#userNodeSelect")?.addEventListener("change", () => {
  const select = $("#userNodeSelect");
  if (!select) return;
  const node = select.value || "master";
  const previous = select.dataset.currentNode || "master";
  const map = state.userRangesByNode || {};
  map[previous] = (getProp("#portRanges", "value") || "").trim();
  state.userRangesByNode = map;
  select.dataset.currentNode = node;
  setProp("#portRanges", "value", map[node] || "");
  setProp("#portRangesHint", "textContent", nodePortPoolHint(node));
});

// 0.10.1.2 规格9：编辑用户对话框多 Tab 切换（重置到第一个 Tab 用 activeUserDialogTab）。
function activeUserDialogTab(name = "base") {
  $$("#userDialogTabs .dialog-tab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.userTab === name);
  });
  $$("[data-user-panel]").forEach((panel) => {
    panel.classList.toggle("hidden", panel.dataset.userPanel !== name);
  });
}

$("#userDialogTabs")?.addEventListener("click", (event) => {
  const tab = event.target.closest("[data-user-tab]");
  if (tab) activeUserDialogTab(tab.dataset.userTab);
});

async function openUserDialog(user = null) {
  if (!state.plansLoaded) {
    try {
      const data = await api("/api/admin/plans");
      state.plans = data.plans;
      state.plansLoaded = true;
    } catch {
      /* 套餐加载失败不阻塞用户编辑 */
    }
  }
  // 0.10.1.2 规格9：每次打开重置到「基本信息」Tab。
  activeUserDialogTab("base");
  setProp("#userDialogTitle", "textContent", user ? "编辑用户" : "新建用户");
  setProp("#userId", "value", user?.id || "");
  setProp("#userUid", "value", user?.uid || "");
  setProp("#username", "value", user?.username || "");
  setProp("#userPassword", "value", "");
  setProp("#userPassword", "required", false);
  setProp("#passwordHint", "textContent", user ? "留空则保持原密码；填写则重置为新初始密码" : "至少 8 位；留空自动生成初始密码");
  // 0.10.0.2：先选节点 → 再选该节点的端口。按节点分组暂存端口段，切换节点时换组编辑。
  await loadClusterPools();
  const rangesByNode = {};
  for (const range of user?.portRanges || []) {
    const node = range.node || "master";
    const segment = range.start === range.end ? String(range.start) : `${range.start}-${range.end}`;
    rangesByNode[node] = rangesByNode[node] ? `${rangesByNode[node]}, ${segment}` : segment;
  }
  state.userRangesByNode = rangesByNode;
  const initialNode = Object.keys(rangesByNode)[0] || "master";
  const nodeSelect = $("#userNodeSelect");
  fillNodeSelect(nodeSelect, { selected: initialNode });
  // 0.10.1.3 规格2：端口段所属节点可能不在端口池列表（端口池加载失败兜底只剩主节点、
  // 节点已删除/改名、离线节点等）——此时 select.value 静默回落第一项（主节点），
  // 用户编辑的却是原节点端口文本，保存后端口被串到主节点。
  // 修复：把这类节点作为选项补进下拉（标注「离线/不存在」），保证所选节点与文本归属一致。
  if (nodeSelect) {
    for (const [name, text] of Object.entries(rangesByNode)) {
      if (name === "master" || !text || nodeSelect.querySelector(`option[value="${CSS.escape(name)}"]`)) {
        continue;
      }
      const option = document.createElement("option");
      option.value = name;
      option.textContent = `${name}（离线/不存在）`;
      nodeSelect.appendChild(option);
    }
    // fillNodeSelect 对缺失选项的 selected 赋值是 no-op——这里以实际存在的选项为准回正选中值。
    nodeSelect.value = nodeSelect.querySelector(`option[value="${CSS.escape(initialNode)}"]`)
      ? initialNode
      : nodeSelect.value || "master";
    nodeSelect.dataset.currentNode = nodeSelect.value;
  }
  const selectedNode = nodeSelect?.value || "master";
  setProp("#portRanges", "value", rangesByNode[selectedNode] ?? "");
  setProp("#portRangesHint", "textContent", nodePortPoolHint(selectedNode));
  // 0.9.3：固定到期时间改为套餐天数（激活时起算）；0.10.1.0：已激活账号到期时间管理员可直接修改。
  setProp("#userDurationDays", "value", user?.durationDays ?? 30);
  const durationInput = $("#userDurationDays");
  const expiresField = $("#userExpiresField");
  const activatedUser = Boolean(user?.activated);
  if (durationInput) durationInput.disabled = activatedUser;
  if (expiresField) expiresField.classList.toggle("hidden", !activatedUser);
  if (activatedUser) {
    setProp("#userExpiresAt", "value", toDatetimeLocalValue(user.expiresAt));
    setProp("#userDurationHint", "textContent", "账号已激活，套餐天数已起算且不可修改；到期时间可在下方直接调整");
  } else {
    setProp("#userExpiresAt", "value", "");
    setProp("#userDurationHint", "textContent", "有效期天数；首次登录（改密激活）后才开始计算");
  }
  const enabledBox = $("#userEnabled");
  if (enabledBox) enabledBox.checked = user?.enabled ?? true;
  const mustChangeBox = $("#userMustChangePassword");
  if (mustChangeBox) mustChangeBox.checked = user ? !!user.mustChangePassword : true;
  const httpAllowedBox = $("#userHttpAllowed");
  if (httpAllowedBox) httpAllowedBox.checked = !!user?.httpAllowed;
  const planSelect = $("#userPlan");
  if (planSelect) {
    planSelect.innerHTML =
      `<option value="">不关联套餐</option>` +
      state.plans
        .map(
          (plan) =>
            `<option value="${plan.id}">${escapeHtml(plan.name)}（${plan.durationDays}天 / ${
              plan.trafficLimitBytes > 0 ? `${plan.trafficGB}GB / ` : "不限流量 / "
            }${plan.rateLimitBps > 0 ? `限${Math.round(plan.rateLimitMbps)}M / ` : ""}${plan.portCount}口 / ¥${plan.priceYuan}）</option>`,
        )
        .join("");
    planSelect.value = user?.planId ? String(user.planId) : "";
  }
  // 0.9.2：限速单位 Mbps（兆比特/秒），落库为比特/秒（×1_000_000）。
  setProp(
    "#rateLimitBps",
    "value",
    user ? Math.floor((user.rateLimitBps || 0) / 1_000_000) : 0,
  );
  setProp(
    "#trafficLimitBytes",
    "value",
    user ? Math.floor((user.trafficLimitBytes || 0) / 1048576) : 0,
  );
  setProp("#userFormError", "textContent", "");
  $("#userDialog")?.showModal();
}

function openRenewDialog(user) {
  setProp("#renewUserId", "value", user.id);
  setProp("#renewUsername", "textContent", user.username);
  // 0.9.3：未激活账号续费累加套餐天数；已激活则顺延期到期时间。
  setProp(
    "#renewCurrentExpiry",
    "textContent",
    user.activated
      ? formatDate(user.expiresAt)
      : `未激活（套餐 ${user.durationDays} 天，激活后起算；续费将累加天数）`,
  );
  setProp("#renewDays", "value", "30");
  setProp("#renewNote", "value", "");
  setProp("#renewFormError", "textContent", "");
  $("#renewDialog")?.showModal();
}

async function saveRenewal(event) {
  event.preventDefault();
  const id = getProp("#renewUserId", "value");
  setProp("#renewFormError", "textContent", "");
  try {
    await api(`/api/admin/users/${id}/renew`, {
      method: "POST",
      body: JSON.stringify({
        days: Number(getProp("#renewDays", "value") || 0),
        note: getProp("#renewNote", "value") || "",
      }),
    });
    $("#renewDialog")?.close();
    toast("用户续费成功");
    await refresh();
  } catch (error) {
    setProp("#renewFormError", "textContent", error.message);
  }
}

// ISO 时间 → datetime-local 输入值（本地时区，分钟精度）。
function toDatetimeLocalValue(iso) {
  if (!iso) return "";
  const date = new Date(iso);
  if (!Number.isFinite(date.getTime())) return "";
  const pad = (n) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

async function saveUser(event) {
  event.preventDefault();
  const id = getProp("#userId", "value") || "";
  // 0.10.1.2 规格3：端口段组装失败（节点选择无效）时明确报错并终止，不跨节点回填。
  const portRanges = buildUserRangesPayload();
  if (portRanges === null) {
    setProp("#userFormError", "textContent", "授权节点无效或未选择，请重新选择节点后再保存");
    return;
  }
  const payload = {
    uid: (getProp("#userUid", "value") || "").trim() || undefined,
    username: getProp("#username", "value") || "",
    password: getProp("#userPassword", "value") || undefined,
    portRanges,
    enabled: $("#userEnabled")?.checked ?? true,
    rateLimitBps: (Number(getProp("#rateLimitBps", "value") || 0)) * 1_000_000,
    trafficLimitBytes: (Number(getProp("#trafficLimitBytes", "value") || 0)) * 1048576,
    planId: Number(getProp("#userPlan", "value") || 0) || null,
    mustChangePassword: $("#userMustChangePassword")?.checked ?? false,
    httpAllowed: $("#userHttpAllowed")?.checked ?? false,
  };
  // 0.9.3：套餐天数仅未激活账号可提交；已激活账号的天数锁定。
  if (!$("#userDurationDays")?.disabled) {
    payload.durationDays = Number(getProp("#userDurationDays", "value") || 30);
  } else {
    // 0.10.1.0：已激活账号管理员直接修改到期时间（空值 = 清除到期限制）。
    const expiresValue = getProp("#userExpiresAt", "value") || "";
    payload.expiresAt = expiresValue
      ? new Date(expiresValue).toISOString()
      : "";
  }
  setProp("#userFormError", "textContent", "");
  try {
    await api(id ? `/api/admin/users/${id}` : "/api/admin/users", {
      method: id ? "PUT" : "POST",
      body: JSON.stringify(payload),
    });
    $("#userDialog")?.close();
    toast(id ? "用户已更新" : "用户已创建");
    await refresh();
  } catch (error) {
    setProp("#userFormError", "textContent", error.message);
  }
}

async function userAction(action, id) {
  const user = state.users.find((item) => item.id === Number(id));
  if (!user) return;
  if (action === "edit") {
    openUserDialog(user);
    return;
  }
  if (action === "renew") {
    openRenewDialog(user);
    return;
  }
  if (action === "mappings") {
    setProp("#mappingSearch", "value", user.username);
    state.mappingFilter = "all";
    $$("[data-mapping-filter]").forEach((button) =>
      button.setAttribute("aria-pressed", String(button.dataset.mappingFilter === "all")),
    );
    renderMappings();
    switchView("mappings");
    return;
  }
  if (action === "disconnect") {
    if (!confirm(`强制断开 ${user.username} 的现有连接？`)) return;
    try {
      await api(`/api/admin/users/${id}/disconnect`, { method: "POST" });
      toast("下线指令已生效");
      await refresh();
    } catch (error) {
      toast(error.message, true);
    }
    return;
  }
  if (action === "reset-traffic") {
    if (!confirm(`重置 ${user.username} 的流量计数为 0？`)) return;
    try {
      await api(`/api/admin/users/${id}/reset-traffic`, { method: "POST" });
      toast("流量计数已重置");
      await refresh();
    } catch (error) {
      toast(error.message, true);
    }
    return;
  }
  // 0.10.1.5：收回用户全部端口并取消所有节点关联（确认后生效，该用户无法再使用任何节点）。
  if (action === "revoke-ports") {
    if (!user.portRanges?.length) {
      toast("该用户当前没有已分配的端口", true);
      return;
    }
    if (
      !confirm(
        `收回用户 ${user.username} 的全部端口并取消所有节点关联？收回后该用户将无法使用任何节点，其现有映射也将停止。`,
      )
    ) {
      return;
    }
    try {
      await api(`/api/admin/users/${id}`, {
        method: "PUT",
        body: JSON.stringify({ portRanges: "0" }),
      });
      toast("已收回全部端口并取消节点关联");
      await refresh();
    } catch (error) {
      toast(error.message, true);
    }
    return;
  }
  if (action === "delete") {
    if (!confirm(`删除用户 ${user.username}？此操作无法撤销。`)) return;
    try {
      await api(`/api/admin/users/${id}`, { method: "DELETE" });
      toast("用户已删除");
      await refresh();
    } catch (error) {
      toast(error.message, true);
    }
  }
}

// ---------- 0.9.0 套餐管理与批量开号 ----------

async function loadPlans() {
  try {
    const [plansData, poolData] = await Promise.all([
      api("/api/admin/plans"),
      api("/api/admin/port-pool"),
    ]);
    state.plans = plansData.plans;
    state.plansLoaded = true;
    state.portPool = poolData.portPool || "";
    renderPlans();
  } catch (error) {
    if (error.status === 401) {
      showLogin();
      return;
    }
    toast(error.message, true);
  }
}

function renderPlans() {
  const cards = $("#planCards");
  if (!cards) return;
  const plans = [...state.plans].sort((a, b) => a.sortOrder - b.sortOrder || a.id - b.id);
  setProp("#plansEmpty", "hidden", plans.length !== 0);
  cards.innerHTML = plans.map(planCardHtml).join("");
  const select = $("#batchPlan");
  if (select) {
    const current = select.value;
    select.innerHTML = plans
      .map(
        (plan) =>
          `<option value="${plan.id}">${escapeHtml(plan.name)}（${plan.durationDays}天 / ${
            plan.trafficLimitBytes > 0 ? `${plan.trafficGB}GB / ` : "不限流量 / "
          }${plan.rateLimitBps > 0 ? `限${Math.round(plan.rateLimitMbps)}M / ` : ""}${plan.portCount}口 / ¥${plan.priceYuan}）</option>`,
      )
      .join("");
    select.value = current || (plans[0] ? String(plans[0].id) : "");
  }
  const poolInput = $("#portPoolInput");
  if (poolInput && document.activeElement !== poolInput) {
    poolInput.value = state.portPool;
  }
  setProp("#portPoolMsg", "textContent", "多个端口段用逗号分隔，例如 20000-30000, 31000-32000");
  // 0.10.0：套餐码生成表单的套餐下拉框同步填充（loadPlans 与 loadPlanCodes 并行到达的兜底）。
  const planCodeSelect = $("#planCodePlanSelect");
  if (planCodeSelect) {
    const currentCode = planCodeSelect.value;
    planCodeSelect.innerHTML = plans
      .map((plan) => `<option value="${plan.id}">${escapeHtml(plan.name)}</option>`)
      .join("");
    planCodeSelect.value = currentCode || (plans[0] ? String(plans[0].id) : "");
  }
  icons();
}

function planCardHtml(plan) {
  const traffic = plan.trafficLimitBytes > 0 ? `${plan.trafficGB} GB 流量` : "不限流量";
  const recommended = /推荐/.test(plan.name);
  return `
    <article class="plan-card${recommended ? " recommended" : ""}">
      <div class="plan-card-head">
        <h3>${escapeHtml(plan.name)}</h3>
        ${recommended ? '<span class="badge success">推荐</span>' : ""}
      </div>
      <div class="plan-price"><small>¥</small>${plan.priceYuan}<small> / ${plan.durationDays} 天</small></div>
      <ul class="plan-features">
        <li><i data-lucide="calendar-days" class="icon"></i>时长 ${plan.durationDays} 天</li>
        <li><i data-lucide="gauge" class="icon"></i>${traffic}</li>
        <li><i data-lucide="activity" class="icon"></i>${plan.rateLimitBps > 0 ? `限速 ${Math.round(plan.rateLimitMbps)} Mbps` : "不限速度"}</li>
        <li><i data-lucide="network" class="icon"></i>${plan.portCount} 个端口</li>
        <li><i data-lucide="users" class="icon"></i>${plan.userCount} 个账号在用</li>
      </ul>
      <div class="plan-card-actions">
        <button class="button" type="button" data-plan-action="batch" data-id="${plan.id}">
          <i data-lucide="users-round" class="icon"></i>开号
        </button>
        <button class="button ghost icon-only" type="button" data-plan-action="edit" data-id="${plan.id}" title="编辑">
          <i data-lucide="pencil" class="icon"></i>
        </button>
        <button class="button ghost icon-only" type="button" data-plan-action="delete" data-id="${plan.id}" title="删除">
          <i data-lucide="trash-2" class="icon"></i>
        </button>
      </div>
    </article>
  `;
}

function openPlanDialog(plan = null) {
  setProp("#planDialogTitle", "textContent", plan ? "编辑套餐" : "新建套餐");
  setProp("#planId", "value", plan?.id || "");
  setProp("#planName", "value", plan?.name || "");
  setProp("#planDuration", "value", plan?.durationDays ?? 30);
  setProp("#planPorts", "value", plan?.portCount ?? 5);
  setProp("#planTraffic", "value", plan ? plan.trafficGB : 0);
  // 0.10.2.1：套餐限速单位 Mbps（存储 bps）；0 表示不限速。
  setProp("#planRateLimit", "value", plan ? Math.round(plan.rateLimitMbps || 0) : 0);
  setProp("#planPrice", "value", plan ? plan.priceYuan : 9.9);
  setProp("#planSort", "value", plan?.sortOrder ?? 0);
  setProp("#planFormError", "textContent", "");
  $("#planDialog")?.showModal();
}

async function savePlan(event) {
  event.preventDefault();
  const id = getProp("#planId", "value") || "";
  const payload = {
    name: (getProp("#planName", "value") || "").trim(),
    durationDays: Number(getProp("#planDuration", "value") || 0),
    portCount: Number(getProp("#planPorts", "value") || 0),
    trafficGB: Number(getProp("#planTraffic", "value") || 0),
    rateLimitMbps: Number(getProp("#planRateLimit", "value") || 0),
    priceYuan: Number(getProp("#planPrice", "value") || 0),
    sortOrder: Number(getProp("#planSort", "value") || 0),
  };
  setProp("#planFormError", "textContent", "");
  try {
    await api(id ? `/api/admin/plans/${id}` : "/api/admin/plans", {
      method: id ? "PUT" : "POST",
      body: JSON.stringify(payload),
    });
    $("#planDialog")?.close();
    toast(id ? "套餐已更新" : "套餐已创建");
    await loadPlans();
  } catch (error) {
    setProp("#planFormError", "textContent", error.message);
  }
}

async function planAction(action, id) {
  const plan = state.plans.find((item) => item.id === Number(id));
  if (action === "edit") {
    if (plan) openPlanDialog(plan);
    return;
  }
  if (action === "batch") {
    openBatchDialog(plan || null);
    return;
  }
  if (action === "delete") {
    if (!plan) return;
    if (!confirm(`删除套餐「${plan.name}」？已开通账号的套餐快照不受影响。`)) return;
    try {
      await api(`/api/admin/plans/${plan.id}`, { method: "DELETE" });
      toast("套餐已删除");
      await loadPlans();
    } catch (error) {
      toast(error.message, true);
    }
  }
}

// ---------- 0.10.0 套餐码管理：生成 / 列表 / 导出 / 删除 ----------
async function loadPlanCodes() {
  try {
    const params = new URLSearchParams();
    const status = getProp("#planCodeStatusFilter", "value") || "";
    const batchId = (getProp("#planCodeBatchFilter", "value") || "").trim();
    if (status) params.set("status", status);
    if (batchId) params.set("batchId", batchId);
    const query = params.toString();
    const data = await api(`/api/admin/plan-codes${query ? `?${query}` : ""}`);
    state.planCodes = data.codes || [];
    state.planCodesLoaded = true;
    renderPlanCodes();
  } catch (error) {
    if (error.status === 401) {
      showLogin();
      return;
    }
    toast(error.message, true);
  }
}

function planCodeStatusLabel(status) {
  if (status === "unused") return '<span class="badge success">未使用</span>';
  if (status === "used") return '<span class="badge">已使用</span>';
  if (status === "disabled") return '<span class="badge danger">已禁用</span>';
  return `<span class="badge">${escapeHtml(status)}</span>`;
}

function renderPlanCodes() {
  const rows = $("#planCodeRows");
  if (!rows) return;
  const codes = state.planCodes;
  setProp("#planCodesEmpty", "hidden", codes.length !== 0);
  rows.innerHTML = codes
    .map(
      (item) => `
      <tr data-plan-code-id="${item.id}">
        <td class="check-cell"><input type="checkbox" data-plan-code-check value="${item.id}" /></td>
        <td class="mono">${escapeHtml(item.code)}</td>
        <td>${escapeHtml(item.planName || "-")}</td>
        <td>${item.nodeName === "master" ? "主节点" : escapeHtml(item.nodeName || "主节点")}</td>
        <td class="mono">${escapeHtml(item.batchId || "-")}</td>
        <td>${planCodeStatusLabel(item.status)}</td>
        <td>${escapeHtml(item.usedByName || "-")}</td>
        <td>${formatDate(item.usedAt)}</td>
        <td>${formatDate(item.createdAt)}</td>
      </tr>`,
    )
    .join("");
  // 套餐码生成表单的套餐下拉框与批量开号下拉框同步填充。
  const select = $("#planCodePlanSelect");
  if (select) {
    const current = select.value;
    const plans = [...state.plans].sort((a, b) => a.sortOrder - b.sortOrder || a.id - b.id);
    select.innerHTML = plans
      .map((plan) => `<option value="${plan.id}">${escapeHtml(plan.name)}</option>`)
      .join("");
    select.value = current || (plans[0] ? String(plans[0].id) : "");
  }
  icons();
}

$("#planCodeGenerateButton")?.addEventListener("click", async () => {
  const form = $("#planCodeGenerateForm");
  const willShow = form?.classList.contains("hidden");
  if (willShow) {
    // 0.10.0.2：生成套餐码前必须先选定目标节点。
    await loadClusterPools();
    fillNodeSelect($("#planCodeNode"), { required: true });
  }
  form?.classList.toggle("hidden");
});

$("#planCodeGenerateForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const node = getProp("#planCodeNode", "value") || "";
  if (!node) {
    toast("请先选定目标节点，再生成套餐码", true);
    return;
  }
  try {
    const data = await api("/api/admin/plan-codes", {
      method: "POST",
      body: JSON.stringify({
        node,
        planId: Number(getProp("#planCodePlanSelect", "value") || 0),
        count: Number(getProp("#planCodeCount", "value") || 0),
      }),
    });
    toast(`已生成 ${data.codes.length} 个套餐码（批次 ${data.batchId}）`);
    setProp("#planCodeBatchFilter", "value", data.batchId);
    setProp("#planCodeStatusFilter", "value", "");
    await loadPlanCodes();
  } catch (error) {
    toast(error.message, true);
  }
});

$("#planCodeStatusFilter")?.addEventListener("change", () => void loadPlanCodes());
$("#planCodeRefresh")?.addEventListener("click", () => void loadPlanCodes());

$("#planCodeCheckAll")?.addEventListener("change", (event) => {
  const checked = Boolean(event.target.checked);
  $$("[data-plan-code-check]").forEach((box) => {
    box.checked = checked;
  });
});

$("#planCodeExport")?.addEventListener("click", () => {
  const params = new URLSearchParams();
  const status = getProp("#planCodeStatusFilter", "value") || "unused";
  const batchId = (getProp("#planCodeBatchFilter", "value") || "").trim();
  params.set("status", status);
  if (batchId) params.set("batchId", batchId);
  window.open(`/api/admin/plan-codes/export?${params.toString()}`, "_blank");
});

$("#planCodeDeleteSelected")?.addEventListener("click", async () => {
  const ids = $$("[data-plan-code-check]")
    .filter((box) => box.checked)
    .map((box) => Number(box.value))
    .filter(Number.isInteger);
  if (ids.length === 0) {
    toast("请先勾选要删除的套餐码", true);
    return;
  }
  if (!confirm(`删除选中的 ${ids.length} 个套餐码？已使用的套餐码不会被删除。`)) return;
  try {
    const data = await api("/api/admin/plan-codes/delete", {
      method: "POST",
      body: JSON.stringify({ ids }),
    });
    toast(`已删除 ${data.deleted} 个套餐码`);
    await loadPlanCodes();
  } catch (error) {
    toast(error.message, true);
  }
});

// ---------- 0.10.0 集群管理：名称 / 节点列表 / 自动部署 / 删除 ----------
async function loadCluster() {
  try {
    const data = await api("/api/admin/cluster/nodes");
    setProp("#clusterNameInput", "value", data.clusterName || "");
    setProp("#clusterDisplayNameInput", "value", data.serverDisplayName || "");
    // 0.10.2.0：集群 id 展示（授权中心心跳分配，客户端可凭该 id 登录集群）。
    const clusterIdLine = $("#clusterIdLine");
    if (clusterIdLine) {
      clusterIdLine.classList.toggle("hidden", !data.clusterId);
      setProp("#clusterIdValue", "textContent", data.clusterId || "");
    }
    // 0.10.1.3 规格1：主节点自身 frps 概况（状态/日志），供集群页主节点行展示。
    state.clusterMasterFrps = data.masterFrps || null;
    renderClusterRows(data.nodes || []);
  } catch (error) {
    if (error.status === 401) {
      showLogin();
      return;
    }
    toast(error.message, true);
  }
  try {
    const env = await api("/api/admin/cluster/env");
    setProp("#clusterRoleBadge", "textContent", env.isLinux ? "主节点" : "主节点（非 Linux）");
    setProp("#clusterRoleBadge", "className", "badge success");
    setProp("#clusterEnvPlatform", "textContent", env.platform);
    const sshpassBadge = $("#clusterEnvSshpass");
    if (sshpassBadge) {
      sshpassBadge.textContent = env.sshpassInstalled ? "已安装" : "未安装";
      sshpassBadge.className = `badge${env.sshpassInstalled ? " success" : " danger"}`;
    }
    const frpsBadge = $("#clusterEnvFrps");
    if (frpsBadge) {
      frpsBadge.textContent = env.frpsInstalled ? "已安装" : "未安装";
      frpsBadge.className = `badge${env.frpsInstalled ? " success" : " danger"}`;
    }
    setProp("#clusterEnvDeployDir", "textContent", env.deployDir);
    const warning = $("#clusterEnvWarning");
    if (warning) {
      const problems = [];
      if (!env.isLinux) problems.push("自动部署仅支持 Linux 主节点");
      if (!env.sshpassInstalled) problems.push(`缺少 sshpass，请先安装：${env.sshpassInstallCmd}`);
      if (!env.frpsInstalled) problems.push("缺少 frps 内核，请先到「FRP 文件」下载");
      warning.textContent = problems.join("；");
      warning.classList.toggle("hidden", problems.length === 0);
    }
  } catch (error) {
    if (error.status !== 401) toast(error.message, true);
  }
}

// 0.10.1.3 规格1：frps 状态徽标（从节点状态随 30 秒同步上报，主节点取本机实时状态）。
function frpsStateBadge(state) {
  const value = String(state || "unknown");
  const label =
    {
      running: "运行中",
      starting: "启动中",
      stopped: "已停止",
      missing: "未安装",
      error: "异常",
      "port-conflict": "端口冲突",
      "license-required": "许可失效",
    }[value] || "未知";
  const cls =
    {
      running: " success",
      starting: "",
      stopped: "",
    }[value] ?? " danger";
  return `<span class="badge${cls}" title="frps 状态：${escapeHtml(label)}">${escapeHtml(label)}</span>`;
}

// 0.10.1.3 规格1：frps 通用操作按钮组（启 / 停 / 重启 / 日志）。
// 主节点行走本机 /api/admin/frps/*（frps-local），从节点行走命令队列（frps）。
function frpsActionButtons(name, isMaster) {
  const actionType = isMaster ? "frps-local" : "frps";
  const attr = ` data-cluster-action="${actionType}" data-name="${escapeHtml(name)}"`;
  const logAttr = ` data-cluster-action="frps-logs" data-name="${escapeHtml(name)}"`;
  return `
    <button class="button ghost icon-only" type="button"${attr} data-frps-action="start" title="启动 frps">
      <i data-lucide="play" class="icon"></i>
    </button>
    <button class="button ghost icon-only" type="button"${attr} data-frps-action="stop" title="停止 frps">
      <i data-lucide="square" class="icon"></i>
    </button>
    <button class="button ghost icon-only" type="button"${attr} data-frps-action="restart" title="重启 frps">
      <i data-lucide="rotate-cw" class="icon"></i>
    </button>
    <button class="button ghost icon-only" type="button"${logAttr} title="查看 frps 运行日志">
      <i data-lucide="scroll-text" class="icon"></i>
    </button>`;
}

function renderClusterRows(nodes) {
  const rows = $("#clusterRows");
  if (!rows) return;
  setProp("#clusterEmpty", "hidden", nodes.length !== 0);
  const onlineCount = nodes.filter((node) => node.online).length;
  const summary = $("#clusterSummaryBadge");
  if (summary) {
    summary.textContent = `主节点 1 · 从节点 ${nodes.length} · 在线 ${onlineCount + 1}`;
  }
  const masterFrps = state.clusterMasterFrps;
  const masterRow = `
      <tr class="cluster-master-row">
        <td>本机</td>
        <td><span class="badge master">主节点</span></td>
        <td class="mono">${escapeHtml(window.location.hostname || "-")}</td>
        <td class="mono">-</td>
        <td class="mono">-</td>
        <td><span class="badge success">在线</span></td>
        <td class="mono">-</td>
        <td>-</td>
        <td>${frpsStateBadge(masterFrps?.state)}</td>
        <td>-</td>
        <td>-</td>
        <td>${frpsActionButtons("", true)}</td>
      </tr>`;
  rows.innerHTML =
    masterRow +
    nodes
      .map((node) => {
        const stats = node.stats || {};
        const slaveFrps = stats.frps || null;
        return `
      <tr>
        <td>${escapeHtml(node.name)}</td>
        <td><span class="badge">从节点</span></td>
        <td class="mono">${escapeHtml(node.host)}</td>
        <td class="mono">${node.clientApiPort}</td>
        <td class="mono">${node.bindPort ?? "-"}</td>
        <td>${
          node.online
            ? '<span class="badge success">在线</span>'
            : node.status === "pending"
              ? '<span class="badge">待接入</span>'
              : '<span class="badge danger">离线</span>'
        }</td>
        <td class="mono">${escapeHtml(node.version ? `v${node.version}` : "-")}</td>
        <td>${formatRelative(node.lastSyncAt)}</td>
        <td>${frpsStateBadge(slaveFrps?.state)}</td>
        <td>${escapeHtml(`${stats.userCount ?? 0} 用户 · ${stats.proxyCount ?? 0} 隧道`)}</td>
        <td>
          <span class="mono">${node.priority ?? 0}</span>
          <button class="button ghost icon-only" type="button" data-cluster-action="priority" data-id="${node.id}" data-name="${escapeHtml(node.name)}" data-priority="${node.priority ?? 0}" title="备用主节点优先级：主节点失联时优先级最高者升主（0 = 不参与）">
            <i data-lucide="pencil" class="icon"></i>
          </button>
        </td>
        <td>
          <button class="button ghost icon-only" type="button" data-cluster-action="promote" data-id="${node.id}" data-name="${escapeHtml(node.name)}" title="设为主节点（原主节点自动转为从节点）">
            <i data-lucide="crown" class="icon"></i>
          </button>
          <button class="button ghost icon-only" type="button" data-cluster-action="deploy" data-id="${node.id}" data-name="${escapeHtml(node.name)}" title="重新部署 / 重置令牌">
            <i data-lucide="refresh-cw" class="icon"></i>
          </button>
          <button class="button ghost icon-only" type="button" data-cluster-action="delete" data-id="${node.id}" data-name="${escapeHtml(node.name)}" title="删除节点">
            <i data-lucide="trash-2" class="icon"></i>
          </button>
          ${node.online ? frpsActionButtons(node.name, false) : ""}
        </td>
      </tr>`;
      })
      .join("");
  icons();
}

$("#clusterNameForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/admin/email-settings", {
      method: "PUT",
      body: JSON.stringify({
        clusterName: (getProp("#clusterNameInput", "value") || "").trim(),
        serverDisplayName: (getProp("#clusterDisplayNameInput", "value") || "").trim(),
      }),
    });
    toast("名称已保存；如需同步到客户端列表请到「设置 → 信息公开」重新推送");
    await loadCluster();
  } catch (error) {
    toast(error.message, true);
  }
});

// 0.10.0.2：同步版本——向所有在线从节点下发版本同步命令（自更新到主节点当前版本）。
$("#clusterSyncVersionButton")?.addEventListener("click", async () => {
  if (!confirm("将主节点当前版本同步到所有在线从节点？从节点将自动下载更新并重启。")) return;
  const button = $("#clusterSyncVersionButton");
  try {
    if (button) button.disabled = true;
    const data = await api("/api/admin/cluster/nodes/sync-version", {
      method: "POST",
      body: JSON.stringify({}),
    });
    if (data.targets?.length) {
      // 0.10.1.2 规格1：outdated 附带节点实时上报版本，仅在确低于 0.10.0.2 时提示重新部署。
      if (data.outdated?.length) {
        toast(
          `已下发命令：${data.targets.join("、")}；但 ${data.outdated.join("、")} 版本低于最低要求 0.10.0.2，无法执行同步命令，请重新部署该节点完成升级`,
          true,
        );
      } else {
        toast(`已下发同步命令：${data.targets.join("、")}；从节点将在 30 秒内拉取命令并自动更新重启`);
      }
    } else {
      // 没有在线从节点：醒目提示并展示集群列表，避免「点了没反应」的困惑。
      toast("没有在线从节点可同步：请先在下方部署从节点，并等其状态变为「在线」后再试", true);
    }
    await loadCluster();
  } catch (error) {
    toast(error.message, true);
  } finally {
    if (button) button.disabled = false;
  }
});

// 「添加节点」：滚动到部署面板并聚焦节点名称（部署时自动登记新节点）。
$("#clusterAddButton")?.addEventListener("click", () => {
  $("#clusterDeployForm")?.scrollIntoView({ behavior: "smooth", block: "center" });
  $("#clusterDeployName")?.focus();
});

$("#clusterDeployForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const name = (getProp("#clusterDeployName", "value") || "").trim();
  const host = (getProp("#clusterDeployHost", "value") || "").trim();
  const sshUser = (getProp("#clusterDeploySshUser", "value") || "root").trim();
  const sshPassword = getProp("#clusterDeploySshPassword", "value") || "";
  const masterAddress = (getProp("#clusterDeployMaster", "value") || "").trim();
  setProp("#clusterDeployError", "textContent", "");
  setProp("#clusterDeployLogWrap", "hidden", true);
  setProp("#clusterDeployLog", "textContent", "");
  const button = $("#clusterDeploySubmit");
  const originalText = button ? button.innerHTML : "";
  if (button) {
    button.disabled = true;
    button.innerHTML = '<i data-lucide="loader-2" class="icon spin"></i> 部署中（约 1-2 分钟）...';
    icons();
  }
  try {
    const data = await api("/api/admin/cluster/nodes/deploy", {
      method: "POST",
      body: JSON.stringify({ name, host, sshUser, sshPassword, masterAddress }),
    });
    setProp("#clusterDeployLogWrap", "hidden", false);
    setProp("#clusterDeployLog", "textContent", (data.log || []).join("\n"));
    toast(`节点 ${name} 部署完成，等待从节点接入同步`);
    setProp("#clusterDeploySshPassword", "value", "");
    await loadCluster();
  } catch (error) {
    setProp("#clusterDeployError", "textContent", error.message);
  } finally {
    if (button) {
      button.disabled = false;
      button.innerHTML = originalText;
      icons();
    }
  }
});

$("#clusterRows")?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-cluster-action]");
  if (!button) return;
  const action = button.dataset.clusterAction;
  const id = Number(button.dataset.id);
  const name = button.dataset.name || "";
  // 0.10.1.3 规格1：主节点本机 frps 启停/重启（集群页主节点行）。
  if (action === "frps-local") {
    const frpsAction = button.dataset.frpsAction || "";
    if (frpsAction === "stop" && !confirm("停止本机 frps？所有隧道将断开，直到重新启动。")) return;
    try {
      await api(`/api/admin/frps/${frpsAction}`, { method: "POST", body: "{}" });
      toast(`已对主节点 frps 执行 ${frpsAction}`);
      await loadCluster();
    } catch (error) {
      toast(error.message, true);
    }
    return;
  }
  // 0.10.1.3 规格1：从节点 frps 启停/重启（命令队列下发，约 30 秒内执行）。
  if (action === "frps") {
    const frpsAction = button.dataset.frpsAction || "";
    if (frpsAction === "stop" && !confirm(`停止「${name}」的 frps？该节点上的隧道将全部断开。`)) return;
    try {
      const data = await api("/api/admin/cluster/nodes/frps-control", {
        method: "POST",
        body: JSON.stringify({ name, action: frpsAction }),
      });
      toast(data.message || "命令已下发");
      await loadCluster();
    } catch (error) {
      toast(error.message, true);
    }
    return;
  }
  // 0.10.1.3 规格1：frps 运行日志查看（主节点读本机日志，从节点下发命令后轮询结果）。
  if (action === "frps-logs") {
    await openFrpsLogDialog(name);
    return;
  }
  if (action === "delete") {
    if (!confirm(`删除节点「${name}」？该节点上的服务不会被卸载，可手动清理。`)) return;
    try {
      await api("/api/admin/cluster/nodes/delete", {
        method: "POST",
        body: JSON.stringify({ id }),
      });
      toast("节点已删除");
      await loadCluster();
    } catch (error) {
      toast(error.message, true);
    }
    return;
  }
  // 0.10.1.1：备用主节点优先级（主节点失联时优先级最高者升主，0 = 不参与）。
  if (action === "priority") {
    const current = Number(button.dataset.priority) || 0;
    const input = prompt(
      `设置「${name}」的备用主节点优先级（0-100，数字越大越优先；0 = 不参与升主）：`,
      String(current),
    );
    if (input === null) return;
    const priority = Math.max(0, Math.min(100, Math.floor(Number(input) || 0)));
    try {
      const data = await api("/api/admin/cluster/nodes/priority", {
        method: "POST",
        body: JSON.stringify({ id, priority }),
      });
      toast(data.message || "优先级已更新");
      await loadCluster();
    } catch (error) {
      toast(error.message, true);
    }
    return;
  }
  if (action === "promote") {
    if (
      !confirm(
        `将「${name}」设为主节点？\n\n该节点将重启并切换为主节点角色；原主节点（本机）将自动转为从节点并向其同步，管理台地址将变更为新主节点。`,
      )
    ) {
      return;
    }
    const adminPassword = prompt("请输入当前管理台管理员密码（验证操作权限）：");
    if (!adminPassword) return;
    const password = prompt(`请输入「${name}」的 root SSH 密码：`);
    if (!password) return;
    try {
      const data = await api("/api/admin/cluster/nodes/promote", {
        method: "POST",
        body: JSON.stringify({ id, sshUser: "root", sshPassword: password, adminPassword }),
      });
      const demoteLines = data.demote?.envLines || [];
      const demoteNote =
        data.demote?.mode === "systemd"
          ? `本机（${data.demote.unit}）将自动重启并切换为从节点。`
          : `本机需手工降级，请在服务启动环境中加入：\n${demoteLines.join("\n")}`;
      setProp("#clusterDeployLogWrap", "hidden", false);
      setProp("#clusterDeployLog", "textContent", [...(data.log || []), "", demoteNote].join("\n"));
      toast(`「${name}」已提升为主节点；请改用 http://${data.newMasterHost}:9400 管理集群`, false);
      if (data.demote?.mode === "manual") {
        alert(`原主节点需手工降级，请按部署日志中的指引配置环境变量并重启本机服务。`);
      }
    } catch (error) {
      toast(error.message, true);
    }
    return;
  }
  if (action === "deploy") {
    const password = prompt(`重新部署「${name}」需要 SSH 密码（用户名沿用 root，可在下方表单改）：`);
    if (!password) return;
    setProp("#clusterDeployName", "value", name);
    setProp("#clusterDeploySshPassword", "value", password);
    $("#clusterDeployForm")?.requestSubmit();
  }
});

// 0.10.1.3 规格1：frps 运行日志弹窗。主节点直接展示本机日志；
// 从节点下发 frps-logs 命令并轮询执行结果（命令经 30 秒同步通道回报）。
async function openFrpsLogDialog(nodeName) {
  const dialog = $("#frpsLogDialog");
  if (!dialog) return;
  const isMaster = !nodeName;
  setProp(
    "#frpsLogTitle",
    "textContent",
    isMaster ? "主节点 frps 运行日志" : `「${nodeName}」frps 运行日志`,
  );
  setProp("#frpsLogContent", "textContent", "获取中…");
  dialog.showModal();
  if (isMaster) {
    const logs = state.clusterMasterFrps?.logs || [];
    setProp(
      "#frpsLogContent",
      "textContent",
      logs.length ? logs.join("\n") : "暂无 frps 日志",
    );
    return;
  }
  let commandId = null;
  try {
    const data = await api("/api/admin/cluster/nodes/frps-logs", {
      method: "POST",
      body: JSON.stringify({ name: nodeName, lines: 200 }),
    });
    commandId = data.id ?? null;
  } catch (error) {
    setProp("#frpsLogContent", "textContent", `下发失败：${error.message}`);
    return;
  }
  // 轮询命令状态：最长约 45 秒（30 秒同步周期 + 余量）。
  for (let attempt = 0; attempt < 15; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 3_000));
    if (!dialog.open) return;
    try {
      const data = await api(
        `/api/admin/cluster/commands?name=${encodeURIComponent(nodeName)}&type=${encodeURIComponent("frps-logs")}`,
      );
      const command = (data.commands || []).find(
        (item) => item.id === commandId || (!commandId && item.id != null),
      );
      if (command && command.status !== "pending") {
        setProp("#frpsLogContent", "textContent", command.result || "从节点未返回日志内容");
        return;
      }
    } catch {
      /* 轮询失败继续重试，超时后提示 */
    }
  }
  if (dialog.open) {
    setProp(
      "#frpsLogContent",
      "textContent",
      "获取超时：节点可能离线或尚未拉取命令（同步周期约 30 秒），请稍后重试。",
    );
  }
}

async function openBatchDialog(plan = null) {
  const selected = plan ? String(plan.id) : state.plans[0] ? String(state.plans[0].id) : "";
  // 0.10.0.2：开号前必须先选定目标节点。
  await loadClusterPools();
  fillNodeSelect($("#batchNode"), { required: true });
  setProp("#batchPlan", "value", selected);
  setProp("#batchCount", "value", "1");
  setProp("#batchPrefix", "value", "");
  setProp("#batchFormError", "textContent", "");
  setProp("#batchResult", "hidden", true);
  state.batchResult = [];
  $("#batchDialog")?.showModal();
}

async function saveBatch(event) {
  event.preventDefault();
  const node = getProp("#batchNode", "value") || "";
  if (!node) {
    setProp("#batchFormError", "textContent", "请先选定目标节点，再执行开号");
    return;
  }
  const payload = {
    node,
    planId: Number(getProp("#batchPlan", "value") || 0),
    count: Number(getProp("#batchCount", "value") || 0),
    prefix: (getProp("#batchPrefix", "value") || "").trim().toLowerCase(),
  };
  setProp("#batchFormError", "textContent", "");
  try {
    const result = await api("/api/admin/users/batch", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    state.batchResult = result.users || [];
    // 0.9.2：创建完成自动关闭弹窗，明确提示成功数量；初始密码可在用户列表查看/复制。
    $("#batchDialog")?.close();
    toast(`批量开号成功：已创建 ${state.batchResult.length} 个账号，初始密码可在用户列表查看`);
    await refresh();
    renderPlans();
  } catch (error) {
    // 失败时保留弹窗并展示原因（不静默）。
    setProp("#batchFormError", "textContent", `批量开号失败：${error.message}`);
  }
}

function renderBatchResult(result) {
  const rows = $("#batchResultRows");
  if (!rows) return;
  rows.innerHTML = (result.users || [])
    .map(
      (account) => `
      <tr>
        <td class="mono">${escapeHtml(account.uid || "-")}</td>
        <td class="mono">${escapeHtml(account.username)}</td>
        <td class="mono">${escapeHtml(account.password)}</td>
        <td class="mono">${escapeHtml(account.portRangesText)}</td>
        <td class="mono">${escapeHtml(String(account.durationDays ?? ""))} 天</td>
      </tr>`,
    )
    .join("");
  setProp("#batchResult", "hidden", (result.users || []).length === 0);
  icons();
}

async function copyBatchResult() {
  if (!state.batchResult.length) return;
  const text = state.batchResult
    .map((account) => `${account.uid || ""}\t${account.username}\t${account.password}\t${account.portRangesText}\t${account.durationDays ?? ""}天`)
    .join("\n");
  try {
    await navigator.clipboard.writeText(text);
    toast("已复制全部账号");
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    document.body.append(area);
    area.select();
    document.execCommand("copy");
    area.remove();
    toast("已复制全部账号");
  }
}

async function savePortPool(event) {
  event.preventDefault();
  const portPool = (getProp("#portPoolInput", "value") || "").trim();
  setProp("#portPoolMsg", "textContent", "保存中…");
  try {
    const result = await api("/api/admin/port-pool", {
      method: "PUT",
      body: JSON.stringify({ portPool }),
    });
    state.portPool = result.portPool || portPool;
    setProp("#portPoolInput", "value", state.portPool);
    setProp("#portPoolMsg", "textContent", "已保存");
    toast("端口池已保存");
  } catch (error) {
    setProp("#portPoolMsg", "textContent", error.message);
    toast(error.message, true);
  }
}

$("#createPlanButton")?.addEventListener("click", () => openPlanDialog());
$("#batchCreateButton")?.addEventListener("click", () => openBatchDialog());
$("#planForm")?.addEventListener("submit", savePlan);
$("#batchForm")?.addEventListener("submit", saveBatch);
$("#batchCopyButton")?.addEventListener("click", () => void copyBatchResult());
$("#portPoolForm")?.addEventListener("submit", savePortPool);
$("#planCards")?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-plan-action]");
  if (!button) return;
  void planAction(button.dataset.planAction, button.dataset.id);
});

// ---------- 0.9.2 账号导入/导出/模板 ----------
function downloadAccountFile(url) {
  // 同源 GET 自动携带管理 cookie，浏览器直接处理下载。
  window.location.href = url;
}

$("#templateUsersButton")?.addEventListener("click", () => {
  downloadAccountFile("/api/admin/users/template?format=xlsx");
});
$("#exportXlsxButton")?.addEventListener("click", () => {
  downloadAccountFile("/api/admin/users/export?format=xlsx");
});
$("#exportTxtButton")?.addEventListener("click", () => {
  downloadAccountFile("/api/admin/users/export?format=txt");
});
$("#importUsersButton")?.addEventListener("click", () => {
  setProp("#importFile", "value", "");
  setProp("#importFormError", "textContent", "");
  setProp("#importResult", "hidden", true);
  $("#importDialog")?.showModal();
  icons();
});
$("#importDialog")?.addEventListener("click", (event) => {
  const templateButton = event.target.closest("[data-template]");
  if (templateButton) {
    downloadAccountFile(`/api/admin/users/template?format=${encodeURIComponent(templateButton.dataset.template)}`);
  }
});

$("#importForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = $("#importFile")?.files?.[0];
  setProp("#importFormError", "textContent", "");
  if (!file) {
    setProp("#importFormError", "textContent", "请先选择要导入的文件");
    return;
  }
  if (file.size > 5 * 1024 * 1024) {
    setProp("#importFormError", "textContent", "文件大小超出 5MB 限制");
    return;
  }
  const submit = $("#importForm button[type='submit']");
  if (submit) submit.disabled = true;
  try {
    const response = await fetch("/api/admin/users/import-accounts", {
      method: "POST",
      credentials: "same-origin",
      headers: { "X-Console-Request": "1" },
      body: file,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `导入失败 (${response.status})`);
    const createdCount = Array.isArray(data.created) ? data.created.length : 0;
    const failed = Array.isArray(data.failed) ? data.failed : [];
    setProp("#importResult", "hidden", false);
    setProp(
      "#importSummary",
      "textContent",
      `成功导入 ${createdCount} 个账号${failed.length ? `；${failed.length} 行失败，明细如下` : ""}。成功账号的用户 ID 与初始密码可在用户列表查看。`,
    );
    const failedBody = $("#importFailedRows");
    if (failedBody) {
      failedBody.innerHTML = failed
        .map(
          (item) => `
            <tr>
              <td class="mono">${escapeHtml(item.row)}</td>
              <td>${escapeHtml(item.username || "-")}</td>
              <td>${escapeHtml(item.reason)}</td>
            </tr>`,
        )
        .join("");
    }
    icons();
    await refresh();
    if (!failed.length) {
      // 全部成功：自动关闭弹窗并给出明确提示（不静默）。
      $("#importDialog")?.close();
      toast(`账号导入成功：已创建 ${createdCount} 个账号`);
    } else {
      toast(`导入完成：成功 ${createdCount} 个，失败 ${failed.length} 行`, createdCount === 0);
    }
  } catch (error) {
    setProp("#importFormError", "textContent", `导入失败：${error.message}`);
  } finally {
    if (submit) submit.disabled = false;
  }
});

// ---------- 0.9.0 HTTP/HTTPS 隧道 vhost 端口 ----------
async function loadVhostPorts() {
  try {
    const data = await api("/api/admin/frps/vhost-ports");
    setProp("#vhostHttpPort", "value", data.httpPort);
    setProp("#vhostHttpsPort", "value", data.httpsPort);
    const httpInput = $("#vhostHttpPort");
    const httpsInput = $("#vhostHttpsPort");
    const submit = $("#vhostForm button[type='submit']");
    const locked = data.envHttpLocked || data.envHttpsLocked;
    if (httpInput) httpInput.disabled = data.envHttpLocked;
    if (httpsInput) httpsInput.disabled = data.envHttpsLocked;
    if (submit) submit.disabled = locked;
    setProp(
      "#vhostMsg",
      "textContent",
      locked
        ? "端口已由环境变量 FRP_VHOST_HTTP_PORT / FRP_VHOST_HTTPS_PORT 固定，无法在页面修改"
        : "保存后 frps 自动重启；填 0 关闭对应协议（默认关闭）",
    );
  } catch (error) {
    if (error.status === 401) {
      showLogin();
      return;
    }
    setProp("#vhostMsg", "textContent", error.message);
  }
}

async function saveVhostPorts(event) {
  event.preventDefault();
  setProp("#vhostMsg", "textContent", "保存并重启中…");
  try {
    const result = await api("/api/admin/frps/vhost-ports", {
      method: "PUT",
      body: JSON.stringify({
        httpPort: Number(getProp("#vhostHttpPort", "value") || 0),
        httpsPort: Number(getProp("#vhostHttpsPort", "value") || 0),
      }),
    });
    setProp(
      "#vhostMsg",
      "textContent",
      result.restarted ? "已保存，frps 已重启" : "已保存（frps 当前未运行，下次启动生效）",
    );
    toast("vhost 端口已保存");
  } catch (error) {
    setProp("#vhostMsg", "textContent", error.message);
    toast(error.message, true);
  }
}

$("#vhostForm")?.addEventListener("submit", saveVhostPorts);

// ---------- 0.10.0 frp 监听端口（bindPort） ----------
async function loadBindPort() {
  try {
    const data = await api("/api/admin/frps/bind-port");
    setProp("#frpBindPort", "value", data.bindPort);
    const input = $("#frpBindPort");
    const submit = $("#bindPortForm button[type='submit']");
    if (input) input.disabled = data.envLocked;
    if (submit) submit.disabled = data.envLocked;
    setProp(
      "#bindPortMsg",
      "textContent",
      data.envLocked
        ? "端口已由环境变量 FRP_BIND_PORT 固定，无法在页面修改"
        : `当前 frpc 连接端口：${data.bindPort}；保存后 frps 自动重启，在线客户端心跳后自动切换`,
    );
  } catch (error) {
    if (error.status === 401) {
      showLogin();
      return;
    }
    setProp("#bindPortMsg", "textContent", error.message);
  }
}

async function saveBindPort(event) {
  event.preventDefault();
  setProp("#bindPortMsg", "textContent", "保存并重启中…");
  try {
    const result = await api("/api/admin/frps/bind-port", {
      method: "PUT",
      body: JSON.stringify({ bindPort: Number(getProp("#frpBindPort", "value") || 0) }),
    });
    setProp(
      "#bindPortMsg",
      "textContent",
      result.restarted
        ? `已保存，frps 已重启；新监听端口 ${result.bindPort}`
        : `已保存（frps 当前未运行，下次启动生效）；新监听端口 ${result.bindPort}`,
    );
    toast("监听端口已保存");
  } catch (error) {
    setProp("#bindPortMsg", "textContent", error.message);
    toast(error.message, true);
  }
}

$("#bindPortForm")?.addEventListener("submit", saveBindPort);

// ---------- 0.10.1.0：从节点监听端口远程修改（命令经主节点下发，从节点 30 秒内执行） ----------
function renderSlavePorts() {
  const wrap = $("#slavePortRows");
  if (!wrap) return;
  const nodes = state.overview?.cluster?.nodes || [];
  if (!nodes.length) {
    wrap.innerHTML = '<p class="muted">暂无从节点；请先在「集群管理」添加并部署</p>';
    return;
  }
  wrap.innerHTML = nodes
    .map(
      (node) => `
      <form class="slave-port-row" data-node="${escapeHtml(node.name)}">
        <div class="slave-port-info">
          <strong>${escapeHtml(node.label || node.name)}</strong>
          <span class="mono">${escapeHtml(node.host || "-")}</span>
          <span class="badge ${node.online ? "success" : ""}">${node.online ? "在线" : "离线"}</span>
          <span class="muted">当前端口 <strong class="mono">${node.bindPort ?? "-"}</strong></span>
        </div>
        <div class="slave-port-actions">
          <input
            type="number"
            min="1"
            max="65535"
            placeholder="新监听端口"
            data-slave-port
            ${node.online ? "" : "disabled"}
          />
          <button class="button tiny" type="submit" ${node.online ? "" : "disabled"}>
            <i data-lucide="upload-cloud" class="icon"></i>
            下发
          </button>
        </div>
      </form>`,
    )
    .join("");
  icons();
}

$("#slavePortRows")?.addEventListener("submit", async (event) => {
  const form = event.target.closest("form[data-node]");
  if (!form) return;
  event.preventDefault();
  const nodeName = form.dataset.node;
  const input = form.querySelector("input[data-slave-port]");
  const port = Number(input?.value || 0);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    setProp("#slavePortMsg", "textContent", "监听端口须为 1-65535 的整数");
    return;
  }
  try {
    const result = await api("/api/admin/cluster/nodes/bind-port", {
      method: "POST",
      body: JSON.stringify({ name: nodeName, bindPort: port }),
    });
    setProp("#slavePortMsg", "textContent", result.message || "命令已下发");
    toast(result.message || "端口修改命令已下发");
    if (input) input.value = "";
  } catch (error) {
    setProp("#slavePortMsg", "textContent", error.message);
    toast(error.message, true);
  }
});

// ---------- 0.9.2 防火墙 ----------
async function loadFirewall() {
  try {
    const data = await api("/api/admin/firewall/ports");
    renderFirewall(data);
    renderFirewallCluster(data.status || {});
  } catch (error) {
    if (error.status === 401) {
      showLogin();
      return;
    }
    setProp(
      "#firewallPortsBody",
      "innerHTML",
      `<tr><td colspan="6" class="muted">${escapeHtml(error.message)}</td></tr>`,
    );
  }
}

function firewallBadge(open) {
  return open
    ? '<span class="badge success"><i data-lucide="check" class="icon"></i> 已放行</span>'
    : '<span class="badge warning"><i data-lucide="shield-alert" class="icon"></i> 未放行</span>';
}

// 0.10.0.2：集群防火墙状态——主节点实时状态 + 从节点同步上报的防火墙快照。
function renderFirewallCluster(status) {
  const body = $("#firewallClusterBody");
  if (!body) return;
  const describe = (fw) => {
    if (!fw) return { backend: "-", active: '<span class="badge">未知</span>', note: "暂无上报数据" };
    if (!fw.supported) {
      return {
        backend: "-",
        active: '<span class="badge warning">不支持</span>',
        note: fw.reason || "未检测到可用的防火墙后端",
      };
    }
    return {
      backend: fw.backendName || fw.backend || "-",
      active: fw.active
        ? '<span class="badge success">运行中</span>'
        : '<span class="badge danger">已关闭</span>',
      note: fw.note || "",
    };
  };
  const rows = [{ name: "主节点", role: '<span class="badge master">主节点</span>', online: '<span class="badge success">在线</span>', ...describe(status) }];
  for (const node of state.overview?.cluster?.nodes || []) {
    rows.push({
      name: node.name,
      role: '<span class="badge">从节点</span>',
      online: node.online
        ? '<span class="badge success">在线</span>'
        : '<span class="badge danger">离线</span>',
      ...describe(node.firewall),
    });
  }
  body.innerHTML = rows
    .map(
      (row) => `
      <tr>
        <td>${escapeHtml(row.name)}</td>
        <td>${row.role}</td>
        <td>${row.online}</td>
        <td>${escapeHtml(row.backend)}</td>
        <td>${row.active}</td>
        <td class="muted">${escapeHtml(row.note)}</td>
      </tr>`,
    )
    .join("");
  icons();
}

function renderFirewall(data) {
  const status = data.status || {};
  const banner = $("#firewallBanner");
  if (banner) {
    if (!status.supported) {
      banner.innerHTML = `
        <div class="notice" style="border-left-color: var(--warning); background: var(--warning-soft); color: var(--warning);">
          <p><i data-lucide="shield-alert" class="icon"></i> <strong>当前服务器不支持自动管理防火墙</strong></p>
          <p style="color: inherit;">${escapeHtml(status.reason || "未检测到可用的防火墙后端")}。请登录服务器手动放行所需端口（frps 通信端口、vhost 端口及用户端口段）。</p>
        </div>`;
    } else {
      // 0.9.3：防火墙运行状态 + 关闭/开启/重启三按钮（iptables 不支持生命周期控制）。
      const activeBadge = status.active
        ? '<span class="badge success"><i data-lucide="play" class="icon"></i> 运行中</span>'
        : '<span class="badge danger"><i data-lucide="stop-circle" class="icon"></i> 已关闭</span>';
      const controls =
        status.lifecycleSupported && status.privileged
          ? `<div class="batch-bar" style="margin: 8px 0 0; padding: 8px 10px;">
              <button class="button tiny secondary" type="button" data-firewall-control="start">
                <i data-lucide="play" class="icon"></i> 开启
              </button>
              <button class="button tiny ghost" type="button" data-firewall-control="restart">
                <i data-lucide="rotate-cw" class="icon"></i> 重启
              </button>
              <button class="button tiny danger" type="button" data-firewall-control="stop">
                <i data-lucide="square" class="icon"></i> 关闭
              </button>
            </div>`
          : status.lifecycleSupported && !status.privileged
            ? '<p class="muted" style="margin: 6px 0 0;">当前服务无 root/管理员权限，防火墙控制按钮不可用。</p>'
            : '<p class="muted" style="margin: 6px 0 0;">当前后端（iptables）不支持关闭/开启/重启整体防火墙，请手动管理。</p>';
      banner.innerHTML = `
        <div class="notice"${status.privileged ? "" : ' style="border-left-color: var(--warning); background: var(--warning-soft); color: var(--warning);"'}>
          <p><i data-lucide="${status.privileged ? "shield-check" : "shield-alert"}" class="icon"></i>
          <strong>防火墙后端：${escapeHtml(status.backendName || status.backend || "")}${
            status.privileged ? "（具备管理权限）" : "（当前服务无 root/管理员权限，仅可查看，放行将被拒绝）"
          }</strong>
          ${activeBadge}</p>
          ${controls}
          <p style="color: inherit;">${status.note ? escapeHtml(status.note) + "。" : ""}放行操作会写入系统防火墙规则；云服务器还需在云控制台安全组中同步放行。</p>
        </div>`;
    }
  }
  const portsBody = $("#firewallPortsBody");
  if (portsBody) {
    const rows = data.ports || [];
    portsBody.innerHTML = rows.length
      ? rows
          .map((row) => {
            const owners = (row.owners || []).map((owner) => escapeHtml(owner.label)).join("<br />");
            const process = row.processName
              ? `${escapeHtml(row.processName)}${row.pid ? ` <small class="muted">PID ${escapeHtml(String(row.pid))}</small>` : ""}`
              : '<span class="muted">-</span>';
            return `<tr>
              <td class="mono">${escapeHtml(String(row.port))}</td>
              <td>${escapeHtml((row.proto || "tcp").toUpperCase())}</td>
              <td>${process}</td>
              <td>${owners}</td>
              <td>${firewallBadge(row.firewallOpen)}</td>
              <td>${
                row.firewallOpen
                  ? '<span class="muted">-</span>'
                  : `<button class="button ghost tiny" type="button" data-firewall-open="${escapeHtml(String(row.port))}" data-firewall-proto="tcp">
                      <i data-lucide="shield-plus" class="icon"></i> 放行
                    </button>`
              }</td>
            </tr>`;
          })
          .join("")
      : '<tr><td colspan="6" class="muted">当前没有监听中的端口</td></tr>';
  }
  const poolsBody = $("#firewallPoolsBody");
  if (poolsBody) {
    const pools = data.pools || [];
    poolsBody.innerHTML = pools.length
      ? pools
          .map((pool) => {
            const ranges = pool.ranges || [];
            const rangesText = ranges.map((r) => `${r.start}-${r.end}`).join("、");
            const allOpen = ranges.length > 0 && ranges.every((r) => r.open);
            return `<tr>
              <td class="mono">${escapeHtml(pool.uid || "-")}</td>
              <td>${escapeHtml(pool.username || "-")}</td>
              <td class="mono">${escapeHtml(rangesText)}</td>
              <td>${firewallBadge(allOpen)}</td>
              <td>${
                allOpen
                  ? '<span class="muted">-</span>'
                  : `<button class="button ghost tiny" type="button" data-firewall-range="${escapeHtml(rangesText)}" data-firewall-proto="tcp">
                      <i data-lucide="shield-plus" class="icon"></i> 放行端口段
                    </button>`
              }</td>
            </tr>`;
          })
          .join("")
      : '<tr><td colspan="5" class="muted">暂无用户端口段</td></tr>';
  }
  icons();
}

async function firewallOpen(ports, proto) {
  try {
    await api("/api/admin/firewall/open", {
      method: "POST",
      body: JSON.stringify({ ports, proto }),
    });
    toast(`已放行 ${Array.isArray(ports) ? ports.join("、") : ports}（${String(proto).toUpperCase()}）`);
    await loadFirewall();
  } catch (error) {
    toast(error.message, true);
  }
}

// 0.9.3：防火墙整体关闭 / 开启 / 重启。
async function firewallControl(action) {
  const labels = { start: "开启", stop: "关闭", restart: "重启" };
  if (action === "stop" && !confirm("确认关闭系统防火墙？关闭后所有入站端口将不再受防火墙保护（云安全组仍然生效）。")) {
    return;
  }
  if (action === "restart" && !confirm("确认重启系统防火墙？规则会重新加载，已建立的连接可能短暂中断。")) {
    return;
  }
  try {
    await api("/api/admin/firewall/control", {
      method: "POST",
      body: JSON.stringify({ action }),
    });
    toast(`防火墙已${labels[action] || action}`);
    await loadFirewall();
  } catch (error) {
    toast(error.message, true);
  }
}

$("#firewallOpenForm")?.addEventListener("submit", (event) => {
  event.preventDefault();
  const ports = (getProp("#firewallPortsInput", "value") || "")
    .split(/[,，\s]+/)
    .filter(Boolean);
  if (ports.length === 0) {
    toast("请填写要放行的端口或端口段", true);
    return;
  }
  const proto = getProp("#firewallProtoSelect", "value") || "tcp";
  void firewallOpen(ports, proto);
});

$("#firewallView")?.addEventListener("click", (event) => {
  const controlButton = event.target.closest("[data-firewall-control]");
  if (controlButton) {
    void firewallControl(controlButton.dataset.firewallControl);
    return;
  }
  const openButton = event.target.closest("[data-firewall-open]");
  if (openButton) {
    void firewallOpen([openButton.dataset.firewallOpen], openButton.dataset.firewallProto || "tcp");
    return;
  }
  const rangeButton = event.target.closest("[data-firewall-range]");
  if (rangeButton) {
    const ranges = (rangeButton.dataset.firewallRange || "").split("、").filter(Boolean);
    void firewallOpen(ranges, rangeButton.dataset.firewallProto || "tcp");
  }
});

document.querySelector('[data-firewall-refresh]')?.addEventListener("click", () => {
  void loadFirewall();
});

const loginForm = $("#loginForm");
loginForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setProp("#loginError", "textContent", "");
  try {
    await api("/api/admin/login", {
      method: "POST",
      body: JSON.stringify({
        username: getProp("#adminUsername", "value") || "",
        password: getProp("#adminPassword", "value") || "",
      }),
    });
    setProp("#adminPassword", "value", "");
    await refresh();
  } catch (error) {
    setProp("#loginError", "textContent", error.message);
  }
});

$("#adminLogoutButton")?.addEventListener("click", async () => {
  try {
    await api("/api/admin/logout", { method: "POST" });
    state.users = [];
    state.proxies = [];
    state.overview = null;
    showLogin();
  } catch (error) {
    toast(error.message, true);
  }
});

$("#changePasswordButton")?.addEventListener("click", () => {
  $("#passwordForm")?.reset();
  setProp("#passwordFormError", "textContent", "");
  $("#passwordDialog")?.showModal();
});

const passwordForm = $("#passwordForm");
passwordForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const currentPassword = getProp("#currentPassword", "value") || "";
  const newPassword = getProp("#newPassword", "value") || "";
  const confirmPassword = getProp("#confirmPassword", "value") || "";
  setProp("#passwordFormError", "textContent", "");
  if (newPassword !== confirmPassword) {
    setProp("#passwordFormError", "textContent", "两次输入的新密码不一致");
    return;
  }
  try {
    await api("/api/admin/password", {
      method: "POST",
      body: JSON.stringify({ currentPassword, newPassword, confirmPassword }),
    });
    $("#passwordDialog")?.close();
    $("#passwordForm")?.reset();
    toast("管理员密码已更新");
    await refresh();
  } catch (error) {
    setProp("#passwordFormError", "textContent", error.message);
  }
});

$("#checkUpdateButton")?.addEventListener("click", async () => {
  try {
    const data = await api("/api/admin/update");
    state.overview = {
      ...(state.overview || {}),
      update: data.update,
      currentVersion: data.currentVersion,
    };
    renderUpdate();
    toast(data.update?.hasUpdate ? "发现新版本" : "已是最新版本");
  } catch (error) {
    toast(error.message, true);
  }
});

$("#applyUpdateButton")?.addEventListener("click", async () => {
  if (!confirm("确认在线更新？进程将下载并替换文件后自动重启。")) return;
  try {
    await api("/api/admin/update/apply", { method: "POST", body: "{}" });
    toast("更新已启动，约 5 秒后服务重启；如长时间无响应请检查服务端日志");
  } catch (error) {
    toast(error.message, true);
  }
});

$(".nav")?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-view]");
  if (button) switchView(button.dataset.view);
});

// 0.10.2.4：手机端侧边栏抽屉——点菜单项/遮罩自动收起，左上角按钮手动展开收起
$(".nav")?.addEventListener("click", () => {
  if (window.matchMedia("(max-width: 760px)").matches) {
    $("#appView")?.classList.add("sidebar-collapsed");
  }
});

$("#sidebarBackdrop")?.addEventListener("click", () =>
  $("#appView")?.classList.add("sidebar-collapsed"),
);

$("#sidebarToggle")?.addEventListener("click", () => {
  const collapsed = $("#appView")?.classList.toggle("sidebar-collapsed") ?? false;
  $("#sidebarToggle")?.setAttribute("aria-expanded", String(!collapsed));
  $("#sidebarToggle")?.setAttribute("aria-label", collapsed ? "展开菜单" : "收起菜单");
});

$("#createUserButton")?.addEventListener("click", () => openUserDialog());
$("#userForm")?.addEventListener("submit", saveUser);
// 0.9.3：新建/未激活账号选择套餐时自动回填套餐天数与流量配额（可再手动调整）。
$("#userPlan")?.addEventListener("change", () => {
  const daysInput = $("#userDurationDays");
  if (daysInput && !daysInput.disabled) {
    const planId = Number($("#userPlan")?.value || 0);
    const plan = state.plans?.find((item) => item.id === planId);
    if (plan) {
      daysInput.value = plan.durationDays;
      setProp("#trafficLimitBytes", "value", Math.floor((plan.trafficLimitBytes || 0) / 1048576));
    }
  }
});
$("#renewForm")?.addEventListener("submit", saveRenewal);
// 0.9.3：用户多选与批量操作。
$("#userCheckAll")?.addEventListener("change", (event) => {
  const on = event.target.checked;
  for (const box of $$(".user-check")) {
    const id = Number(box.dataset.id);
    if (on) selectedUserIds.add(id);
    else selectedUserIds.delete(id);
  }
  syncUserCheckboxes();
});
$("#userRows")?.addEventListener("change", (event) => {
  const box = event.target.closest(".user-check");
  if (!box) return;
  const id = Number(box.dataset.id);
  if (box.checked) selectedUserIds.add(id);
  else selectedUserIds.delete(id);
  syncUserCheckboxes();
});
$("#batchBar")?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-batch-action]");
  if (button) void runUsersBatchAction(button.dataset.batchAction);
});
$("#usersBatchForm")?.addEventListener("submit", (event) => void submitUsersBatch(event));
bindLogoPicker("site");
bindLogoPicker("client");
bindBrandingForm("site", "siteName", "siteBrandingError");
bindBrandingForm("client", "clientName", "clientBrandingError");
$("#renewalUrlForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setProp("#renewalUrlError", "textContent", "");
  try {
    await api("/api/admin/renewal-url", {
      method: "POST",
      body: JSON.stringify({ renewalUrl: getProp("#renewalUrlInput", "value") || "" }),
    });
    toast("续费地址已保存");
  } catch (error) {
    setProp("#renewalUrlError", "textContent", error.message);
  }
});
$("#fetchFrpcButton")?.addEventListener("click", () => fetchFrpc());
$("#uploadFrpcButton")?.addEventListener("click", () => $("#frpcFileInput")?.click());
$("#frpcFileInput")?.addEventListener("change", async () => {
  const input = $("#frpcFileInput");
  const file = input.files?.[0];
  if (!file) return;
  await uploadFrpc(file);
  input.value = "";
});
$("#frpcCacheBody")?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-frpc-delete]");
  if (!button) return;
  const [platform, arch] = button.dataset.frpcDelete.split("/");
  void deleteFrpcCache(platform, arch);
});
document.querySelector('[data-action="refresh-frp"]')?.addEventListener("click", () => loadFrpcCache());
$("#icpForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setProp("#icpFormError", "textContent", "");
  try {
    await api("/api/admin/icp-text", {
      method: "POST",
      body: JSON.stringify({
        icpText: getProp("#icpText", "value") || "",
        policeText: getProp("#policeText", "value") || "",
      }),
    });
    toast("备案信息已保存");
    void loadPublicBranding();
  } catch (error) {
    setProp("#icpFormError", "textContent", error.message);
  }
});
$("#copyrightForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setProp("#copyrightFormError", "textContent", "");
  setProp("#copyrightFormMsg", "textContent", "");
  const text = (getProp("#cpText", "value") || "").trim();
  const url = (getProp("#cpUrl", "value") || "").trim();
  const reason = (getProp("#cpReason", "value") || "").trim();
  if (!text) return setProp("#copyrightFormError", "textContent", "请填写期望版权文字");
  if (!reason) return setProp("#copyrightFormError", "textContent", "请填写申请理由");
  try {
    await api("/api/admin/copyright/apply", {
      method: "POST",
      body: JSON.stringify({ text, url, reason }),
    });
    setProp(
      "#copyrightFormMsg",
      "textContent",
      "申请已提交，请等待授权中心审批。审批通过后将自动同步到本服务端及所有客户端。",
    );
    toast("版权申请已提交");
    void loadCopyrightForm();
    void loadPublicBranding();
  } catch (error) {
    setProp("#copyrightFormError", "textContent", error.message);
  }
});
$("#settingsTabs")?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-settings-tab]");
  if (button) switchSettingsTab(button.dataset.settingsTab);
});
$("#userSearch")?.addEventListener("input", renderUsers);
$("#mappingSearch")?.addEventListener("input", renderMappings);
$("#mappingNodeFilters")?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-mapping-node]");
  if (!button) return;
  state.mappingNode = button.dataset.mappingNode || "all";
  $$("[data-mapping-node]").forEach((item) =>
    item.setAttribute("aria-pressed", String(item.dataset.mappingNode === state.mappingNode)),
  );
  renderMappings();
});
$("#mappingFilters")?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-mapping-filter]");
  if (!button) return;
  state.mappingFilter = button.dataset.mappingFilter;
  $$("[data-mapping-filter]").forEach((item) =>
    item.setAttribute("aria-pressed", String(item === button)),
  );
  renderMappings();
});
$("#mappingRows")?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-rate-limit]");
  if (!button) return;
  openRateLimitDialog(button.dataset.rateLimit, Number(button.dataset.userId));
});

function openRateLimitDialog(qualifiedName, userId) {
  // 0.10.0.2：从节点映射快照无 qualifiedName，按 name + userId 兜底查找。
  const proxy =
    (state.proxies || []).find((p) => p.qualifiedName === qualifiedName) ||
    (state.clusterProxies || []).find((p) => p.name === qualifiedName && p.userId === userId);
  setProp("#rateLimitUserId", "value", String(userId));
  setProp("#rateLimitProxyName", "value", qualifiedName);
  setProp(
    "#rateLimitProxyLabel",
    "textContent",
    `${proxy ? proxy.username + " / " + proxy.name : qualifiedName}（${(proxy?.type || "").toUpperCase()}${proxy?.node && proxy.node !== "master" ? ` · ${proxy.node}` : ""}）`,
  );
  // 0.9.2：限速单位 Mbps（比特/秒 ÷ 1_000_000 展示）。
  setProp("#rateLimitValue", "value", String(Math.round((proxy?.rateLimitBps || 0) / 1_000_000)));
  setProp("#rateLimitError", "textContent", "");
  $("#rateLimitDialog")?.showModal();
}

$("#rateLimitForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const userId = Number(getProp("#rateLimitUserId", "value"));
  const proxyName = getProp("#rateLimitProxyName", "value");
  const mbps = Math.max(0, Math.floor(Number(getProp("#rateLimitValue", "value")) || 0));
  try {
    await api("/api/admin/proxies/rate-limit", {
      method: "POST",
      body: JSON.stringify({ userId, proxyName, rateLimitBps: mbps * 1_000_000 }),
    });
    toast(mbps > 0 ? `已设置限速 ${mbps} Mbps` : "已清除隧道限速");
    $("#rateLimitDialog")?.close();
    await refreshMappings();
  } catch (error) {
    setProp("#rateLimitError", "textContent", error.message || "保存失败");
  }
});
$("#userRows")?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-user-action]");
  if (button) userAction(button.dataset.userAction, button.dataset.id);
});

const licenseForm = $("#licenseForm");
licenseForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setProp("#licenseFormError", "textContent", "");
  try {
    await api("/api/admin/license", {
      method: "PUT",
      body: JSON.stringify({ licenseKey: getProp("#licenseKey", "value") || "" }),
    });
    setProp("#licenseKey", "value", "");
    toast("许可密钥激活成功");
    await refresh();
  } catch (error) {
    setProp("#licenseFormError", "textContent", error.message);
  }
});

$("#refreshLicenseButton")?.addEventListener("click", async () => {
  try {
    await api("/api/admin/license/refresh", {
      method: "POST",
      body: "{}",
    });
    toast("许可状态已更新");
    await refresh();
  } catch (error) {
    toast(error.message, true);
  }
});

$("#removeLicenseButton")?.addEventListener("click", async () => {
  if (!confirm("移除当前服务端的许可密钥？")) return;
  try {
    await api("/api/admin/license", { method: "DELETE" });
    toast("许可密钥已移除");
    await refresh();
  } catch (error) {
    toast(error.message, true);
  }
});

$$("[data-close-dialog]").forEach((button) =>
  button.addEventListener("click", () => button.closest("dialog")?.close()),
);

$$("[data-close-password]").forEach((button) =>
  button.addEventListener("click", () => $("#passwordDialog")?.close()),
);

$$("[data-close-renew]").forEach((button) =>
  button.addEventListener("click", () => $("#renewDialog")?.close()),
);

$$("[data-action='refresh']").forEach((button) =>
  button.addEventListener("click", refresh),
);

$$("[data-frps]").forEach((button) =>
  button.addEventListener("click", async () => {
    try {
      await api(`/api/admin/frps/${button.dataset.frps}`, { method: "POST" });
      await new Promise((resolve) => setTimeout(resolve, 350));
      await refresh();
    } catch (error) {
      toast(error.message, true);
    }
  }),
);

// ---------- frps 更新 / 手动导入 ----------
function frpsUpdateMessage(text, isError = false) {
  const element = $("#frpsUpdateMessage");
  if (!element) return;
  element.classList.toggle("hidden", !text);
  element.textContent = text;
  element.classList.toggle("error-text", Boolean(isError));
}

$("#fetchFrpsButton")?.addEventListener("click", async () => {
  const btn = $("#fetchFrpsButton");
  btn.disabled = true;
  frpsUpdateMessage("正在从授权中心拉取与本机匹配的 frps...");
  try {
    const data = await api("/api/admin/frps/fetch", { method: "POST", body: "{}" });
    frpsUpdateMessage(`frps 已更新${data.version ? ` 到 v${data.version}` : ""}，正在重启...`);
    await refresh();
  } catch (error) {
    frpsUpdateMessage(error.message, true);
  } finally {
    btn.disabled = false;
  }
});

$("#uploadFrpsButton")?.addEventListener("click", () => $("#frpsFile")?.click());
$("#frpsFile")?.addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  event.target.value = "";
  if (!file) return;
  frpsUpdateMessage("正在导入 frps...");
  try {
    const resp = await fetch("/api/admin/frps/upload", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/octet-stream" },
      body: file,
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || `导入失败（HTTP ${resp.status}）`);
    frpsUpdateMessage(`frps 已导入${data.version ? `（v${data.version}）` : ""}`);
    await refresh();
  } catch (error) {
    frpsUpdateMessage(error.message, true);
  }
});

// ---------- 网络设置 ----------
$("#networkForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setProp("#networkFormError", "textContent", "");
  const portValue = getProp("#networkPort", "value").trim();
  const submitBtn = event.submitter;
  const originalText = submitBtn ? submitBtn.innerHTML : "";
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i data-lucide="loader-2" class="icon spin"></i> 重启中...';
    icons();
  }
  try {
    const data = await api("/api/admin/network", {
      method: "POST",
      body: JSON.stringify({
        port: portValue ? Number(portValue) : undefined,
        httpsEnabled: $("#networkHttps").checked,
      }),
    });
    renderNetwork(data.network);
    if (data.redirectUrl) {
      toast(data.message || "网络配置已保存，正在跳转...");
      // 短暂延迟后重定向到新端口，给 Web 服务重启留出时间。
      setTimeout(() => {
        let attempts = 0;
        const probe = () => {
          attempts += 1;
          fetch(`${data.redirectUrl}/healthz`, { mode: "no-cors" })
            .then(() => {
              window.location.href = data.redirectUrl;
            })
            .catch(() => {
              if (attempts < 20) {
                setTimeout(probe, 300);
              } else {
                toast("新端口未就绪，请手动访问 " + data.redirectUrl, true);
                if (submitBtn) {
                  submitBtn.disabled = false;
                  submitBtn.innerHTML = originalText;
                  icons();
                }
              }
            });
        };
        probe();
      }, 500);
    } else {
      toast(data.message || "网络配置已保存");
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
        icons();
      }
    }
  } catch (error) {
    setProp("#networkFormError", "textContent", error.message);
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = originalText;
      icons();
    }
  }
});

$("#uploadCertButton")?.addEventListener("click", () => $("#certFile")?.click());
$("#certFile")?.addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  event.target.value = "";
  if (file) await uploadNetworkCert("cert", file);
});
$("#uploadKeyButton")?.addEventListener("click", () => $("#keyFile")?.click());
$("#keyFile")?.addEventListener("change", async (event) => {
  const file = event.target.files?.[0];
  event.target.value = "";
  if (file) await uploadNetworkCert("key", file);
});
$("#clearCertButton")?.addEventListener("click", async () => {
  if (!confirm("确认清除已上传的证书与私钥？HTTPS 将关闭（重启后回到 HTTP）。")) return;
  try {
    const data = await api("/api/admin/network/cert", { method: "DELETE" });
    renderNetwork(data.network);
    toast("证书已清除");
  } catch (error) {
    toast(error.message, true);
  }
});

// ---------- 账号：修改管理员用户名 ----------
$("#usernameForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  setProp("#usernameFormError", "textContent", "");
  try {
    const data = await api("/api/admin/username", {
      method: "POST",
      body: JSON.stringify({
        currentPassword: getProp("#usernamePassword", "value") || "",
        newUsername: getProp("#newUsername", "value") || "",
      }),
    });
    toast(`用户名已修改为 ${data.admin.username}`);
    setTimeout(() => {
      window.location.reload();
    }, 1_200);
  } catch (error) {
    setProp("#usernameFormError", "textContent", error.message);
  }
});

icons();
loadPublicBranding();
refresh();
refreshMappings();
setInterval(() => {
  const appView = $("#appView");
  if (!document.hidden && appView && !appView.classList.contains("hidden")) refresh();
}, 3_000);
startMappingTimer();

// ---------- 0.10.2.8：消息中心（公告发布 / 删除） ----------
$("#announcementForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const err = $("#announcementFormError");
  if (err) err.classList.add("hidden");
  const submit = event.target.querySelector('button[type="submit"]');
  if (submit) submit.disabled = true;
  try {
    const data = await api("/api/admin/announcements", {
      method: "POST",
      body: JSON.stringify({
        title: $("#announcementTitle").value.trim(),
        content: $("#announcementContent").value.trim(),
        level: $("#announcementLevel").value,
      }),
    });
    renderAnnouncementManage(data.announcements);
    $("#announcementTitle").value = "";
    $("#announcementContent").value = "";
    toast("公告已发布，客户端将弹窗提醒未读用户");
  } catch (error) {
    if (err) {
      err.textContent = error.message;
      err.classList.remove("hidden");
    }
  } finally {
    if (submit) submit.disabled = false;
  }
});

$("#announcementManageList")?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-announcement-delete]");
  if (!button) return;
  if (!confirm("确定删除这条公告吗？删除后客户端将不再展示。")) return;
  button.disabled = true;
  try {
    const data = await api("/api/admin/announcements/delete", {
      method: "POST",
      body: JSON.stringify({ id: Number(button.dataset.announcementDelete) }),
    });
    renderAnnouncementManage(data.announcements);
    toast("公告已删除");
  } catch (error) {
    toast(error.message, true);
    button.disabled = false;
  }
});

$("#mappingRefresh")?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-mapping-refresh]");
  if (!button) return;
  state.mappingRefreshMs = Number(button.dataset.mappingRefresh);
  $$("[data-mapping-refresh]").forEach((item) =>
    item.setAttribute("aria-pressed", String(item === button)),
  );
  startMappingTimer();
  refreshMappings();
});
