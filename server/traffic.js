const METRIC_PATTERN =
  /^frp_server_traffic_(in|out)\{([^}]*)\}\s+([^\s#]+)(?:\s+\d+)?$/;
const LABEL_PATTERN = /([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"/g;

function metricKey(name, type) {
  return `${type}\0${name}`;
}

function decodeLabel(value) {
  return value.replace(/\\(.)/g, (_, character) => {
    if (character === "n") return "\n";
    if (character === "\\" || character === '"') return character;
    return `\\${character}`;
  });
}

function parseLabels(value) {
  const labels = {};
  for (const match of value.matchAll(LABEL_PATTERN)) {
    labels[match[1]] = decodeLabel(match[2]);
  }
  return labels;
}

export function parseFrpTrafficMetrics(text) {
  const totals = new Map();
  for (const rawLine of String(text || "").split(/\r?\n/)) {
    const match = METRIC_PATTERN.exec(rawLine.trim());
    if (!match) continue;
    const labels = parseLabels(match[2]);
    const bytes = Number(match[3]);
    if (!labels.name || !labels.type || !Number.isFinite(bytes) || bytes < 0) continue;
    const key = metricKey(labels.name, labels.type);
    const traffic = totals.get(key) || {
      name: labels.name,
      type: labels.type,
      incomingBytes: 0,
      outgoingBytes: 0,
    };
    traffic[match[1] === "in" ? "incomingBytes" : "outgoingBytes"] = bytes;
    totals.set(key, traffic);
  }
  return [...totals.values()];
}

export class TrafficRateTracker {
  constructor(windowMs = 10_000) {
    if (!Number.isFinite(windowMs) || windowMs <= 0) {
      throw new Error("traffic rate window must be greater than zero");
    }
    this.windowMs = windowMs;
    this.samples = new Map();
    this.available = false;
    this.sampledAt = null;
    this.lastUpdateTimestamp = null;
    this.lastError = null;
    // 0.10.2.8：永久累计流量——frps 重启（含服务端更新）会把 metrics 计数器清零，
    // 历史实现直接用进程内计数器当「累计流量」，导致每次更新后统计被清空。
    // 现按 key 维护跨重启单调累计值（cumulative）与上次原始计数（lastSeen），
    // 计数器回落视为 frps 重启，把当前计数全额计入；配合 persistState/restore 持久化。
    this.cumulative = new Map();
    this.lastSeen = new Map();
  }

  // 计算并累加本采样周期的增量；返回传入 total 的累计值引用。
  advanceCumulative(key, total) {
    const last = this.lastSeen.get(key);
    const incomingDelta =
      last && total.incomingBytes >= last.incomingBytes
        ? total.incomingBytes - last.incomingBytes
        : total.incomingBytes;
    const outgoingDelta =
      last && total.outgoingBytes >= last.outgoingBytes
        ? total.outgoingBytes - last.outgoingBytes
        : total.outgoingBytes;
    const entry = this.cumulative.get(key) || { incomingBytes: 0, outgoingBytes: 0 };
    entry.incomingBytes += incomingDelta;
    entry.outgoingBytes += outgoingDelta;
    this.cumulative.set(key, entry);
    this.lastSeen.set(key, {
      incomingBytes: total.incomingBytes,
      outgoingBytes: total.outgoingBytes,
    });
    return entry;
  }

  update(totals, timestamp = Date.now()) {
    const nextSamples = new Map();
    for (const total of totals) {
      const key = metricKey(total.name, total.type);
      this.advanceCumulative(key, total);
      const previousSamples = this.samples.get(key) || [];
      const previous = previousSamples.at(-1);
      const current = {
        ...total,
        timestamp,
      };
      const countersReset =
        previous &&
        (total.incomingBytes < previous.incomingBytes ||
          total.outgoingBytes < previous.outgoingBytes);
      const timeReset = previous && timestamp <= previous.timestamp;
      let history = countersReset || timeReset ? [] : previousSamples;
      if (
        history.length === 0 &&
        !countersReset &&
        this.lastUpdateTimestamp !== null &&
        timestamp > this.lastUpdateTimestamp
      ) {
        history = [
          {
            name: total.name,
            type: total.type,
            incomingBytes: 0,
            outgoingBytes: 0,
            timestamp: this.lastUpdateTimestamp,
          },
        ];
      }
      nextSamples.set(
        key,
        [...history, current].filter(
          (sample) => sample.timestamp >= timestamp - this.windowMs,
        ),
      );
    }
    this.samples = nextSamples;
    this.available = true;
    this.lastUpdateTimestamp = timestamp;
    this.sampledAt = new Date(timestamp).toISOString();
    this.lastError = null;
  }

  markUnavailable(error) {
    this.available = false;
    this.lastError = error?.message || String(error || "metrics unavailable");
  }

  get(name, type) {
    const samples = this.samples.get(metricKey(name, type)) || [];
    const first = samples[0];
    const last = samples.at(-1);
    const elapsedSeconds =
      first && last ? (last.timestamp - first.timestamp) / 1000 : 0;
    const incomingDelta =
      first && last ? last.incomingBytes - first.incomingBytes : 0;
    const outgoingDelta =
      first && last ? last.outgoingBytes - first.outgoingBytes : 0;
    // 0.10.2.8：totalIncoming/OutgoingBytes 为跨重启永久累计值（与 frps 进程生命周期解耦）。
    const cumulative = this.cumulative.get(metricKey(name, type)) || {
      incomingBytes: 0,
      outgoingBytes: 0,
    };
    return {
      available: this.available,
      sampledAt: this.sampledAt,
      error: this.lastError,
      hasMetrics: Boolean(last),
      incomingBytes: last?.incomingBytes || 0,
      outgoingBytes: last?.outgoingBytes || 0,
      totalIncomingBytes: cumulative.incomingBytes,
      totalOutgoingBytes: cumulative.outgoingBytes,
      incomingBytesPerSecond:
        this.available && elapsedSeconds > 0 && incomingDelta >= 0
          ? incomingDelta / elapsedSeconds
          : 0,
      outgoingBytesPerSecond:
        this.available && elapsedSeconds > 0 && outgoingDelta >= 0
          ? outgoingDelta / elapsedSeconds
          : 0,
    };
  }

  status() {
    return {
      available: this.available,
      sampledAt: this.sampledAt,
      error: this.lastError,
      seriesCount: this.samples.size,
      windowSeconds: this.windowMs / 1000,
    };
  }

  // 0.10.2.8：全部 key 的永久累计流量合计（含已删除映射/已下线代理的历史流量）。
  cumulativeTotals() {
    const totals = { incomingBytes: 0, outgoingBytes: 0 };
    for (const entry of this.cumulative.values()) {
      totals.incomingBytes += entry.incomingBytes;
      totals.outgoingBytes += entry.outgoingBytes;
    }
    return totals;
  }

  // 永久累计流量持久化快照（服务端存入 settings，随进程重启/更新恢复）。
  persistState() {
    const totals = {};
    for (const [key, entry] of this.cumulative) {
      totals[key] = {
        incomingBytes: entry.incomingBytes,
        outgoingBytes: entry.outgoingBytes,
      };
    }
    const lastSeen = {};
    for (const [key, entry] of this.lastSeen) {
      lastSeen[key] = {
        incomingBytes: entry.incomingBytes,
        outgoingBytes: entry.outgoingBytes,
      };
    }
    return { totals, lastSeen, savedAt: new Date().toISOString() };
  }

  // 恢复持久化的累计流量：lastSeen 一并恢复，可正确区分「frps 计数器回落（重启）」
  // 与「服务端自身重启但 frps 未动（计数器未变，不重复累计）」两种场景。
  restore(state) {
    if (!state || typeof state !== "object") return;
    const totals = state.totals && typeof state.totals === "object" ? state.totals : {};
    const lastSeen = state.lastSeen && typeof state.lastSeen === "object" ? state.lastSeen : {};
    for (const [key, entry] of Object.entries(totals)) {
      if (!entry || typeof entry !== "object") continue;
      const incomingBytes = Number(entry.incomingBytes);
      const outgoingBytes = Number(entry.outgoingBytes);
      if (!Number.isFinite(incomingBytes) || !Number.isFinite(outgoingBytes)) continue;
      this.cumulative.set(key, { incomingBytes, outgoingBytes });
    }
    for (const [key, entry] of Object.entries(lastSeen)) {
      if (!entry || typeof entry !== "object") continue;
      const incomingBytes = Number(entry.incomingBytes);
      const outgoingBytes = Number(entry.outgoingBytes);
      if (!Number.isFinite(incomingBytes) || !Number.isFinite(outgoingBytes)) continue;
      this.lastSeen.set(key, { incomingBytes, outgoingBytes });
    }
  }
}

export class FrpTrafficMonitor {
  constructor({
    url,
    username,
    password,
    intervalMs = 1_000,
    windowMs = 10_000,
    timeoutMs = 1_500,
    fetchImpl = fetch,
  }) {
    this.url = url;
    this.username = username;
    this.password = password;
    this.intervalMs = intervalMs;
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl;
    this.tracker = new TrafficRateTracker(windowMs);
    this.timer = null;
    this.pending = null;
  }

  async sample() {
    if (this.pending) return this.pending;
    this.pending = this.sampleNow();
    try {
      await this.pending;
    } finally {
      this.pending = null;
    }
  }

  async sampleNow() {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    timeout.unref?.();
    try {
      const authorization = Buffer.from(`${this.username}:${this.password}`).toString("base64");
      const response = await this.fetchImpl(this.url, {
        headers: { Authorization: `Basic ${authorization}` },
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`frps metrics returned ${response.status}`);
      this.tracker.update(parseFrpTrafficMetrics(await response.text()));
    } catch (error) {
      this.tracker.markUnavailable(error);
    } finally {
      clearTimeout(timeout);
    }
  }

  start() {
    if (this.timer) return;
    void this.sample();
    this.timer = setInterval(() => void this.sample(), this.intervalMs);
    this.timer.unref?.();
  }

  stop() {
    if (!this.timer) return;
    clearInterval(this.timer);
    this.timer = null;
  }

  get(name, type) {
    return this.tracker.get(name, type);
  }

  status() {
    return this.tracker.status();
  }

  // 0.10.2.8：永久累计流量透传（持久化到服务端 settings，跨更新/重启累计不清零）。
  cumulativeTotals() {
    return this.tracker.cumulativeTotals();
  }

  persistState() {
    return this.tracker.persistState();
  }

  restore(state) {
    this.tracker.restore(state);
  }
}
