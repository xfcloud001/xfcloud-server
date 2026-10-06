import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { TrafficRateTracker } from "./traffic.js";

// frps 的 Prometheus 流量指标在每条连接关闭后才结算，无法反映正在进行的
// 下载。此模块直接读取操作系统网卡字节计数，提供实时的整机入站/出站速率。
export class SystemTrafficSampler {
  constructor({ intervalMs = 2_000, windowMs = 8_000 } = {}) {
    this.platform = process.platform;
    this.intervalMs = intervalMs;
    this.tracker = new TrafficRateTracker(windowMs);
    this.timer = null;
    this.pending = null;
    this.ifaceName = null;
  }

  start() {
    if (!["linux", "win32"].includes(this.platform)) return;
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

  async sample() {
    if (this.pending) return this.pending;
    this.pending = this.readCounters()
      .then(({ rx, tx }) => {
        this.tracker.update([
          { name: "system", type: "link", incomingBytes: rx, outgoingBytes: tx },
        ]);
      })
      .catch((error) => {
        this.tracker.markUnavailable(error);
      })
      .finally(() => {
        this.pending = null;
      });
    return this.pending;
  }

  async readCounters() {
    if (this.platform === "linux") return readLinuxCounters();
    if (this.platform === "win32") return readWindowsCounters();
    throw new Error(`unsupported platform: ${this.platform}`);
  }

  status() {
    const stats = this.tracker.get("system", "link");
    return {
      available: this.tracker.available,
      sampledAt: stats.sampledAt,
      error: stats.error,
      interfaceName: this.ifaceName,
      incomingBytesPerSecond: stats.incomingBytesPerSecond,
      outgoingBytesPerSecond: stats.outgoingBytesPerSecond,
    };
  }
}

async function readLinuxCounters() {
  let defaultIface = null;
  try {
    const route = await readFile("/proc/net/route", "utf8");
    for (const line of route.split("\n").slice(1)) {
      const parts = line.trim().split(/\s+/);
      if (parts[1] === "00000000") {
        defaultIface = parts[0];
        break;
      }
    }
  } catch {
    // 无默认路由时回退到全部物理接口合计
  }

  const dev = await readFile("/proc/net/dev", "utf8");
  let rx = 0;
  let tx = 0;
  let matched = false;
  for (const line of dev.split("\n").slice(2)) {
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    const name = line.slice(0, colon).trim();
    const fields = line
      .slice(colon + 1)
      .trim()
      .split(/\s+/)
      .map(Number);
    if (!Number.isFinite(fields[0]) || !Number.isFinite(fields[8])) continue;
    if (defaultIface) {
      if (name !== defaultIface) continue;
      matched = true;
    } else if (name === "lo") {
      continue;
    }
    rx += fields[0];
    tx += fields[8];
  }
  if (defaultIface && !matched) throw new Error(`默认网卡 ${defaultIface} 无统计数据`);
  return { rx, tx };
}

function readWindowsCounters() {
  return new Promise((resolve, reject) => {
    const child = spawn(
      "powershell",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "$r=0; $t=0; Get-NetAdapterStatistics -ErrorAction SilentlyContinue | ForEach-Object { $r += [int64]$_.ReceivedBytes; $t += [int64]$_.SentBytes }; Write-Output ($r.ToString() + ' ' + $t.ToString())",
      ],
      { windowsHide: true },
    );
    let stdout = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("网卡统计读取超时"));
    }, 5_000);
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.resume();
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", () => {
      clearTimeout(timer);
      const parts = stdout.trim().split(/\s+/).map(Number);
      if (parts.length >= 2 && Number.isFinite(parts[0]) && Number.isFinite(parts[1])) {
        resolve({ rx: parts[0], tx: parts[1] });
      } else {
        reject(new Error("无法读取网卡统计"));
      }
    });
  });
}
