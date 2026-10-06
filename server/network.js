import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

// 服务端网络配置（管理端口 + HTTPS），持久化在 data/server-config.json。
// 优先级：环境变量 MANAGER_PORT > 配置文件 > 默认 8080。
// HTTPS 仅由配置文件控制；证书/私钥保存在 data/server/tls/ 下。

export function tlsDir(dataDir) {
  return join(dataDir, "tls");
}

export function tlsCertPath(dataDir) {
  return join(tlsDir(dataDir), "manager.crt");
}

export function tlsKeyPath(dataDir) {
  return join(tlsDir(dataDir), "manager.key");
}

function readConfig(dataDir) {
  let config = {};
  try {
    config = JSON.parse(readFileSync(join(dataDir, "server-config.json"), "utf8"));
  } catch {
    // 首次运行或文件损坏时按默认值处理。
  }
  return config;
}

function writeConfig(dataDir, config) {
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(
    join(dataDir, "server-config.json"),
    JSON.stringify(config, null, 2),
  );
}

/**
 * 解析当前网络配置。
 * @returns {{
 *   configuredPort: number|null,
 *   envLockedPort: boolean,
 *   port: number,
 *   httpsEnabled: boolean,
 *   certReady: boolean,
 *   httpsActive: boolean,
 * }}
 */
export function resolveNetworkConfig(dataDir) {
  const config = readConfig(dataDir);
  const configuredPortValue = Number(config.port);
  const configuredPort =
    Number.isInteger(configuredPortValue) &&
    configuredPortValue >= 1 &&
    configuredPortValue <= 65535
      ? configuredPortValue
      : null;
  const envLockedPort = Boolean(process.env.MANAGER_PORT);
  const port = envLockedPort ? Number(process.env.MANAGER_PORT) : configuredPort || 8080;
  const httpsEnabled = Boolean(config.https?.enabled);
  const certReady = existsSync(tlsCertPath(dataDir)) && existsSync(tlsKeyPath(dataDir));
  // 配置开启但证书缺失时回退 HTTP，由启动日志提示。
  const httpsActive = httpsEnabled && certReady;
  return {
    configuredPort,
    envLockedPort,
    port,
    httpsEnabled,
    certReady,
    httpsActive,
  };
}

/** 保存网络配置，返回校验后的配置。 */
export function saveNetworkConfig(dataDir, { port, httpsEnabled }) {
  const config = readConfig(dataDir);
  if (port !== undefined) {
    if (process.env.MANAGER_PORT) {
      throw new Error("管理端口由环境变量 MANAGER_PORT 固定，请在环境变量中修改");
    }
    const value = Number(port);
    if (!Number.isInteger(value) || value < 1 || value > 65535) {
      throw new Error("端口须为 1-65535 的整数");
    }
    config.port = value;
  }
  if (httpsEnabled !== undefined) {
    const enabled = Boolean(httpsEnabled);
    if (enabled) {
      const certReady =
        existsSync(tlsCertPath(dataDir)) && existsSync(tlsKeyPath(dataDir));
      if (!certReady) {
        throw new Error("请先上传 HTTPS 证书和私钥，再开启 HTTPS");
      }
    }
    config.https = { ...(config.https || {}), enabled };
  }
  writeConfig(dataDir, config);
  return resolveNetworkConfig(dataDir);
}

/** 读取 TLS 选项；开启 HTTPS 且证书齐备时返回 { cert, key }，否则 null。 */
export function loadManagerTlsOptions(dataDir, logger = () => {}) {
  const { httpsEnabled, certReady } = resolveNetworkConfig(dataDir);
  if (!httpsEnabled) return null;
  if (!certReady) {
    logger("HTTPS enabled in config but certificate/key missing, falling back to HTTP");
    return null;
  }
  return {
    cert: readFileSync(tlsCertPath(dataDir)),
    key: readFileSync(tlsKeyPath(dataDir)),
  };
}

/** 保存上传的证书/私钥。 */
export function saveTlsMaterial(dataDir, kind, buffer) {
  if (!["cert", "key"].includes(kind)) throw new Error("证书类型无效");
  if (buffer.length === 0) throw new Error("上传内容为空");
  if (buffer.length > 200 * 1024) throw new Error("证书/私钥文件不能超过 200KB");
  mkdirSync(tlsDir(dataDir), { recursive: true });
  const file = kind === "cert" ? tlsCertPath(dataDir) : tlsKeyPath(dataDir);
  writeFileSync(file, buffer, { mode: 0o600 });
  return { kind, path: file, size: buffer.length };
}

/** 清除证书/私钥并关闭 HTTPS。 */
export function clearTlsMaterial(dataDir) {
  rmSync(tlsCertPath(dataDir), { force: true });
  rmSync(tlsKeyPath(dataDir), { force: true });
  const config = readConfig(dataDir);
  config.https = { ...(config.https || {}), enabled: false };
  writeConfig(dataDir, config);
  return resolveNetworkConfig(dataDir);
}
