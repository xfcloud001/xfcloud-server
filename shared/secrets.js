// 0.9.3：敏感本地状态加密落盘（AES-256-GCM）。
// 密钥为每个部署独立随机生成的 32 字节，存于 DATA_DIR 下 0600 权限文件；
// 密文文件格式：magic("XFC1") + iv(12) + authTag(16) + ciphertext。
// 仅防止普通用户直接读取明文（frpc 令牌、服务端地址、代理配置等），
// 不防御获得该机器文件系统完整访问权限的攻击者。
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import {
  chmodSync,
  existsSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";

const MAGIC = Buffer.from("XFC1", "ascii");
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const KEY_LENGTH = 32;

// 读取或创建 0600 权限的随机密钥文件。
export function loadOrCreateKey(keyPath) {
  if (existsSync(keyPath)) {
    const raw = readFileSync(keyPath);
    if (raw.length === KEY_LENGTH) return Buffer.from(raw);
    throw new Error("密钥文件长度无效，请删除后由程序重新生成");
  }
  const key = randomBytes(KEY_LENGTH);
  writeFileSync(keyPath, key, { mode: 0o600 });
  try {
    chmodSync(keyPath, 0o600);
  } catch {
    // Windows 等平台 chmod 为近似实现，忽略失败。
  }
  return key;
}

export function encryptJson(value, key) {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([MAGIC, iv, tag, ciphertext]);
}

export function decryptJson(buffer, key) {
  const data = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  if (data.length < MAGIC.length + IV_LENGTH + TAG_LENGTH || !data.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error("密文格式无效");
  }
  let offset = MAGIC.length;
  const iv = data.subarray(offset, offset + IV_LENGTH);
  offset += IV_LENGTH;
  const tag = data.subarray(offset, offset + TAG_LENGTH);
  offset += TAG_LENGTH;
  const ciphertext = data.subarray(offset);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8"));
}

// 加密写入（tmp + rename 原子替换，0600 权限）。
export function writeEncryptedJson(filePath, value, keyPath) {
  const key = loadOrCreateKey(keyPath);
  const temporary = `${filePath}.tmp`;
  writeFileSync(temporary, encryptJson(value, key), { mode: 0o600 });
  try {
    renameSync(temporary, filePath);
  } catch (error) {
    // rename 失败（Windows 杀软占用等）时清理临时文件，避免密文残片堆积。
    try {
      rmSync(temporary, { force: true });
    } catch {
      // 忽略清理失败。
    }
    throw error;
  }
  try {
    chmodSync(filePath, 0o600);
  } catch {
    // 忽略不支持的平台。
  }
}

// 解密读取；文件不存在返回 null；密钥缺失或解密失败抛错。
export function readEncryptedJson(filePath, keyPath) {
  if (!existsSync(filePath)) return null;
  const key = loadOrCreateKey(keyPath);
  return decryptJson(readFileSync(filePath), key);
}

// 0.9.3：迁移旧的明文 JSON 文件——读取、加密落盘、删除明文（尽力而为）。
// 返回 { value, plaintextRemoved }；明文文件不存在时返回 null。
// plaintextRemoved=false 表示明文仍残留（删除失败），调用方应告警并在下次启动重试。
export function migratePlaintextJson(plaintextPath, encryptedPath, keyPath) {
  if (!existsSync(plaintextPath)) return null;
  const parsed = JSON.parse(readFileSync(plaintextPath, "utf8"));
  writeEncryptedJson(encryptedPath, parsed, keyPath);
  let plaintextRemoved = false;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      rmSync(plaintextPath, { force: true });
      plaintextRemoved = true;
      break;
    } catch {
      // Windows 上偶发文件占用，短暂重试。
      if (attempt === 2) break;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 200);
    }
  }
  return { value: parsed, plaintextRemoved };
}
