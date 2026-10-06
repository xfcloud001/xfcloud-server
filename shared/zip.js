import { inflateRawSync } from "node:zlib";

// 最小 ZIP 读取器：仅支持 STORE(0) 与 DEFLATE(8)，满足 frp 官方发布包解析。
// 返回与 tar.js 一致的 [{ path, data }] 结构。

const EOCD_SIG = 0x06054b50;
const CENTRAL_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;
const ZIP64_EOCD_SIG = 0x06064b50;

function readUInt32LE(buf, offset) {
  return buf.readUInt32LE(offset);
}

/**
 * Parse a ZIP archive buffer into regular file entries.
 * Each entry: { path, data }
 * Skips directories. Supports compression methods 0 (stored) and 8 (deflate).
 * @param {Buffer} buffer
 * @returns {Array<{path: string, data: Buffer}>}
 */
export function parseZip(buffer) {
  if (!Buffer.isBuffer(buffer)) throw new Error("ZIP 数据格式不正确");

  // 从尾部查找 EOCD（注释最长 64KB）。
  let eocdOffset = -1;
  const scanStart = Math.max(0, buffer.length - 65557);
  for (let i = buffer.length - 22; i >= scanStart; i -= 1) {
    if (buffer.readUInt32LE(i) === EOCD_SIG) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) {
    if (buffer.includes(Buffer.from([0x50, 0x4b, 0x06, 0x06]))) {
      throw new Error("ZIP64 格式暂不支持");
    }
    throw new Error("无法识别的 ZIP 文件（缺少中央目录结束标记）");
  }

  let centralOffset = readUInt32LE(buffer, eocdOffset + 16);
  const centralCount = buffer.readUInt16LE(eocdOffset + 10);
  if (centralOffset === 0xffffffff || buffer.readUInt32LE(eocdOffset + 12) === 0xffffffff) {
    throw new Error("ZIP64 格式暂不支持");
  }

  const files = [];
  let cursor = centralOffset;
  for (let index = 0; index < centralCount; index += 1) {
    if (cursor + 46 > buffer.length || readUInt32LE(buffer, cursor) !== CENTRAL_SIG) {
      throw new Error("ZIP 中央目录已损坏");
    }
    const method = buffer.readUInt16LE(cursor + 10);
    const compressedSize = readUInt32LE(buffer, cursor + 20);
    const uncompressedSize = readUInt32LE(buffer, cursor + 24);
    const nameLength = buffer.readUInt16LE(cursor + 28);
    const extraLength = buffer.readUInt16LE(cursor + 30);
    const commentLength = buffer.readUInt16LE(cursor + 32);
    const localHeaderOffset = readUInt32LE(buffer, cursor + 42);
    const name = buffer.toString("utf8", cursor + 46, cursor + 46 + nameLength);
    cursor += 46 + nameLength + extraLength + commentLength;

    if (!name || name.endsWith("/")) continue; // 目录条目

    if (localHeaderOffset + 30 > buffer.length || readUInt32LE(buffer, localHeaderOffset) !== LOCAL_SIG) {
      throw new Error(`ZIP 本地文件头已损坏: ${name}`);
    }
    const localNameLength = buffer.readUInt16LE(localHeaderOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localHeaderOffset + 28);
    const dataOffset = localHeaderOffset + 30 + localNameLength + localExtraLength;
    const compressed = buffer.subarray(dataOffset, dataOffset + compressedSize);
    if (compressed.length !== compressedSize) {
      throw new Error(`ZIP 文件数据不完整: ${name}`);
    }

    let data;
    if (method === 0) {
      data = Buffer.from(compressed);
    } else if (method === 8) {
      try {
        data = inflateRawSync(compressed);
      } catch {
        throw new Error(`ZIP 解压失败（DEFLATE）: ${name}`);
      }
    } else {
      throw new Error(`不支持的 ZIP 压缩方式 (${method}): ${name}`);
    }
    if (uncompressedSize > 0 && data.length !== uncompressedSize) {
      throw new Error(`ZIP 文件大小校验失败: ${name}`);
    }
    files.push({ path: name.replace(/\\/g, "/"), data });
  }

  return files;
}
