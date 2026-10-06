import { gzipSync } from "node:zlib";
import { extname } from "node:path";

const BLOCK_SIZE = 512;

/**
 * Parse a tar buffer (uncompressed) into a list of regular file entries.
 * Each entry: { path, data }
 * Skips directories, symlinks, and empty names.
 */
export function parseTar(buffer) {
  const files = [];
  let offset = 0;
  while (offset + BLOCK_SIZE <= buffer.length) {
    let name = buffer.toString("utf8", offset, offset + 100).replace(/\0+$/, "");
    if (!name) break; // End of archive

    // Read size field (octal, possibly with space prefix)
    const sizeStr = buffer
      .toString("ascii", offset + 124, offset + 136)
      .replace(/\0/g, "")
      .trim();
    const size = sizeStr ? parseInt(sizeStr, 8) : 0;
    if (!Number.isFinite(size) || size < 0) {
      offset += BLOCK_SIZE;
      continue;
    }

    const typeFlag = buffer.toString("ascii", offset + 156, offset + 157).charCodeAt(0);

    // Handle GNU long names (type 'L')
    if (typeFlag === 76) {
      const longName = buffer.toString("utf8", offset + BLOCK_SIZE, offset + BLOCK_SIZE + size).replace(/\0+$/, "");
      const dataBlocks = Math.ceil(size / BLOCK_SIZE);
      offset += BLOCK_SIZE + dataBlocks * BLOCK_SIZE;
      // Next block contains the actual file entry with this long name
      if (offset + BLOCK_SIZE > buffer.length) break;
      const nextType = buffer.toString("ascii", offset + 156, offset + 157).charCodeAt(0);
      const nextSizeStr = buffer
        .toString("ascii", offset + 124, offset + 136)
        .replace(/\0/g, "")
        .trim();
      const nextSize = nextSizeStr ? parseInt(nextSizeStr, 8) : 0;
      if (nextType === 0 || nextType === 48) {
        // Regular file (type 0 or '0')
        const dataOffset = offset + BLOCK_SIZE;
        const fileData = buffer.subarray(dataOffset, dataOffset + nextSize);
        files.push({ path: longName, data: Buffer.from(fileData) });
        const nextDataBlocks = Math.ceil(nextSize / BLOCK_SIZE);
        offset += BLOCK_SIZE + nextDataBlocks * BLOCK_SIZE;
      }
      continue;
    }

    // Only process regular files (type 0, '0', or null for old tar)
    if (typeFlag === 0 || typeFlag === 48) {
      // Check for prefix (USTAR format)
      const prefix = buffer.toString("utf8", offset + 345, offset + 500).replace(/\0+$/, "");
      const fullPath = prefix ? `${prefix}/${name}` : name;

      const dataOffset = offset + BLOCK_SIZE;
      const fileData = buffer.subarray(dataOffset, dataOffset + size);
      files.push({ path: fullPath, data: Buffer.from(fileData) });
    }

    const dataBlocks = Math.ceil(size / BLOCK_SIZE);
    offset += BLOCK_SIZE + dataBlocks * BLOCK_SIZE;
  }
  return files;
}

function octal(value, length) {
  const text = value.toString(8).padStart(length - 1, "0");
  return `${text}\0`;
}

/**
 * Create a gzip-compressed USTAR tar archive.
 * @param {Array<{path: string, data: Buffer}>} files
 * @returns {Buffer}
 */
export function createTarGz(files) {
  const blocks = [];

  for (const file of files) {
    const name = file.path.split("/").pop();
    const prefixParts = file.path.split("/");
    prefixParts.pop();
    const prefix = prefixParts.join("/");
    if (name.length > 100 || prefix.length > 155) {
      throw new Error(`更新包内路径过长: ${file.path}`);
    }

    const header = Buffer.alloc(BLOCK_SIZE);
    header.write(name, 0, 100, "utf8");
    header.write(octal(0o644, 7), 100, 7, "ascii"); // mode
    header.write(octal(0, 7), 108, 7, "ascii"); // uid
    header.write(octal(0, 7), 116, 7, "ascii"); // gid
    header.write(octal(file.data.length, 11), 124, 12, "ascii"); // size
    header.write(octal(Math.floor(Date.now() / 1000), 11), 136, 12, "ascii"); // mtime
    header.write("        ", 148, 8, "ascii"); // checksum placeholder (spaces)
    header.write("0", 156, 1, "ascii"); // type flag: regular file
    header.write("ustar\0", 257, 6, "ascii"); // magic
    header.write("00", 263, 2, "ascii"); // version
    if (prefix) header.write(prefix, 345, 155, "utf8");

    // USTAR checksum: sum of all header bytes, with checksum field as spaces.
    let checksum = 0;
    for (let i = 0; i < BLOCK_SIZE; i += 1) checksum += header[i];
    header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");

    blocks.push(header);

    const dataBlock = Buffer.alloc(Math.ceil(file.data.length / BLOCK_SIZE) * BLOCK_SIZE);
    file.data.copy(dataBlock);
    blocks.push(dataBlock);
  }

  // Two zero blocks mark the end of the archive.
  blocks.push(Buffer.alloc(BLOCK_SIZE * 2));
  return gzipSync(Buffer.concat(blocks));
}

/**
 * Normalize an in-package relative path. Rejects traversal/absolute/drive paths.
 * Returns a forward-slash normalized path like "server/app.js".
 */
export function normalizePackagePath(rawPath) {
  let p = String(rawPath || "").trim().replace(/\\/g, "/");
  if (!p) throw new Error("更新包中存在空文件名");
  if (p.includes("\0")) throw new Error(`非法文件路径: ${rawPath}`);
  if (/^[a-zA-Z]:/.test(p) || p.startsWith("/")) {
    throw new Error(`更新包中不允许绝对路径: ${rawPath}`);
  }
  // Collide repeated slashes and resolve "." segments.
  const parts = [];
  for (const part of p.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") {
      throw new Error(`更新包中不允许上级目录路径: ${rawPath}`);
    }
    parts.push(part);
  }
  if (parts.length === 0) throw new Error(`非法文件路径: ${rawPath}`);
  return parts.join("/");
}

const TEXT_EXTENSIONS = new Set([
  ".js",
  ".mjs",
  ".cjs",
  ".json",
  ".html",
  ".css",
  ".svg",
  ".md",
  ".txt",
  ".sh",
  ".cmd",
  ".bat",
  ".ps1",
  ".yaml",
  ".yml",
  ".env",
  // 官网静态资源（截图/图标/字体）
  ".png",
  ".jpg",
  ".jpeg",
  ".webp",
  ".ico",
  ".woff2",
]);

const ALLOWED_EXACT_FILES = new Set([
  "LICENSE",
  ".env.example",
  ".gitignore",
]);

// Node 内置模块（legacy 无 node: 前缀形式）。本项目零第三方依赖，
// 因此任何不属于内置模块的裸导入都说明更新包缺文件或误引入了依赖。
const NODE_BUILTIN_MODULES = new Set([
  "fs", "path", "os", "url", "http", "https", "net", "crypto", "child_process",
  "zlib", "stream", "events", "util", "buffer", "process", "tty", "dns", "tls",
  "assert", "string_decoder", "timers", "readline", "worker_threads", "module",
  "cluster", "dgram", "perf_hooks", "vm", "querystring",
]);

// 各角色更新包必须包含的核心文件，防止误传其他端的目录。
const ROLE_REQUIRED_FILES = {
  server: ["server/app.js", "shared/core.js", "shared/version.js"],
  client: ["client/app.js", "shared/core.js", "shared/version.js"],
  license: ["license/app.js", "shared/core.js", "shared/version.js"],
  website: ["site/serve.mjs", "site/index.html", "shared/version.js"],
};

/**
 * 校验更新包内所有 JS 文件的本地导入都能在包内找到对应文件。
 * 防止“新版 app.js 引用了新增模块，但更新包漏传该模块”导致更新后服务起不来。
 */
function validateImportGraph(files, paths) {
  // 注意：副作用导入语句要求关键字前为行首/分号/花括号，避免把
  // 字符串里出现的路径片段（如 /import 紧跟引号）误判为导入语句。
  const importPattern =
    /\bfrom\s*["']([^"']+)["']|(?:^|[;{}\n])[ \t]*import\s+["']([^"']+)["']|\bimport\(\s*["']([^"']+)["']\s*\)/gm;

  for (const file of files) {
    const path = normalizePackagePath(file.path);
    if (!/\.(js|mjs|cjs)$/i.test(path)) continue;
    const content = file.data.toString("utf8");
    let match;
    while ((match = importPattern.exec(content)) !== null) {
      const specifier = match[1] || match[2] || match[3] || "";
      if (!specifier || specifier.startsWith("node:")) continue;

      if (specifier.startsWith("/")) {
        throw new Error(`更新包中 ${path} 使用了绝对路径导入: ${specifier}`);
      }

      if (specifier.startsWith(".")) {
        const target = resolveInPackage(path, specifier);
        if (!target) {
          throw new Error(
            `更新包导入路径越界: ${path} 导入 ${specifier}（请使用项目内相对路径）`,
          );
        }
        const exists =
          paths.has(target) || paths.has(`${target}.js`) || paths.has(`${target}/index.js`);
        if (!exists) {
          throw new Error(
            `更新包缺少文件: ${path} 依赖的 ${specifier}（包内找不到 ${target}）。请把完整的项目目录/压缩包重新上传。`,
          );
        }
        continue;
      }

      // 裸模块名：本项目零依赖，只允许 Node 内置模块。
      const bareName = specifier.startsWith("@")
        ? specifier.split("/").slice(0, 2).join("/")
        : specifier.split("/")[0];
      if (!NODE_BUILTIN_MODULES.has(bareName)) {
        throw new Error(
          `更新包中 ${path} 引用了未包含的第三方模块: ${specifier}（本项目不使用 node_modules，请勿引入外部依赖）`,
        );
      }
    }
  }
}

/** 把包内相对导入解析为包根相对路径；越界（.. 超出包根）返回 null。 */
function resolveInPackage(fromFile, specifier) {
  const parts = String(fromFile).split("/").slice(0, -1);
  for (const piece of specifier.split("/")) {
    if (!piece || piece === ".") continue;
    if (piece === "..") {
      if (parts.length === 0) return null;
      parts.pop();
    } else {
      parts.push(piece);
    }
  }
  return parts.join("/");
}

/**
 * Validate the contents of an update package before accepting it.
 * @param {object} options
 * @param {"server"|"client"|"license"} options.role
 * @param {string} options.version Declared version (required)
 * @param {Array<{path: string, data: Buffer}>} options.files Parsed file entries
 * @returns {{paths: string[], packageVersion: string}}
 */
export function validateUpdateFiles({ role, version, files }) {
  const required = ROLE_REQUIRED_FILES[role];
  if (!required) throw new Error(`未知的更新角色: ${role}`);
  const declaredVersion = String(version || "").trim();
  if (!/^\d+\.\d+\.\d+[0-9A-Za-z.+-]*$/.test(declaredVersion)) {
    throw new Error("版本号格式不正确（示例：0.8.4）");
  }
  if (!Array.isArray(files) || files.length === 0) {
    throw new Error("更新包中未找到任何文件");
  }
  if (files.length > 800) {
    throw new Error("更新包文件数量过多（超过 800 个）");
  }

  const paths = new Set();
  let totalSize = 0;
  for (const file of files) {
    const path = normalizePackagePath(file.path);
    if (paths.has(path)) throw new Error(`更新包中存在重复文件: ${path}`);
    paths.add(path);

    const data = Buffer.isBuffer(file.data) ? file.data : Buffer.from(file.data || "");
    totalSize += data.length;
    if (totalSize > 200 * 1024 * 1024) {
      throw new Error("更新包内容过大（超过 200MB）");
    }
    if (data.length === 0) continue;

    const base = path.split("/").pop();
    const ext = extname(base).toLowerCase();
    if (!TEXT_EXTENSIONS.has(ext) && !ALLOWED_EXACT_FILES.has(base)) {
      throw new Error(
        `更新包包含不支持的文件类型: ${path}（仅允许代码/文本类文件，二进制文件请先移除）`,
      );
    }
  }

  for (const requiredPath of required) {
    if (!paths.has(requiredPath)) {
      throw new Error(`更新包缺少必需文件: ${requiredPath}（请确认选择的是${roleLabel(role)}的项目目录或压缩包）`);
    }
  }

  // shared/version.js 中的 VERSION 必须与声明版本一致，防止传错版本目录。
  const versionFile = files.find(
    (file) => normalizePackagePath(file.path) === "shared/version.js",
  );
  const content = versionFile ? versionFile.data.toString("utf8") : "";
  const match = /VERSION\s*=\s*["']([^"']+)["']/.exec(content);
  if (!match) {
    throw new Error("无法从 shared/version.js 读取版本号，请确认更新包结构完整");
  }
  const packageVersion = match[1].trim();
  if (packageVersion !== declaredVersion) {
    throw new Error(
      `版本不一致：表单填写 ${declaredVersion}，但包内 shared/version.js 为 ${packageVersion}`,
    );
  }

  // 校验所有 JS 文件的本地导入在包内闭合，防止漏传文件导致更新后无法启动。
  validateImportGraph(files, paths);

  return { paths: [...paths], packageVersion };
}

function roleLabel(role) {
  return { server: "服务端", client: "客户端", license: "授权中心", website: "官网" }[role] || role;
}
