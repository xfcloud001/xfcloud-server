import { existsSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";

// 服务端 HTML 片段拼装：index.html 作为外壳，菜单/功能区拆分为独立片段文件，
// 通过 `<!--include:partials/xxx.html-->` 标记在服务 "/" 时注入，拼装结果与单文件时
// 的 DOM 完全一致，从而前端脚本无需改动即可继续按 ID 取元素。
const INCLUDE_PATTERN = /<!--\s*include:\s*([a-zA-Z0-9_.\\/-]+?)\s*-->/g;

function safeResolve(baseDir, rel) {
  const normalized = String(rel).replace(/\\/g, "/");
  const target = resolve(baseDir, normalized);
  const baseWithSep = baseDir.endsWith(sep) ? baseDir : baseDir + sep;
  if (!target.startsWith(baseWithSep) && target !== baseDir) {
    throw new Error(`非法的片段路径: ${rel}`);
  }
  return target;
}

// 读取外壳 HTML 并递归（仅一层）替换 include 标记为片段内容。
export function renderHtmlWithIncludes(shellPath) {
  const baseDir = dirname(resolve(shellPath));
  const readInclude = (relPath) => {
    const target = isAbsolute(relPath) ? relPath : safeResolve(baseDir, relPath);
    if (!existsSync(target)) throw new Error(`缺少页面片段文件: ${relPath}`);
    return readFileSync(target, "utf8");
  };
  const shell = readFileSync(shellPath, "utf8");
  return shell.replace(INCLUDE_PATTERN, (_match, rel) => {
    const content = readInclude(rel.trim());
    // 片段内若仍有 include 标记（一层嵌套），一并展开。
    return content.replace(INCLUDE_PATTERN, (_inner, innerRel) =>
      readInclude(join(dirname(rel.trim()), innerRel.trim())),
    );
  });
}
