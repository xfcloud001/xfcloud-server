import { spawn } from "node:child_process";
import { gunzipSync } from "node:zlib";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parseTar, normalizePackagePath } from "./tar.js";

const PROTECTED_PREFIXES = ["data/", "runtime/"];
const MARKER_FILE = "updating.json";
const PLAN_FILE = "_update_plan.json";
const RESULT_FILE = "update_result.json";
const LOG_FILE = "updater.log";
const START_ATTEMPTS = 2;
const PORT_WAIT_MS = 20_000;
const HEALTH_TIMEOUT_MS = 45_000;

function markerFile(dataDir) {
  return join(dataDir, MARKER_FILE);
}

function isProcessAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function readJsonSafe(file) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

/** 读取更新标记：{ role, stage, startedAt, backupDir, addedFiles, pid } 或 null。 */
export function readUpdateMarker(dataDir) {
  if (!dataDir) return null;
  const marker = readJsonSafe(markerFile(dataDir));
  if (!marker || !marker.stage) return null;
  return marker;
}

/**
 * 启动时恢复中断的更新：
 * - stage "backup"：文件替换未完成即崩溃，从备份还原旧文件。
 * - stage "replaced"：新文件已就位。若看门狗仍存活（正在重启/健康检查）则不干预，
 *   由看门狗决定成功清标记或失败回滚；若看门狗已丢失（如断电重启）且备份仍在，
 *   此处还原旧文件保证可运行。
 */
export function recoverInterruptedUpdate(dataDir, logger = () => {}) {
  const marker = readUpdateMarker(dataDir);
  if (!marker) return null;
  if (isProcessAlive(marker.watchdogPid)) {
    logger(`update watchdog (pid ${marker.watchdogPid}) is active, skip recovery`);
    return marker;
  }
  try {
    const backupDir = marker.backupDir ? resolve(marker.backupDir) : "";
    if (backupDir && existsSync(backupDir)) {
      restoreBackup(backupDir, marker.addedFiles || []);
      logger(`interrupted update recovered: restored backup ${marker.backupDirName || ""}`);
    } else {
      logger("interrupted update recovered: no backup left, marker cleared");
    }
  } catch (error) {
    logger(`recover interrupted update failed: ${error.message}`);
  }
  clearUpdateMarker(dataDir);
  return marker;
}

/** 更新成功（新进程健康检查通过）后清除标记并记录结果。 */
export function clearUpdateMarker(dataDir, extraResult = {}) {
  const data = readUpdateMarker(dataDir);
  rmSync(markerFile(dataDir), { force: true });
  if (data) {
    writeUpdateResult(dataDir, {
      status: "success",
      role: data.role || "",
      finishedAt: new Date().toISOString(),
      ...extraResult,
    });
  }
}

function writeUpdateResult(dataDir, result) {
  try {
    writeFileSync(join(dataDir, RESULT_FILE), JSON.stringify(result, null, 2));
  } catch {
    // 结果记录失败不影响主流程。
  }
}

export function readUpdateResult(dataDir) {
  if (!dataDir) return null;
  return readJsonSafe(join(dataDir, RESULT_FILE));
}

function restoreBackup(backupDir, addedFiles) {
  const manifest = readJsonSafe(join(backupDir, "manifest.json")) || {
    replaced: [],
    added: addedFiles || [],
  };
  // backupDir = <rootDir>/data/<role>/_backup_xxx，向上三级即项目根目录。
  const rootDir = resolve(backupDir, "..", "..", "..");
  for (const relative of manifest.replaced || []) {
    const source = join(backupDir, relative);
    if (!existsSync(source)) continue;
    const target = resolve(rootDir, relative);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(source, target);
  }
  for (const relative of manifest.added || []) {
    const target = resolve(rootDir, relative);
    rmSync(target, { force: true });
  }
  rmSync(backupDir, { recursive: true, force: true });
}

/**
 * 应用更新并交给看门狗进程完成重启、健康检查与失败回滚。
 *
 * @param {object} options
 * @param {string} [options.downloadUrl] - .tar.gz 下载地址
 * @param {string} [options.filePath] - 本地 .tar.gz 路径
 * @param {Array<{path:string,data:Buffer|string}>} [options.files] - 散文件（跳过压缩包解析）
 * @param {string} options.rootDir - 项目根目录
 * @param {string} options.dataDir - 数据目录（更新过程保留）
 * @param {string} options.role - "server" | "client" | "license"
 * @param {number[]} [options.ports] - 重启前需等待释放的端口（管理端口、frp 端口等）
 * @param {string} [options.healthScheme] - 健康检查协议，默认 http
 * @param {number} [options.healthPort] - 健康检查端口，默认取 ports[0]
 * @param {function} [options.logger]
 */
export async function applyUpdateAndRestart({
  downloadUrl,
  filePath,
  files: providedFiles,
  rootDir,
  dataDir,
  role,
  ports = [],
  healthScheme = "http",
  healthPort,
  logger = () => {},
}) {
  let files = providedFiles;
  if (!files) {
    let compressed;
    if (filePath) {
      logger(`reading local update package ${filePath}`);
      compressed = readFileSync(filePath);
    } else if (downloadUrl) {
      logger(`downloading update from ${downloadUrl}`);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 120_000);
      let response;
      try {
        response = await fetch(downloadUrl, { signal: controller.signal });
        if (!response.ok) throw new Error(`下载失败: HTTP ${response.status}`);
      } catch (error) {
        clearTimeout(timeout);
        throw new Error(`下载更新包失败: ${error.message}`);
      }
      clearTimeout(timeout);
      compressed = Buffer.from(await response.arrayBuffer());
    } else {
      throw new Error("缺少更新来源（下载地址、本地包或文件列表）");
    }
    if (compressed.length === 0) throw new Error("更新包为空");

    logger(`decompressing ${compressed.length} bytes`);
    let tarBuffer;
    try {
      tarBuffer = gunzipSync(compressed);
    } catch (error) {
      throw new Error(`解压失败: ${error.message}`);
    }
    files = parseTar(tarBuffer);
  }
  if (!Array.isArray(files) || files.length === 0) throw new Error("更新内容为空");

  logger(`found ${files.length} files`);

  // 归一化路径并过滤保护目录，得到最终要写入的文件清单。
  const entries = [];
  for (const file of files) {
    const path = normalizePackagePath(file.path);
    if (PROTECTED_PREFIXES.some((prefix) => path.startsWith(prefix))) continue;
    const data = Buffer.isBuffer(file.data) ? file.data : Buffer.from(file.data || "");
    entries.push({ path, data });
  }
  if (entries.length === 0) throw new Error("更新包中没有可应用的文件");

  // 1. 备份将被替换/新增的文件，并写入更新标记（任何一步失败都可还原）。
  const backupDirName = `_backup_${Date.now()}`;
  const backupDir = join(dataDir, backupDirName);
  const manifest = { replaced: [], added: [] };
  for (const entry of entries) {
    const target = resolve(rootDir, entry.path);
    if (existsSync(target)) {
      mkdirSync(dirname(join(backupDir, entry.path)), { recursive: true });
      copyFileSync(target, join(backupDir, entry.path));
      manifest.replaced.push(entry.path);
    } else {
      manifest.added.push(entry.path);
    }
  }
  mkdirSync(backupDir, { recursive: true });
  writeFileSync(join(backupDir, "manifest.json"), JSON.stringify(manifest, null, 2));
  const markerBase = {
    role,
    startedAt: new Date().toISOString(),
    backupDir,
    backupDirName,
    addedFiles: manifest.added,
    pid: process.pid,
  };
  writeFileSync(markerFile(dataDir), JSON.stringify({ ...markerBase, stage: "backup" }));
  logger(`backup created: ${manifest.replaced.length} replaced, ${manifest.added.length} added`);

  // 2. 替换文件；失败立即回滚并抛出。
  try {
    for (const entry of entries) {
      const target = resolve(rootDir, entry.path);
      mkdirSync(dirname(target), { recursive: true });
      const staged = join(dataDir, "_update", entry.path);
      mkdirSync(dirname(staged), { recursive: true });
      writeFileSync(staged, entry.data);
      try {
        renameSync(staged, target);
      } catch {
        writeFileSync(target, entry.data);
        rmSync(staged, { force: true });
      }
    }
  } catch (error) {
    restoreBackup(backupDir, manifest.added);
    rmSync(markerFile(dataDir), { force: true });
    throw new Error(`应用更新失败（已回滚）: ${error.message}`);
  } finally {
    rmSync(join(dataDir, "_update"), { recursive: true, force: true });
  }

  // 3. 标记替换完成，交给看门狗重启并做健康检查。
  writeFileSync(markerFile(dataDir), JSON.stringify({ ...markerBase, stage: "replaced" }));
  logger("update applied, handing over to watchdog");

  const planPath = join(dataDir, PLAN_FILE);
  const logPath = join(dataDir, LOG_FILE);
  const plan = {
    parentPid: process.pid,
    entry: process.argv[1],
    // 捕获主进程的 Node 启动参数（如 --experimental-sqlite），
    // 看门狗重启新版本时一并传入，避免 22.5–22.12 下 node:sqlite 等实验模块不可用。
    nodeArgs: process.execArgv.slice(),
    cwd: process.cwd(),
    rootDir,
    dataDir,
    logPath,
    ports: (ports || []).filter((port) => Number.isInteger(port) && port > 0),
    healthScheme: healthScheme === "https" ? "https" : "http",
    healthPort: healthPort || (ports || [])[0] || 0,
    markerPath: markerFile(dataDir),
    resultPath: join(dataDir, RESULT_FILE),
    startedAt: new Date().toISOString(),
  };
  writeFileSync(planPath, JSON.stringify(plan, null, 2));

  const script = join(dataDir, "updater.mjs");
  writeFileSync(script, WATCHDOG_SOURCE);
  try {
    chmodSync(script, 0o755);
  } catch {
    // Windows 下 chmod 近乎空操作。
  }

  const watchdog = spawn(process.execPath, [script, planPath], {
    detached: true,
    stdio: "ignore",
    cwd: process.cwd(),
    env: process.env,
  });
  watchdog.unref();
  // 把看门狗 pid 记入标记：新进程启动时可据此判断看门狗是否仍在接管，
  // 避免恢复逻辑误回滚一次正常的更新。
  try {
    writeFileSync(
      markerFile(dataDir),
      JSON.stringify({ ...markerBase, stage: "replaced", watchdogPid: watchdog.pid }),
    );
  } catch {
    // 标记补写失败不影响更新主流程。
  }
  logger(`watchdog spawned (pid ${watchdog.pid}), log: ${logPath}`);
  process.exit(0);
}

// 独立看门狗脚本源码（写入 data/<role>/updater.mjs 后脱离父进程运行）：
// 等旧进程退出 → 等端口释放 → 启动新进程 → 轮询 /healthz → 失败重试 1 次 → 仍失败则回滚旧版本。
const WATCHDOG_SOURCE = [
  "import { spawn } from 'node:child_process';",
  "import http from 'node:http';",
  "import https from 'node:https';",
  "import net from 'node:net';",
  "import { appendFileSync, chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';",
  "import { dirname, join, resolve } from 'node:path';",
  "",
  "const plan = JSON.parse(readFileSync(process.argv[2], 'utf8'));",
  "const log = (msg) => {",
  "  try { appendFileSync(plan.logPath, new Date().toISOString() + ' ' + msg + '\\n'); } catch {}",
  "};",
  "",
  "const isAlive = (pid) => { try { process.kill(pid, 0); return true; } catch { return false; } };",
  "",
  "function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }",
  "",
  "function portFree(port) {",
  "  return new Promise((resolveFree) => {",
  "    const probe = net.createServer();",
  "    probe.once('error', () => resolveFree(false));",
  "    probe.once('listening', () => probe.close(() => resolveFree(true)));",
  "    probe.listen(port, '127.0.0.1');",
  "  });",
  "}",
  "",
  "async function waitPortsFree(ports, timeoutMs) {",
  "  const start = Date.now();",
  "  for (const port of ports) {",
  "    while (Date.now() - start < timeoutMs && !(await portFree(port))) {",
  "      log(`port ${port} still in use, waiting`);",
  "      await wait(500);",
  "    }",
  "    if (!(await portFree(port))) log(`warning: port ${port} still busy after timeout`);",
  "  }",
  "}",
  "",
  "function healthOk() {",
  "  const port = plan.healthPort;",
  "  if (!port) return Promise.resolve(true);",
  "  return new Promise((resolveCheck) => {",
  "    const mod = plan.healthScheme === 'https' ? https : http;",
  "    const req = mod.request(",
  "      { host: '127.0.0.1', port, path: '/healthz', timeout: 3000, rejectUnauthorized: false },",
  "      (res) => {",
  "        res.resume();",
  "        resolveCheck(res.statusCode === 200);",
  "      },",
  "    );",
  "    req.once('timeout', () => { req.destroy(); resolveCheck(false); });",
  "    req.once('error', () => resolveCheck(false));",
  "    req.end();",
  "  });",
  "}",
  "",
  "async function waitHealth(timeoutMs) {",
  "  const start = Date.now();",
  "  while (Date.now() - start < timeoutMs) {",
  "    if (await healthOk()) return true;",
  "    await wait(1000);",
  "  }",
  "  return false;",
  "}",
  "",
  "function fixPermissions() {",
  "  for (const name of ['service.sh', 'start.sh']) {",
  "    const file = join(plan.rootDir, name);",
  "    if (existsSync(file)) {",
  "      try { chmodSync(file, 0o755); } catch (e) { log(`chmod ${name} failed: ${e.message}`); }",
  "    }",
  "  }",
  "}",
  "",
  "function writeResult(result) {",
  "  try {",
  "    mkdirSync(dirname(plan.resultPath), { recursive: true });",
  "    writeFileSync(plan.resultPath, JSON.stringify(result, null, 2));",
  "  } catch {}",
  "}",
  "",
  "function startProcess() {",
  "  const nodeArgs = Array.isArray(plan.nodeArgs) ? plan.nodeArgs : [];",
  "  const child = spawn(process.execPath, [...nodeArgs, plan.entry], {",
  "    detached: true,",
  "    stdio: ['ignore', 'ignore', 'ignore'],",
  "    cwd: plan.cwd,",
  "    env: process.env,",
  "  });",
  "  child.unref();",
  "  child.on('error', (err) => log(`spawn error: ${err.message}`));",
  "  try {",
  "    mkdirSync(join(plan.rootDir, 'data'), { recursive: true });",
  "    writeFileSync(join(plan.rootDir, 'data', 'service.pid'), String(child.pid));",
  "    if (process.env.APP_PID_FILE) writeFileSync(process.env.APP_PID_FILE, String(child.pid));",
  "  } catch (e) { log(`pid file write failed: ${e.message}`); }",
  "  log(`spawned process pid=${child.pid}`);",
  "  return child;",
  "}",
  "",
  "function restoreBackup() {",
  "  const marker = JSON.parse(readFileSync(plan.markerPath, 'utf8'));",
  "  const backupDir = resolve(marker.backupDir);",
  "  if (!existsSync(backupDir)) {",
  "    log('rollback skipped: backup directory missing');",
  "    return;",
  "  }",
  "  const rootDir = resolve(backupDir, '..', '..', '..');",
  "  let manifest = { replaced: [], added: marker.addedFiles || [] };",
  "  try { manifest = JSON.parse(readFileSync(join(backupDir, 'manifest.json'), 'utf8')); } catch {}",
  "  for (const relative of manifest.replaced || []) {",
  "    const source = join(backupDir, relative);",
  "    if (!existsSync(source)) continue;",
  "    const target = resolve(rootDir, relative);",
  "    mkdirSync(dirname(target), { recursive: true });",
  "    copyFileSync(source, target);",
  "    log(`restored ${relative}`);",
  "  }",
  "  for (const relative of manifest.added || []) {",
  "    rmSync(resolve(rootDir, relative), { force: true });",
  "    log(`removed added file ${relative}`);",
  "  }",
  "  rmSync(backupDir, { recursive: true, force: true });",
  "}",
  "",
  "const run = async () => {",
  "  log(`watchdog started, waiting for parent pid=${plan.parentPid} to exit`);",
  "  let waited = 0;",
  "  while (isAlive(plan.parentPid) && waited < 30000) {",
  "    await wait(200);",
  "    waited += 200;",
  "  }",
  "  log(`parent exited after ${waited}ms, waiting for ports [${plan.ports.join(', ')}] to release`);",
  "  await waitPortsFree(plan.ports, 20000);",
  "  fixPermissions();",
  "",
  "  let marker = {};",
  "  try { marker = JSON.parse(readFileSync(plan.markerPath, 'utf8')); } catch {}",
  "  let child = null;",
  "  for (let attempt = 1; attempt <= 2; attempt += 1) {",
  "    child = startProcess();",
  "    const healthy = await waitHealth(45000);",
  "    if (healthy) {",
  "      log(`health check passed on attempt ${attempt}, update completed`);",
  "      rmSync(plan.markerPath, { force: true });",
  "      writeResult({ status: 'success', role: marker.role || '', finishedAt: new Date().toISOString() });",
  "      return;",
  "    }",
  "    log(`health check failed on attempt ${attempt}`);",
  "    if (child && isAlive(child.pid)) {",
  "      log(`stopping unhealthy process pid=${child.pid}`);",
  "      try { process.kill(child.pid); } catch {}",
  "      await wait(2000);",
  "    }",
  "  }",
  "",
  "  log('update failed after retries, rolling back to previous version');",
  "  try { restoreBackup(); } catch (e) { log(`rollback failed: ${e.message}`); }",
  "  writeResult({ status: 'rolled-back', finishedAt: new Date().toISOString(), error: 'health check failed' });",
  "  rmSync(plan.markerPath, { force: true });",
  "  child = startProcess();",
  "  const recovered = await waitHealth(30000);",
  "  log(recovered ? 'previous version restored and healthy' : 'previous version restored but health check failed');",
  "  process.exit(0);",
  "};",
  "",
  "run().catch((error) => {",
  "  log(`watchdog crashed: ${error.message}`);",
  "  process.exit(1);",
  "});",
].join("\n");
