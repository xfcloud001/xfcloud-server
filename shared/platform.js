import { isAbsolute, join, resolve } from "node:path";

const RELEASE_TARGETS = Object.freeze({
  win32: Object.freeze({
    name: "windows",
    architectures: Object.freeze({ x64: "amd64", arm64: "arm64" }),
  }),
  linux: Object.freeze({
    name: "linux",
    architectures: Object.freeze({ x64: "amd64", arm64: "arm64", arm: "arm" }),
  }),
  darwin: Object.freeze({
    name: "darwin",
    architectures: Object.freeze({ x64: "amd64", arm64: "arm64" }),
  }),
});

export function frpBinaryName(name, platform = process.platform) {
  return `${name}${platform === "win32" ? ".exe" : ""}`;
}

export function resolveFrpBinary(
  root,
  name,
  configuredPath = "",
  platform = process.platform,
) {
  const configured = String(configuredPath || "").trim();
  if (!configured) return join(root, "bin", frpBinaryName(name, platform));
  return isAbsolute(configured) ? configured : resolve(root, configured);
}

export function frpReleaseTarget(
  platform = process.platform,
  architecture = process.arch,
) {
  const target = RELEASE_TARGETS[platform];
  const releaseArchitecture = target?.architectures[architecture];
  if (!target || !releaseArchitecture) {
    throw new Error(`Unsupported platform: ${platform}/${architecture}`);
  }
  return {
    platform: target.name,
    architecture: releaseArchitecture,
    extension: platform === "win32" ? "zip" : "tar.gz",
  };
}
