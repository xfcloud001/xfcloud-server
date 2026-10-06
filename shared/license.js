import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
} from "node:crypto";

const LICENSE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const LICENSE_PATTERN = /^XFT(?:-[A-HJ-NP-Z2-9]{5}){5}$/;

function encodeJson(value) {
  return Buffer.from(JSON.stringify(value)).toString("base64url");
}

export function generateLicenseKey() {
  const bytes = randomBytes(25);
  const body = [...bytes]
    .map((value) => LICENSE_ALPHABET[value % LICENSE_ALPHABET.length])
    .join("");
  return `XFT-${body.match(/.{5}/g).join("-")}`;
}

export function normalizeLicenseKey(value) {
  const key = String(value ?? "").trim().toUpperCase();
  if (!LICENSE_PATTERN.test(key)) {
    throw new Error("许可密钥格式无效");
  }
  return key;
}

export function hashLicenseKey(value) {
  return createHash("sha256")
    .update(normalizeLicenseKey(value))
    .digest("hex");
}

export function licenseKeyPreview(value) {
  const key = normalizeLicenseKey(value);
  const groups = key.split("-");
  return `${groups[0]}-${groups[1]}-****-****-****-${groups.at(-1)}`;
}

export function generateLicenseSigningKeys() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "pem" }),
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

export function publicKeyFingerprint(publicKey) {
  return createHash("sha256")
    .update(String(publicKey).trim())
    .digest("hex")
    .match(/.{1,4}/g)
    .join(":");
}

export function signLicenseLease(payload, privateKey) {
  const header = encodeJson({ alg: "EdDSA", typ: "XFT-LICENSE" });
  const body = encodeJson({ ...payload, type: "license" });
  const signature = sign(
    null,
    Buffer.from(`${header}.${body}`),
    privateKey,
  ).toString("base64url");
  return `${header}.${body}.${signature}`;
}

export function verifyLicenseLease(
  token,
  publicKey,
  { installationId = null, now = Date.now() } = {},
) {
  const parts = String(token ?? "").split(".");
  if (parts.length !== 3) throw new Error("授权凭证格式无效");
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  if (header.alg !== "EdDSA" || header.typ !== "XFT-LICENSE") {
    throw new Error("授权凭证类型无效");
  }
  const valid = verify(
    null,
    Buffer.from(`${parts[0]}.${parts[1]}`),
    publicKey,
    Buffer.from(parts[2], "base64url"),
  );
  if (!valid) throw new Error("授权凭证签名无效");
  const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  if (payload.type !== "license") throw new Error("授权凭证内容无效");
  if (installationId && payload.installationId !== installationId) {
    throw new Error("许可密钥与当前服务端不匹配");
  }
  if (!Number.isFinite(payload.exp) || payload.exp * 1000 <= now) {
    throw new Error("授权凭证已过期，请连接授权中心");
  }
  if (
    !payload.licenseExpiresAt ||
    !Number.isFinite(Date.parse(payload.licenseExpiresAt)) ||
    Date.parse(payload.licenseExpiresAt) <= now
  ) {
    throw new Error("许可密钥已到期");
  }
  return payload;
}
