// 0.10.0：图形验证码（零依赖 SVG）——服务端生成 4 位字符 SVG，答案经 HMAC 签名下发（无状态、5 分钟有效、一次性）。
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const CHARSET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // 去除易混淆字符 0/1/I/O
const TTL_MS = 5 * 60_000;

function sign(secret, payload) {
  return createHmac("sha256", secret).update(payload).digest("base64url").slice(0, 24);
}

// 生成验证码：返回 { token, svg }；token = base64url(答案|过期时间).签名，答案不落地、无状态校验。
export function createCaptcha(secret) {
  const answer = Array.from(randomBytes(4))
    .map((byte) => CHARSET[byte % CHARSET.length])
    .join("");
  const expires = Date.now() + TTL_MS;
  const body = Buffer.from(`${answer}|${expires}`).toString("base64url");
  const token = `${body}.${sign(secret, body)}`;
  return { token, answer, svg: renderSvg(answer) };
}

// 校验：token 签名/有效期 + 用户答案比对（不区分大小写）。成功后应调用 consume 使其失效。
export function verifyCaptcha(secret, token, answer) {
  try {
    if (!token || !token.includes(".")) return false;
    const [body, sig] = token.split(".");
    if (sign(secret, body) !== sig) return false;
    const [expected, expires] = Buffer.from(body, "base64url").toString().split("|");
    if (Number(expires) <= Date.now()) return false;
    const given = String(answer || "").trim().toUpperCase();
    if (given.length !== expected.length) return false;
    return timingSafeEqual(Buffer.from(given), Buffer.from(expected.toUpperCase()));
  } catch {
    return false;
  }
}

// 一次性消费：重新签发同一 token 的"已用"标记不现实（无状态），由调用方以「验证成功后立即失效签名表」替代；
// 简化实现：验证成功即从调用方的 pendingCaptcha 集合移除（配合有状态去重，见 server/app.js）。
export function renderSvg(text) {
  const width = 132;
  const height = 44;
  const colors = ["#2563eb", "#7c3aed", "#0f766e", "#b45309", "#be123c"];
  const glyphs = text
    .split("")
    .map((char, index) => {
      const x = 18 + index * 26 + Math.floor(Math.random() * 6) - 3;
      const y = 30 + Math.floor(Math.random() * 8) - 4;
      const rotate = Math.floor(Math.random() * 36) - 18;
      const color = colors[Math.floor(Math.random() * colors.length)];
      return `<text x="${x}" y="${y}" fill="${color}" font-size="26" font-family="Georgia, serif" font-weight="bold" transform="rotate(${rotate} ${x} ${y})">${char}</text>`;
    })
    .join("");
  const noise = Array.from({ length: 5 })
    .map(() => {
      const x1 = Math.floor(Math.random() * width);
      const y1 = Math.floor(Math.random() * height);
      const x2 = Math.floor(Math.random() * width);
      const y2 = Math.floor(Math.random() * height);
      return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="#94a3b8" stroke-width="1" opacity="0.55"/>`;
    })
    .join("");
  const dots = Array.from({ length: 40 })
    .map(
      () =>
        `<circle cx="${Math.floor(Math.random() * width)}" cy="${Math.floor(Math.random() * height)}" r="1" fill="#94a3b8" opacity="0.4"/>`,
    )
    .join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="验证码"><rect width="${width}" height="${height}" rx="8" fill="#f1f5f9"/>${noise}${dots}${glyphs}</svg>`;
}
