// 0.10.0.1：滑动验证码（零依赖 SVG）——服务端生成背景图 + 缺口 + 拼图块，
// 缺口横坐标服务端保密（HMAC 签名下发，无状态、5 分钟有效、一次性消费由调用方保证）。
// 用户拖动拼图块到缺口位置，前端提交横坐标，服务端比对误差（默认 ±8px）即通过。
import { createHmac, randomInt } from "node:crypto";

export const SLIDER_WIDTH = 280;
export const SLIDER_HEIGHT = 140;
export const SLIDER_PIECE_SIZE = 44;
export const SLIDER_TOLERANCE_PX = 8;
const TTL_MS = 5 * 60_000;

function sign(secret, payload) {
  return createHmac("sha256", secret).update(payload).digest("base64url").slice(0, 24);
}

// 生成挑战：返回 { token, background, piece, pieceY, width, height, pieceSize }。
// token = base64url(目标X|过期时间).签名，目标 X 不落地、无状态校验。
export function createSliderChallenge(secret) {
  const margin = 12;
  const targetX = randomInt(margin, SLIDER_WIDTH - SLIDER_PIECE_SIZE - margin);
  const pieceY = randomInt(margin, SLIDER_HEIGHT - SLIDER_PIECE_SIZE - margin);
  const expires = Date.now() + TTL_MS;
  const body = Buffer.from(`${targetX}|${expires}`).toString("base64url");
  const token = `${body}.${sign(secret, body)}`;
  return {
    token,
    background: renderBackground(targetX, pieceY),
    piece: renderPiece(),
    pieceY,
    width: SLIDER_WIDTH,
    height: SLIDER_HEIGHT,
    pieceSize: SLIDER_PIECE_SIZE,
  };
}

// 校验：token 签名/有效期 + 横坐标误差比对。成功后调用方应立即使 token 失效（一次性）。
export function verifySliderChallenge(secret, token, givenX, tolerance = SLIDER_TOLERANCE_PX) {
  try {
    if (!token || !token.includes(".")) return false;
    const [body, sig] = token.split(".");
    if (sign(secret, body) !== sig) return false;
    const [expected, expires] = Buffer.from(body, "base64url").toString().split("|");
    if (Number(expires) <= Date.now()) return false;
    const given = Math.round(Number(givenX));
    if (!Number.isFinite(given) || given < 0 || given > SLIDER_WIDTH) return false;
    return Math.abs(given - Number(expected)) <= Number(tolerance);
  } catch {
    return false;
  }
}

// 背景：随机色块 + 干扰线条的风景式 SVG，缺口处绘制深色凹槽。
function renderBackground(targetX, pieceY) {
  const size = SLIDER_PIECE_SIZE;
  const palette = ["#dbeafe", "#e0e7ff", "#d1fae5", "#fef3c7", "#fce7f3", "#e2e8f0"];
  const blobs = Array.from({ length: 7 })
    .map(() => {
      const cx = randomInt(0, SLIDER_WIDTH);
      const cy = randomInt(0, SLIDER_HEIGHT);
      const r = randomInt(18, 56);
      const fill = palette[randomInt(0, palette.length)];
      return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${fill}" opacity="0.85"/>`;
    })
    .join("");
  const lines = Array.from({ length: 4 })
    .map(() => {
      const x1 = randomInt(0, SLIDER_WIDTH);
      const y1 = randomInt(0, SLIDER_HEIGHT);
      const x2 = randomInt(0, SLIDER_WIDTH);
      const y2 = randomInt(0, SLIDER_HEIGHT);
      return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="#94a3b8" stroke-width="1" opacity="0.35"/>`;
    })
    .join("");
  // 缺口：外框 + 内阴影 + 虚线边，提示拼图目标位置。
  const hole = `
    <rect x="${targetX}" y="${pieceY}" width="${size}" height="${size}" rx="8" fill="#0f172a" opacity="0.82"/>
    <rect x="${targetX + 3}" y="${pieceY + 3}" width="${size - 6}" height="${size - 6}" rx="6" fill="#1e293b" opacity="0.9"/>
    <rect x="${targetX}" y="${pieceY}" width="${size}" height="${size}" rx="8" fill="none" stroke="#64748b" stroke-width="1.5" stroke-dasharray="4 3"/>`;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${SLIDER_WIDTH}" height="${SLIDER_HEIGHT}" viewBox="0 0 ${SLIDER_WIDTH} ${SLIDER_HEIGHT}" role="img" aria-label="滑动验证背景"><rect width="${SLIDER_WIDTH}" height="${SLIDER_HEIGHT}" rx="10" fill="#f8fafc"/>${blobs}${lines}${hole}</svg>`;
}

// 拼图块：圆角方块，与缺口同尺寸，带高光与纹路。
function renderPiece() {
  const size = SLIDER_PIECE_SIZE;
  const texture = Array.from({ length: 3 })
    .map(() => {
      const x1 = randomInt(4, size - 4);
      const y1 = randomInt(4, size - 4);
      const x2 = randomInt(4, size - 4);
      const y2 = randomInt(4, size - 4);
      return `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="#94a3b8" stroke-width="1" opacity="0.4"/>`;
    })
    .join("");
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" role="img" aria-label="拼图块"><defs><linearGradient id="pieceGrad" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#f1f5f9"/><stop offset="1" stop-color="#cbd5e1"/></linearGradient></defs><rect width="${size}" height="${size}" rx="8" fill="url(#pieceGrad)" stroke="#475569" stroke-width="1.5"/>${texture}<rect x="6" y="6" width="${size - 12}" height="${size - 12}" rx="5" fill="none" stroke="#e2e8f0" stroke-width="1" opacity="0.7"/></svg>`;
}
