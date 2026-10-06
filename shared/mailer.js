// 0.10.0：极简 SMTP 客户端（零第三方依赖）——支持 465 隐式 TLS / 587 STARTTLS / 25 明文，AUTH LOGIN。
// 供注册 / 忘记密码验证码邮件与「测试邮箱」使用；网易、QQ、阿里等常见服务商均可。
import net from "node:net";
import tls from "node:tls";

function readReply(socket) {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const onData = (chunk) => {
      buffer += chunk.toString("utf8");
      // SMTP 多行应答以 "250-..." 继续、"250 " 结束；按最后一行 "code " 判定完成。
      const lines = buffer.split(/\r?\n/);
      if (lines.length >= 2 && /^\d{3} /.test(lines[lines.length - 2] || "")) {
        socket.removeListener("data", onData);
        resolve(buffer.trim());
      }
    };
    socket.on("data", onData);
    socket.once("error", (error) => reject(new Error(`SMTP 连接错误：${error.message}`)));
  });
}

function smtpCommand(socket, command, expect) {
  return new Promise(async (resolve, reject) => {
    if (command !== null) socket.write(`${command}\r\n`);
    try {
      const reply = await readReply(socket);
      const code = Number(reply.slice(0, 3));
      if (expect && code !== expect) {
        reject(new Error(`SMTP 响应异常（${code}）：${reply.split("\n")[0]}`));
        return;
      }
      resolve(reply);
    } catch (error) {
      reject(error);
    }
  });
}

function buildMessage({ from, to, subject, text }) {
  const boundary = `xfcloud-${Date.now().toString(36)}`;
  const encodedSubject = `=?UTF-8?B?${Buffer.from(subject, "utf8").toString("base64")}?=`;
  return [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${encodedSubject}`,
    "MIME-Version: 1.0",
    `Content-Type: multipart/alternative; boundary="${boundary}"`,
    "",
    `--${boundary}`,
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: base64",
    "",
    Buffer.from(text, "utf8").toString("base64"),
    `--${boundary}--`,
    "",
  ].join("\r\n");
}

// 发送邮件。config: { host, port, secure(465=true), user, pass, from }；返回 void，失败抛错。
export async function sendMail(config, { to, subject, text }) {
  const host = String(config.host || "").trim();
  const port = Number(config.port) || (config.secure ? 465 : 25);
  const secure = Boolean(config.secure) || port === 465;
  const from = String(config.from || config.user || "").trim();
  if (!host || !from) throw new Error("SMTP 配置不完整：请填写服务器地址与发件人");
  if (!to) throw new Error("缺少收件人地址");

  let socket = secure
    ? tls.connect({ host, port, servername: host, rejectUnauthorized: false })
    : net.connect({ host, port });
  await new Promise((resolve, reject) => {
    socket.once(secure ? "secureConnect" : "connect", resolve);
    socket.once("error", (error) => reject(new Error(`SMTP 连接失败：${error.message}`)));
    socket.setTimeout(20_000, () => {
      socket.destroy();
      reject(new Error("SMTP 连接超时（20 秒）"));
    });
  });

  try {
    await readReply(socket); // 220 greeting
    await smtpCommand(socket, `EHLO xfcloud`, 250);
    if (!secure) {
      // 587 STARTTLS：服务端 advertised 时升级 TLS。
      await smtpCommand(socket, "STARTTLS").catch(() => null);
      socket = tls.connect({ socket, servername: host, rejectUnauthorized: false });
      await new Promise((resolve, reject) => {
        socket.once("secureConnect", resolve);
        socket.once("error", (error) => reject(new Error(`TLS 升级失败：${error.message}`)));
      });
      await smtpCommand(socket, `EHLO xfcloud`, 250);
    }
    if (config.user) {
      await smtpCommand(socket, "AUTH LOGIN", 334);
      await smtpCommand(socket, Buffer.from(config.user).toString("base64"), 334);
      await smtpCommand(socket, Buffer.from(config.pass || "").toString("base64"), 235);
    }
    await smtpCommand(socket, `MAIL FROM:<${from.replace(/.*</, "").replace(/>.*$/, "")}>`, 250);
    await smtpCommand(socket, `RCPT TO:<${to}>`, 250);
    await smtpCommand(socket, "DATA", 354);
    const message = buildMessage({ from, to, subject, text }).replace(/\r?\n\./g, "\r\n..");
    await smtpCommand(socket, `${message}\r\n.`, 250);
    await smtpCommand(socket, "QUIT").catch(() => null);
  } finally {
    socket.destroy();
  }
}
