/* خادم بسيط بدون مكتبات خارجية: يقدّم ملفات الموقع ويتحقق من دخول الأستاذ من ملف .env */
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = __dirname;
const ENV_PATH = path.join(ROOT, ".env");

function loadEnv() {
  const out = {};
  if (!fs.existsSync(ENV_PATH)) return out;
  fs.readFileSync(ENV_PATH, "utf8").split(/\r?\n/).forEach((line) => {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m && !line.trim().startsWith("#")) out[m[1]] = m[2];
  });
  return out;
}
function saveEnvValue(key, value) {
  let text = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, "utf8") : "";
  const re = new RegExp("^\\s*" + key + "\\s*=.*$", "m");
  text = re.test(text) ? text.replace(re, () => key + "=" + value) : text.replace(/\s*$/, "\n") + key + "=" + value + "\n";
  fs.writeFileSync(ENV_PATH, text);
}

let env = loadEnv();
if (!env.TEACHER_USERNAME || !env.TEACHER_PASSWORD) {
  console.error("خطأ: عرّف TEACHER_USERNAME و TEACHER_PASSWORD داخل ملف .env");
  process.exit(1);
}
const PORT = Number(process.env.PORT || env.PORT || 3000);

function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
function json(res, code, obj) {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => { data += c; if (data.length > 10000) { req.destroy(); reject(new Error("too large")); } });
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch { resolve({}); } });
    req.on("error", reject);
  });
}

// حماية بسيطة من تخمين كلمة المرور: 5 محاولات فاشلة ← انتظار دقيقة
const fails = new Map();
function blocked(ip) {
  const f = fails.get(ip);
  return f && f.count >= 5 && Date.now() - f.last < 60000;
}
function noteFail(ip) {
  const f = fails.get(ip) || { count: 0, last: 0 };
  f.count = Date.now() - f.last > 60000 ? 1 : f.count + 1;
  f.last = Date.now();
  fails.set(ip, f);
}

const MIME = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".ico": "image/x-icon",
};
const HIDDEN = new Set(["server.js", "package.json", "package-lock.json"]);

http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const ip = req.socket.remoteAddress;

  if (req.method === "POST" && url.pathname === "/api/teacher-login") {
    if (blocked(ip)) return json(res, 429, { ok: false, message: "محاولات كثيرة. انتظر دقيقة ثم حاول مرة أخرى." });
    const { username = "", password = "" } = await readBody(req);
    env = loadEnv();
    if (safeEqual(String(username).trim().toLowerCase(), env.TEACHER_USERNAME.toLowerCase()) && safeEqual(password, env.TEACHER_PASSWORD)) {
      fails.delete(ip);
      return json(res, 200, { ok: true, username: env.TEACHER_USERNAME });
    }
    noteFail(ip);
    return json(res, 401, { ok: false, message: "اسم المستخدم أو كلمة المرور غير صحيحة." });
  }

  if (req.method === "POST" && url.pathname === "/api/teacher-change-password") {
    if (blocked(ip)) return json(res, 429, { ok: false, message: "محاولات كثيرة. انتظر دقيقة ثم حاول مرة أخرى." });
    const { currentPassword = "", newPassword = "" } = await readBody(req);
    env = loadEnv();
    if (!safeEqual(currentPassword, env.TEACHER_PASSWORD)) {
      noteFail(ip);
      return json(res, 401, { ok: false, message: "كلمة المرور الحالية غير صحيحة." });
    }
    if (String(newPassword).length < 6 || /[\r\n]/.test(newPassword)) {
      return json(res, 400, { ok: false, message: "كلمة المرور الجديدة غير صالحة." });
    }
    saveEnvValue("TEACHER_PASSWORD", newPassword);
    return json(res, 200, { ok: true });
  }

  // ملفات الموقع الثابتة
  let rel = decodeURIComponent(url.pathname);
  if (rel === "/") rel = "/index.html";
  const file = path.normalize(path.join(ROOT, rel));
  const name = path.basename(file);
  if (!file.startsWith(ROOT + path.sep) || name.startsWith(".") || HIDDEN.has(name)) {
    res.writeHead(404); return res.end("Not found");
  }
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404); return res.end("Not found"); }
    res.writeHead(200, { "Content-Type": MIME[path.extname(file).toLowerCase()] || "application/octet-stream" });
    res.end(buf);
  });
}).listen(PORT, () => console.log("الموقع يعمل على: http://localhost:" + PORT));
