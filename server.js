'use strict';
// Return to Earth — game server: serves the game, Google sign-in, saved scores, leaderboard. No npm dependencies (Node 18+).
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = +process.env.PORT || 3000;
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const DEV = process.env.DEV_LOGIN === '1' || !CLIENT_ID;          // username-only login for testing when Google is not configured
const ROOT = path.join(__dirname, 'public');
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DATA, { recursive: true });
const DB_FILE = path.join(DATA, 'db.json'), SEC_FILE = path.join(DATA, 'secret.txt');
let SECRET = process.env.SESSION_SECRET;
if (!SECRET) { try { SECRET = fs.readFileSync(SEC_FILE, 'utf8').trim(); } catch (e) { SECRET = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(SEC_FILE, SECRET); } }
let db = { users: {} };
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) {}
let dirty = false;
function save() { if (!dirty) return; dirty = false; const t = DB_FILE + '.tmp'; fs.writeFileSync(t, JSON.stringify(db)); fs.renameSync(t, DB_FILE); }
setInterval(save, 2000).unref();
['SIGINT', 'SIGTERM'].forEach(s => process.on(s, () => { save(); process.exit(0); }));

const b64 = b => Buffer.from(b).toString('base64url');
function sign(p) { const body = b64(JSON.stringify(p)); return body + '.' + crypto.createHmac('sha256', SECRET).update(body).digest('base64url'); }
function verify(t) {
  if (!t || typeof t !== 'string') return null;
  const [body, sig] = t.split('.'); if (!body || !sig) return null;
  const ok = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (ok.length !== sig.length || !crypto.timingSafeEqual(Buffer.from(ok), Buffer.from(sig))) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString()); return p.exp > Date.now() ? p : null; } catch (e) { return null; }
}
const clean = n => String(n || '').replace(/[<>&"'`\\\u0000-\u001f]/g, '').replace(/\s+/g, ' ').trim().slice(0, 20);
const lower = s => s.toLowerCase();
function uniqueName(want, sub) {
  let base = clean(want) || 'لاعب', name = base, i = 1;
  const taken = n => Object.entries(db.users).some(([k, u]) => k !== sub && lower(u.name) === lower(n));
  while (taken(name)) { i++; name = base.slice(0, 16) + ' ' + i; }
  return name;
}
async function googleVerify(cred) {
  const r = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(cred));
  if (!r.ok) throw new Error('invalid token');
  const j = await r.json();
  if (j.aud !== CLIENT_ID) throw new Error('wrong audience');
  if (!/^(https:\/\/)?accounts\.google\.com$/.test(j.iss)) throw new Error('wrong issuer');
  if (+j.exp * 1000 < Date.now()) throw new Error('expired');
  return { sub: 'g:' + j.sub, name: j.name || j.given_name || 'لاعب', picture: j.picture || '' };
}
function login(sub, name, picture) {
  let u = db.users[sub];
  if (!u) { u = db.users[sub] = { name: uniqueName(name, sub), picture: picture || '', best: 0, level: 0, final: false, plays: 0, created: Date.now(), updated: Date.now(), last: 0 }; dirty = true; }
  return { token: sign({ sub, exp: Date.now() + 30 * 864e5 }), user: pub(u) };
}
const pub = u => ({ name: u.name, picture: u.picture, best: u.best, level: u.level, final: u.final, plays: u.plays });
const hits = new Map();
function limited(key, max, ms) { const n = Date.now(), a = (hits.get(key) || []).filter(t => n - t < ms); a.push(n); hits.set(key, a); return a.length > max; }
setInterval(() => hits.clear(), 600000).unref();

function send(res, code, obj) { const b = JSON.stringify(obj); res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(b); }
function body(req) { return new Promise((ok, no) => { let d = ''; req.on('data', c => { d += c; if (d.length > 20000) { no(new Error('big')); req.destroy(); } }); req.on('end', () => { try { ok(d ? JSON.parse(d) : {}); } catch (e) { no(e); } }); }); }
const userOf = req => { const m = /^Bearer (.+)$/.exec(req.headers.authorization || ''); const p = m && verify(m[1]); return p && db.users[p.sub] ? { sub: p.sub, u: db.users[p.sub] } : null; };

async function api(req, res, url) {
  const ip = req.socket.remoteAddress || '?';
  if (req.method === 'GET' && url.pathname === '/api/config') return send(res, 200, { clientId: CLIENT_ID, dev: DEV });
  if (req.method === 'POST' && url.pathname === '/api/login') {
    if (!CLIENT_ID) return send(res, 400, { error: 'Google غير مُعدّ على السيرفر' });
    if (limited('l' + ip, 20, 60000)) return send(res, 429, { error: 'محاولات كثيرة، انتظر قليلاً' });
    try { const b = await body(req); const g = await googleVerify(b.credential); return send(res, 200, login(g.sub, g.name, g.picture)); }
    catch (e) { return send(res, 401, { error: 'فشل التحقق من حساب قوقل' }); }
  }
  if (req.method === 'POST' && url.pathname === '/api/dev-login') {
    if (!DEV) return send(res, 404, { error: 'غير متاح' });
    if (limited('d' + ip, 30, 60000)) return send(res, 429, { error: 'محاولات كثيرة' });
    const b = await body(req).catch(() => ({})), n = clean(b.name); if (n.length < 2) return send(res, 400, { error: 'اكتب اسماً من حرفين فأكثر' });
    return send(res, 200, login('dev:' + lower(n), n, ''));
  }
  if (req.method === 'GET' && url.pathname === '/api/me') { const a = userOf(req); return a ? send(res, 200, { user: pub(a.u) }) : send(res, 401, { error: 'غير مسجّل' }); }
  if (req.method === 'POST' && url.pathname === '/api/profile') {
    const a = userOf(req); if (!a) return send(res, 401, { error: 'سجّل الدخول أولاً' });
    const b = await body(req).catch(() => ({})), n = clean(b.name);
    if (n.length < 2) return send(res, 400, { error: 'الاسم من حرفين إلى 20 حرفاً' });
    if (Object.entries(db.users).some(([k, u]) => k !== a.sub && lower(u.name) === lower(n))) return send(res, 409, { error: 'هذا الاسم مستخدم، اختر غيره' });
    a.u.name = n; a.u.updated = Date.now(); dirty = true; return send(res, 200, { user: pub(a.u) });
  }
  if (req.method === 'POST' && url.pathname === '/api/score') {
    const a = userOf(req); if (!a) return send(res, 401, { error: 'سجّل الدخول أولاً' });
    if (limited('s' + a.sub, 12, 60000)) return send(res, 429, { error: 'إرسال متكرر' });
    const b = await body(req).catch(() => ({})), lvl = Math.max(1, Math.min(21, Math.floor(+b.level || 0))), sc = Math.floor(+b.score);
    if (!(sc >= 0) || sc > 7000 * lvl) return send(res, 400, { error: 'نتيجة غير مقبولة' });
    const u = a.u; u.plays++; u.last = Date.now();
    if (sc > u.best) { u.best = sc; u.updated = Date.now(); }
    if (lvl > u.level) u.level = lvl; if (b.final === true && lvl >= 21) u.final = true;
    dirty = true; return send(res, 200, { user: pub(u) });
  }
  if (req.method === 'GET' && url.pathname === '/api/leaderboard') {
    const lim = Math.max(1, Math.min(50, +url.searchParams.get('limit') || 10)), a = userOf(req);
    const all = Object.entries(db.users).filter(([, u]) => u.best > 0).sort((x, y) => y[1].best - x[1].best || x[1].updated - y[1].updated);
    const top = all.slice(0, lim).map(([k, u], i) => ({ rank: i + 1, name: u.name, picture: u.picture, best: u.best, level: u.level, final: u.final, me: !!a && a.sub === k }));
    const mi = a ? all.findIndex(([k]) => k === a.sub) : -1;
    return send(res, 200, { top, total: all.length, meRank: mi + 1 || null });
  }
  return send(res, 404, { error: 'غير موجود' });
}
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript', '.css': 'text/css', '.png': 'image/png', '.ico': 'image/x-icon', '.mp3': 'audio/mpeg', '.json': 'application/json', '.txt': 'text/plain; charset=utf-8', '.svg': 'image/svg+xml' };
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    let p = decodeURIComponent(url.pathname); if (p.endsWith('/')) p += 'index.html';
    const f = path.normalize(path.join(ROOT, p));
    if (!f.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
    fs.stat(f, (e, st) => {
      if (e || !st.isFile()) { res.writeHead(404); return res.end('Not found'); }
      res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Cache-Control': path.extname(f) === '.html' ? 'no-cache' : 'public, max-age=86400', 'X-Content-Type-Options': 'nosniff' });
      fs.createReadStream(f).pipe(res);
    });
  } catch (e) { try { send(res, 500, { error: 'خطأ في السيرفر' }); } catch (x) {} }
});
server.listen(PORT, () => console.log(`Return to Earth server on http://localhost:${PORT}  |  Google login: ${CLIENT_ID ? 'ON' : 'OFF (dev login only)'}`));
