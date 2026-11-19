// ============================================================
// dinzzz — Monitoring Keuangan (dinzzz.my.id)
// Cloudflare Worker + D1 (data teks transaksi) + KV (foto bukti)
// ============================================================

const COOKIE_NAME = 'dinzzz_session';
const SESSION_TTL = 60 * 60 * 24 * 30; // 30 hari

function b64e(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64d(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
const te = (s) => new TextEncoder().encode(s);

function timingEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey('raw', te(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, te(msg));
  return b64e(sig);
}
async function makeSession(env) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL;
  const sig = await hmac(env.SESSION_SECRET, String(exp));
  return exp + '.' + sig;
}
async function validSession(env, token) {
  if (!token) return false;
  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const exp = parseInt(parts[0], 10);
  if (!exp || exp < Math.floor(Date.now() / 1000)) return false;
  const expect = await hmac(env.SESSION_SECRET, parts[0]);
  return timingEq(parts[1], expect);
}
function cookieOf(req, name) {
  const c = req.headers.get('Cookie') || '';
  const parts = c.split(';');
  for (const p of parts) {
    const i = p.indexOf('=');
    if (i > 0 && p.slice(0, i).trim() === name) return decodeURIComponent(p.slice(i + 1).trim());
  }
  return null;
}
function sessionCookie(token, clear) {
  return COOKIE_NAME + '=' + (clear ? '' : token) + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + (clear ? 0 : SESSION_TTL);
}

async function pwHash(password, saltB64) {
  const salt = saltB64 ? b64d(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', te(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return { salt: b64e(salt), hash: b64e(bits) };
}

async function getSetting(env, key) {
  const row = await env.DB.prepare('SELECT value FROM settings WHERE key = ?').bind(key).first();
  return row ? row.value : null;
}
async function setSetting(env, key, value) {
  await env.DB.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(key, value).run();
}

function jsonRes(obj, status, extraHeaders) {
  const h = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' };
  if (extraHeaders) Object.assign(h, extraHeaders);
  return new Response(JSON.stringify(obj), { status: status || 200, headers: h });
}
function htmlRes(html) {
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
}

const loginFails = new Map();
function tooManyFails(ip) {
  const rec = loginFails.get(ip);
  if (!rec) return false;
  if (Date.now() - rec.first > 10 * 60 * 1000) { loginFails.delete(ip); return false; }
  return rec.count >= 10;
}
function noteFail(ip) {
  const now = Date.now();
  const rec = loginFails.get(ip);
  if (!rec || now - rec.first > 10 * 60 * 1000) loginFails.set(ip, { count: 1, first: now });
  else rec.count++;
}

// ---------------- Halaman login / buat password ----------------
function loginPage(mode) {
  const isSetup = mode === 'setup';
  const title = isSetup ? 'Buat Password' : 'Masuk';
  const sub = isSetup
    ? 'Pertama kali — buat password untuk dashboard keuanganmu. Hanya kamu yang tahu password ini, simpan baik-baik ya.'
    : 'Masukkan password untuk membuka dashboard keuanganmu.';
  const btn = isSetup ? 'Buat Password & Masuk' : 'Masuk';
  const confirmField = isSetup
    ? '<label>Ulangi Password<input type="password" id="pw2" autocomplete="new-password" placeholder="Ketik ulang password"></label>'
    : '';
  return '<!DOCTYPE html>\n<html lang="id">\n<head>\n<meta charset="UTF-8">\n' +
    '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n' +
    '<title>' + title + ' — dinzzz.my.id</title>\n' +
    '<link rel="preconnect" href="https://fonts.googleapis.com">\n' +
    '<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700;800;900&display=swap" rel="stylesheet">\n' +
    '<style>\n' +
    '*{margin:0;padding:0;box-sizing:border-box}\n' +
    'body{background:#0C1020;color:#EDF0FA;font-family:Montserrat,system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}\n' +
    '.card{background:#151B31;border:1px solid #26304F;border-radius:24px;padding:32px 26px;max-width:400px;width:100%;animation:up .6s ease both}\n' +
    '@keyframes up{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}\n' +
    '.lbl{color:#2DD4EE;font-weight:700;font-size:14px;letter-spacing:.4px}\n' +
    'h1{font-size:32px;font-weight:900;margin:8px 0 6px}\n' +
    'p{color:#9AA6C7;font-size:14px;line-height:1.55;margin-bottom:22px}\n' +
    'label{display:block;font-size:12px;font-weight:700;color:#9AA6C7;letter-spacing:.6px;text-transform:uppercase;margin-bottom:16px}\n' +
    'input{width:100%;margin-top:8px;background:#0C1020;border:1px solid #26304F;border-radius:14px;padding:14px 16px;color:#EDF0FA;font-family:inherit;font-size:16px;outline:none}\n' +
    'input:focus{border-color:#5B5BD6}\n' +
    'button{width:100%;background:#5B5BD6;color:#fff;border:none;border-radius:16px;padding:16px;font-family:inherit;font-size:16px;font-weight:800;cursor:pointer;margin-top:6px}\n' +
    'button:active{transform:scale(.98)}\n' +
    '.err{color:#FB7185;font-size:13px;font-weight:600;min-height:18px;margin-bottom:10px}\n' +
    '</style>\n</head>\n<body>\n' +
    '<form class="card" id="f">\n' +
    '<div class="lbl">dinzzz.my.id</div>\n<h1>' + title + '</h1>\n<p>' + sub + '</p>\n' +
    '<div class="err" id="err"></div>\n' +
    '<label>Password<input type="password" id="pw" autocomplete="' + (isSetup ? 'new-password' : 'current-password') + '" placeholder="Password kamu"></label>\n' +
    confirmField + '\n' +
    '<button type="submit" id="btn">' + btn + '</button>\n' +
    '</form>\n' +
    '<script>\n' +
    'var isSetup = ' + (isSetup ? 'true' : 'false') + ';\n' +
    'document.getElementById("f").addEventListener("submit", function(ev){\n' +
    '  ev.preventDefault();\n' +
    '  var pw = document.getElementById("pw").value;\n' +
    '  var err = document.getElementById("err");\n' +
    '  if (isSetup) {\n' +
    '    var pw2 = document.getElementById("pw2").value;\n' +
    '    if (pw.length < 6) { err.textContent = "Password minimal 6 karakter."; return; }\n' +
    '    if (pw !== pw2) { err.textContent = "Password kedua tidak sama."; return; }\n' +
    '  }\n' +
    '  var btn = document.getElementById("btn"); btn.disabled = true; btn.textContent = "Sebentar...";\n' +
    '  fetch(isSetup ? "/api/setup" : "/api/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ password: pw }) })\n' +
    '    .then(function(r){ return r.json().then(function(j){ return { ok: r.ok, j: j }; }); })\n' +
    '    .then(function(res){ if (res.ok) { location.href = "/"; } else { err.textContent = res.j.error || "Gagal. Coba lagi."; btn.disabled = false; btn.textContent = "' + btn + '"; } })\n' +
    '    .catch(function(){ err.textContent = "Koneksi bermasalah. Coba lagi."; btn.disabled = false; btn.textContent = "' + btn + '"; });\n' +
    '});\n' +
    '</' + 'script>\n</body>\n</html>';
}

// ---------------- Aplikasi utama ----------------
const APP_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Monitoring Keuangan — dinzzz.my.id</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;600;700;800;900&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0C1020;--card:#151B31;--line:#26304F;--txt:#EDF0FA;--mut:#9AA6C7;--ind:#5B5BD6;--cyn:#2DD4EE;--ros:#FB7185;--gld:#F5C451}
body{background:var(--bg);color:var(--txt);font-family:Montserrat,system-ui,sans-serif;padding:22px 16px 120px;-webkit-font-smoothing:antialiased}
.wrap{max-width:560px;margin:0 auto}
@keyframes up{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
.anim{animation:up .55s ease both}
.d1{animation-delay:.05s}.d2{animation-delay:.12s}.d3{animation-delay:.19s}.d4{animation-delay:.26s}.d5{animation-delay:.33s}
header.top{display:flex;justify-content:space-between;align-items:flex-start}
.lbl{color:var(--cyn);font-weight:700;font-size:15px;letter-spacing:.4px}
h1.title{font-size:34px;font-weight:900;line-height:1.12;margin:6px 0 4px}
.sub{color:var(--mut);font-size:15px}
.logout{background:none;border:1px solid var(--line);color:var(--mut);border-radius:999px;padding:8px 14px;font-family:inherit;font-size:12px;font-weight:700;cursor:pointer;margin-top:6px}
.card{background:var(--card);border:1px solid var(--line);border-radius:24px;padding:20px}
.hero{margin-top:20px;background:linear-gradient(135deg,#1B2140,#151B31 60%);position:relative;overflow:hidden}
.hero .cap{color:var(--mut);font-size:12px;font-weight:800;letter-spacing:1.6px}
.hero .badge{float:right;background:rgba(245,196,81,.14);color:var(--gld);border:1px solid rgba(245,196,81,.35);font-size:11px;font-weight:800;letter-spacing:1px;padding:6px 12px;border-radius:999px}
.hero .amt{color:var(--gld);font-size:clamp(30px,9vw,44px);font-weight:900;margin:10px 0 8px;font-variant-numeric:tabular-nums}
.hero .meta{color:var(--mut);font-size:13.5px;line-height:1.6}
.hero .meta b.in{color:var(--cyn)} .hero .meta b.out{color:var(--ros)}
.hero .note{color:var(--mut);font-size:12.5px;line-height:1.55;margin-top:10px;opacity:.85}
.chips{display:flex;gap:10px;margin-top:20px;flex-wrap:wrap}
.chip{background:var(--card);border:1px solid var(--line);color:var(--txt);border-radius:999px;padding:12px 20px;font-family:inherit;font-size:14.5px;font-weight:700;cursor:pointer;transition:all .25s}
.chip.on{background:var(--ind);border-color:var(--ind);color:#fff;box-shadow:0 6px 20px rgba(91,91,214,.45)}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:14px}
.sum{padding:16px 14px}
.sum .cap{font-size:11px;font-weight:800;letter-spacing:1.2px;display:flex;align-items:center;gap:6px}
.sum .cap .ic{width:20px;height:20px;border-radius:7px;display:inline-flex;align-items:center;justify-content:center;font-size:13px;font-weight:900}
.sum .amt{font-size:clamp(13px,4.2vw,19px);font-weight:900;margin:10px 0 6px;font-variant-numeric:tabular-nums;word-break:break-word}
.sum .cnt{color:var(--mut);font-size:12px;line-height:1.45}
.c-in{color:var(--cyn)} .c-out{color:var(--ros)} .c-net{color:var(--gld)}
.bg-in{background:rgba(45,212,238,.15)} .bg-out{background:rgba(251,113,133,.15)} .bg-net{background:rgba(245,196,81,.15)}
.sect{margin-top:16px}
.secthead{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.secthead h2{font-size:19px;font-weight:800}
.linkbtn{background:none;border:none;color:var(--cyn);font-family:inherit;font-size:13.5px;font-weight:700;cursor:pointer}
.txrow{display:flex;gap:12px;align-items:flex-start;padding:13px 2px;border-bottom:1px solid rgba(38,48,79,.6)}
.txrow:last-child{border-bottom:none}
.txic{flex:none;width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:19px;font-weight:900}
.txic.in{background:rgba(45,212,238,.14);color:var(--cyn)} .txic.out{background:rgba(251,113,133,.14);color:var(--ros)}
.txmain{flex:1;min-width:0}
.txtitle{font-weight:700;font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.txmeta{color:var(--mut);font-size:12px;margin-top:3px;line-height:1.5}
.txbal{color:var(--mut);font-size:12px;margin-top:2px;opacity:.8}
.txamt{font-weight:800;font-size:14px;font-variant-numeric:tabular-nums;text-align:right}
.txamt.in{color:var(--cyn)} .txamt.out{color:var(--ros)}
.empty{color:var(--mut);text-align:center;padding:26px 10px;font-size:14px;line-height:1.6}
.acc-head{display:flex;justify-content:space-between;align-items:center;cursor:pointer;background:none;border:none;width:100%;color:var(--txt);font-family:inherit;text-align:left;padding:0}
.acc-head h2{font-size:19px;font-weight:800}
.chev{color:var(--mut);font-size:20px;transition:transform .45s ease;display:inline-block}
.acc.open .chev{transform:rotate(180deg)}
.acc-body{max-height:0;overflow:hidden;transition:max-height .5s ease,opacity .5s ease;opacity:0}
.acc.open .acc-body{opacity:1}
.chart{display:flex;align-items:flex-end;gap:6px;height:150px;margin-top:16px}
.bcol{flex:1;display:flex;flex-direction:column;align-items:center;gap:6px;height:100%;justify-content:flex-end}
.bars{display:flex;gap:3px;align-items:flex-end;height:104px}
.bar{width:13px;border-radius:5px 5px 2px 2px;transition:height .8s cubic-bezier(.22,.8,.3,1);min-height:2px}
.bar.in{background:var(--cyn)} .bar.out{background:var(--ros)}
.bval{font-size:9.5px;color:var(--mut);font-weight:700;text-align:center;line-height:1.3}
.blab{font-size:10.5px;color:var(--mut);font-weight:700;text-align:center}
.legend{display:flex;gap:18px;margin-top:14px;color:var(--mut);font-size:12.5px;font-weight:600}
.dot{display:inline-block;width:9px;height:9px;border-radius:3px;margin-right:6px}
.catrow{margin-top:14px}
.catrow .r1{display:flex;justify-content:space-between;font-size:14px;margin-bottom:7px}
.catrow .r1 b{font-variant-numeric:tabular-nums}
.track{height:8px;background:rgba(38,48,79,.8);border-radius:99px;overflow:hidden}
.fill{height:100%;background:var(--ros);border-radius:99px;transition:width .8s cubic-bezier(.22,.8,.3,1)}
.bottombar{position:fixed;left:0;right:0;bottom:0;padding:14px 16px calc(14px + env(safe-area-inset-bottom));background:rgba(12,16,32,.88);backdrop-filter:blur(10px);border-top:1px solid var(--line);z-index:30}
.bottombar .inwrap{max-width:560px;margin:0 auto;display:flex;gap:12px}
.btn{flex:1;border-radius:18px;padding:17px 10px;font-family:inherit;font-size:16.5px;font-weight:800;cursor:pointer;transition:transform .15s}
.btn:active{transform:scale(.97)}
.btn-in{background:var(--ind);color:#fff;border:none;box-shadow:0 8px 24px rgba(91,91,214,.4)}
.btn-out{background:var(--card);color:var(--ros);border:1.5px solid rgba(251,113,133,.55)}
.overlay{position:fixed;inset:0;background:rgba(4,6,14,.66);opacity:0;pointer-events:none;transition:opacity .35s;z-index:40}
.overlay.show{opacity:1;pointer-events:auto}
.sheet{position:fixed;left:0;right:0;bottom:0;z-index:50;background:#171E36;border:1px solid var(--line);border-bottom:none;border-radius:26px 26px 0 0;padding:22px 20px calc(22px + env(safe-area-inset-bottom));max-width:560px;margin:0 auto;transform:translateY(105%);transition:transform .45s cubic-bezier(.22,.8,.3,1);max-height:92vh;overflow-y:auto}
.sheet.show{transform:none}
.sheet h3{font-size:21px;font-weight:900;margin-bottom:4px}
.sheet .ssub{color:var(--mut);font-size:13px;margin-bottom:18px}
.fld{margin-bottom:14px}
.fld label{display:block;font-size:11.5px;font-weight:800;color:var(--mut);letter-spacing:.8px;text-transform:uppercase;margin-bottom:7px}
.fld input,.fld select,.fld textarea{width:100%;background:var(--bg);border:1px solid var(--line);border-radius:14px;padding:13px 14px;color:var(--txt);font-family:inherit;font-size:15.5px;outline:none}
.fld input:focus,.fld select:focus,.fld textarea:focus{border-color:var(--ind)}
.fld textarea{resize:vertical;min-height:56px}
.frow{display:flex;gap:12px}.frow .fld{flex:1}
.opt{border-top:1px dashed var(--line);margin-top:4px;padding-top:14px}
.photoBox{border:1.5px dashed var(--line);border-radius:14px;padding:14px;text-align:center;color:var(--mut);font-size:13.5px;cursor:pointer}
.photoBox img{max-width:100%;max-height:180px;border-radius:10px;margin-bottom:8px}
.photoSize{font-size:12px;color:var(--cyn);font-weight:700;margin-top:6px}
.sheetbtns{display:flex;gap:12px;margin-top:18px}
.btn-cancel{flex:0 0 110px;background:none;border:1px solid var(--line);color:var(--mut);border-radius:16px;padding:15px;font-family:inherit;font-size:15px;font-weight:700;cursor:pointer}
.btn-save{flex:1;border:none;border-radius:16px;padding:15px;font-family:inherit;font-size:15.5px;font-weight:800;cursor:pointer;color:#fff;background:var(--ind)}
.btn-save.out{background:var(--ros)}
.monthrow{display:flex;justify-content:space-between;align-items:center;width:100%;background:var(--bg);border:1px solid var(--line);color:var(--txt);border-radius:14px;padding:15px 16px;font-family:inherit;font-size:15px;font-weight:700;cursor:pointer;margin-bottom:10px}
.monthrow small{color:var(--mut);font-weight:600}
.toast{position:fixed;top:18px;left:50%;transform:translate(-50%,-80px);background:#1E2A1E;border:1px solid #3E7C43;color:#B9F0BE;padding:13px 22px;border-radius:999px;font-size:14px;font-weight:700;z-index:80;transition:transform .45s cubic-bezier(.22,.8,.3,1);box-shadow:0 10px 30px rgba(0,0,0,.4)}
.toast.show{transform:translate(-50%,0)}
.backbtn{background:var(--card);border:1px solid var(--line);color:var(--txt);width:44px;height:44px;border-radius:50%;font-size:19px;cursor:pointer;flex:none}
.dhead{display:flex;gap:14px;align-items:center}
.dhead h1{font-size:25px;font-weight:900}
.dhead .sub{font-size:13px}
.fchips{display:flex;gap:9px;margin-top:18px;flex-wrap:wrap}
.fchip{background:var(--card);border:1px solid var(--line);color:var(--txt);border-radius:999px;padding:10px 16px;font-family:inherit;font-size:13.5px;font-weight:700;cursor:pointer;transition:all .25s}
.fchip.on{background:var(--ind);border-color:var(--ind);color:#fff}
.fchip.tool{border-style:dashed;color:var(--cyn)}
.scope{display:flex;gap:10px;margin-top:14px}
.scope .sc{flex:1;background:var(--card);border:1px solid var(--line);border-radius:18px;padding:13px 12px}
.scope .cap{font-size:10.5px;font-weight:800;letter-spacing:1px}
.scope .amt{font-size:clamp(12.5px,3.9vw,17px);font-weight:900;margin-top:6px;font-variant-numeric:tabular-nums;word-break:break-word}
.mgroup{margin-top:20px}
.mhead{display:flex;justify-content:space-between;align-items:baseline;border-bottom:1px solid var(--line);padding-bottom:9px;margin-bottom:4px}
.mhead h3{font-size:16.5px;font-weight:800}
.mhead .mtot{font-size:11.5px;color:var(--mut);text-align:right;line-height:1.5}
.txrow.click{cursor:pointer}
.detail-photo{width:100%;border-radius:14px;margin-top:6px;border:1px solid var(--line)}
.kv{display:flex;justify-content:space-between;gap:14px;padding:9px 0;border-bottom:1px solid rgba(38,48,79,.55);font-size:14px}
.kv span{color:var(--mut)} .kv b{text-align:right;font-variant-numeric:tabular-nums}
.btn-del{width:100%;background:none;border:1px solid rgba(251,113,133,.5);color:var(--ros);border-radius:14px;padding:13px;font-family:inherit;font-size:14.5px;font-weight:800;cursor:pointer;margin-top:16px}
footer.foot{color:var(--mut);font-size:12px;text-align:center;margin-top:28px;opacity:.7;line-height:1.6}
[hidden]{display:none !important}
</style>
</head>
<body>
<div class="wrap">

<!-- ================= DASHBOARD ================= -->
<div id="viewDash">
  <header class="top anim">
    <div>
      <div class="lbl">dinzzz.my.id</div>
      <h1 class="title">Monitoring<br>Keuangan</h1>
      <div class="sub">Dashboard uang pribadi</div>
    </div>
    <button class="logout" id="btnLogout">Keluar</button>
  </header>

  <section class="card hero anim d1">
    <span class="badge">SEMUA WAKTU</span>
    <div class="cap">SALDO TOTAL</div>
    <div class="amt" id="heroAmt">Rp 0</div>
    <div class="meta" id="heroMeta">Masuk <b class="in">Rp 0</b> · Keluar <b class="out">Rp 0</b> · dari 0 transaksi</div>
    <div class="note">Saldo ini dari semua catatan dari awal — tidak berubah walau periode di bawah diganti. Tiap transaksi juga nunjukin sisa saldo setelahnya.</div>
  </section>

  <nav class="chips anim d2" id="dashChips">
    <button class="chip" data-p="kemarin">Kemarin</button>
    <button class="chip" data-p="hariini">Hari ini</button>
    <button class="chip on" data-p="bulanini">Bulan ini</button>
  </nav>

  <section class="grid3 anim d2">
    <div class="card sum">
      <div class="cap c-in"><span class="ic bg-in">↑</span>TOTAL MASUK</div>
      <div class="amt c-in" id="sumIn">Rp 0</div>
      <div class="cnt" id="sumInCnt">0 transaksi masuk</div>
    </div>
    <div class="card sum">
      <div class="cap c-out"><span class="ic bg-out">↓</span>TOTAL KELUAR</div>
      <div class="amt c-out" id="sumOut">Rp 0</div>
      <div class="cnt" id="sumOutCnt">0 transaksi keluar</div>
    </div>
    <div class="card sum">
      <div class="cap c-net"><span class="ic bg-net">→</span>SELISIH</div>
      <div class="amt c-net" id="sumNet">Rp 0</div>
      <div class="cnt" id="sumNetNote">—</div>
    </div>
  </section>

  <section class="card sect anim d3">
    <div class="secthead">
      <h2>Transaksi Terakhir</h2>
      <button class="linkbtn" id="btnMore">Selengkapnya →</button>
    </div>
    <div id="dashList"></div>
  </section>

  <section class="card sect acc anim d4" id="accChart">
    <button class="acc-head" data-acc="accChart"><h2>Arus Kas</h2><span class="chev">⌄</span></button>
    <div class="acc-body">
      <div class="chart" id="chart"></div>
      <div class="legend"><span><span class="dot" style="background:var(--cyn)"></span>Masuk</span><span><span class="dot" style="background:var(--ros)"></span>Keluar</span></div>
    </div>
  </section>

  <section class="card sect acc anim d5" id="accCat">
    <button class="acc-head" data-acc="accCat"><h2>Pengeluaran per Kategori</h2><span class="chev">⌄</span></button>
    <div class="acc-body"><div id="catList"></div></div>
  </section>

  <footer class="foot">dinzzz.my.id — catatan keuangan pribadi.<br>Data tersimpan aman di database milikmu sendiri.</footer>
</div>

<!-- ================= DETAIL TRANSAKSI ================= -->
<div id="viewDetail" hidden>
  <div class="dhead anim">
    <button class="backbtn" id="btnBack">←</button>
    <div>
      <h1>Detail Transaksi</h1>
      <div class="sub" style="color:var(--mut)">dinzzz.my.id/detail-transaksi</div>
    </div>
  </div>

  <div class="fchips anim d1" id="detailChips">
    <button class="fchip on" data-dp="bulanini">Bulan ini</button>
    <button class="fchip" data-dp="bulanlalu">Bulan lalu</button>
    <button class="fchip" data-dp="3bulan">3 Bulan Terakhir</button>
    <button class="fchip" data-dp="tahunini">Tahun ini</button>
    <button class="fchip" data-dp="semua">Semua</button>
    <button class="fchip tool" id="btnMonth">📅 Pilih Bulan</button>
    <button class="fchip tool" id="btnCal">🗓 Kalender</button>
  </div>
  <div class="sub anim d1" id="scopeLabel" style="color:var(--cyn);font-weight:700;margin-top:12px;font-size:13.5px"></div>

  <div class="scope anim d2">
    <div class="sc"><div class="cap c-in">MASUK</div><div class="amt c-in" id="dIn">Rp 0</div></div>
    <div class="sc"><div class="cap c-out">KELUAR</div><div class="amt c-out" id="dOut">Rp 0</div></div>
    <div class="sc"><div class="cap c-net">SELISIH</div><div class="amt c-net" id="dNet">Rp 0</div></div>
  </div>

  <div id="detailList" class="anim d2"></div>
  <footer class="foot">Ketuk satu transaksi untuk melihat detail<br>dan foto buktinya.</footer>
</div>

</div><!-- /wrap -->

<div class="bottombar" id="bottomBar">
  <div class="inwrap">
    <button class="btn btn-in" id="btnAddIn">+ Catat Masuk</button>
    <button class="btn btn-out" id="btnAddOut">− Catat Keluar</button>
  </div>
</div>

<div class="overlay" id="overlay"></div>

<!-- Form catat -->
<div class="sheet" id="formSheet">
  <h3 id="formTitle">Catat Masuk</h3>
  <div class="ssub" id="formSub">Uang masuk — dari mana?</div>
  <form id="txForm">
    <div class="fld">
      <label>Jumlah (Rp)</label>
      <input type="text" id="fAmount" inputmode="numeric" placeholder="0" autocomplete="off">
    </div>
    <div class="fld">
      <label id="fTitleLabel">Dari mana</label>
      <input type="text" id="fTitle" placeholder="Contoh: Gaji bulanan" autocomplete="off">
    </div>
    <div class="fld">
      <label>Foto bukti transfer (opsional)</label>
      <div class="photoBox" id="photoBox">
        <div id="photoEmpty">📷 Ketuk untuk pilih foto bukti<br><small>boleh dikosongkan</small></div>
        <img id="photoImg" hidden alt="Foto bukti">
        <div id="photoName"></div>
        <div class="photoSize" id="photoSize"></div>
        <div id="photoRemove" class="photoSize" style="color:var(--ros)" hidden>Hapus foto ✕</div>
      </div>
      <input type="file" id="fPhoto" accept="image/*" hidden>
    </div>
    <div class="opt">
      <div class="frow">
        <div class="fld"><label>Kategori (opsional)</label><select id="fCategory"></select></div>
        <div class="fld"><label>Dompet (opsional)</label>
          <select id="fWallet"><option value="">—</option><option>Tunai</option><option>Bank</option><option>E-Wallet</option></select>
        </div>
      </div>
      <div class="frow">
        <div class="fld"><label>Tanggal</label><input type="date" id="fDate"></div>
        <div class="fld"><label>Jam</label><input type="time" id="fTime"></div>
      </div>
      <div class="fld"><label>Catatan (opsional)</label><textarea id="fNote" placeholder="Catatan tambahan..."></textarea></div>
    </div>
    <div class="sheetbtns">
      <button type="button" class="btn-cancel" id="btnCancelForm">Batal</button>
      <button type="submit" class="btn-save" id="btnSave">Simpan</button>
    </div>
  </form>
</div>

<!-- Pilih bulan -->
<div class="sheet" id="monthSheet">
  <h3>Pilih Bulan</h3>
  <div class="ssub">Tampilkan transaksi satu bulan penuh</div>
  <div id="monthList"></div>
  <div class="sheetbtns"><button type="button" class="btn-cancel" data-close>Batal</button></div>
</div>

<!-- Kalender -->
<div class="sheet" id="calSheet">
  <h3>Pilih Rentang Tanggal</h3>
  <div class="ssub">Kayak dashboard iklan — pilih mulai & selesai</div>
  <div class="fld"><label>Tanggal Mulai</label><input type="date" id="calFrom"></div>
  <div class="fld"><label>Tanggal Selesai</label><input type="date" id="calTo"></div>
  <div class="sheetbtns">
    <button type="button" class="btn-cancel" data-close>Batal</button>
    <button type="button" class="btn-save" id="btnCalApply">Terapkan</button>
  </div>
</div>

<!-- Detail satu transaksi -->
<div class="sheet" id="detailSheet">
  <h3 id="dtTitle">Detail</h3>
  <div class="ssub" id="dtDate">—</div>
  <div id="dtBody"></div>
  <img id="dtPhoto" class="detail-photo" hidden alt="Foto bukti transfer">
  <div id="dtNoPhoto" class="empty" hidden>Tidak ada foto bukti</div>
  <button class="btn-del" id="btnDelete">Hapus Catatan Ini</button>
  <div class="sheetbtns"><button type="button" class="btn-cancel" data-close style="flex:1">Tutup</button></div>
</div>

<div class="toast" id="toast">Transaksi tersimpan ✓</div>

<script>
var $ = function(id){ return document.getElementById(id); };
var txs = [];
var dashPeriod = 'bulanini';
var detail = { mode: 'preset', preset: 'bulanini', month: null, from: null, to: null };
var prevVals = {};
var formType = 'in';
var pendingPhoto = null;
var pendingPhotoOrig = 0;
var currentDetailId = null;

function esc(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){ return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
function rp(n){ var neg = n < 0; var v = Math.abs(Math.round(n)); var s = String(v).replace(/\B(?=(\d{3})+(?!\d))/g, '.'); return (neg ? '-Rp ' : 'Rp ') + s; }
function rpSigned(n, type){ return (type === 'in' ? '+' : '-') + rp(Math.abs(n)); }
function compact(n){ n = Math.abs(Math.round(n)); if (n >= 1000000) { var v = Math.round(n / 100000) / 10; return String(v).replace('.', ',') + ' jt'; } if (n >= 1000) return Math.round(n / 1000) + ' rb'; return String(n); }
function fmtBytes(n){ if (n < 1024) return n + ' B'; if (n < 1048576) return Math.round(n / 1024) + ' KB'; return (Math.round(n / 104857.6) / 10).toString().replace('.', ',') + ' MB'; }

function pad(n){ return (n < 10 ? '0' : '') + n; }
function todayJKT(){ return new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Jakarta' }); }
function nowJKT(){ return new Date().toLocaleTimeString('en-GB', { timeZone: 'Asia/Jakarta', hour12: false }).slice(0, 5); }
function parseD(s){ var p = s.split('-'); return { y: +p[0], m: +p[1], d: +p[2] }; }
function fmtD(y, m, d){ return y + '-' + pad(m) + '-' + pad(d); }
function addDays(s, n){ var p = parseD(s); var dt = new Date(Date.UTC(p.y, p.m - 1, p.d + n)); return fmtD(dt.getUTCFullYear(), dt.getUTCMonth() + 1, dt.getUTCDate()); }
function dayDiff(a, b){ var pa = parseD(a), pb = parseD(b); return Math.round((Date.UTC(pb.y, pb.m - 1, pb.d) - Date.UTC(pa.y, pa.m - 1, pa.d)) / 86400000); }
function monthOf(s){ return s.slice(0, 7); }
function monthStart(s){ var p = parseD(s); return fmtD(p.y, p.m, 1); }
function addMonths(ym, n){ var y = +ym.slice(0, 4), m = +ym.slice(5, 7) + n; while (m < 1) { m += 12; y--; } while (m > 12) { m -= 12; y++; } return y + '-' + pad(m); }
var MONTHS_ID = ['Januari','Februari','Maret','April','Mei','Juni','Juli','Agustus','September','Oktober','November','Desember'];
var MON3 = ['Jan','Feb','Mar','Apr','Mei','Jun','Jul','Agu','Sep','Okt','Nov','Des'];
function monthLabel(ym){ return MONTHS_ID[+ym.slice(5, 7) - 1] + ' ' + ym.slice(0, 4); }
function dateLabel(s){ var p = parseD(s); var wd = new Date(Date.UTC(p.y, p.m - 1, p.d)).toLocaleDateString('id-ID', { weekday: 'short', timeZone: 'UTC' }); return wd + ', ' + p.d + ' ' + MON3[p.m - 1] + ' ' + p.y; }
function dateShort(s){ var p = parseD(s); return p.d + ' ' + MON3[p.m - 1] + ' ' + p.y; }

function dashRange(){ var t = todayJKT(); if (dashPeriod === 'kemarin') { var y = addDays(t, -1); return { from: y, to: y }; } if (dashPeriod === 'hariini') return { from: t, to: t }; return { from: monthStart(t), to: t }; }
function detailRange(){
  var t = todayJKT();
  if (detail.mode === 'month' && detail.month) return { from: detail.month + '-01', to: addDays(addMonths(detail.month, 1) + '-01', -1) };
  if (detail.mode === 'range' && detail.from && detail.to) return { from: detail.from, to: detail.to };
  var p = detail.preset;
  if (p === 'bulanlalu') { var cur = monthOf(t); var prev = addMonths(cur, -1); return { from: prev + '-01', to: addDays(cur + '-01', -1) }; }
  if (p === '3bulan') return { from: addMonths(monthOf(t), -2) + '-01', to: t };
  if (p === 'tahunini') return { from: t.slice(0, 4) + '-01-01', to: t };
  if (p === 'semua') return { from: '0000-01-01', to: '9999-12-31' };
  return { from: monthStart(t), to: t };
}
function inRange(tx, r){ return tx.date >= r.from && tx.date <= r.to; }
function sums(list){ var i = 0, o = 0, ci = 0, co = 0; for (var k = 0; k < list.length; k++) { if (list[k].type === 'in') { i += list[k].amount; ci++; } else { o += list[k].amount; co++; } } return { in: i, out: o, net: i - o, ci: ci, co: co }; }
function computeBalances(){ var bal = 0; for (var k = 0; k < txs.length; k++) { bal += (txs[k].type === 'in' ? txs[k].amount : -txs[k].amount); txs[k]._bal = bal; } return bal; }

function tweenNum(el, key, to, formatter){
  var from = prevVals[key] || 0; prevVals[key] = to;
  var start = null, dur = 650;
  function step(ts){ if (!start) start = ts; var p = Math.min(1, (ts - start) / dur); var e = 1 - Math.pow(1 - p, 3); el.textContent = formatter(Math.round(from + (to - from) * e)); if (p < 1) requestAnimationFrame(step); }
  requestAnimationFrame(step);
}
function showToast(msg, isErr){
  var t = $('toast'); t.textContent = msg;
  t.style.background = isErr ? '#2A1E24' : '#1E2A1E'; t.style.borderColor = isErr ? '#7C3E4E' : '#3E7C43'; t.style.color = isErr ? '#F0B9C4' : '#B9F0BE';
  t.classList.add('show'); setTimeout(function(){ t.classList.remove('show'); }, 2600);
}

function txRow(tx, clickable){
  var meta = dateLabel(tx.date);
  if (tx.category) meta += ' · ' + esc(tx.category);
  if (tx.wallet) meta += ' · ' + esc(tx.wallet);
  return '<div class="txrow' + (clickable ? ' click' : '') + '" data-id="' + tx.id + '">' +
    '<div class="txic ' + tx.type + '">' + (tx.type === 'in' ? '+' : '−') + '</div>' +
    '<div class="txmain"><div class="txtitle">' + esc(tx.title) + '</div>' +
    '<div class="txmeta">' + meta + '</div>' +
    '<div class="txbal">Saldo: ' + rp(tx._bal) + '</div></div>' +
    '<div class="txamt ' + tx.type + '">' + rpSigned(tx.amount, tx.type) + '</div></div>';
}

function renderHero(){
  var total = computeBalances();
  var s = sums(txs);
  tweenNum($('heroAmt'), 'hero', total, rp);
  $('heroMeta').innerHTML = 'Masuk <b class="in">' + rp(s.in) + '</b> · Keluar <b class="out">' + rp(s.out) + '</b> · dari ' + txs.length + ' transaksi';
}

function bucketsFor(range, list){
  var buckets = [];
  if (range.from === range.to) {
    var defs = [ { label: 'Pagi', test: function(h){ return h >= 6 && h < 12; } }, { label: 'Siang', test: function(h){ return h >= 12 && h < 18; } }, { label: 'Sore', test: function(h){ return h >= 18 && h < 24; } }, { label: 'Malam', test: function(h){ return h >= 0 && h < 6; } } ];
    defs.forEach(function(d){ buckets.push({ label: d.label, in: 0, out: 0, test: d.test }); });
    list.forEach(function(tx){ var h = parseInt((tx.time || '12:00').slice(0, 2), 10); for (var i = 0; i < buckets.length; i++) { if (buckets[i].test(h)) { if (tx.type === 'in') buckets[i].in += tx.amount; else buckets[i].out += tx.amount; break; } } });
    return buckets;
  }
  var cur = range.from, i = 1;
  while (cur <= range.to && i <= 8) {
    var end = addDays(cur, 6); if (end > range.to) end = range.to;
    buckets.push({ label: 'Mgg ' + i, from: cur, to: end, in: 0, out: 0 });
    cur = addDays(end, 1); i++;
  }
  list.forEach(function(tx){ for (var j = 0; j < buckets.length; j++) { if (tx.date >= buckets[j].from && tx.date <= buckets[j].to) { if (tx.type === 'in') buckets[j].in += tx.amount; else buckets[j].out += tx.amount; break; } } });
  return buckets;
}

function renderChart(range, list){
  var buckets = bucketsFor(range, list);
  var max = 1;
  buckets.forEach(function(b){ max = Math.max(max, b.in, b.out); });
  var html = '';
  buckets.forEach(function(b){
    html += '<div class="bcol"><div class="bval"><span style="color:var(--cyn)">' + (b.in ? compact(b.in) : '') + '</span><br><span style="color:var(--ros)">' + (b.out ? compact(b.out) : '') + '</span></div>' +
      '<div class="bars"><div class="bar in" data-h="' + Math.round(b.in / max * 100) + '"></div><div class="bar out" data-h="' + Math.round(b.out / max * 100) + '"></div></div>' +
      '<div class="blab">' + b.label + '</div></div>';
  });
  var chart = $('chart'); chart.innerHTML = html;
  requestAnimationFrame(function(){ requestAnimationFrame(function(){ var bars = chart.querySelectorAll('.bar'); for (var i = 0; i < bars.length; i++) bars[i].style.height = bars[i].getAttribute('data-h') + '%'; }); });
}

function renderCats(list){
  var map = {};
  list.forEach(function(tx){ if (tx.type === 'out') { var c = tx.category || 'Lainnya'; map[c] = (map[c] || 0) + tx.amount; } });
  var keys = Object.keys(map).sort(function(a, b){ return map[b] - map[a]; });
  if (!keys.length) { $('catList').innerHTML = '<div class="empty">Belum ada pengeluaran di periode ini.</div>'; return; }
  var max = map[keys[0]];
  var html = '';
  keys.forEach(function(k){ html += '<div class="catrow"><div class="r1"><span>' + esc(k) + '</span><b>' + rp(map[k]) + '</b></div><div class="track"><div class="fill" data-w="' + Math.round(map[k] / max * 100) + '"></div></div></div>'; });
  var el = $('catList'); el.innerHTML = html;
  requestAnimationFrame(function(){ requestAnimationFrame(function(){ var fills = el.querySelectorAll('.fill'); for (var i = 0; i < fills.length; i++) fills[i].style.width = fills[i].getAttribute('data-w') + '%'; }); });
}

function renderDash(){
  var range = dashRange();
  var list = txs.filter(function(tx){ return inRange(tx, range); });
  var s = sums(list);
  tweenNum($('sumIn'), 'sumIn', s.in, rp);
  tweenNum($('sumOut'), 'sumOut', s.out, rp);
  tweenNum($('sumNet'), 'sumNet', s.net, rp);
  $('sumInCnt').textContent = s.ci + ' transaksi masuk';
  $('sumOutCnt').textContent = s.co + ' transaksi keluar';
  $('sumNetNote').textContent = s.net >= 0 ? 'Masih surplus, aman' : 'Keluar lebih besar';
  var desc = list.slice().reverse();
  var top = desc.slice(0, 10);
  $('dashList').innerHTML = top.length ? top.map(function(tx){ return txRow(tx, false); }).join('') : '<div class="empty">Belum ada catatan di periode ini.<br>Ketuk + Catat Masuk atau − Catat Keluar untuk mulai.</div>';
  renderChart(range, list);
  renderCats(list);
  var acc = $('accChart'); if (acc.classList.contains('open')) { var b = acc.querySelector('.acc-body'); b.style.maxHeight = b.scrollHeight + 'px'; }
}

function scopeText(){
  if (detail.mode === 'month' && detail.month) return 'Bulan: ' + monthLabel(detail.month);
  if (detail.mode === 'range') return 'Rentang: ' + dateShort(detail.from) + ' – ' + dateShort(detail.to);
  var names = { bulanini: 'Bulan ini', bulanlalu: 'Bulan lalu', '3bulan': '3 Bulan Terakhir', tahunini: 'Tahun ini', semua: 'Semua riwayat' };
  return names[detail.preset] || 'Bulan ini';
}

function renderDetail(){
  var range = detailRange();
  var list = txs.filter(function(tx){ return inRange(tx, range); });
  var s = sums(list);
  $('scopeLabel').textContent = scopeText();
  tweenNum($('dIn'), 'dIn', s.in, rp);
  tweenNum($('dOut'), 'dOut', s.out, rp);
  tweenNum($('dNet'), 'dNet', s.net, rp);
  if (!list.length) { $('detailList').innerHTML = '<div class="empty">Belum ada transaksi pada cakupan ini.</div>'; return; }
  var desc = list.slice().reverse();
  var groups = [], byMonth = {};
  desc.forEach(function(tx){ var m = monthOf(tx.date); if (!byMonth[m]) { byMonth[m] = []; groups.push(m); } byMonth[m].push(tx); });
  var html = '';
  groups.forEach(function(m){
    var gs = sums(byMonth[m]);
    html += '<div class="mgroup"><div class="mhead"><h3>' + monthLabel(m) + '</h3><div class="mtot">Masuk ' + rp(gs.in) + '<br>Keluar ' + rp(gs.out) + ' · Selisih ' + rp(gs.net) + '</div></div>';
    byMonth[m].forEach(function(tx){ html += txRow(tx, true); });
    html += '</div>';
  });
  $('detailList').innerHTML = html;
}

function renderAll(){ renderHero(); renderDash(); if (!$('viewDetail').hidden) renderDetail(); }

function loadTxs(){
  return fetch('/api/transactions').then(function(r){ if (r.status === 401) { location.href = '/'; throw new Error('unauth'); } return r.json(); })
    .then(function(j){ txs = j.transactions || []; renderAll(); })
    .catch(function(e){ if (e.message !== 'unauth') showToast('Gagal memuat data', true); });
}

// ---------- Sheets ----------
function openSheet(id){ closeSheets(true); $('overlay').classList.add('show'); $(id).classList.add('show'); }
function closeSheets(keepOverlay){
  var sheets = document.querySelectorAll('.sheet'); for (var i = 0; i < sheets.length; i++) sheets[i].classList.remove('show');
  if (!keepOverlay) $('overlay').classList.remove('show');
}
$('overlay').addEventListener('click', function(){ closeSheets(); });
document.querySelectorAll('[data-close]').forEach(function(b){ b.addEventListener('click', function(){ closeSheets(); }); });

// ---------- Accordion ----------
document.querySelectorAll('.acc-head').forEach(function(h){
  h.addEventListener('click', function(){
    var acc = $(h.getAttribute('data-acc'));
    var body = acc.querySelector('.acc-body');
    var open = acc.classList.toggle('open');
    body.style.maxHeight = open ? body.scrollHeight + 'px' : '0px';
  });
});

// ---------- Navigasi ----------
function showView(name, push){
  $('viewDash').hidden = name !== 'dash';
  $('viewDetail').hidden = name !== 'detail';
  $('bottomBar').style.display = name === 'dash' ? '' : 'none';
  window.scrollTo(0, 0);
  if (push) history.pushState({}, '', name === 'detail' ? '/detail-transaksi' : '/');
  if (name === 'detail') renderDetail();
}
$('btnMore').addEventListener('click', function(){ showView('detail', true); });
$('btnBack').addEventListener('click', function(){ showView('dash', true); });
window.addEventListener('popstate', function(){ showView(location.pathname.indexOf('detail-transaksi') >= 0 ? 'detail' : 'dash', false); });
$('btnLogout').addEventListener('click', function(){ fetch('/api/logout', { method: 'POST' }).then(function(){ location.href = '/'; }); });

// ---------- Chips dashboard ----------
$('dashChips').addEventListener('click', function(e){
  var b = e.target.closest('.chip'); if (!b) return;
  dashPeriod = b.getAttribute('data-p');
  var chips = $('dashChips').querySelectorAll('.chip'); for (var i = 0; i < chips.length; i++) chips[i].classList.toggle('on', chips[i] === b);
  renderDash();
});

// ---------- Filter detail ----------
$('detailChips').addEventListener('click', function(e){
  var b = e.target.closest('[data-dp]'); if (!b) return;
  detail.mode = 'preset'; detail.preset = b.getAttribute('data-dp');
  var chips = $('detailChips').querySelectorAll('[data-dp]'); for (var i = 0; i < chips.length; i++) chips[i].classList.toggle('on', chips[i] === b);
  renderDetail();
});
function clearDetailChips(){ var chips = $('detailChips').querySelectorAll('[data-dp]'); for (var i = 0; i < chips.length; i++) chips[i].classList.remove('on'); }

$('btnMonth').addEventListener('click', function(){
  var set = {};
  txs.forEach(function(tx){ set[monthOf(tx.date)] = true; });
  set[monthOf(todayJKT())] = true;
  var months = Object.keys(set).sort().reverse();
  var html = '';
  months.forEach(function(m){
    var mt = txs.filter(function(tx){ return monthOf(tx.date) === m; });
    var s = sums(mt);
    html += '<button class="monthrow" data-month="' + m + '"><span>' + monthLabel(m) + '</span><small>' + mt.length + ' transaksi · ' + rp(s.net) + '</small></button>';
  });
  $('monthList').innerHTML = html;
  openSheet('monthSheet');
});
$('monthList').addEventListener('click', function(e){
  var b = e.target.closest('[data-month]'); if (!b) return;
  detail.mode = 'month'; detail.month = b.getAttribute('data-month');
  clearDetailChips(); closeSheets(); renderDetail();
});
$('btnCal').addEventListener('click', function(){ $('calFrom').value = monthStart(todayJKT()); $('calTo').value = todayJKT(); openSheet('calSheet'); });
$('btnCalApply').addEventListener('click', function(){
  var f = $('calFrom').value, t = $('calTo').value;
  if (!f || !t) { showToast('Isi kedua tanggal dulu', true); return; }
  if (f > t) { var tmp = f; f = t; t = tmp; }
  detail.mode = 'range'; detail.from = f; detail.to = t;
  clearDetailChips(); closeSheets(); renderDetail();
});

// ---------- Form catat ----------
var CATS = { in: ['Gaji', 'Bonus', 'Usaha', 'Transfer Masuk', 'Lainnya'], out: ['Belanja', 'Makan & Minum', 'Tagihan', 'Transport', 'Kesehatan', 'Hiburan', 'Lainnya'] };
function openForm(type){
  formType = type;
  $('formTitle').textContent = type === 'in' ? 'Catat Masuk' : 'Catat Keluar';
  $('formSub').textContent = type === 'in' ? 'Uang masuk — dari mana?' : 'Uang keluar — buat apa / ke mana?';
  $('formSub').style.color = '';
  $('fTitleLabel').textContent = type === 'in' ? 'Dari mana' : 'Buat apa / ke mana';
  $('btnSave').className = 'btn-save' + (type === 'out' ? ' out' : '');
  var opts = '<option value="">—</option>';
  CATS[type].forEach(function(c){ opts += '<option>' + c + '</option>'; });
  $('fCategory').innerHTML = opts;
  $('fAmount').value = ''; $('fTitle').value = ''; $('fNote').value = ''; $('fWallet').value = '';
  $('fDate').value = todayJKT(); $('fTime').value = nowJKT();
  resetPhoto();
  openSheet('formSheet');
}
$('btnAddIn').addEventListener('click', function(){ openForm('in'); });
$('btnAddOut').addEventListener('click', function(){ openForm('out'); });
$('btnCancelForm').addEventListener('click', function(){ closeSheets(); });
$('fAmount').addEventListener('input', function(){
  var digits = $('fAmount').value.replace(/\D/g, '');
  $('fAmount').value = digits ? String(parseInt(digits, 10)).replace(/\B(?=(\d{3})+(?!\d))/g, '.') : '';
});

function resetPhoto(){
  pendingPhoto = null; pendingPhotoOrig = 0;
  $('fPhoto').value = ''; $('photoImg').hidden = true; $('photoImg').src = '';
  $('photoEmpty').hidden = false; $('photoName').textContent = ''; $('photoSize').textContent = ''; $('photoRemove').hidden = true;
}
$('photoBox').addEventListener('click', function(e){ if (e.target === $('photoRemove')) return; $('fPhoto').click(); });
$('photoRemove').addEventListener('click', function(e){ e.stopPropagation(); resetPhoto(); });
function compressPhoto(file){
  return new Promise(function(resolve, reject){
    var url = URL.createObjectURL(file);
    var img = new Image();
    img.onload = function(){
      var w = img.naturalWidth, h = img.naturalHeight, max = 1280;
      if (w > max || h > max) { var r = max / Math.max(w, h); w = Math.round(w * r); h = Math.round(h * r); }
      var c = document.createElement('canvas'); c.width = w; c.height = h;
      c.getContext('2d').drawImage(img, 0, 0, w, h);
      c.toBlob(function(blob){ URL.revokeObjectURL(url); if (blob) resolve(blob); else reject(new Error('compress')); }, 'image/jpeg', 0.72);
    };
    img.onerror = function(){ URL.revokeObjectURL(url); reject(new Error('load')); };
    img.src = url;
  });
}
$('fPhoto').addEventListener('change', function(){
  var file = $('fPhoto').files[0]; if (!file) return;
  pendingPhotoOrig = file.size;
  $('photoName').textContent = file.name; $('photoSize').textContent = 'Mengompres...';
  compressPhoto(file).then(function(blob){
    pendingPhoto = blob;
    $('photoImg').src = URL.createObjectURL(blob); $('photoImg').hidden = false; $('photoEmpty').hidden = true; $('photoRemove').hidden = false;
    $('photoSize').textContent = fmtBytes(pendingPhotoOrig) + ' → ' + fmtBytes(blob.size) + ' setelah dikompres';
  }).catch(function(){ $('photoSize').textContent = 'Foto gagal diproses — coba foto lain'; });
});

$('txForm').addEventListener('submit', function(ev){
  ev.preventDefault();
  var amount = parseInt(($('fAmount').value || '').replace(/\D/g, ''), 10) || 0;
  var title = $('fTitle').value.trim();
  if (!amount || amount <= 0 || !title) { $('formSub').textContent = 'Jumlah dan ' + (formType === 'in' ? 'sumber (dari mana)' : 'tujuan (buat apa)') + ' wajib diisi.'; $('formSub').style.color = 'var(--ros)'; return; }
  var fd = new FormData();
  fd.append('type', formType); fd.append('amount', amount); fd.append('title', title);
  fd.append('category', $('fCategory').value); fd.append('wallet', $('fWallet').value);
  fd.append('date', $('fDate').value || todayJKT()); fd.append('time', $('fTime').value || nowJKT());
  fd.append('note', $('fNote').value.trim());
  if (pendingPhoto) fd.append('photo', pendingPhoto, 'bukti.jpg');
  var btn = $('btnSave'); btn.disabled = true; btn.textContent = 'Menyimpan...';
  fetch('/api/transactions', { method: 'POST', body: fd }).then(function(r){ return r.json().then(function(j){ return { ok: r.ok, j: j }; }); })
    .then(function(res){
      btn.disabled = false; btn.textContent = 'Simpan';
      if (res.ok) { closeSheets(); showToast('Transaksi tersimpan ✓'); loadTxs(); }
      else { $('formSub').textContent = res.j.error || 'Gagal menyimpan.'; $('formSub').style.color = 'var(--ros)'; }
    })
    .catch(function(){ btn.disabled = false; btn.textContent = 'Simpan'; showToast('Koneksi bermasalah', true); });
});

// ---------- Detail satu transaksi ----------
$('detailList').addEventListener('click', function(e){
  var row = e.target.closest('.txrow'); if (!row) return;
  openTxDetail(parseInt(row.getAttribute('data-id'), 10));
});
function kvRow(k, v){ return '<div class="kv"><span>' + k + '</span><b>' + v + '</b></div>'; }
function openTxDetail(id){
  var tx = null;
  for (var i = 0; i < txs.length; i++) if (txs[i].id === id) tx = txs[i];
  if (!tx) return;
  currentDetailId = id;
  $('dtTitle').textContent = tx.title;
  $('dtDate').textContent = dateLabel(tx.date) + ' · ' + (tx.time || '');
  var html = '';
  html += kvRow('Jenis', tx.type === 'in' ? 'Uang Masuk' : 'Uang Keluar');
  html += kvRow('Jumlah', '<span style="color:var(--' + (tx.type === 'in' ? 'cyn' : 'ros') + ')">' + rpSigned(tx.amount, tx.type) + '</span>');
  html += kvRow('Kategori', esc(tx.category || '—'));
  html += kvRow('Dompet', esc(tx.wallet || '—'));
  html += kvRow('Catatan', esc(tx.note || '—'));
  html += kvRow('Saldo setelahnya', rp(tx._bal));
  $('dtBody').innerHTML = html;
  if (tx.photo_key) { $('dtPhoto').src = '/api/photo/' + encodeURIComponent(tx.photo_key); $('dtPhoto').hidden = false; $('dtNoPhoto').hidden = true; }
  else { $('dtPhoto').hidden = true; $('dtPhoto').src = ''; $('dtNoPhoto').hidden = false; }
  openSheet('detailSheet');
}
$('btnDelete').addEventListener('click', function(){
  if (!currentDetailId) return;
  if (!confirm('Hapus catatan ini? Saldo akan dihitung ulang.')) return;
  fetch('/api/transactions/' + currentDetailId, { method: 'DELETE' }).then(function(r){ return r.json(); })
    .then(function(j){ if (j.ok) { closeSheets(); showToast('Catatan dihapus'); loadTxs(); } else showToast(j.error || 'Gagal menghapus', true); })
    .catch(function(){ showToast('Koneksi bermasalah', true); });
});

// ---------- Init ----------
if (location.pathname.indexOf('detail-transaksi') >= 0) showView('detail', false); else showView('dash', false);
loadTxs();
</script>
</body>
</html>`;

// ---------------- Router ----------------
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    try {
      const hasPw = (await getSetting(env, 'pw_hash')) !== null;
      const authed = await validSession(env, cookieOf(req, COOKIE_NAME));

      if (path === '/api/state') return jsonRes({ hasPassword: hasPw, authed: authed });

      if (path === '/api/setup' && req.method === 'POST') {
        if (hasPw) return jsonRes({ error: 'Password sudah dibuat.' }, 400);
        const body = await req.json().catch(() => ({}));
        const pw = String(body.password || '');
        if (pw.length < 6) return jsonRes({ error: 'Password minimal 6 karakter.' }, 400);
        const r = await pwHash(pw);
        await setSetting(env, 'pw_salt', r.salt);
        await setSetting(env, 'pw_hash', r.hash);
        const token = await makeSession(env);
        return jsonRes({ ok: true }, 200, { 'Set-Cookie': sessionCookie(token) });
      }

      if (path === '/api/login' && req.method === 'POST') {
        const ip = req.headers.get('CF-Connecting-IP') || 'unknown';
        if (tooManyFails(ip)) return jsonRes({ error: 'Terlalu banyak percobaan. Coba lagi beberapa menit lagi.' }, 429);
        const body = await req.json().catch(() => ({}));
        const pw = String(body.password || '');
        const salt = await getSetting(env, 'pw_salt');
        const stored = await getSetting(env, 'pw_hash');
        if (!salt || !stored) return jsonRes({ error: 'Password belum dibuat.' }, 400);
        const r = await pwHash(pw, salt);
        if (!timingEq(r.hash, stored)) { noteFail(ip); return jsonRes({ error: 'Password salah.' }, 401); }
        loginFails.delete(ip);
        const token = await makeSession(env);
        return jsonRes({ ok: true }, 200, { 'Set-Cookie': sessionCookie(token) });
      }

      if (path === '/api/logout' && req.method === 'POST') {
        return jsonRes({ ok: true }, 200, { 'Set-Cookie': sessionCookie('', true) });
      }

      if (path.startsWith('/api/')) {
        if (!authed) return jsonRes({ error: 'Belum login.' }, 401);

        if (path === '/api/transactions' && req.method === 'GET') {
          const res = await env.DB.prepare('SELECT id, type, amount, title, category, wallet, date, time, note, photo_key FROM transactions ORDER BY date ASC, time ASC, id ASC').all();
          return jsonRes({ transactions: res.results || [] });
        }

        if (path === '/api/transactions' && req.method === 'POST') {
          const fd = await req.formData();
          const type = String(fd.get('type') || '');
          const amount = Math.floor(Number(fd.get('amount') || 0));
          const title = String(fd.get('title') || '').trim().slice(0, 200);
          const category = String(fd.get('category') || '').slice(0, 40);
          const wallet = String(fd.get('wallet') || '').slice(0, 40);
          const date = String(fd.get('date') || '');
          const time = String(fd.get('time') || '12:00').slice(0, 5);
          const note = String(fd.get('note') || '').slice(0, 500);
          if (type !== 'in' && type !== 'out') return jsonRes({ error: 'Jenis tidak valid.' }, 400);
          if (!amount || amount <= 0 || amount > 100000000000) return jsonRes({ error: 'Jumlah tidak valid.' }, 400);
          if (!title) return jsonRes({ error: 'Sumber/tujuan wajib diisi.' }, 400);
          if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return jsonRes({ error: 'Tanggal tidak valid.' }, 400);
          let photoKey = '';
          const photo = fd.get('photo');
          if (photo && typeof photo === 'object' && typeof photo.size === 'number' && photo.size > 0) {
            if (photo.size > 8 * 1024 * 1024) return jsonRes({ error: 'Foto terlalu besar.' }, 400);
            photoKey = 'tx/' + Date.now() + '-' + Math.random().toString(36).slice(2, 9) + '.jpg';
            await env.PHOTOS.put(photoKey, await photo.arrayBuffer(), { metadata: { ct: photo.type || 'image/jpeg' } });
          }
          const r = await env.DB.prepare('INSERT INTO transactions (type, amount, title, category, wallet, date, time, note, photo_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
            .bind(type, amount, title, category, wallet, date, time, note, photoKey, Date.now()).run();
          return jsonRes({ ok: true, id: r.meta.last_row_id });
        }

        const delMatch = path.match(/^\/api\/transactions\/(\d+)$/);
        if (delMatch && req.method === 'DELETE') {
          const id = parseInt(delMatch[1], 10);
          const row = await env.DB.prepare('SELECT photo_key FROM transactions WHERE id = ?').bind(id).first();
          if (!row) return jsonRes({ error: 'Tidak ditemukan.' }, 404);
          await env.DB.prepare('DELETE FROM transactions WHERE id = ?').bind(id).run();
          if (row.photo_key) { try { await env.PHOTOS.delete(row.photo_key); } catch (e) { /* abaikan */ } }
          return jsonRes({ ok: true });
        }

        if (path.startsWith('/api/photo/') && req.method === 'GET') {
          const key = decodeURIComponent(path.slice('/api/photo/'.length));
          if (!key.startsWith('tx/')) return jsonRes({ error: 'Tidak ditemukan.' }, 404);
          const obj = await env.PHOTOS.getWithMetadata(key, { type: 'arrayBuffer' });
          if (!obj || !obj.value) return jsonRes({ error: 'Tidak ditemukan.' }, 404);
          return new Response(obj.value, { headers: { 'Content-Type': (obj.metadata && obj.metadata.ct) || 'image/jpeg', 'Cache-Control': 'private, max-age=3600', 'X-Content-Type-Options': 'nosniff' } });
        }

        return jsonRes({ error: 'Tidak ditemukan.' }, 404);
      }

      if (path === '/' || path === '/detail-transaksi') {
        if (!hasPw) return htmlRes(loginPage('setup'));
        if (!authed) return htmlRes(loginPage('login'));
        return htmlRes(APP_HTML);
      }
      if (path === '/favicon.ico') return new Response('', { status: 204 });
      return new Response('Tidak ditemukan', { status: 404 });
    } catch (e) {
      return jsonRes({ error: 'Server error: ' + (e && e.message ? e.message : 'unknown') }, 500);
    }
  }
};
