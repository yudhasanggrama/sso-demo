'use strict';
// Fungsi bersama Pusat Akun: sesi browser, tampilan, penyelesaian login, logout antar-server.
const crypto = require('crypto');
const cfg = require('../config');
const jwt = require('../lib/jwt');
const sec = require('../lib/security');
const ui = require('../lib/ui');
const store = require('./store');

const { esc } = ui;
const ISSUER = cfg.PORTAL;
const BS_COOKIE = 'pa_bs';
const DEV_COOKIE = 'pa_dev';

// ---- Kunci penanda tangan token ----
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const KID = `pa-${sec.randomToken(6)}`;
const jwks = { keys: [{ ...publicKey.export({ format: 'jwk' }), kid: KID, use: 'sig', alg: 'RS256' }] };
const signToken = (payload, typ) => jwt.sign(payload, privateKey, KID, typ);

// ---- Label ----
const METHOD_LABEL = {
  pwd: 'Password',
  totp: 'Aplikasi kode',
  sms: 'SMS',
  passkey: 'Sidik jari / wajah',
  backup: 'Kode cadangan',
  trusted_device: 'Perangkat tepercaya',
};
const SCOPE_LABEL = {
  openid: 'ID pengguna Anda (wajib untuk masuk)',
  profile: 'Nama dan nama pengguna',
  email: 'Alamat email',
  keuangan: 'Peran Anda (untuk akses data keuangan)',
};

function deviceLabel(ua = '') {
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Chrome\//.test(ua) ? 'Chrome'
    : /Firefox\//.test(ua) ? 'Firefox' : /Safari\//.test(ua) ? 'Safari' : /node|undici/i.test(ua) ? 'Skrip Node.js' : 'Peramban';
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS'
    : /Mac OS/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'OS tidak dikenal';
  return `${browser} di ${os}`;
}
const locationOf = ip => (/^(::1|127\.|::ffff:127\.)/.test(ip || '') ? 'Lokal (komputer ini)' : ip || 'Tidak diketahui');

const hasTwoFa = user => !!user.twoFa && Object.keys(user.twoFa.methods).length > 0;
const sleep = ms => new Promise(r => setTimeout(r, ms));

function audit(req, userId, level, title, detail = '') {
  store.addAudit({ userId, level, title, detail, ip: req?.ip, ua: req?.ua });
}

// ---- Sesi browser ("penanda" akun) ----
function loadBS(req) {
  const bs = store.browserSessions.get(req.cookies[BS_COOKIE]);
  if (!bs) return null;
  bs.lastSeen = Date.now();
  bs.ua = req.ua;
  bs.ip = req.ip;
  // Akun yang sudah dikunci/dinonaktifkan tidak lagi dikenali.
  bs.accounts = bs.accounts.filter(a => store.users.get(a.userId)?.status === 'active');
  if (!bs.accounts.some(a => a.userId === bs.activeUserId)) bs.activeUserId = bs.accounts[0]?.userId ?? null;
  return bs;
}

function ensureBS(req, res) {
  let bs = loadBS(req);
  if (!bs) {
    bs = { id: sec.randomToken(), createdAt: Date.now(), lastSeen: Date.now(), ua: req.ua, ip: req.ip, accounts: [], activeUserId: null, pending: null };
    store.browserSessions.set(bs.id, bs);
    res.cookie(BS_COOKIE, bs.id, { maxAge: cfg.policy.browserSessionDays * 86400 });
  }
  return bs;
}

function deviceId(req, res) {
  let id = req.cookies[DEV_COOKIE];
  if (!id) {
    id = sec.randomToken();
    res.cookie(DEV_COOKIE, id, { maxAge: 365 * 86400 });
  }
  return id;
}

const activeAccount = bs => bs?.accounts.find(a => a.userId === bs.activeUserId) || null;
const activeUser = bs => (activeAccount(bs) ? store.users.get(bs.activeUserId) : null);

// Status proses yang sedang berjalan (login, daftar 2FA, verifikasi ulang).
function pendingCtx(req, stages) {
  const bs = loadBS(req);
  const p = bs?.pending;
  if (!p || !stages.includes(p.stage)) return null;
  const user = store.users.get(p.userId);
  const stillSignedIn = p.purpose === 'login' || bs.accounts.some(a => a.userId === p.userId);
  if (!user || user.status !== 'active' || !stillSignedIn) { bs.pending = null; return null; }
  return { bs, p, user };
}

// ---- Tampilan Portal ----
const BRAND = { name: 'Pusat Akun', logo: 'P', color: '#4f46e5', home: '/' };

function accountMenu(bs, user) {
  const others = bs.accounts.filter(a => a.userId !== user.id).map(a => store.users.get(a.userId)).filter(Boolean);
  const switchItems = others.length
    ? others.map(o => `<form method="post" action="/switch"><input type="hidden" name="userId" value="${esc(o.id)}">
        <button class="menu-item">${ui.avatar(o, 28)}<span>${esc(o.name)}<br><span class="muted small">${esc(o.email)}</span></span></button></form>`).join('')
    : '<div class="menu-item muted small">Belum ada akun lain di browser ini</div>';
  return `<details class="menu"><summary title="Menu akun">${ui.avatar(user)}</summary><div class="menu-panel">
    <div class="menu-head">${ui.avatar(user, 44)}<div><strong>${esc(user.name)}</strong><div class="muted small">${esc(user.email)}</div></div></div>
    <div style="padding:0 10px"><span class="flow" style="margin:0">Alur 4 · Menu apa yang dipilih?</span></div>
    <hr>
    <a class="menu-item" href="/login?add=1">➕ Tambah akun</a>
    <div class="menu-label">Ganti akun</div>${switchItems}
    <hr>
    <a class="menu-item" href="/account">⚙️ Kelola akun</a>
    <a class="menu-item" href="/logout">🚪 Keluar</a>
  </div></details>`;
}

function view(bs, { title, flow, body, narrow = false, hideMenu = false }) {
  const user = activeUser(bs);
  const right = user && !hideMenu ? accountMenu(bs, user) : '';
  return ui.page({ title, brand: BRAND, flow, body, right, narrow });
}

function errorPage(res, bs, title, message, status = 400) {
  res.html(view(bs, { title, narrow: true, body: `<div class="card"><h1>${esc(title)}</h1>${ui.alert('error', esc(message))}<a class="btn secondary" href="/">Ke Halaman Utama</a></div>` }), status);
}

// Alur 4: "Layanan yang terbuka disesuaikan agar akun tidak tertukar" —
// sesi layanan milik akun selain akun aktif di browser ini ditutup; saat dibuka lagi, layanan masuk dengan akun aktif.
async function alignServiceSessions(bs) {
  const others = store.serviceSessions.filter(s => s.bsId === bs.id && s.userId !== bs.activeUserId);
  if (others.length) await endServiceSessions(others);
  return others.length;
}

// ---- Alur 2 (akhir): "Pengguna resmi dikenali, catat waktu, perangkat, dan lokasi" → B ----
async function completeLogin(req, res, bs, user, { amr, mfa }) {
  const now = Date.now();
  const returnTo = bs.pending?.returnTo;
  let acct = bs.accounts.find(a => a.userId === user.id);
  if (!acct) {
    acct = { userId: user.id, sid: sec.randomToken(16) };
    bs.accounts.push(acct);
  }
  Object.assign(acct, { authTime: now, mfaTime: mfa ? now : null, amr });
  bs.activeUserId = user.id;
  bs.pending = null;

  const device = deviceLabel(req.ua);
  const location = locationOf(req.ip);
  user.previousLogin = user.lastLogin;
  user.lastLogin = { at: now, device, location, ip: req.ip };
  audit(req, user.id, 'info', 'Berhasil masuk', `${device} · ${location} · ${amr.map(m => METHOD_LABEL[m] || m).join(' + ')}`);
  await alignServiceSessions(bs);
  return res.redirect(returnTo || '/');
}

// ---- Alur 5: kirim perintah keluar langsung antar server, dengan percobaan ulang ----
async function backchannelLogout(target, { recordFailure = true } = {}) {
  const client = cfg.clients[target.clientId];
  const maxAttempts = 1 + cfg.policy.logoutRetries;
  let lastError = '';
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const now = Math.floor(Date.now() / 1000);
    const logoutToken = signToken({
      iss: ISSUER, aud: client.id, iat: now, exp: now + 120, jti: sec.randomToken(12),
      sub: target.userId, sid: target.sid, events: { [cfg.BACKCHANNEL_LOGOUT_EVENT]: {} },
    }, 'logout+jwt');
    try {
      const r = await fetch(client.backchannelLogoutUri, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ logout_token: logoutToken }),
        signal: AbortSignal.timeout(cfg.policy.logoutTimeoutMs),
      });
      if (r.ok) return { clientId: client.id, name: client.name, ok: true, attempts: attempt };
      lastError = `Layanan menjawab HTTP ${r.status}`;
    } catch (err) {
      lastError = err.name === 'TimeoutError' ? 'Tidak ada jawaban (timeout)' : 'Layanan tidak dapat dihubungi';
    }
    if (attempt < maxAttempts) await sleep(cfg.policy.logoutBaseDelayMs * 2 ** (attempt - 1));
  }
  const result = { clientId: client.id, name: client.name, ok: false, attempts: maxAttempts, error: lastError };
  if (recordFailure) {
    const item = { id: sec.randomToken(6), at: Date.now(), clientId: client.id, sid: target.sid, userId: target.userId, attempts: maxAttempts, lastError, resolved: false };
    store.failedLogouts.unshift(item);
    store.addAudit({ userId: target.userId, level: 'warn', title: `Gagal menutup sesi di layanan ${client.name}`, detail: `${lastError}; dicatat untuk ditindaklanjuti (#${item.id})` });
    result.followUpId = item.id;
  }
  return result;
}

function revokeTokens(predicate) {
  let n = 0;
  for (const t of store.accessTokens.values()) if (!t.revoked && predicate(t)) { t.revoked = true; n++; }
  for (const [code, c] of store.authCodes) if (predicate(c)) store.authCodes.delete(code);
  return n;
}

// Tutup sesi di layanan-layanan untuk sejumlah akun (sesi), lalu batalkan kunci akses.
async function endServiceSessions(targets) {
  const results = await Promise.all(targets.map(t => backchannelLogout(t)));
  const key = t => `${t.sid}|${t.clientId}`;
  const ended = new Set(targets.map(key));
  store.serviceSessions = store.serviceSessions.filter(s => !ended.has(key(s)));
  const revoked = revokeTokens(t => ended.has(key(t)));
  return { results, revoked };
}

async function logoutAccounts(req, accounts, label) {
  const sids = new Set(accounts.map(a => a.sid));
  // "Ambil daftar layanan yang sedang terbuka"
  const open = store.serviceSessions.filter(s => sids.has(s.sid));
  const { results } = await endServiceSessions(open);
  // "Batalkan semua kunci akses yang pernah diberikan"
  const revoked = revokeTokens(t => sids.has(t.sid));
  // "Catat kejadian keluar di riwayat keamanan"
  for (const a of accounts) {
    const mine = results.filter(r => open.some(o => o.sid === a.sid && o.clientId === r.clientId));
    const summary = mine.length ? mine.map(r => `${r.name}: ${r.ok ? 'tertutup' : 'GAGAL'}`).join(', ') : 'tidak ada layanan terbuka';
    audit(req, a.userId, mine.some(r => !r.ok) ? 'warn' : 'info', label, summary);
  }
  return { results, revoked };
}

module.exports = {
  ISSUER, BS_COOKIE, DEV_COOKIE, KID, jwks, signToken, METHOD_LABEL, SCOPE_LABEL,
  deviceLabel, locationOf, hasTwoFa, audit, loadBS, ensureBS, deviceId, activeAccount, activeUser,
  pendingCtx, view, errorPage, completeLogin, backchannelLogout, endServiceSessions, logoutAccounts, revokeTokens, alignServiceSessions,
};
