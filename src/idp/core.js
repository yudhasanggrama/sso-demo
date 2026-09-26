'use strict';
// Fungsi bersama Pusat Akun: sesi browser, tampilan, penyelesaian login, logout antar-server.
// Sejak bermigrasi ke MySQL + Redis, hampir semua fungsi di sini jadi ASYNC karena harus menunggu
// baca/tulis ke database — pemanggilnya (routes-*.js) juga karena itu memakai async/await.
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

async function audit(req, userId, level, title, detail = '') {
  await store.addAudit({ userId, level, title, detail, ip: req?.ip, ua: req?.ua });
}

// Simpan balik akun/sesi browser yang barusan dimutasi di dalam handler — dipanggil sekali sebelum
// merespons, menggantikan "otomatis tersimpan" seperti dulu waktu semuanya masih objek di memori.
async function persist({ bs, user } = {}) {
  if (bs) await store.saveBS(bs);
  if (user) await store.saveUser(user);
}

// ---- Sesi browser ("penanda" akun) ----
async function loadBS(req) {
  const id = req.cookies[BS_COOKIE];
  if (!id) return null;
  const bs = await store.getBS(id);
  if (!bs) return null;
  bs.lastSeen = Date.now();
  bs.ua = req.ua;
  bs.ip = req.ip;
  // Akun yang sudah dikunci/dinonaktifkan tidak lagi dikenali.
  const kept = [];
  for (const a of bs.accounts) {
    const u = await store.getUser(a.userId);
    if (u?.status === 'active') kept.push(a);
  }
  bs.accounts = kept;
  if (!bs.accounts.some(a => a.userId === bs.activeUserId)) bs.activeUserId = bs.accounts[0]?.userId ?? null;
  return bs;
}

async function ensureBS(req, res) {
  let bs = await loadBS(req);
  if (!bs) {
    bs = { id: sec.randomToken(), createdAt: Date.now(), lastSeen: Date.now(), ua: req.ua, ip: req.ip, accounts: [], activeUserId: null, pending: null };
    await store.saveBS(bs);
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
const activeUser = async bs => (activeAccount(bs) ? store.getUser(bs.activeUserId) : null);

// Header Bersama dipakai lintas origin (Portal dan tiap layanan): validasi "kembali ke sini setelah ganti akun"
// hanya boleh menuju Portal sendiri atau salah satu layanan terdaftar — mencegah open redirect.
function safeExternalReturn(url) {
  if (typeof url !== 'string' || !url) return null;
  try {
    const u = new URL(url);
    const known = [ISSUER, ...cfg.services.map(s => s.url)];
    return known.includes(u.origin) ? url : null;
  } catch { return null; }
}

// Status proses yang sedang berjalan (login, daftar 2FA, verifikasi ulang).
async function pendingCtx(req, stages) {
  const bs = await loadBS(req);
  const p = bs?.pending;
  if (!p || !stages.includes(p.stage)) return null;
  const user = await store.getUser(p.userId);
  const stillSignedIn = p.purpose === 'login' || bs.accounts.some(a => a.userId === p.userId);
  if (!user || user.status !== 'active' || !stillSignedIn) { bs.pending = null; await store.saveBS(bs); return null; }
  return { bs, p, user };
}

// ---- Tampilan Portal ----
const BRAND = { name: 'Pusat Akun', logo: 'P', color: '#4f46e5', home: '/' };

// Alur 3a: layanan yang jadi hak akun ini — dipakai untuk grid 3x3 di header maupun untuk isi Halaman Utama.
const visibleServices = user => cfg.services.filter(s => !s.requiredRole || user.roles.includes(s.requiredRole))
  .map(s => ({ id: s.id, name: s.name, icon: s.icon, color: s.color, url: s.url }));

async function accountMenu(bs, user) {
  const others = [];
  for (const a of bs.accounts) {
    if (a.userId === user.id) continue;
    const u = await store.getUser(a.userId);
    if (u) others.push({ id: u.id, name: u.name, email: u.email });
  }
  return ui.avatarMenu({ user, others, switchAction: '/switch', addHref: '/login?add=1', manageHref: '/account', logoutHref: '/logout' });
}

// Alur 3a · Header Bersama: grid 3x3 + avatar, posisi dan markup sama di setiap halaman Portal.
async function sharedHeaderRight(bs, user) {
  return ui.appLauncher(visibleServices(user), ISSUER) + await accountMenu(bs, user);
}

async function view(bs, { title, flow, body, narrow = false, hideMenu = false }) {
  const user = bs && !hideMenu ? await activeUser(bs) : null;
  const right = user ? await sharedHeaderRight(bs, user) : '';
  return ui.page({ title, brand: BRAND, flow, body, right, narrow });
}

async function errorPage(res, bs, title, message, status = 400) {
  res.html(await view(bs, { title, narrow: true, body: `<div class="card"><h1>${esc(title)}</h1>${ui.alert('error', esc(message))}<a class="btn secondary" href="/">Ke Halaman Utama</a></div>` }), status);
}

// Alur 4: "Layanan yang terbuka disesuaikan agar akun tidak tertukar" —
// sesi layanan milik akun selain akun aktif di browser ini ditutup; saat dibuka lagi, layanan masuk dengan akun aktif.
async function alignServiceSessions(bs) {
  const all = await store.serviceSessionsByBs(bs.id);
  const others = all.filter(s => s.userId !== bs.activeUserId);
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
  await audit(req, user.id, 'info', 'Berhasil masuk', `${device} · ${location} · ${amr.map(m => METHOD_LABEL[m] || m).join(' + ')}`);
  await persist({ bs, user });
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
    await store.addFailedLogout(item);
    await store.addAudit({ userId: target.userId, level: 'warn', title: `Gagal menutup sesi di layanan ${client.name}`, detail: `${lastError}; dicatat untuk ditindaklanjuti (#${item.id})` });
    result.followUpId = item.id;
  }
  return result;
}

async function revokeTokens(predicate) {
  return store.revokeTokens(predicate);
}

// Tutup sesi di layanan-layanan untuk sejumlah akun (sesi), lalu batalkan kunci akses.
async function endServiceSessions(targets) {
  const results = await Promise.all(targets.map(t => backchannelLogout(t)));
  await store.removeServiceSessions(targets);
  const key = t => `${t.sid}|${t.clientId}`;
  const ended = new Set(targets.map(key));
  const revoked = await revokeTokens(t => ended.has(key(t)));
  return { results, revoked };
}

async function logoutAccounts(req, accounts, label) {
  const sids = new Set(accounts.map(a => a.sid));
  // "Ambil daftar layanan yang sedang terbuka"
  const open = await store.serviceSessionsBySids(sids);
  const { results } = await endServiceSessions(open);
  // "Batalkan semua kunci akses yang pernah diberikan"
  const revoked = await revokeTokens(t => sids.has(t.sid));
  // "Catat kejadian keluar di riwayat keamanan"
  for (const a of accounts) {
    const mine = results.filter(r => open.some(o => o.sid === a.sid && o.clientId === r.clientId));
    const summary = mine.length ? mine.map(r => `${r.name}: ${r.ok ? 'tertutup' : 'GAGAL'}`).join(', ') : 'tidak ada layanan terbuka';
    await audit(req, a.userId, mine.some(r => !r.ok) ? 'warn' : 'info', label, summary);
  }
  return { results, revoked };
}

module.exports = {
  ISSUER, BS_COOKIE, DEV_COOKIE, KID, jwks, signToken, METHOD_LABEL, SCOPE_LABEL,
  deviceLabel, locationOf, hasTwoFa, audit, loadBS, ensureBS, deviceId, activeAccount, activeUser,
  pendingCtx, view, errorPage, completeLogin, backchannelLogout, endServiceSessions, logoutAccounts, revokeTokens, alignServiceSessions,
  visibleServices, safeExternalReturn, persist,
};
