'use strict';
// Lapisan akses data Pusat Akun — pengganti Map di memori sebelumnya.
//  · MySQL (db_sso_demo): data yang TETAP — akun pengguna (incl. metode 2FA, perangkat tepercaya,
//    consents sebagai kolom JSON), riwayat keamanan (audit_log), logout gagal, dan admin.
//  · Redis: data SESI/SEMENTARA — penanda sesi browser (termasuk status login yang sedang
//    berjalan), tiket sekali pakai, kunci akses, sesi tiap layanan, token pemulihan, counter
//    gagal 2FA beserta kunci sementaranya (TTL bawaan, wajar kedaluwarsa sendiri), dan kode
//    cadangan contoh untuk Panel Demo, serta kotak keluar email simulasi (tautan pemulihan akun).
//  · Memori proses (bukan Redis/MySQL): password demo dalam teks polos (demoPasswords di bawah) —
//    cuma petunjuk tampilan, bukan data yang perlu dibagi antar proses atau bertahan lewat restart.
const sec = require('../lib/security');
const cfg = require('../config');
const db = require('../db/mysql');
const redis = require('../db/redis');

async function init() {
  await db.migrate();
  await redis.connect();
}

// ============================== Pengguna (MySQL) ==============================

function rowToUser(row) {
  if (!row) return null;
  const j = v => (v == null ? v : typeof v === 'string' ? JSON.parse(v) : v); // mysql2 kadang sudah mem-parse JSON, kadang tidak
  return {
    id: row.id, username: row.username, email: row.email, name: row.name, passwordHash: row.password_hash,
    status: row.status, org: j(row.org), roles: j(row.roles), failedLogins: row.failed_logins,
    twoFa: j(row.two_fa), twoFaDeferredAt: Number(row.two_fa_deferred_at),
    trustedDevices: j(row.trusted_devices) || [], consents: j(row.consents) || {},
    lastLogin: j(row.last_login), previousLogin: j(row.previous_login), createdAt: Number(row.created_at),
  };
}

// Counter gagal 2FA dan kunci sementaranya (Alur 2) sengaja di Redis, BUKAN kolom MySQL — sifatnya
// sementara dan wajar kedaluwarsa sendiri (TTL), beda dari data akun yang harus tetap ada.
const twoFaFailKey = userId => `sso:2fa-fail:${userId}`;
const twoFaLockKey = userId => `sso:2fa-lock:${userId}`;

async function get2faFailures(userId) {
  const v = await redis.client.get(twoFaFailKey(userId));
  return v ? Number(v) : 0;
}
async function get2faLockedUntil(userId) {
  const ttl = await redis.client.pTTL(twoFaLockKey(userId)); // ms tersisa; -2 = tidak ada kunci, -1 = tidak ada TTL
  return ttl > 0 ? Date.now() + ttl : 0;
}
// Dipanggil dari saveUser() — menyamakan isi Redis dengan field di objek user (0/lewat = hapus kuncinya).
async function syncTwoFaCounters(u) {
  if (u.twoFaFailures) await redis.client.set(twoFaFailKey(u.id), u.twoFaFailures);
  else await redis.client.del(twoFaFailKey(u.id));
  const remaining = (u.twoFaLockedUntil || 0) - Date.now();
  if (remaining > 0) await redis.client.set(twoFaLockKey(u.id), '1', { PX: remaining });
  else await redis.client.del(twoFaLockKey(u.id));
}
async function hydrateTwoFaCounters(user) {
  if (!user) return user;
  const [failures, lockedUntil] = await Promise.all([get2faFailures(user.id), get2faLockedUntil(user.id)]);
  user.twoFaFailures = failures;
  user.twoFaLockedUntil = lockedUntil;
  return user;
}

async function getUser(id) {
  if (!id) return null;
  const [rows] = await db.pool.query('SELECT * FROM users WHERE id=? LIMIT 1', [id]);
  return hydrateTwoFaCounters(rowToUser(rows[0]));
}

async function findUser(login) {
  const l = String(login || '').trim().toLowerCase();
  if (!l) return null;
  const [rows] = await db.pool.query('SELECT * FROM users WHERE email=? OR username=? LIMIT 1', [l, l]);
  return hydrateTwoFaCounters(rowToUser(rows[0]));
}

async function hasUser(id) {
  const [rows] = await db.pool.query('SELECT 1 FROM users WHERE id=? LIMIT 1', [id]);
  return rows.length > 0;
}

async function listUsers() {
  const [rows] = await db.pool.query('SELECT * FROM users ORDER BY created_at');
  return Promise.all(rows.map(r => hydrateTwoFaCounters(rowToUser(r))));
}

async function saveUser(u) {
  await db.pool.query(
    `INSERT INTO users (id, username, email, name, password_hash, status, org, roles, failed_logins,
       two_fa, two_fa_deferred_at, trusted_devices, consents,
       last_login, previous_login, created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
     ON DUPLICATE KEY UPDATE
       username=VALUES(username), email=VALUES(email), name=VALUES(name), password_hash=VALUES(password_hash),
       status=VALUES(status), org=VALUES(org), roles=VALUES(roles), failed_logins=VALUES(failed_logins),
       two_fa=VALUES(two_fa), two_fa_deferred_at=VALUES(two_fa_deferred_at),
       trusted_devices=VALUES(trusted_devices), consents=VALUES(consents),
       last_login=VALUES(last_login), previous_login=VALUES(previous_login)`,
    [u.id, u.username, u.email.toLowerCase(), u.name, u.passwordHash, u.status,
      JSON.stringify(u.org), JSON.stringify(u.roles), u.failedLogins || 0,
      u.twoFa ? JSON.stringify(u.twoFa) : null, u.twoFaDeferredAt || 0,
      JSON.stringify(u.trustedDevices || []), JSON.stringify(u.consents || {}),
      u.lastLogin ? JSON.stringify(u.lastLogin) : null, u.previousLogin ? JSON.stringify(u.previousLogin) : null,
      u.createdAt || Date.now()],
  );
  await syncTwoFaCounters(u);
}

// Dipakai panel admin. Memutuskan sesi/kunci akses yang sedang berjalan (agar efeknya langsung terasa,
// bukan menunggu token lama kedaluwarsa sendiri) adalah tanggung jawab core.forceLogoutUser() — dipanggil
// pemanggil SEBELUM ini, karena butuh memberi tahu tiap layanan lewat backchannel logout (logika di core.js).
async function deleteUser(id) {
  await db.pool.query('DELETE FROM users WHERE id=?', [id]);
  await redis.client.del([twoFaFailKey(id), twoFaLockKey(id)]);
}

// ============================== Riwayat keamanan (MySQL) ==============================

async function addAudit({ userId = null, level = 'info', title, detail = '', ip = '', ua = '' }) {
  const id = sec.randomToken(6);
  const at = Date.now();
  await db.pool.query('INSERT INTO audit_log (id, at, user_id, level, title, detail, ip, ua) VALUES (?,?,?,?,?,?,?,?)',
    [id, at, userId, level, title, detail, ip, ua]);
  const who = userId ? (await getUser(userId))?.email || userId : '-';
  console.log(`[riwayat] ${level.toUpperCase().padEnd(8)} ${who.padEnd(16)} ${title}${detail ? ` — ${detail}` : ''}`);
}

function rowToAudit(r) { return { id: r.id, at: Number(r.at), userId: r.user_id, level: r.level, title: r.title, detail: r.detail, ip: r.ip, ua: r.ua }; }

async function auditFor(userId, limit = 25) {
  const [rows] = await db.pool.query('SELECT * FROM audit_log WHERE user_id=? ORDER BY at DESC LIMIT ?', [userId, limit]);
  return rows.map(rowToAudit);
}

async function auditRecent(limit = 60) {
  const [rows] = await db.pool.query('SELECT * FROM audit_log ORDER BY at DESC LIMIT ?', [limit]);
  return rows.map(rowToAudit);
}

// ============================== Logout gagal (MySQL) ==============================

async function addFailedLogout(item) {
  await db.pool.query('INSERT INTO failed_logouts (id, at, client_id, sid, user_id, attempts, last_error, resolved) VALUES (?,?,?,?,?,?,?,0)',
    [item.id, item.at, item.clientId, item.sid, item.userId, item.attempts, item.lastError]);
}
function rowToFailedLogout(r) { return { id: r.id, at: Number(r.at), clientId: r.client_id, sid: r.sid, userId: r.user_id, attempts: r.attempts, lastError: r.last_error, resolved: !!r.resolved }; }
async function getFailedLogout(id) {
  const [rows] = await db.pool.query('SELECT * FROM failed_logouts WHERE id=?', [id]);
  return rows[0] ? rowToFailedLogout(rows[0]) : null;
}
async function updateFailedLogout(id, patch) {
  await db.pool.query('UPDATE failed_logouts SET attempts=?, last_error=?, resolved=? WHERE id=?',
    [patch.attempts, patch.lastError || '', patch.resolved ? 1 : 0, id]);
}
async function listFailedLogouts() {
  const [rows] = await db.pool.query('SELECT * FROM failed_logouts ORDER BY at DESC');
  return rows.map(rowToFailedLogout);
}

// ============================== Admin (MySQL) ==============================

async function getAdmin(username) {
  const [rows] = await db.pool.query('SELECT * FROM admins WHERE username=?', [String(username || '').trim().toLowerCase()]);
  return rows[0] || null;
}

// ============================== Sesi browser — "penanda akun" (Redis) ==============================

const BS_TTL_SEC = () => cfg.policy.browserSessionDays * 86400;
const bsKey = id => `sso:bs:${id}`;
const sid2bsKey = sid => `sso:sid2bs:${sid}`;

async function getBS(id) {
  if (!id) return null;
  return redis.getJSON(bsKey(id));
}

async function saveBS(bs) {
  await redis.setJSON(bsKey(bs.id), bs, BS_TTL_SEC());
  await Promise.all(bs.accounts.map(a => redis.client.set(sid2bsKey(a.sid), bs.id, { EX: BS_TTL_SEC() })));
}

async function deleteBS(id) {
  const bs = await getBS(id);
  if (bs) await Promise.all(bs.accounts.map(a => redis.client.del(sid2bsKey(a.sid))));
  await redis.client.del(bsKey(id));
}

// Dipakai endpoint server-ke-server (/internal/*): layanan hanya tahu sid, bukan cookie pa_bs.
async function findBSBySid(sid) {
  const id = await redis.client.get(sid2bsKey(sid));
  return id ? getBS(id) : null;
}

async function allBrowserSessions() {
  const keys = await redis.client.keys(`${bsKey('*')}`);
  if (!keys.length) return [];
  const vals = await redis.client.mGet(keys);
  return vals.filter(Boolean).map(v => JSON.parse(v));
}

// ============================== Sesi tiap layanan (Redis) ==============================
// Satu hash per (sid, clientId) + dua set indeks (per-sid dan per-bs) supaya bisa dicari dari dua arah,
// karena Redis sendiri tidak punya query sekunder seperti find()/filter() di objek biasa.

const svcSessKey = (sid, clientId) => `sso:svcsess:${sid}:${clientId}`;
const svcBySidKey = sid => `sso:svcsess:by-sid:${sid}`;
const svcByBsKey = bsId => `sso:svcsess:by-bs:${bsId}`;
const svcByUserKey = userId => `sso:svcsess:by-user:${userId}`;

async function addServiceSession(s) {
  await redis.setJSON(svcSessKey(s.sid, s.clientId), s);
  await Promise.all([
    redis.client.sAdd(svcBySidKey(s.sid), s.clientId),
    redis.client.sAdd(svcByBsKey(s.bsId), `${s.sid}|${s.clientId}`),
    redis.client.sAdd(svcByUserKey(s.userId), `${s.sid}|${s.clientId}`),
  ]);
}

async function removeServiceSessions(list) {
  for (const s of list) {
    await Promise.all([
      redis.client.del(svcSessKey(s.sid, s.clientId)),
      redis.client.sRem(svcBySidKey(s.sid), s.clientId),
      s.bsId ? redis.client.sRem(svcByBsKey(s.bsId), `${s.sid}|${s.clientId}`) : null,
      s.userId ? redis.client.sRem(svcByUserKey(s.userId), `${s.sid}|${s.clientId}`) : null,
    ].filter(Boolean));
  }
}

async function serviceSessionsBySid(sid) {
  const clientIds = await redis.client.sMembers(svcBySidKey(sid));
  const vals = await Promise.all(clientIds.map(cid => redis.getJSON(svcSessKey(sid, cid))));
  return vals.filter(Boolean);
}

async function serviceSessionsBySids(sids) {
  const arrays = await Promise.all([...sids].map(serviceSessionsBySid));
  return arrays.flat();
}

async function serviceSessionsByBs(bsId) {
  const members = await redis.client.sMembers(svcByBsKey(bsId));
  const vals = await Promise.all(members.map(m => { const [sid, clientId] = m.split('|'); return redis.getJSON(svcSessKey(sid, clientId)); }));
  return vals.filter(Boolean);
}

async function serviceSessionsByUser(userId) {
  const members = await redis.client.sMembers(svcByUserKey(userId));
  const vals = await Promise.all(members.map(m => { const [sid, clientId] = m.split('|'); return redis.getJSON(svcSessKey(sid, clientId)); }));
  return vals.filter(Boolean);
}

// ============================== Tiket sekali pakai & kunci akses (Redis) ==============================

const authCodeKey = c => `sso:authcode:${c}`;
async function setAuthCode(code, rec) { await redis.setJSON(authCodeKey(code), rec, Math.ceil(cfg.policy.authCodeTtlMs / 1000)); }
async function getAuthCode(code) { return redis.getJSON(authCodeKey(code)); }
// Menyetel ulang isi tiket (mis. menandai "used") — TTL dihitung ulang dari rec.expiresAt yang sudah
// tersimpan di datanya sendiri (bukan KEEPTTL, supaya kompatibel dengan Redis versi lama juga).
async function updateAuthCode(code, rec) {
  const ttl = Math.max(1, Math.ceil((rec.expiresAt - Date.now()) / 1000));
  await redis.setJSON(authCodeKey(code), rec, ttl);
}
async function deleteAuthCode(code) { await redis.client.del(authCodeKey(code)); }

const tokenKey = t => `sso:token:${t}`;
async function setAccessToken(token, rec) { await redis.setJSON(tokenKey(token), rec, cfg.policy.accessTokenTtlSec); }
async function getAccessToken(token) {
  const t = await redis.getJSON(tokenKey(token));
  return t; // tidak ada lagi di Redis = otomatis dianggap tidak aktif (TTL sudah menghapusnya, atau sudah dicabut)
}

// "Cabut kunci akses dan tiket yang memenuhi kriteria" — dipindai (SCAN via KEYS, wajar untuk skala demo)
// karena Redis sendiri tidak mendukung query sembarang predikat seperti Array.prototype.filter.
async function revokeTokens(predicate) {
  let n = 0;
  const tokenKeys = await redis.client.keys('sso:token:*');
  if (tokenKeys.length) {
    const vals = await redis.client.mGet(tokenKeys);
    for (let i = 0; i < tokenKeys.length; i++) {
      if (!vals[i]) continue;
      if (predicate(JSON.parse(vals[i]))) { await redis.client.del(tokenKeys[i]); n++; }
    }
  }
  const codeKeys = await redis.client.keys('sso:authcode:*');
  if (codeKeys.length) {
    const vals = await redis.client.mGet(codeKeys);
    for (let i = 0; i < codeKeys.length; i++) {
      if (!vals[i]) continue;
      if (predicate(JSON.parse(vals[i]))) await redis.client.del(codeKeys[i]);
    }
  }
  return n;
}

// ============================== Pemulihan akun (Redis, TTL 15 menit) ==============================

const recoveryKey = h => `sso:recovery:${h}`;
async function setRecoveryToken(hash, rec) { await redis.setJSON(recoveryKey(hash), rec, 15 * 60); }
async function getRecoveryToken(hash) { return redis.getJSON(recoveryKey(hash)); }
async function deleteRecoveryToken(hash) { await redis.client.del(recoveryKey(hash)); }

// ============================== Bantuan demo (Redis) ==============================

async function sendMessage(channel, to, text) {
  await redis.client.lPush('sso:outbox', JSON.stringify({ at: Date.now(), channel, to, text }));
  await redis.client.lTrim('sso:outbox', 0, 99);
}
async function outboxRecent(limit = 15) {
  const items = await redis.client.lRange('sso:outbox', 0, limit - 1);
  return items.map(x => JSON.parse(x));
}

// Password demo (teks polos, cuma untuk ditampilkan sebagai petunjuk di UI) sengaja TIDAK di Redis dan
// tidak bergantung pada proses seed — dihardcode langsung di sini, supaya tetap benar walau server
// direstart tanpa menjalankan ulang seed (tabel users sudah terisi dari sebelumnya, ensureSeed dilewati).
// Kalau password sungguhan diganti (lewat "Ganti password" atau pemulihan akun), map ini diperbarui juga
// supaya hint tetap sesuai SELAMA proses ini berjalan; setelah restart lagi, hint kembali ke nilai awal.
const demoPasswords = new Map([
  ['u-budi', 'budi12345'],
  ['u-sari', 'sari12345'],
  ['u-andi', 'andi12345'],
  ['u-rina', 'rina12345'],
]);
async function demoSetPassword(userId, pw) { demoPasswords.set(userId, pw); }
async function demoGetPassword(userId) { return demoPasswords.get(userId) ?? null; }

async function demoSetBackupCodes(userId, codes) { await redis.setJSON(`sso:demo:backup:${userId}`, codes); }
async function demoGetBackupCodes(userId) { return redis.getJSON(`sso:demo:backup:${userId}`); }
async function demoDeleteBackupCodes(userId) { await redis.client.del(`sso:demo:backup:${userId}`); }

// HANYA untuk skrip tes/reset demo — mengosongkan semua tabel MySQL dan cache Redis, supaya keadaan
// awal deterministik. Tidak dipanggil dari mana pun di aplikasi sungguhan (tidak ada tombol untuk ini).
async function resetAllForTests() {
  for (const t of ['users', 'audit_log', 'failed_logouts', 'admins']) await db.pool.query(`TRUNCATE TABLE ${t}`);
  await redis.client.flushDb();
  demoPasswords.clear();
}

module.exports = {
  init, resetAllForTests,
  getUser, findUser, hasUser, listUsers, saveUser, deleteUser,
  addAudit, auditFor, auditRecent,
  addFailedLogout, getFailedLogout, updateFailedLogout, listFailedLogouts,
  getAdmin,
  getBS, saveBS, deleteBS, findBSBySid, allBrowserSessions,
  addServiceSession, removeServiceSessions, serviceSessionsBySid, serviceSessionsBySids, serviceSessionsByBs, serviceSessionsByUser,
  setAuthCode, getAuthCode, updateAuthCode, deleteAuthCode,
  setAccessToken, getAccessToken, revokeTokens,
  setRecoveryToken, getRecoveryToken, deleteRecoveryToken,
  sendMessage, outboxRecent,
  demoSetPassword, demoGetPassword, demoSetBackupCodes, demoGetBackupCodes, demoDeleteBackupCodes,
};
