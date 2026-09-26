'use strict';
// Penyimpanan di memori. Semua data hilang saat server dimatikan (cukup untuk demo).
const sec = require('../lib/security');

const store = {
  users: new Map(),
  browserSessions: new Map(),   // "penanda" akun di browser (cookie pa_bs)
  authCodes: new Map(),         // tiket sekali pakai
  accessTokens: new Map(),      // kunci akses
  serviceSessions: [],          // layanan yang sedang terbuka per sesi akun
  failedLogouts: [],            // logout gagal yang dicatat untuk ditindaklanjuti
  audit: [],                    // riwayat keamanan
  outbox: [],                   // SMS & email simulasi
  recoveryTokens: new Map(),
  demo: { passwords: {}, backupCodes: {} },
};

store.findUser = login => {
  const l = String(login || '').trim().toLowerCase();
  if (!l) return null;
  for (const u of store.users.values()) if (u.email === l || u.username === l) return u;
  return null;
};

store.addAudit = ({ userId = null, level = 'info', title, detail = '', ip = '', ua = '' }) => {
  store.audit.unshift({ id: sec.randomToken(6), at: Date.now(), userId, level, title, detail, ip, ua });
  if (store.audit.length > 500) store.audit.pop();
  const who = userId ? store.users.get(userId)?.email || userId : '-';
  console.log(`[riwayat] ${level.toUpperCase().padEnd(8)} ${who.padEnd(16)} ${title}${detail ? ` — ${detail}` : ''}`);
};

store.sendMessage = (channel, to, text) => {
  store.outbox.unshift({ at: Date.now(), channel, to, text });
  if (store.outbox.length > 100) store.outbox.pop();
};

function addUser({ password, ...u }) {
  store.users.set(u.id, {
    status: 'active',
    roles: [],
    failedLogins: 0,
    twoFa: null,
    twoFaFailures: 0,
    twoFaLockedUntil: 0,
    twoFaDeferredAt: 0,
    trustedDevices: [],
    consents: {},
    lastLogin: null,
    ...u,
    passwordHash: sec.hashPassword(password),
  });
  store.demo.passwords[u.id] = password;
}

// ---- Data awal ----
const UMUM = { name: 'Divisi Umum', require2fa: false };
const KEUANGAN = { name: 'Divisi Keuangan', require2fa: true };

addUser({ id: 'u-budi', username: 'budi', email: 'budi@contoh.id', name: 'Budi Santoso', password: 'budi12345', org: UMUM, roles: ['staf'] });
addUser({ id: 'u-sari', username: 'sari', email: 'sari@contoh.id', name: 'Sari Wulandari', password: 'sari12345', org: KEUANGAN, roles: ['staf', 'keuangan'] });
addUser({ id: 'u-andi', username: 'andi', email: 'andi@contoh.id', name: 'Andi Pratama', password: 'andi12345', org: KEUANGAN, roles: ['staf', 'keuangan'] });
addUser({ id: 'u-rina', username: 'rina', email: 'rina@contoh.id', name: 'Rina Kusuma', password: 'rina12345', org: UMUM, roles: ['staf'], status: 'disabled' });

// Andi sudah punya verifikasi dua langkah (aplikasi kode + SMS) dan kode cadangan.
const andiBackup = ['K7PM-4QXT', 'W2HD-9RNB', 'C8LV-3FJY', 'T5GE-6ZUA', 'P9SK-2MWD'];
store.users.get('u-andi').twoFa = {
  enrolledAt: Date.now(),
  methods: {
    totp: { secretEnc: sec.encrypt('JBSWY3DPEHPK3PXP'), lastStep: -1, addedAt: Date.now() },
    sms: { phoneEnc: sec.encrypt('+6281234567890'), phoneMasked: '+62•••••••7890', addedAt: Date.now() },
  },
  backupCodes: andiBackup.map(c => ({ hash: sec.sha256(c), usedAt: null })),
};
store.demo.backupCodes['u-andi'] = andiBackup;

module.exports = store;
