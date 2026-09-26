'use strict';
// Data awal demo — dulu langsung dibuat di memori saat modul store.js dimuat; sekarang ditulis ke
// MySQL/Redis sungguhan, dan hanya dijalankan kalau tabel users masih kosong (supaya akun yang sudah
// dihapus lewat panel admin tidak muncul lagi begitu server direstart).
const sec = require('../lib/security');
const db = require('../db/mysql');
const store = require('./store');

const UMUM = { name: 'Divisi Umum', require2fa: false };
const KEUANGAN = { name: 'Divisi Keuangan', require2fa: true };

async function seedUser({ id, username, email, name, password, org, roles, status = 'active' }) {
  await store.saveUser({
    id, username, email, name, org, roles, status,
    passwordHash: sec.hashPassword(password),
    failedLogins: 0, twoFa: null, twoFaFailures: 0, twoFaLockedUntil: 0, twoFaDeferredAt: 0,
    trustedDevices: [], consents: {}, lastLogin: null, previousLogin: null, createdAt: Date.now(),
  });
  await store.demoSetPassword(id, password);
}

async function ensureSeed() {
  const [[{ n }]] = await db.pool.query('SELECT COUNT(*) AS n FROM users');
  if (n > 0) return false;

  await seedUser({ id: 'u-budi', username: 'budi', email: 'budi@contoh.id', name: 'Budi Santoso', password: 'budi12345', org: UMUM, roles: ['staf'] });
  await seedUser({ id: 'u-sari', username: 'sari', email: 'sari@contoh.id', name: 'Sari Wulandari', password: 'sari12345', org: KEUANGAN, roles: ['staf', 'keuangan'] });
  await seedUser({ id: 'u-andi', username: 'andi', email: 'andi@contoh.id', name: 'Andi Pratama', password: 'andi12345', org: KEUANGAN, roles: ['staf', 'keuangan'] });
  await seedUser({ id: 'u-rina', username: 'rina', email: 'rina@contoh.id', name: 'Rina Kusuma', password: 'rina12345', org: UMUM, roles: ['staf'], status: 'disabled' });

  // Andi sudah punya verifikasi dua langkah (aplikasi kode + SMS) dan kode cadangan.
  const andi = await store.getUser('u-andi');
  const andiBackup = ['K7PM-4QXT', 'W2HD-9RNB', 'C8LV-3FJY', 'T5GE-6ZUA', 'P9SK-2MWD'];
  andi.twoFa = {
    enrolledAt: Date.now(),
    methods: {
      totp: { secretEnc: sec.encrypt('JBSWY3DPEHPK3PXP'), lastStep: -1, addedAt: Date.now() },
      sms: { phoneEnc: sec.encrypt('+6281234567890'), phoneMasked: '+62•••••••7890', addedAt: Date.now() },
    },
    backupCodes: andiBackup.map(c => ({ hash: sec.sha256(c), usedAt: null })),
  };
  await store.saveUser(andi);
  await store.demoSetBackupCodes('u-andi', andiBackup);

  // Admin bawaan untuk /admin — ganti lewat ADMIN_USERNAME/ADMIN_PASSWORD di .env untuk pemakaian sungguhan.
  const adminUser = (process.env.ADMIN_USERNAME || 'admin').toLowerCase();
  const adminPass = process.env.ADMIN_PASSWORD || 'admin12345';
  await db.pool.query('INSERT IGNORE INTO admins (username, password_hash, created_at) VALUES (?,?,?)',
    [adminUser, sec.hashPassword(adminPass), Date.now()]);

  console.log(`[seed] Data demo dibuat. Admin panel: ${adminUser} / ${adminPass} (ganti lewat .env untuk pemakaian sungguhan).`);
  return true;
}

module.exports = { ensureSeed };
