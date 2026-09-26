'use strict';
require('dotenv').config(); // dijalankan sepaling awal — sebelum modul lain (mis. lib/security) membaca process.env
const cfg = require('./config');
const store = require('./idp/store');
const seed = require('./idp/seed');
const { createPortal } = require('./idp/server');
const { createService } = require('./service/server');

async function main() {
  if (!process.env.SSO_DEMO_KEY) {
    console.warn('\n⚠️  SSO_DEMO_KEY belum diisi di .env — kunci enkripsi 2FA dibuat acak tiap kali server start.');
    console.warn('   Data 2FA (TOTP) yang sudah ada tidak akan terbaca lagi setelah restart. Lihat .env.example.\n');
  }

  await store.init(); // migrasi skema MySQL + sambungkan Redis
  const seeded = await seed.ensureSeed();
  if (!seeded) console.log('[seed] Data sudah ada, tidak menulis ulang (hapus/unlock akun lewat /admin akan tetap berlaku setelah restart).');

  createPortal().listen(cfg.PORTAL_PORT, () => {
    console.log(`\n  Pusat Akun (Portal)  ${cfg.PORTAL}`);
    console.log(`  Panel Demo           ${cfg.PORTAL}/demo`);
    console.log(`  Panel Admin          ${cfg.PORTAL}/admin`);
  });

  for (const svc of cfg.services) {
    createService(svc).listen(svc.port, () => console.log(`  Layanan ${svc.name.padEnd(12)} ${svc.url}`));
  }
}

main().catch(err => {
  console.error('Gagal menyalakan server (cek koneksi MySQL/Redis):', err);
  process.exit(1);
});
