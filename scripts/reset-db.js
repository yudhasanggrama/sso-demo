// 'use strict';
// // Kosongkan MySQL + Redis lalu tulis ulang data demo dari awal (akun contoh + admin bawaan).
// // Berguna kalau ingin kembali ke keadaan awal setelah bereksperimen di /admin atau di aplikasi.
// require('dotenv').config();
// const store = require('../src/idp/store');
// const seed = require('../src/idp/seed');

// (async () => {
//   await store.init();
//   await store.resetAllForTests();
//   await seed.ensureSeed();
//   console.log('Selesai: MySQL (db_sso_demo) dan Redis dikosongkan lalu diisi ulang data demo.');
//   process.exit(0);
// })().catch(err => { console.error(err); process.exit(1); });
