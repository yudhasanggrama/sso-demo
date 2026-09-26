'use strict';
// Tes end-to-end: menjalankan server lalu menelusuri cabang-cabang flowchart seperti browser sungguhan.
const assert = require('assert');
const totp = require('../src/lib/totp');
require('../src/index');

const P = 'http://localhost:3000';
const SUREL = 'http://localhost:4001';
const KEU = 'http://localhost:4002';

class Browser {
  constructor() { this.jar = new Map(); }
  cookieHeader() { return [...this.jar].map(([k, v]) => `${k}=${v}`).join('; '); }
  store(res) {
    for (const c of res.headers.getSetCookie()) {
      const [pair, ...attrs] = c.split(';');
      const i = pair.indexOf('=');
      const name = pair.slice(0, i).trim();
      if (attrs.some(a => /max-age=0/i.test(a.trim()))) this.jar.delete(name);
      else this.jar.set(name, pair.slice(i + 1));
    }
  }
  async req(url, { method = 'GET', form, maxRedirects = 20 } = {}) {
    let res;
    for (let i = 0; i <= maxRedirects; i++) {
      res = await fetch(url, {
        method, redirect: 'manual',
        headers: { cookie: this.cookieHeader(), 'user-agent': 'Mozilla/5.0 (Windows NT 10.0) Chrome/130', ...(form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}) },
        body: form ? new URLSearchParams(form) : undefined,
      });
      this.store(res);
      if (res.status < 300 || res.status >= 400) break;
      url = new URL(res.headers.get('location'), url).href;
      method = 'GET'; form = undefined;
    }
    return { url, status: res.status, text: await res.text() };
  }
  get(url) { return this.req(url); }
  post(url, form) { return this.req(url, { method: 'POST', form }); }
}

const step = (name) => console.log(`  ✔ ${name}`);
const andiCode = () => totp.codeAt('JBSWY3DPEHPK3PXP');

// Buka layanan; bila muncul halaman persetujuan, setujui.
async function openService(b, url) {
  let r = await b.get(url);
  const m = /name="return" value="([^"]+)"/.exec(r.text);
  if (m) r = await b.post(`${P}/consent`, { return: m[1].replace(/&amp;/g, '&'), decision: 'allow' });
  return r;
}

async function login(b, email, password) {
  let r = await b.post(`${P}/login/identifier`, { login: email });
  assert.match(r.url, /\/login\/password$/);
  return b.post(`${P}/login/password`, { password });
}

async function main() {
  await new Promise(r => setTimeout(r, 400));
  const b = new Browser();

  // --- Alur 1: tamu ---
  let r = await b.get(`${P}/`);
  assert.match(r.text, /Portal Layanan/);
  step('Alur 1: pengunjung baru → mode tamu');

  // Akun tidak dikenal → pesan umum
  await b.get(`${P}/login`);
  r = await b.post(`${P}/login/identifier`, { login: 'siapa@contoh.id' });
  assert.match(r.text, /Email atau password salah/);
  step('Alur 1: akun tidak ditemukan → pesan umum');

  // --- Alur 3: buka layanan tanpa sesi → Pusat Akun → login (C) ---
  r = await b.get(`${SUREL}/`);
  assert.match(r.url, /\/login\?return=%2Fauthorize/);
  step('Alur 3: layanan belum kenal & Pusat Akun belum kenal → C ke Alur 1');

  r = await login(b, 'budi', 'budi12345');
  assert.match(r.url, /\/login\/2fa\/offer$/);
  step('Alur 2: belum punya 2FA, tidak wajib → tawaran aktifkan');
  r = await b.post(`${P}/login/2fa/offer`, { choice: 'later' });
  assert.match(r.text, /ingin mengakses akun Anda/);
  step('Alur 2: nanti saja → dikenali → kembali ke layanan → halaman persetujuan');

  const ret = /name="return" value="([^"]+)"/.exec(r.text)[1].replace(/&amp;/g, '&');
  r = await b.post(`${P}/consent`, { return: ret, decision: 'allow' });
  assert.equal(new URL(r.url).origin, SUREL);
  assert.match(r.text, /Kotak masuk/);
  step('Alur 3: setuju → tiket → kartu identitas diverifikasi → layanan terbuka');

  r = await b.get(`${P}/`);
  assert.match(r.text, /Sedang terbuka/);
  step('Alur 3: Pusat Akun mencatat layanan sedang dipakai');

  r = await b.get(`${SUREL}/`);
  assert.equal(new URL(r.url).origin, SUREL);
  assert.match(r.text, /Kotak masuk/);
  step('Alur 3: layanan sudah mengenali pengguna → langsung terbuka');

  r = await b.get(`${KEU}/`);
  assert.match(r.text, /tidak memiliki hak/);
  step('Alur 3: akun tanpa hak → akses ke Keuangan ditolak');

  // --- Alur 4: tambah akun (Andi, sudah punya 2FA) ---
  await b.get(`${P}/login?add=1`);
  r = await login(b, 'andi@contoh.id', 'andi12345');
  assert.match(r.url, /\/2fa\/verify$/);
  step('Alur 4 → Alur 2: tambah akun; perangkat belum tepercaya → minta kode');
  r = await b.post(`${P}/2fa/verify`, { code: '000000' });
  assert.match(r.text, /Kode salah/);
  step('Alur 2: kode salah → dicatat, coba lagi');
  r = await b.post(`${P}/2fa/verify`, { code: andiCode() });
  assert.match(r.url, /\/login\/trust$/);
  r = await b.post(`${P}/login/trust`, { trust: 'yes' });
  assert.match(r.text, /Halo, Andi/);
  step('Alur 2: kode benar → percayai perangkat 30 hari → Halaman Utama');

  r = await b.get(`${SUREL}/`);
  assert.match(r.url, /\/authorize|ingin mengakses/);
  step('Alur 4: sesi Surel milik Budi ditutup agar akun tidak tertukar');

  r = await b.get(`${KEU}/`);
  assert.match(r.text, /Keuangan ingin mengakses/);
  const ret2 = /name="return" value="([^"]+)"/.exec(r.text)[1].replace(/&amp;/g, '&');
  r = await b.post(`${P}/consent`, { return: ret2, decision: 'allow' });
  assert.match(r.text, /Saldo kas/);
  step('Alur 3: layanan sensitif dibuka (2FA masih baru)');

  // --- Alur 4: ganti akun ke Budi ---
  const menu = await b.get(`${P}/`);
  assert.match(menu.text, /Ganti akun/);
  r = await b.post(`${P}/switch`, { userId: 'u-budi' });
  assert.match(r.text, /Halo, Budi/);
  assert.doesNotMatch(r.text, /localhost:4002/);
  step('Alur 4: ganti akun → daftar layanan dimuat ulang sesuai hak (Keuangan hilang)');
  r = await b.get(`${KEU}/`);
  assert.match(r.text, /tidak memiliki hak/);
  step('Alur 4: sesi Keuangan milik Andi sudah ditutup');

  // --- Alur 5: keluar dengan layanan yang gagal menjawab ---
  r = await b.get(`${SUREL}/`);
  assert.match(r.text, /Kotak masuk/);
  await b.post(`${P}/demo/service-fail`, { clientId: 'surel', n: '2' });
  r = await b.post(`${P}/logout`, { scope: 'one' });
  assert.match(r.text, /setelah 3 percobaan/);
  assert.match(r.text, /Masih masuk sebagai/);
  step('Alur 5: gagal 2× → coba lagi dengan jeda → berhasil; masih ada akun lain → B');

  // Andi masuk lagi → perangkat tepercaya → Keuangan tetap minta kode lagi
  r = await b.get(`${P}/`);
  assert.match(r.text, /Halo, Andi/);
  await b.get(`${P}/login?add=1`);
  r = await login(b, 'budi', 'budi12345');
  r = await b.post(`${P}/login/2fa/offer`, { choice: 'later' });
  r = await b.post(`${P}/switch`, { userId: 'u-andi' });
  const acctAndi = await b.get(`${KEU}/`);
  assert.match(acctAndi.text, /Saldo kas|Verifikasi ulang/);
  step('Alur 3: Keuangan untuk Andi');

  r = await openService(b, `${SUREL}/`);
  assert.match(r.text, /Kotak masuk/);
  await b.post(`${P}/demo/service-fail`, { clientId: 'surel', n: '10' });
  r = await b.post(`${P}/logout`, { scope: 'all' });
  assert.match(r.text, /dicatat untuk ditindaklanjuti/);
  assert.match(r.text, /Selesai/);
  step('Alur 5: semua akun; layanan gagal melewati batas → dicatat untuk ditindaklanjuti → mode tamu');

  r = await b.get(`${P}/`);
  assert.match(r.text, /Portal Layanan/);
  await b.post(`${P}/demo/service-fail`, { clientId: 'surel', n: '0' });
  r = await b.get(`${SUREL}/`);
  assert.match(r.text, /Sesi Anda sudah berakhir/);
  step('Alur 5: kunci akses dibatalkan → sesi layanan yang tertinggal ikut berakhir');

  // Perangkat tepercaya + step-up
  await b.get(`${P}/login`);
  r = await login(b, 'andi', 'andi12345');
  assert.match(r.text, /Halo, Andi/);
  step('Alur 2: perangkat tepercaya → tanpa kode');
  r = await b.get(`${KEU}/`);
  assert.match(r.url, /\/2fa\/verify$/);
  assert.match(r.text, /Verifikasi ulang/);
  r = await b.post(`${P}/2fa/verify`, { code: 'K7PM-4QXT' });
  assert.match(r.text, /Saldo kas/);
  step('Alur 3: layanan sensitif → minta kode lagi (kode cadangan) → terbuka');
  await b.get(`${P}/logout`);
  await b.post(`${P}/logout`, { scope: 'all' });

  // Token palsu
  r = await b.get(`${SUREL}/demo/forged`);
  assert.equal(r.status, 403);
  assert.match(r.text, /Tanda tangan tidak sah/);
  step('Alur 3: kartu identitas palsu → ditolak & dicatat sebagai insiden');

  // --- Sari: 2FA wajib, pendaftaran lewat aplikasi kode ---
  const s = new Browser();
  await s.get(`${P}/login`);
  r = await login(s, 'sari@contoh.id', 'sari12345');
  assert.match(r.url, /\/2fa\/enroll$/);
  assert.match(r.text, /tidak dapat dilewati/);
  step('Alur 2: organisasi mewajibkan → pendaftaran wajib tanpa tombol lewati');
  r = await s.get(`${P}/2fa/enroll/totp`);
  const secret = /class="secret">([A-Z2-7 ]+)</.exec(r.text)[1].replace(/ /g, '');
  r = await s.post(`${P}/2fa/enroll/totp`, { code: totp.codeAt(secret) });
  assert.match(r.text, /Kode cadangan/);
  r = await s.post(`${P}/2fa/enrolled`, {});
  assert.match(r.text, /Halo, Sari/);
  step('Alur 2: uji kode pertama → simpan terenkripsi + kode cadangan → dikenali');

  // --- Kunci akun ---
  const x = new Browser();
  await x.get(`${P}/login`);
  await x.post(`${P}/login/identifier`, { login: 'budi' });
  for (let i = 0; i < 5; i++) r = await x.post(`${P}/login/password`, { password: 'salah' });
  assert.match(r.url, /\/locked$/);
  step('Alur 1: gagal terlalu sering → halaman akun terkunci');
  r = await x.post(`${P}/login/identifier`, { login: 'rina' });
  assert.match(r.text, /dinonaktifkan/);
  step('Alur 1: akun nonaktif → halaman akun terkunci');

  r = await x.get(`${P}/demo`);
  assert.match(r.text, /Insiden keamanan di layanan Surel/);
  assert.match(r.text, /Akun dikunci otomatis/);
  step('Riwayat keamanan mencatat semuanya');

  console.log('\nSemua tes lolos.');
  process.exit(0);
}

main().catch(err => { console.error('\n✘ Tes gagal:', err); process.exit(1); });
