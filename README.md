# Demo SSO — Pusat Akun

Demo Single Sign-On yang berjalan sungguhan, dibangun mengikuti flowchart Alur 1–5.
Satu **Pusat Akun** (identity provider, OpenID Connect, di atas **Express**) dan tiga **layanan** terpisah
yang masing-masing berjalan di port sendiri. Data akun & riwayat keamanan tersimpan tetap di **MySQL**
(`db_sso_demo`); sesi browser, tiket, kunci akses, dan bantuan demo tersimpan sementara di **Redis**.

## Menjalankan

1. Siapkan MySQL/MariaDB (server lain dengan database kosong bernama `db_sso_demo`, atau lewat XAMPP)
   dan Redis (`docker run -p 6379:6379 redis` paling gampang; lihat juga `.env.example`).
2. `cp .env.example .env` lalu isi `SSO_DEMO_KEY` dengan string acak yang panjang — **wajib** diisi dan
   **jangan diubah** setelah ada data 2FA asli (lihat komentar di `.env.example`).
3. `npm install`
4. `npm start` — otomatis membuat tabel yang belum ada (migrasi) dan mengisi akun contoh kalau tabel `users`
   masih kosong.

```bash
npm start      # jalankan semua server (migrasi + seed otomatis kalau tabel masih kosong)
npm test       # tes end-to-end (mengosongkan lalu mengisi ulang db_sso_demo/Redis dulu supaya deterministik)
npm run db:reset  # kosongkan & isi ulang data demo kapan saja, tanpa harus lewat npm test
```

| Aplikasi | Alamat |
|---|---|
| Pusat Akun (Portal) | http://localhost:3000 |
| Panel Demo | http://localhost:3000/demo |
| Panel Admin (hapus/unlock akun) | http://localhost:3000/admin |
| Layanan Surel | http://localhost:4001 |
| Layanan Keuangan (sensitif, butuh peran `keuangan`) | http://localhost:4002 |
| Layanan Dokumen | http://localhost:4003 |

## Akun contoh

| Email | Password | Untuk mencoba |
|---|---|---|
| budi@contoh.id | budi12345 | 2FA opsional → tawaran "Aktifkan sekarang / Nanti saja". Tidak punya hak ke Keuangan. |
| sari@contoh.id | sari12345 | Organisasi mewajibkan 2FA → pendaftaran wajib tanpa tombol lewati. |
| andi@contoh.id | andi12345 | Sudah punya 2FA (aplikasi kode + kode cadangan). |
| rina@contoh.id | rina12345 | Akun dinonaktifkan → halaman akun terkunci. |

Verifikasi dua langkah cuma satu cara: **aplikasi kode TOTP (Google Authenticator)**, plus kode cadangan
sebagai jalan darurat. Kode aplikasi (TOTP) Andi bisa dilihat di Panel Demo, atau pindai langsung kode QR
di halaman pendaftaran (`/2fa/enroll/totp`) dengan Google Authenticator — atau ketik manual kunci
`JBSWY3DPEHPK3PXP`. Email pemulihan akun tidak benar-benar dikirim; isinya muncul di **Panel Demo → Kotak keluar**.

## Panel Admin

`/admin` — login terpisah dari akun pengguna (dibuat otomatis dari `ADMIN_USERNAME`/`ADMIN_PASSWORD` di
`.env` saat pertama kali tabel `admins` masih kosong; default `admin` / `admin12345`, **ganti untuk
pemakaian sungguhan**). Dari sini IdP bisa:

- **Melihat daftar semua akun** — status (aktif/terkunci/nonaktif), organisasi, peran, dan metode 2FA.
- **Membuka kunci akun** yang terkunci (baik karena gagal 2FA berulang maupun sebab lain).
- **Menghapus akun** — mencabut semua kunci akses & tiket miliknya, menutup sesi di tiap layanan lewat
  perintah keluar antar-server (mekanisme yang sama seperti Alur 5), dan mengeluarkannya dari sesi
  browser mana pun sebelum baris akunnya dihapus dari MySQL.

## Header Bersama (grid 3x3 + avatar)

## Header Bersama (grid 3x3 + avatar)

Setelah masuk, header di kanan atas selalu menampilkan dua widget yang sama — posisi dan tampilannya identik
di Portal maupun di ketiga layanan (Surel, Dokumen, Keuangan):

- **Grid 3x3** (ikon waffle) — daftar layanan yang jadi hak akun aktif; mengeklik salah satunya membuka layanan itu.
- **Avatar** — menu tambah akun, ganti akun, kelola akun, dan keluar; sama persis dengan menu di Portal.

Karena tiap layanan berjalan di server/origin terpisah, headernya diisi lewat panggilan server-ke-server
`POST /internal/header` ke Pusat Akun (lihat `fetchHeaderContext` di `src/service/server.js`), bukan dengan
membaca cookie Pusat Akun secara langsung. Ganti akun dari header sebuah layanan akan membawa Anda kembali
ke layanan itu juga (lewat `POST /switch` dengan `return` yang divalidasi ke daftar layanan terdaftar saja,
mencegah open redirect).

## Peta flowchart → kode

| Flowchart | Rute / fungsi | Berkas |
|---|---|---|
| **Alur 1** Mulai → masih dikenali? → mode tamu | `GET /` | `src/idp/routes-oidc.js` |
| Ketik email → cari akun → ditemukan & aktif? | `POST /login/identifier` | `src/idp/routes-login.js` |
| Password → cocok? → catat gagal → terlalu sering? → terkunci | `POST /login/password`, `GET /locked`, `/recover` | `src/idp/routes-login.js` |
| **Alur 2** Punya 2FA? → wajib? → mau aktifkan? | `GET /login/2fa`, `/login/2fa/offer` | `src/idp/routes-login.js` |
| Pendaftaran TOTP: tampilkan QR (bisa discan) + kunci manual → uji kode → simpan terenkripsi + kode cadangan | `/2fa/enroll/totp`, `/2fa/enrolled`, `src/lib/qrcode.js` | `src/idp/routes-login.js` |
| Perangkat tepercaya? → masukkan kode → kunci sementara → percayai 30 hari | `/2fa/verify`, `/login/trust` | `src/idp/routes-login.js` |
| Dikenali; catat waktu, perangkat, lokasi | `completeLogin()` | `src/idp/core.js` |
| **Alur 3a** Header Bersama: grid 3x3 + avatar, sama di Portal & tiap layanan | `sharedHeaderRight()`, `POST /internal/header` | `src/idp/core.js`, `src/idp/routes-oidc.js`, `src/service/server.js` |
| Halaman Utama (grid layanan + foto profil) | `renderHome()` | `src/idp/routes-oidc.js` |
| **Alur 3b** Layanan sudah mengenali pengguna? | `GET /` layanan | `src/service/server.js` |
| Layanan bertanya ke Pusat Akun → sensitif? → persetujuan? → tiket | `GET /authorize`, `POST /consent` | `src/idp/routes-oidc.js` |
| Tukar tiket jadi kartu identitas → asli & belum kedaluwarsa? | `POST /token` ↔ `GET /callback` layanan | kedua berkas di atas |
| Pusat Akun mencatat layanan sedang dipakai | `POST /internal/service-session` | `src/idp/routes-oidc.js` |
| **Alur 4** Menu avatar: tambah / ganti / kelola / keluar | `accountMenu()`, `POST /switch`, `GET /account` | `src/idp/core.js`, `src/idp/routes-account.js` |
| **Alur 5** Keluar dari mana? → hapus penanda | `GET/POST /logout` | `src/idp/routes-account.js` |
| Kirim perintah keluar antar server, coba ulang dengan jeda makin panjang | `backchannelLogout()` | `src/idp/core.js` |
| Layanan memeriksa keaslian perintah lalu menutup sesi | `POST /backchannel-logout` | `src/service/server.js` |
| Batalkan kunci akses, catat di riwayat keamanan | `logoutAccounts()` | `src/idp/core.js` |

## Skenario yang bisa dicoba

1. **SSO dasar:** buka Surel → diarahkan ke Pusat Akun → masuk sebagai Budi → setujui → Surel terbuka. Buka Dokumen: langsung masuk tanpa password.
2. **Layanan sensitif:** masuk sebagai Andi, centang "percayai perangkat", keluar, lalu masuk lagi (tanpa kode). Buka Keuangan → tetap diminta kode.
3. **Multi-akun:** foto profil → Tambah akun → masuk akun kedua. Ganti akun → daftar layanan berubah sesuai hak; layanan yang terbuka dengan akun lain ditutup supaya akun tidak tertukar.
4. **Logout yang gagal:** Panel Demo → atur Surel "gagal 2 kali" → keluar → berhasil setelah dicoba ulang. Atur "gagal 10 kali" → melewati batas → dicatat untuk ditindaklanjuti. Karena kunci aksesnya sudah dibatalkan, sesi Surel yang tertinggal tetap berakhir saat dibuka lagi.
5. **Serangan:** Panel Demo → "Kirim token palsu" → ditolak dan dicatat sebagai insiden. Salah password 5× → akun terkunci → pulihkan lewat email di Kotak keluar.

## Penyimpanan: apa di MySQL, apa di Redis

| MySQL (`db_sso_demo`, tetap) | Redis (sementara/TTL) |
|---|---|
| `users` — profil, password hash, status, 2FA (kolom JSON), perangkat tepercaya, consents | Sesi browser `pa_bs` (termasuk status login yang sedang berjalan) |
| `audit_log` — riwayat keamanan | Tiket sekali pakai (`authorize` → `token`) dan kunci akses |
| `failed_logouts` — logout yang gagal, untuk ditindaklanjuti | Sesi tiap layanan (dipakai Header Bersama & Alur 4) |
| `admins` — akun panel admin | Token pemulihan akun (TTL 15 menit), counter gagal 2FA + kunci sementaranya, kode cadangan contoh untuk Panel Demo, kotak keluar email simulasi |

Password demo (teks polos, cuma untuk ditampilkan sebagai petunjuk) **dihardcode** di `src/idp/store.js` — bukan di MySQL/Redis, karena bukan data yang perlu bertahan lewat restart.

Lihat `src/idp/store.js` untuk seluruh fungsi akses datanya, dan `sql` schema-nya langsung di `src/db/mysql.js` (dibuat otomatis lewat `CREATE TABLE IF NOT EXISTS`, tidak perlu migration tool terpisah).

## Batasan demo

- Sesi tiap **layanan** (bukan Pusat Akun) — `sessions`/`pendingAuth` di `src/service/server.js` — sengaja
  tetap di memori per proses: itu representasi wajar dari sebuah Service Provider biasa, dan hilang
  begitu saja hanya berarti pengguna diautentikasi ulang lewat SSO (transparan, tanpa mengetik password lagi).
- Semua berjalan di `localhost`; karena cookie tidak dipisahkan per port, setiap aplikasi memakai nama cookie sendiri. Di produksi, Pusat Akun dan layanan berada di domain berbeda dan wajib memakai HTTPS (cookie `Secure`).
- Verifikasi dua langkah sengaja cuma satu cara (TOTP/Google Authenticator + kode cadangan) — SMS dan sidik jari/wajah (WebAuthn/passkey) tidak diimplementasikan di demo ini.
- Petunjuk bertanda "Bantuan demo" (kode TOTP, password) dan Panel Demo sengaja membocorkan rahasia agar demo mudah dicoba. Jangan dibawa ke produksi.
- `SSO_DEMO_KEY` di `.env` dipakai mengenkripsi secret TOTP di MySQL — wajib diisi dan tidak
  boleh berubah setelah ada data 2FA asli, kalau tidak semuanya tidak bisa dibaca lagi setelah restart.
