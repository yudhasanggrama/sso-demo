# Demo SSO — Pusat Akun

Demo Single Sign-On yang berjalan sungguhan, dibangun mengikuti flowchart Alur 1–5.
Satu **Pusat Akun** (identity provider, OpenID Connect) dan tiga **layanan** terpisah yang masing-masing berjalan di port sendiri.
Tidak ada dependensi: cukup Node.js 18.17 atau lebih baru.

```bash
npm start      # jalankan semua server
npm test       # tes end-to-end yang menelusuri cabang-cabang flowchart
```

| Aplikasi | Alamat |
|---|---|
| Pusat Akun (Portal) | http://localhost:3000 |
| Panel Demo | http://localhost:3000/demo |
| Layanan Surel | http://localhost:4001 |
| Layanan Keuangan (sensitif, butuh peran `keuangan`) | http://localhost:4002 |
| Layanan Dokumen | http://localhost:4003 |

## Akun contoh

| Email | Password | Untuk mencoba |
|---|---|---|
| budi@contoh.id | budi12345 | 2FA opsional → tawaran "Aktifkan sekarang / Nanti saja". Tidak punya hak ke Keuangan. |
| sari@contoh.id | sari12345 | Organisasi mewajibkan 2FA → pendaftaran wajib tanpa tombol lewati. |
| andi@contoh.id | andi12345 | Sudah punya 2FA (aplikasi kode + SMS + kode cadangan). |
| rina@contoh.id | rina12345 | Akun dinonaktifkan → halaman akun terkunci. |

Kode aplikasi (TOTP) Andi bisa dilihat di Panel Demo, atau tambahkan kunci `JBSWY3DPEHPK3PXP` ke Google/Microsoft Authenticator.
SMS dan email tidak benar-benar dikirim; isinya muncul di **Panel Demo → Kotak keluar**.

## Peta flowchart → kode

| Flowchart | Rute / fungsi | Berkas |
|---|---|---|
| **Alur 1** Mulai → masih dikenali? → mode tamu | `GET /` | `src/idp/routes-oidc.js` |
| Ketik email → cari akun → ditemukan & aktif? | `POST /login/identifier` | `src/idp/routes-login.js` |
| Password → cocok? → catat gagal → terlalu sering? → terkunci | `POST /login/password`, `GET /locked`, `/recover` | `src/idp/routes-login.js` |
| **Alur 2** Punya 2FA? → wajib? → mau aktifkan? | `GET /login/2fa`, `/login/2fa/offer` | `src/idp/routes-login.js` |
| Pendaftaran: pilih cara → uji kode → simpan terenkripsi + kode cadangan | `/2fa/enroll/*`, `/2fa/enrolled` | `src/idp/routes-login.js` |
| Perangkat tepercaya? → masukkan kode → kunci sementara → percayai 30 hari | `/2fa/verify`, `/login/trust` | `src/idp/routes-login.js` |
| Dikenali; catat waktu, perangkat, lokasi | `completeLogin()` | `src/idp/core.js` |
| **Alur 3** Halaman Utama (grid layanan + foto profil) | `renderHome()` | `src/idp/routes-oidc.js` |
| Layanan sudah mengenali pengguna? | `GET /` layanan | `src/service/server.js` |
| Layanan bertanya ke Pusat Akun → sensitif? → persetujuan? → tiket | `GET /authorize`, `POST /consent` | `src/idp/routes-oidc.js` |
| Tukar tiket jadi kartu identitas → asli & belum kedaluwarsa? | `POST /token` ↔ `GET /callback` layanan | kedua berkas di atas |
| Pusat Akun mencatat layanan sedang dipakai | `POST /internal/service-session` | `src/idp/routes-oidc.js` |
| **Alur 4** Menu foto profil: tambah / ganti / kelola / keluar | `accountMenu()`, `POST /switch`, `GET /account` | `src/idp/core.js`, `src/idp/routes-account.js` |
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

## Batasan demo

- Semua data disimpan di memori dan hilang saat server dimatikan.
- Semua berjalan di `localhost`; karena cookie tidak dipisahkan per port, setiap aplikasi memakai nama cookie sendiri. Di produksi, Pusat Akun dan layanan berada di domain berbeda dan wajib memakai HTTPS (cookie `Secure`).
- "Sidik jari/wajah" disimulasikan dengan kunci ECDSA di `localStorage`. Untuk produksi, gunakan WebAuthn/passkey sungguhan.
- Petunjuk bertanda "Bantuan demo" (kode TOTP, password) dan Panel Demo sengaja membocorkan rahasia agar demo mudah dicoba. Jangan dibawa ke produksi.
