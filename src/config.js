'use strict';

const PORTAL_PORT = Number(process.env.PORTAL_PORT || 3000);
const PORTAL = `http://localhost:${PORTAL_PORT}`;

// Layanan yang terdaftar di Pusat Akun (klien OIDC).
const services = [
  {
    id: 'surel',
    name: 'Surel',
    icon: '✉️',
    color: '#2563eb',
    port: 4001,
    description: 'Kotak masuk surat elektronik',
    sensitive: false,
    requiredRole: null,
    scopes: ['openid', 'profile', 'email'],
  },
  {
    id: 'dokumen',
    name: 'Dokumen',
    icon: '📄',
    color: '#0d9488',
    port: 4003,
    description: 'Berkas dan dokumen bersama',
    sensitive: false,
    requiredRole: null,
    scopes: ['openid', 'profile'],
  },
  {
    id: 'keuangan',
    name: 'Keuangan',
    icon: '💰',
    color: '#b45309',
    port: 4002,
    description: 'Saldo, transaksi, dan persetujuan pembayaran',
    sensitive: true, // Alur 3: minta kode verifikasi lagi walaupun sudah masuk
    requiredRole: 'keuangan',
    scopes: ['openid', 'profile', 'email', 'keuangan'],
  },
].map(s => ({
  ...s,
  secret: `${s.id}-rahasia-demo`,
  url: `http://localhost:${s.port}`,
  redirectUri: `http://localhost:${s.port}/callback`,
  backchannelLogoutUri: `http://localhost:${s.port}/backchannel-logout`,
}));

const clients = Object.fromEntries(services.map(s => [s.id, s]));

const policy = {
  browserSessionDays: 7,        // Alur 1: "masih dikenali dari kunjungan sebelumnya"
  maxPasswordFailures: 5,       // Alur 1: "sudah gagal terlalu sering?"
  max2faFailures: 5,            // Alur 2: "kunci sementara bila berulang"
  twoFaLockMs: 60_000,
  trustDeviceDays: 30,          // Alur 2: "percayai perangkat ini selama 30 hari"
  smsCodeTtlMs: 5 * 60_000,
  authCodeTtlMs: 60_000,        // Alur 3: "tiket sekali pakai, masa berlaku sangat singkat"
  stepUpMaxAgeMs: 5 * 60_000,   // Alur 3: layanan sensitif butuh verifikasi dua langkah yang masih baru
  idTokenTtlSec: 300,
  accessTokenTtlSec: 3600,
  logoutRetries: 3,             // Alur 5: "masih dalam batas percobaan ulang?"
  logoutBaseDelayMs: 400,       // Alur 5: "coba lagi dengan jeda yang makin panjang"
  logoutTimeoutMs: 2000,
};

const ACR_MFA = 'urn:pusat-akun:mfa';
const ACR_PWD = 'urn:pusat-akun:pwd';
const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

module.exports = { PORTAL, PORTAL_PORT, services, clients, policy, ACR_MFA, ACR_PWD, BACKCHANNEL_LOGOUT_EVENT };
