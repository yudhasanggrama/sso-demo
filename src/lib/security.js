'use strict';
const crypto = require('crypto');

// Kunci enkripsi data rahasia (mis. kunci TOTP). Di produksi: dari KMS / secret manager.
const ENC_KEY = process.env.SSO_DEMO_KEY
  ? crypto.createHash('sha256').update(process.env.SSO_DEMO_KEY).digest()
  : crypto.randomBytes(32);

const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
const sha256 = s => crypto.createHash('sha256').update(String(s)).digest('base64url');

function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 32);
  return `scrypt$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

function verifyPassword(password, stored) {
  const [, salt, hash] = String(stored).split('$');
  const calc = crypto.scryptSync(String(password), Buffer.from(salt, 'base64url'), 32);
  return crypto.timingSafeEqual(calc, Buffer.from(hash, 'base64url'));
}

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const ct = Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), ct].map(b => b.toString('base64url')).join('.');
}

function decrypt(payload) {
  const [iv, tag, ct] = payload.split('.').map(p => Buffer.from(p, 'base64url'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

const BACKUP_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function makeBackupCodes(n = 8) {
  return Array.from({ length: n }, () => {
    const chars = Array.from(crypto.randomBytes(8), b => BACKUP_ALPHABET[b % BACKUP_ALPHABET.length]).join('');
    return `${chars.slice(0, 4)}-${chars.slice(4)}`;
  });
}
const normalizeBackupCode = code => String(code).toUpperCase().replace(/[^A-Z0-9]/g, '').replace(/^(.{4})(.{4})$/, '$1-$2');

module.exports = {
  randomToken, sha256, safeEqual, hashPassword, verifyPassword, encrypt, decrypt,
  makeBackupCodes, normalizeBackupCode,
};
