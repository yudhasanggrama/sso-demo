'use strict';
// JWT RS256 minimal: cukup untuk "kartu identitas digital" (ID token) dan logout token.
const crypto = require('crypto');

const b64u = v => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');

function sign(payload, privateKey, kid, typ = 'JWT') {
  const data = `${b64u({ alg: 'RS256', typ, kid })}.${b64u(payload)}`;
  const sig = crypto.sign('RSA-SHA256', Buffer.from(data), privateKey);
  return `${data}.${sig.toString('base64url')}`;
}

function fail(message, code = 'INVALID') {
  const err = new Error(message);
  err.code = code;
  return err;
}

function decode(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw fail('Format token tidak valid');
  try {
    return {
      header: JSON.parse(Buffer.from(parts[0], 'base64url')),
      payload: JSON.parse(Buffer.from(parts[1], 'base64url')),
      signed: `${parts[0]}.${parts[1]}`,
      signature: Buffer.from(parts[2], 'base64url'),
    };
  } catch {
    throw fail('Token tidak dapat dibaca');
  }
}

function verify(token, jwks, { issuer, audience, typ, clockSkewSec = 60 } = {}) {
  const { header, payload, signed, signature } = decode(token);
  if (header.alg !== 'RS256') throw fail(`Algoritma "${header.alg}" tidak diizinkan`);
  if (typ && header.typ !== typ) throw fail('Jenis token tidak sesuai');
  const jwk = (jwks.keys || []).find(k => k.kid === header.kid);
  if (!jwk) throw fail('Kunci penanda tangan tidak dikenal', 'NO_KEY');
  const key = crypto.createPublicKey({ key: { kty: jwk.kty, n: jwk.n, e: jwk.e }, format: 'jwk' });
  if (!crypto.verify('RSA-SHA256', Buffer.from(signed), key, signature)) {
    throw fail('Tanda tangan tidak sah — token bukan diterbitkan oleh Pusat Akun');
  }
  const now = Math.floor(Date.now() / 1000);
  if (issuer && payload.iss !== issuer) throw fail('Penerbit token tidak dikenal');
  if (audience) {
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(audience)) throw fail('Token ini bukan untuk layanan ini');
  }
  if (payload.exp != null && payload.exp + clockSkewSec < now) throw fail('Token sudah kedaluwarsa');
  if (payload.iat != null && payload.iat - clockSkewSec > now) throw fail('Token diterbitkan di masa depan');
  return payload;
}

module.exports = { sign, verify, decode };
