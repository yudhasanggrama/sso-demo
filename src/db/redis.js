'use strict';
// Data yang SEMENTARA/berumur pendek: sesi browser (termasuk status login yang sedang berjalan),
// tiket sekali pakai, kunci akses, sesi tiap layanan, token pemulihan, dan bantuan demo — semuanya
// wajar hilang/kedaluwarsa sendiri, jadi cocok di Redis (TTL bawaan) ketimbang MySQL.
const { createClient } = require('redis');
const cfg = require('../config');

// RESP2 dipilih eksplisit supaya tetap kompatibel dengan Redis versi lama (mis. build Windows lama
// yang belum mendukung HELLO/RESP3) — tetap bekerja normal di Redis modern (6/7+) juga.
const client = createClient({ url: cfg.redisUrl, RESP: 2 });
client.on('error', err => console.error('[redis]', err.message));

let connecting = null;
function connect() {
  connecting ||= client.connect();
  return connecting;
}

const getJSON = async key => {
  const raw = await client.get(key);
  return raw ? JSON.parse(raw) : null;
};
// ttlSec tidak wajib — beberapa data (mis. sesi browser) diperpanjang manual tiap disentuh.
const setJSON = (key, value, ttlSec) => (ttlSec ? client.set(key, JSON.stringify(value), { EX: Math.ceil(ttlSec) }) : client.set(key, JSON.stringify(value)));

module.exports = { client, connect, getJSON, setJSON };
