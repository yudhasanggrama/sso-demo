'use strict';
// Pembungkus tipis di atas Express — permukaan API (req.cookies/req.ip/req.ua/req.body,
// res.html/res.json/res.cookie/res.clearCookie/res.redirect) dipertahankan SAMA PERSIS
// dengan router mini kustom yang dipakai sebelumnya, supaya seluruh route (routes-*.js,
// service/server.js) tidak perlu diubah sedikit pun saat bermigrasi ke Express.
const express = require('express');
const cookieParser = require('cookie-parser');

function createApp(name) {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.urlencoded({ extended: false, limit: '1mb' }));
  app.use(express.json({ limit: '1mb' }));
  app.use(cookieParser());

  app.use((req, res, next) => {
    req.body ||= {};
    // req.ip sudah disediakan Express (req.connection.remoteAddress secara default) — jangan ditimpa,
    // karena di Express modern properti ini getter tanpa setter di prototipe-nya.
    req.ua = req.headers['user-agent'] || '';

    res.set({
      'Cache-Control': 'no-store',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    });

    res.html = (body, status = 200) => res.status(status).type('html').send(body);

    // res.json(obj, status) — urutan argumen lama, beda dari bawaan Express (res.status(x).json(obj)).
    res.json = (obj, status = 200) => res.status(status).type('application/json').send(JSON.stringify(obj));

    // res.redirect(location, status) — urutan argumen lama, kebalikan dari bawaan Express.
    const rawRedirect = res.redirect.bind(res);
    res.redirect = (location, status = 302) => rawRedirect(status, location);

    // res.cookie(name, value, { httpOnly, sameSite, path, maxAge }) — maxAge dalam DETIK (bukan ms)
    // seperti router lama, dan HttpOnly aktif secara default kecuali diminta sebaliknya.
    const rawCookie = res.cookie.bind(res);
    res.cookie = (n, v, o = {}) => rawCookie(n, v, {
      httpOnly: o.httpOnly !== false,
      sameSite: o.sameSite || 'Lax',
      path: o.path || '/',
      ...(o.maxAge != null ? { maxAge: Math.floor(o.maxAge) * 1000 } : {}),
    });

    next();
  });

  const realListen = app.listen.bind(app);
  app.listen = (port, cb) => {
    // Dipasang paling akhir (setelah semua route didaftarkan modul lain) — Express mensyaratkan
    // urutan ini supaya rute spesifik dicoba dulu sebelum jatuh ke 404, dan error handler harus
    // punya 4 parameter (req, res, next, err) supaya Express mengenalinya sebagai error middleware.
    app.use((req, res) => res.html('<h1>404</h1><p>Halaman tidak ditemukan.</p>', 404));
    app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
      console.error(`[${name}]`, err);
      if (!res.headersSent) res.html('<h1>500</h1><p>Terjadi kesalahan pada server.</p>', 500);
    });
    return realListen(port, cb);
  };

  return app;
}

module.exports = { createApp };
