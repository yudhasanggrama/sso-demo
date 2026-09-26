'use strict';
// Router HTTP mini tanpa dependensi: cookie, body form/JSON, parameter rute.
const http = require('http');

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const key = part.slice(0, i).trim();
    const raw = part.slice(i + 1).trim();
    if (!key) continue;
    try { out[key] = decodeURIComponent(raw); } catch { out[key] = raw; }
  }
  return out;
}

function serializeCookie(name, value, opts = {}) {
  let s = `${name}=${encodeURIComponent(value)}; Path=${opts.path || '/'}; SameSite=${opts.sameSite || 'Lax'}`;
  if (opts.httpOnly !== false) s += '; HttpOnly';
  if (opts.maxAge != null) s += `; Max-Age=${Math.floor(opts.maxAge)}`;
  return s;
}

function readBody(req, limit = 1_000_000) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > limit) { reject(new Error('Body terlalu besar')); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const type = (req.headers['content-type'] || '').split(';')[0].trim();
      try {
        if (type === 'application/json') return resolve(raw ? JSON.parse(raw) : {});
        return resolve(Object.fromEntries(new URLSearchParams(raw)));
      } catch (err) { reject(err); }
    });
    req.on('error', reject);
  });
}

function compile(path) {
  const keys = [];
  const pattern = path.replace(/:[^/]+/g, m => { keys.push(m.slice(1)); return '([^/]+)'; });
  return { re: new RegExp(`^${pattern}/?$`), keys };
}

function createApp(name) {
  const routes = [];
  const add = method => (path, handler) => routes.push({ method, ...compile(path), handler });

  async function handle(req, res) {
    const url = new URL(req.url, 'http://localhost');
    req.path = url.pathname;
    req.query = Object.fromEntries(url.searchParams);
    req.cookies = parseCookies(req.headers.cookie);
    req.ip = req.socket.remoteAddress || '';
    req.ua = req.headers['user-agent'] || '';

    const setCookies = [];
    res.cookie = (n, v, o) => { setCookies.push(serializeCookie(n, v, o)); res.setHeader('Set-Cookie', setCookies); };
    res.clearCookie = n => res.cookie(n, '', { maxAge: 0 });
    res.html = (body, status = 200) => { res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(body); };
    res.json = (obj, status = 200) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
    res.redirect = (location, status = 302) => { res.writeHead(status, { Location: location }); res.end(); };

    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');

    try {
      req.body = req.method === 'POST' ? await readBody(req) : {};
      for (const r of routes) {
        if (r.method !== req.method) continue;
        const m = r.re.exec(req.path);
        if (!m) continue;
        req.params = Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])]));
        return await r.handler(req, res);
      }
      res.html('<h1>404</h1><p>Halaman tidak ditemukan.</p>', 404);
    } catch (err) {
      console.error(`[${name}]`, err);
      if (!res.headersSent) res.html('<h1>500</h1><p>Terjadi kesalahan pada server.</p>', 500);
    }
  }

  return {
    get: add('GET'),
    post: add('POST'),
    listen: (port, cb) => http.createServer(handle).listen(port, cb),
  };
}

module.exports = { createApp };
