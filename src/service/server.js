'use strict';
// Satu aplikasi layanan (klien SSO). Dijalankan beberapa kali dengan konfigurasi berbeda.
const crypto = require('crypto');
const cfg = require('../config');
const jwt = require('../lib/jwt');
const sec = require('../lib/security');
const ui = require('../lib/ui');
const { createApp } = require('../lib/http');
const content = require('./content');

const { esc } = ui;
const { PORTAL } = cfg;

function createService(svc) {
  const app = createApp(svc.id);
  const COOKIE = `svc_${svc.id}`;           // cookie tiap layanan terpisah (di localhost, port tidak memisahkan cookie)
  const AUTH_COOKIE = `svc_${svc.id}_auth`;
  const sessions = new Map();               // sesi lokal layanan
  const pendingAuth = new Map();            // state → { nonce, verifier, browserKey }
  const seenLogoutJti = new Map();
  let failNext = 0;
  let jwksCache = null;

  const brand = { name: svc.name, logo: svc.icon, color: svc.color, home: '/' };
  const log = msg => console.log(`[${svc.id}] ${msg}`);

  async function getJwks(force = false) {
    if (!jwksCache || force) jwksCache = await (await fetch(`${PORTAL}/jwks`, { signal: AbortSignal.timeout(3000) })).json();
    return jwksCache;
  }
  async function verifyJwt(token, opts) {
    try {
      return jwt.verify(token, await getJwks(), opts);
    } catch (err) {
      if (err.code === 'NO_KEY') return jwt.verify(token, await getJwks(true), opts);
      throw err;
    }
  }

  // Panggilan langsung ke Pusat Akun (antar server, tidak lewat browser)
  async function idp(path, body) {
    const r = await fetch(`${PORTAL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: svc.id, client_secret: svc.secret, ...body }),
      signal: AbortSignal.timeout(3000),
    });
    return { status: r.status, data: await r.json() };
  }

  function page(res, { title, flow, body, user, status = 200 }) {
    const right = user
      ? `<span class="small muted">${esc(user.email || user.preferred_username || user.sub)}</span>
         <a class="btn sm ghost" href="${PORTAL}/">Portal</a><a class="btn sm secondary" href="${PORTAL}/logout">Keluar</a>`
      : `<a class="btn sm ghost" href="${PORTAL}/">Portal</a>`;
    res.html(ui.page({ title, brand, flow, body, right }), status);
  }

  function startLogin(req, res) {
    const state = sec.randomToken(16);
    const nonce = sec.randomToken(16);
    const verifier = sec.randomToken(32);
    const browserKey = sec.randomToken(16);
    pendingAuth.set(state, { nonce, verifier, browserKey, createdAt: Date.now() });
    res.cookie(AUTH_COOKIE, browserKey, { maxAge: 600 });
    // "Browser berpindah ke alamat layanan" → layanan bertanya ke Pusat Akun: siapa pengguna ini?
    const params = new URLSearchParams({
      response_type: 'code', client_id: svc.id, redirect_uri: svc.redirectUri, scope: svc.scopes.join(' '),
      state, nonce, code_challenge: sec.sha256(verifier), code_challenge_method: 'S256',
    });
    res.redirect(`${PORTAL}/authorize?${params}`);
  }

  // "Akses ditolak dan dicatat sebagai insiden keamanan"
  async function denied(req, res, reason, sub) {
    log(`INSIDEN: ${reason}`);
    await idp('/internal/incident', { reason, sub: sub || '', ip: req.ip, ua: req.ua }).catch(() => {});
    page(res, {
      title: 'Akses ditolak', status: 403,
      flow: 'Alur 3 · Kartu identitas tidak sah → akses ditolak dan dicatat sebagai insiden keamanan',
      body: `<div class="card"><h1>⛔ Akses ditolak</h1>${ui.alert('error', esc(reason))}
        <p class="small muted">Kejadian ini sudah dilaporkan ke riwayat keamanan Pusat Akun.</p>
        <a class="btn secondary" href="${PORTAL}/">Kembali ke Portal</a></div>`,
    });
  }

  // "Layanan sudah mengenali pengguna ini?"
  app.get('/', async (req, res) => {
    const localSid = req.cookies[COOKIE];
    const s = sessions.get(localSid);
    if (!s) return startLogin(req, res);

    // Kunci akses masih berlaku? (mis. sudah dicabut karena logout tapi perintah keluar gagal sampai)
    let introspection;
    try {
      introspection = (await idp('/introspect', { token: s.accessToken })).data;
    } catch {
      introspection = { active: true, offline: true }; // Pusat Akun tidak bisa dihubungi: pakai sesi lokal
    }
    if (!introspection.active) {
      sessions.delete(localSid);
      res.clearCookie(COOKIE);
      log('Sesi lokal diakhiri: kunci akses sudah dicabut Pusat Akun');
      return page(res, {
        title: 'Sesi berakhir',
        flow: 'Alur 5 · Kunci akses sudah dibatalkan → sesi layanan diakhiri',
        body: `<div class="card"><h1>Sesi Anda sudah berakhir</h1><p>Pusat Akun telah membatalkan kunci akses untuk sesi ini (Anda sudah keluar).</p>
          <a class="btn" href="/login">Masuk lagi</a></div>`,
      });
    }

    const c = s.claims;
    page(res, {
      title: svc.name, user: c,
      flow: 'Alur 3 · Layanan terbuka',
      body: `<h1>${svc.icon} ${esc(svc.name)}</h1>
        <p class="muted">Halo, ${esc(c.name || c.preferred_username || c.sub)}. Anda masuk lewat Pusat Akun tanpa mengetik password di layanan ini.</p>
        ${content[svc.id](c)}
        <div class="card"><h2>Kartu identitas digital yang diterima layanan ini</h2>
          <dl class="kv">
            <dt>sub (ID pengguna)</dt><dd class="mono">${esc(c.sub)}</dd>
            ${c.email ? `<dt>email</dt><dd>${esc(c.email)}</dd>` : ''}
            ${c.roles ? `<dt>peran</dt><dd>${c.roles.map(esc).join(', ')}</dd>` : ''}
            <dt>diterbitkan oleh</dt><dd>${esc(c.iss)}</dd>
            <dt>untuk layanan</dt><dd>${esc(c.aud)}</dd>
            <dt>tingkat verifikasi</dt><dd>${c.acr === cfg.ACR_MFA ? '<span class="tag ok">Dua langkah (baru)</span>' : '<span class="tag">Password / perangkat tepercaya</span>'} <span class="small muted">${(c.amr || []).map(esc).join(' + ')}</span></dd>
            <dt>waktu masuk</dt><dd>${ui.fmtTime(c.auth_time * 1000)}</dd>
            <dt>sesi Pusat Akun (sid)</dt><dd class="mono small">${esc(c.sid)}</dd>
            <dt>kunci akses</dt><dd>${introspection.offline ? '<span class="tag warn">Tidak dapat dicek</span>' : '<span class="tag ok">Aktif (dicek ke Pusat Akun)</span>'}</dd>
          </dl>
          <details class="small" style="margin-top:12px"><summary>ID token mentah (JWT)</summary><code style="word-break:break-all">${esc(s.idToken)}</code></details>
        </div>`,
    });
  });

  app.get('/login', startLogin);

  // Pusat Akun mengembalikan tiket sekali pakai (atau penolakan) ke sini.
  app.get('/callback', async (req, res) => {
    const { code, state, error, error_description: errorDesc } = req.query;
    const pa = pendingAuth.get(state);
    if (!pa || !sec.safeEqual(pa.browserKey, req.cookies[AUTH_COOKIE] || '') || Date.now() - pa.createdAt > 600_000) {
      return page(res, { title: 'Permintaan tidak valid', status: 400, body: `<div class="card"><h1>Permintaan masuk tidak valid</h1><p>Permintaan kedaluwarsa atau bukan dari browser ini.</p><a class="btn" href="/login">Coba lagi</a></div>` });
    }
    pendingAuth.delete(state);
    res.clearCookie(AUTH_COOKIE);

    if (error) {
      return page(res, {
        title: 'Akses ditolak', status: 403,
        flow: 'Alur 3 · Pusat Akun menolak memberi akses',
        body: `<div class="card"><h1>⛔ Tidak dapat membuka ${esc(svc.name)}</h1>${ui.alert('error', esc(errorDesc || error))}
          <a class="btn secondary" href="${PORTAL}/">Kembali ke Portal</a></div>`,
      });
    }

    // "Layanan menukar tiket menjadi kartu identitas digital"
    let tokens;
    try {
      const r = await idp('/token', { grant_type: 'authorization_code', code, redirect_uri: svc.redirectUri, code_verifier: pa.verifier });
      if (r.status !== 200) return denied(req, res, `Penukaran tiket ditolak: ${r.data.error_description || r.data.error}`);
      tokens = r.data;
    } catch {
      return page(res, { title: 'Gangguan', status: 502, body: `<div class="card"><h1>Pusat Akun tidak dapat dihubungi</h1><a class="btn" href="/login">Coba lagi</a></div>` });
    }

    // "Kartu identitas asli, untuk layanan ini, dan belum kedaluwarsa?"
    let claims;
    try {
      claims = await verifyJwt(tokens.id_token, { issuer: PORTAL, audience: svc.id });
      if (claims.nonce !== pa.nonce) throw new Error('Nonce tidak cocok — kemungkinan token diputar ulang');
      if (svc.sensitive && claims.acr !== cfg.ACR_MFA) throw new Error('Layanan sensitif membutuhkan verifikasi dua langkah yang baru');
    } catch (err) {
      return denied(req, res, err.message, jwt.decode(tokens.id_token)?.payload?.sub);
    }

    // "Layanan mencatat pengguna sebagai sudah masuk di sisinya"
    const localSid = sec.randomToken();
    sessions.set(localSid, { claims, idpSid: claims.sid, sub: claims.sub, accessToken: tokens.access_token, idToken: tokens.id_token, createdAt: Date.now() });
    res.cookie(COOKIE, localSid, { maxAge: 8 * 3600 });
    log(`Sesi dibuat untuk ${claims.email || claims.sub}`);

    // "Pusat Akun mencatat: layanan ini sedang dipakai"
    await idp('/internal/service-session', { sid: claims.sid, sub: claims.sub }).catch(() => {});
    res.redirect('/');
  });

  // Alur 5: "Tiap layanan memeriksa keaslian perintah lalu menutup sesinya"
  app.post('/backchannel-logout', async (req, res) => {
    if (failNext > 0) {
      failNext--;
      log(`Simulasi gangguan: menolak perintah keluar (sisa ${failNext})`);
      return res.json({ error: 'temporarily_unavailable' }, 503);
    }
    try {
      const c = await verifyJwt(req.body.logout_token, { issuer: PORTAL, audience: svc.id, typ: 'logout+jwt' });
      if (!c.events || !(cfg.BACKCHANNEL_LOGOUT_EVENT in c.events)) throw new Error('Bukan perintah keluar');
      if ('nonce' in c) throw new Error('Perintah keluar tidak boleh berisi nonce');
      if (!c.sid && !c.sub) throw new Error('Perintah keluar tanpa sid/sub');
      if (!c.jti || seenLogoutJti.has(c.jti)) throw new Error('Perintah keluar diputar ulang');
      if (Math.floor(Date.now() / 1000) - c.iat > 300) throw new Error('Perintah keluar terlalu lama');
      seenLogoutJti.set(c.jti, Date.now());

      let closed = 0;
      for (const [k, s] of sessions) {
        if (c.sid ? s.idpSid === c.sid : s.sub === c.sub) { sessions.delete(k); closed++; }
      }
      log(`Perintah keluar sah dari Pusat Akun: ${closed} sesi ditutup`);
      res.json({ ok: true, closed });
    } catch (err) {
      log(`Perintah keluar DITOLAK: ${err.message}`);
      res.json({ error: 'invalid_request', error_description: err.message }, 400);
    }
  });

  // ---- Alat bantu demo ----
  app.get('/demo/state', (req, res) => res.json({ failNext, sessions: sessions.size }));
  app.post('/demo/control', (req, res) => {
    failNext = Math.max(0, Number(req.body.failNext) || 0);
    log(`Simulasi: perintah keluar akan gagal ${failNext} kali berikutnya`);
    res.json({ failNext });
  });

  // Penyerang mengirim "kartu identitas" buatan sendiri (ditandatangani kunci palsu).
  let attackerKey = null;
  app.get('/demo/forged', async (req, res) => {
    attackerKey ||= crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
    const realKid = (await getJwks()).keys[0].kid;
    const now = Math.floor(Date.now() / 1000);
    const forged = jwt.sign({ iss: PORTAL, sub: 'u-andi', aud: svc.id, iat: now, exp: now + 300, email: 'andi@contoh.id', acr: cfg.ACR_MFA }, attackerKey, realKid);
    try {
      await verifyJwt(forged, { issuer: PORTAL, audience: svc.id });
      page(res, { title: 'Aneh', body: '<p>Token palsu diterima?!</p>' });
    } catch (err) {
      await denied(req, res, `Token palsu terdeteksi: ${err.message}`, 'u-andi');
    }
  });

  return app;
}

module.exports = { createService };
