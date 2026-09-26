'use strict';
// Alur 3: Halaman Utama, lalu pertukaran identitas dengan layanan (OpenID Connect, authorization code + PKCE).
const cfg = require('../config');
const sec = require('../lib/security');
const ui = require('../lib/ui');
const store = require('./store');
const core = require('./core');

const { esc } = ui;
const { policy } = cfg;

const MESSAGES = {
  consent_rejected: ['info', 'Anda menolak berbagi data. Layanan tidak dibuka.'],
  switched: ['ok', 'Akun diganti. Daftar layanan dimuat ulang sesuai hak akun ini.'],
  password_reset: ['ok', 'Password berhasil diatur ulang dan akun dibuka kembali. Silakan masuk.'],
  logged_out_one: ['ok', 'Akun tadi sudah keluar. Akun lain di browser ini tetap masuk.'],
};

const isFreshMfa = acct => !!acct.mfaTime && Date.now() - acct.mfaTime < policy.stepUpMaxAgeMs;

function authClient(req) {
  let id = req.body.client_id, secret = req.body.client_secret;
  const basic = /^Basic (.+)$/.exec(req.headers.authorization || '');
  if (basic) [id, secret] = Buffer.from(basic[1], 'base64').toString().split(':');
  const client = cfg.clients[id];
  return client && sec.safeEqual(secret || '', client.secret) ? client : null;
}

module.exports = function registerOidcRoutes(app) {
  // ---- Mulai: pengguna membuka Portal → "Masih dikenali dari kunjungan sebelumnya?" ----
  app.get('/', async (req, res) => {
    const bs = await core.loadBS(req);
    const msg = MESSAGES[req.query.msg];
    if (!bs || !bs.accounts.length) {
      return res.html(await core.view(bs, {
        title: 'Selamat datang', narrow: true,
        flow: 'Alur 1 · Tidak dikenali → halaman mode tamu, hanya ada tombol Masuk',
        body: `${msg ? ui.alert(msg[0], msg[1]) : ''}<div class="card" style="text-align:center">
          <div style="font-size:44px">🔑</div><h1>Portal Layanan</h1>
          <p class="muted">Masuk sekali untuk membuka semua layanan: ${cfg.services.map(s => esc(s.name)).join(', ')}.</p>
          <a class="btn block" href="/login">Masuk</a></div>`,
      }));
    }
    renderHome(req, res, bs, msg);
  });

  // B → Halaman Utama: grid layanan dan foto profil
  async function renderHome(req, res, bs, msg) {
    const user = await core.activeUser(bs);
    const acct = core.activeAccount(bs);
    const visible = cfg.services.filter(s => !s.requiredRole || user.roles.includes(s.requiredRole));
    // (grid 3x3 di header memakai core.visibleServices; grid di badan halaman ini dibuat lebih kaya, dengan deskripsi dan status)
    const hidden = cfg.services.length - visible.length;
    const openList = await store.serviceSessionsBySid(acct.sid);
    const open = new Set(openList.map(s => s.clientId));
    const tiles = visible.map(s => `<a class="tile" href="${s.url}/" style="--c:${s.color}">
        <span class="tile-icon">${s.icon}</span><strong>${esc(s.name)}</strong><span class="muted small">${esc(s.description)}</span>
        <span class="tags">${s.sensitive ? '<span class="tag warn">Sensitif · minta kode lagi</span>' : ''}${open.has(s.id) ? '<span class="tag ok">Sedang terbuka</span>' : ''}${user.consents[s.id] ? '' : '<span class="tag">Perlu persetujuan</span>'}</span></a>`).join('');
    const closed = Number(req.query.closed) || 0;
    const prev = user.previousLogin;

    res.html(await core.view(bs, {
      title: 'Halaman Utama',
      flow: 'Alur 3 · Halaman Utama → pengguna mengklik apa? (ikon layanan / foto profil)',
      body: `${msg ? ui.alert(msg[0], msg[1] + (closed ? ` ${closed} sesi layanan milik akun sebelumnya ditutup agar akun tidak tertukar.` : '')) : ''}
        ${core.hasTwoFa(user) ? '' : ui.alert('warn', `Verifikasi dua langkah belum aktif${user.twoFaDeferredAt ? ' (ditunda)' : ''}. <a href="/account/2fa/add">Aktifkan sekarang</a>`)}
        <h1>Halo, ${esc(user.name.split(' ')[0])} 👋</h1>
        <p class="muted">Klik layanan untuk membukanya — Anda tidak perlu masuk lagi. Klik foto profil di kanan atas untuk menu akun.</p>
        <div class="grid">${tiles}</div>
        ${hidden ? `<p class="muted small">${hidden} layanan tidak ditampilkan karena akun ini tidak memiliki haknya.</p>` : ''}
        <div class="card"><h2>Aktivitas masuk</h2><dl class="kv">
          <dt>Sesi ini</dt><dd>${ui.fmtTime(acct.authTime)} · ${esc(user.lastLogin?.device)} · ${esc(user.lastLogin?.location)}</dd>
          <dt>Metode</dt><dd>${acct.amr.map(m => esc(core.METHOD_LABEL[m] || m)).join(' + ')}${isFreshMfa(acct) ? ' <span class="tag ok">2FA baru saja</span>' : ''}</dd>
          <dt>Sebelumnya</dt><dd>${prev ? `${ui.fmtTime(prev.at)} · ${esc(prev.device)} · ${esc(prev.location)}` : '—'}</dd>
          <dt>Akun di browser ini</dt><dd>${bs.accounts.length}</dd></dl></div>`,
    }));
  }

  // ---- Discovery & kunci publik ----
  app.get('/.well-known/openid-configuration', (req, res) => res.json({
    issuer: core.ISSUER,
    authorization_endpoint: `${core.ISSUER}/authorize`,
    token_endpoint: `${core.ISSUER}/token`,
    userinfo_endpoint: `${core.ISSUER}/userinfo`,
    introspection_endpoint: `${core.ISSUER}/introspect`,
    jwks_uri: `${core.ISSUER}/jwks`,
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256'],
    id_token_signing_alg_values_supported: ['RS256'],
    backchannel_logout_supported: true,
    backchannel_logout_session_supported: true,
  }));
  app.get('/jwks', (req, res) => res.json(core.jwks));

  // ---- "Layanan bertanya ke Pusat Akun: siapa pengguna ini?" ----
  app.get('/authorize', async (req, res) => {
    const q = req.query;
    const client = cfg.clients[q.client_id];
    const bs = await core.loadBS(req);
    if (!client || q.redirect_uri !== client.redirectUri) {
      return core.errorPage(res, bs, 'Permintaan tidak valid', 'Layanan tidak terdaftar atau alamat kembali tidak cocok.');
    }
    const back = params => res.redirect(`${client.redirectUri}?${new URLSearchParams({ ...params, state: q.state || '' })}`);
    const scopes = String(q.scope || '').split(' ').filter(Boolean);
    if (q.response_type !== 'code') return back({ error: 'unsupported_response_type' });
    if (!q.code_challenge || q.code_challenge_method !== 'S256') return back({ error: 'invalid_request', error_description: 'PKCE (S256) wajib' });
    if (!scopes.includes('openid') || scopes.some(s => !client.scopes.includes(s))) return back({ error: 'invalid_scope' });

    // "Pusat Akun masih mengenali pengguna?" — Tidak → C ke Alur 1
    const acct = core.activeAccount(bs);
    if (!acct) return res.redirect(`/login?return=${encodeURIComponent(req.url)}`);
    const user = await store.getUser(acct.userId);

    if (client.requiredRole && !user.roles.includes(client.requiredRole)) {
      await core.audit(req, user.id, 'warn', `Akses ke ${client.name} ditolak`, 'Akun tidak memiliki hak');
      return back({ error: 'access_denied', error_description: `Akun ${user.email} tidak memiliki hak untuk layanan ini.` });
    }

    // "Layanan ini sensitif?" — Ya → minta kode verifikasi lagi walaupun sudah masuk
    if (client.sensitive && !isFreshMfa(acct)) {
      const enrolled = core.hasTwoFa(user);
      bs.pending = { purpose: 'stepup', stage: enrolled ? 'verify' : 'enroll', mandatory: true, userId: user.id, returnTo: req.url, clientName: client.name };
      await core.persist({ bs });
      return res.redirect(enrolled ? '/2fa/verify' : '/2fa/enroll');
    }

    // "Pengguna pernah menyetujui data yang akan dibagikan?"
    const granted = user.consents[client.id] || [];
    if (!scopes.every(s => granted.includes(s))) {
      return res.html(await core.view(bs, {
        title: 'Persetujuan', narrow: true,
        flow: 'Alur 3 · Belum pernah menyetujui → halaman persetujuan',
        body: `<div class="card"><div style="font-size:36px">${client.icon}</div>
          <h1>${esc(client.name)} ingin mengakses akun Anda</h1>
          <div class="row">${ui.avatar(user, 28)}<span class="small">${esc(user.email)}</span></div>
          <h3>Data yang akan dibagikan</h3>
          <ul>${scopes.map(s => `<li>${esc(core.SCOPE_LABEL[s] || s)}</li>`).join('')}</ul>
          <p class="small muted">Persetujuan ini diingat. Anda dapat mencabutnya di Kelola akun.</p>
          <form method="post" action="/consent" class="row">
            <input type="hidden" name="return" value="${esc(req.url)}">
            <button name="decision" value="allow">Setuju</button>
            <button name="decision" value="deny" class="secondary">Tolak</button>
          </form></div>`,
      }));
    }

    // "Pusat Akun memberi tiket sekali pakai, masa berlaku sangat singkat"
    const code = sec.randomToken(32);
    await store.setAuthCode(code, {
      clientId: client.id, userId: user.id, sid: acct.sid, redirectUri: client.redirectUri, scopes,
      nonce: q.nonce, codeChallenge: q.code_challenge, expiresAt: Date.now() + policy.authCodeTtlMs, used: false,
      authTime: acct.authTime, acr: isFreshMfa(acct) ? cfg.ACR_MFA : cfg.ACR_PWD, amr: acct.amr,
    });
    back({ code });
  });

  app.post('/consent', async (req, res) => {
    const bs = await core.loadBS(req);
    const user = await core.activeUser(bs);
    const ret = String(req.body.return || '');
    if (!user || !ret.startsWith('/authorize?')) return res.redirect('/');
    const params = new URL(ret, core.ISSUER).searchParams;
    const client = cfg.clients[params.get('client_id')];
    if (!client) return res.redirect('/');
    if (req.body.decision === 'allow') {
      const scopes = (params.get('scope') || '').split(' ').filter(s => client.scopes.includes(s));
      user.consents[client.id] = [...new Set([...(user.consents[client.id] || []), ...scopes])];
      await core.audit(req, user.id, 'info', `Menyetujui berbagi data dengan ${client.name}`, scopes.join(', '));
      await core.persist({ user });
      return res.redirect(ret);
    }
    // Tolak → 1 (kembali ke Halaman Utama)
    await core.audit(req, user.id, 'info', `Menolak berbagi data dengan ${client.name}`);
    res.redirect('/?msg=consent_rejected');
  });

  // ---- "Layanan menukar tiket menjadi kartu identitas digital" (antar server) ----
  app.post('/token', async (req, res) => {
    const client = authClient(req);
    if (!client) return res.json({ error: 'invalid_client' }, 401);
    if (req.body.grant_type !== 'authorization_code') return res.json({ error: 'unsupported_grant_type' }, 400);
    const bad = desc => res.json({ error: 'invalid_grant', error_description: desc }, 400);

    const code = String(req.body.code || '');
    const rec = await store.getAuthCode(code);
    if (!rec) return bad('Tiket tidak dikenal');
    if (rec.used) {
      // Tiket dipakai dua kali: tanda pencurian. Cabut semua yang pernah diterbitkan dari tiket ini.
      await core.revokeTokens(t => t.fromCode === code);
      await store.addAudit({ userId: rec.userId, level: 'critical', title: 'Tiket sekali pakai dipakai ulang', detail: `Layanan ${client.name}; kunci akses terkait dicabut` });
      return bad('Tiket sudah pernah dipakai');
    }
    rec.used = true;
    await store.updateAuthCode(code, rec);
    if (rec.expiresAt < Date.now()) return bad('Tiket sudah kedaluwarsa');
    if (rec.clientId !== client.id || rec.redirectUri !== req.body.redirect_uri) return bad('Tiket bukan untuk layanan ini');
    if (sec.sha256(req.body.code_verifier || '') !== rec.codeChallenge) return bad('Verifikasi PKCE gagal');
    const user = await store.getUser(rec.userId);
    if (user?.status !== 'active') return bad('Akun tidak aktif');

    const now = Math.floor(Date.now() / 1000);
    const accessToken = sec.randomToken(32);
    await store.setAccessToken(accessToken, {
      clientId: client.id, userId: user.id, sid: rec.sid, scopes: rec.scopes, fromCode: code,
      issuedAt: Date.now(), expiresAt: Date.now() + policy.accessTokenTtlSec * 1000, revoked: false,
    });

    const claims = { iss: core.ISSUER, sub: user.id, aud: client.id, iat: now, exp: now + policy.idTokenTtlSec, auth_time: Math.floor(rec.authTime / 1000), nonce: rec.nonce, sid: rec.sid, acr: rec.acr, amr: rec.amr };
    if (rec.scopes.includes('profile')) Object.assign(claims, { name: user.name, preferred_username: user.username });
    if (rec.scopes.includes('email')) Object.assign(claims, { email: user.email, email_verified: true });
    if (rec.scopes.includes('keuangan')) claims.roles = user.roles;

    res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: policy.accessTokenTtlSec, scope: rec.scopes.join(' '), id_token: core.signToken(claims) });
  });

  // Layanan memeriksa apakah kunci akses masih berlaku (dipakai setiap kali halaman layanan dibuka).
  app.post('/introspect', async (req, res) => {
    const client = authClient(req);
    if (!client) return res.json({ error: 'invalid_client' }, 401);
    const t = await store.getAccessToken(String(req.body.token || ''));
    if (!t || t.revoked || t.expiresAt < Date.now() || t.clientId !== client.id) return res.json({ active: false });
    res.json({ active: true, sub: t.userId, client_id: t.clientId, scope: t.scopes.join(' '), sid: t.sid, exp: Math.floor(t.expiresAt / 1000) });
  });

  app.get('/userinfo', async (req, res) => {
    const token = /^Bearer (.+)$/.exec(req.headers.authorization || '')?.[1];
    const t = token && await store.getAccessToken(token);
    if (!t || t.revoked || t.expiresAt < Date.now()) return res.json({ error: 'invalid_token' }, 401);
    const u = await store.getUser(t.userId);
    const out = { sub: u.id };
    if (t.scopes.includes('profile')) Object.assign(out, { name: u.name, preferred_username: u.username });
    if (t.scopes.includes('email')) Object.assign(out, { email: u.email, email_verified: true });
    if (t.scopes.includes('keuangan')) out.roles = u.roles;
    res.json(out);
  });

  // "Pusat Akun mencatat: layanan ini sedang dipakai"
  app.post('/internal/service-session', async (req, res) => {
    const client = authClient(req);
    if (!client) return res.json({ error: 'invalid_client' }, 401);
    const { sid, sub } = req.body;
    const bs = await store.findBSBySid(sid);
    if (!bs || !bs.accounts.some(a => a.sid === sid && a.userId === sub)) return res.json({ error: 'unknown_session' }, 400);
    await store.addServiceSession({ sid, clientId: client.id, userId: sub, bsId: bs.id, since: Date.now() });
    await store.addAudit({ userId: sub, level: 'info', title: `Layanan ${client.name} dibuka`, detail: 'Tercatat sebagai layanan yang sedang dipakai' });
    res.json({ ok: true });
  });

  // Alur 3a · Header Bersama: layanan meminta data untuk merender grid 3x3 + avatar yang
  // markup-nya identik dengan Portal (posisi dan tampilan sama di setiap halaman).
  app.post('/internal/header', async (req, res) => {
    const client = authClient(req);
    if (!client) return res.json({ error: 'invalid_client' }, 401);
    const sid = String(req.body.sid || '');
    const bs = await store.findBSBySid(sid);
    const acct = bs?.accounts.find(a => a.sid === sid);
    const user = acct && await store.getUser(acct.userId);
    if (!bs || !user || user.status !== 'active') return res.json({ error: 'unknown_session' }, 404);
    const accountUsers = await Promise.all(bs.accounts.map(a => store.getUser(a.userId)));
    const accounts = accountUsers.filter(Boolean).map(u => ({ id: u.id, name: u.name, email: u.email }));
    res.json({ user: { id: user.id, name: user.name, email: user.email }, services: core.visibleServices(user), accounts });
  });

  // "Akses ditolak dan dicatat sebagai insiden keamanan"
  app.post('/internal/incident', async (req, res) => {
    const client = authClient(req);
    if (!client) return res.json({ error: 'invalid_client' }, 401);
    const sub = await store.hasUser(req.body.sub) ? req.body.sub : null;
    await store.addAudit({ userId: sub, level: 'critical', title: `Insiden keamanan di layanan ${client.name}`, detail: String(req.body.reason || '').slice(0, 200), ip: req.body.ip, ua: req.body.ua });
    res.json({ ok: true });
  });
};
