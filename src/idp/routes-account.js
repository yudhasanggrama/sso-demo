'use strict';
// Alur 4 (menu foto profil: tambah/ganti/kelola akun) dan Alur 5 (keluar).
const cfg = require('../config');
const sec = require('../lib/security');
const ui = require('../lib/ui');
const store = require('./store');
const core = require('./core');

const { esc } = ui;

const ACCOUNT_MESSAGES = {
  '2fa_added': ['ok', 'Metode verifikasi dua langkah ditambahkan.'],
  '2fa_disabled': ['warn', 'Verifikasi dua langkah dimatikan.'],
  profile: ['ok', 'Profil disimpan.'],
  password: ['ok', 'Password diganti.'],
  password_wrong: ['error', 'Password lama salah.'],
  password_short: ['error', 'Password baru minimal 8 karakter.'],
  device_revoked: ['ok', 'Perangkat tidak lagi dipercaya.'],
  consent_revoked: ['ok', 'Persetujuan dicabut. Layanan akan meminta persetujuan lagi.'],
  session_revoked: ['ok', 'Sesi di perangkat lain sudah dikeluarkan.'],
};

module.exports = function registerAccountRoutes(app) {
  const requireUser = (req, res) => {
    const bs = core.loadBS(req);
    const user = core.activeUser(bs);
    if (!user) { res.redirect('/'); return null; }
    return { bs, user, acct: core.activeAccount(bs) };
  };

  // ---- Ganti akun: tentukan akun → muat ulang daftar layanan → sesuaikan layanan yang terbuka ----
  app.post('/switch', async (req, res) => {
    const bs = core.loadBS(req);
    const acct = bs?.accounts.find(a => a.userId === req.body.userId);
    if (!acct) return res.redirect('/');
    bs.activeUserId = acct.userId;
    const closed = await core.alignServiceSessions(bs);
    core.audit(req, acct.userId, 'info', 'Beralih ke akun ini', closed ? `${closed} sesi layanan akun sebelumnya ditutup` : '');
    res.redirect(`/?msg=switched${closed ? `&closed=${closed}` : ''}`);
  });

  // ---- Kelola akun: profil, keamanan, perangkat, verifikasi dua langkah, sesi aktif ----
  app.get('/account', (req, res) => {
    const c = requireUser(req, res);
    if (!c) return;
    const { bs, user } = c;
    const msg = ACCOUNT_MESSAGES[req.query.msg];
    const m = user.twoFa?.methods || {};
    const now = Date.now();
    const myDevice = req.cookies[core.DEV_COOKIE] && sec.sha256(req.cookies[core.DEV_COOKIE]);

    const methodRows = Object.entries(m).map(([k, v]) =>
      `<tr><td>${esc(core.METHOD_LABEL[k])}</td><td class="small">${k === 'sms' ? esc(v.phoneMasked) : k === 'passkey' ? 'Kunci di browser ini' : 'Terdaftar'}</td><td class="small">${ui.fmtTime(v.addedAt)}</td></tr>`).join('');
    const backupLeft = user.twoFa ? user.twoFa.backupCodes.filter(b => !b.usedAt).length : 0;
    const missing = ['totp', 'passkey', 'sms'].filter(k => !m[k]);

    const devices = user.trustedDevices.filter(d => d.expiresAt > now).map(d =>
      `<tr><td>${esc(d.label)} ${d.deviceHash === myDevice ? '<span class="tag info">Perangkat ini</span>' : ''}</td><td class="small">${esc(d.location)}</td><td class="small">s.d. ${ui.fmtTime(d.expiresAt)}</td>
       <td><form method="post" action="/account/devices/revoke"><input type="hidden" name="id" value="${esc(d.id)}"><button class="sm ghost">Hapus</button></form></td></tr>`).join('');

    const sessions = [...store.browserSessions.values()].filter(b => b.accounts.some(a => a.userId === user.id)).map(b => {
      const a = b.accounts.find(x => x.userId === user.id);
      const svc = store.serviceSessions.filter(s => s.sid === a.sid).map(s => cfg.clients[s.clientId].name);
      const current = b.id === bs.id;
      return `<tr><td>${esc(core.deviceLabel(b.ua))} ${current ? '<span class="tag info">Browser ini</span>' : ''}<br><span class="small muted">${esc(core.locationOf(b.ip))}</span></td>
        <td class="small">Masuk ${ui.fmtTime(a.authTime)}<br>Aktif ${ui.fmtTime(b.lastSeen)}</td>
        <td class="small">${svc.length ? svc.map(esc).join(', ') : '—'}</td>
        <td>${current ? '<a class="btn sm ghost" href="/logout">Keluar</a>' : `<form method="post" action="/account/sessions/revoke"><input type="hidden" name="bsId" value="${esc(b.id)}"><button class="sm danger">Keluarkan</button></form>`}</td></tr>`;
    }).join('');

    const consents = Object.entries(user.consents).map(([cid, scopes]) =>
      `<tr><td>${esc(cfg.clients[cid]?.name || cid)}</td><td class="small">${scopes.map(s => esc(core.SCOPE_LABEL[s] || s)).join('; ')}</td>
       <td><form method="post" action="/account/consents/revoke"><input type="hidden" name="clientId" value="${esc(cid)}"><button class="sm ghost">Cabut</button></form></td></tr>`).join('');

    const history = store.audit.filter(e => e.userId === user.id).slice(0, 25).map(e =>
      `<tr><td class="small">${ui.fmtTime(e.at)}</td><td class="lvl-${e.level}">${esc(e.title)}</td><td class="small muted">${esc(e.detail)}</td></tr>`).join('');

    res.html(core.view(bs, {
      title: 'Kelola akun',
      flow: 'Alur 4 · Kelola akun → halaman pengaturan',
      body: `${msg ? ui.alert(msg[0], msg[1]) : ''}
      <div class="row" style="margin-bottom:16px">${ui.avatar(user, 56)}<div><h1 style="margin:0">${esc(user.name)}</h1><span class="muted">${esc(user.email)} · ${esc(user.org.name)}</span></div></div>
      <div class="two">
        <div class="card" id="profil"><h2>Profil</h2>
          <form method="post" action="/account/profile"><label for="name">Nama</label><input id="name" name="name" type="text" value="${esc(user.name)}" maxlength="60" required>
          <p class="small muted">Nama pengguna: ${esc(user.username)} · Peran: ${user.roles.map(esc).join(', ')}</p><button class="sm">Simpan</button></form></div>
        <div class="card" id="keamanan"><h2>Keamanan</h2>
          <form method="post" action="/account/password">
            <label for="cur">Password lama</label><input id="cur" name="current" type="password" autocomplete="current-password" required>
            <label for="new">Password baru</label><input id="new" name="password" type="password" minlength="8" autocomplete="new-password" required>
            <div style="margin-top:12px"><button class="sm">Ganti password</button></div></form></div>
      </div>
      <div class="card" id="dua-langkah"><h2>Verifikasi dua langkah ${core.hasTwoFa(user) ? '<span class="tag ok">Aktif</span>' : '<span class="tag err">Belum aktif</span>'}</h2>
        ${user.org.require2fa ? `<p class="small muted">${esc(user.org.name)} mewajibkan verifikasi dua langkah.</p>` : ''}
        ${!core.hasTwoFa(user) && user.twoFaDeferredAt ? `<p class="small muted">Ditunda pada ${ui.fmtTime(user.twoFaDeferredAt)}.</p>` : ''}
        ${methodRows ? `<div class="table-wrap"><table><tr><th>Metode</th><th>Keterangan</th><th>Ditambahkan</th></tr>${methodRows}</table></div>
          <p class="small">Kode cadangan tersisa: <strong>${backupLeft}</strong></p>` : ''}
        <div class="row">
          ${missing.length ? `<a class="btn sm" href="/account/2fa/add">${core.hasTwoFa(user) ? 'Tambah metode' : 'Aktifkan'}</a>` : ''}
          ${core.hasTwoFa(user) ? `<form method="post" action="/account/2fa/backup-codes"><button class="sm secondary">Buat kode cadangan baru</button></form>` : ''}
          ${core.hasTwoFa(user) && !user.org.require2fa ? `<form method="post" action="/account/2fa/disable"><button class="sm danger">Matikan</button></form>` : ''}
        </div></div>
      <div class="card" id="perangkat"><h2>Perangkat tepercaya</h2>
        ${devices ? `<div class="table-wrap"><table><tr><th>Perangkat</th><th>Lokasi</th><th>Berlaku</th><th></th></tr>${devices}</table></div>` : '<p class="muted small">Belum ada perangkat tepercaya.</p>'}</div>
      <div class="card" id="sesi"><h2>Sesi aktif</h2>
        <div class="table-wrap"><table><tr><th>Perangkat</th><th>Waktu</th><th>Layanan terbuka</th><th></th></tr>${sessions}</table></div></div>
      <div class="card" id="persetujuan"><h2>Layanan yang Anda beri akses</h2>
        ${consents ? `<div class="table-wrap"><table><tr><th>Layanan</th><th>Data</th><th></th></tr>${consents}</table></div>` : '<p class="muted small">Belum ada.</p>'}</div>
      <div class="card" id="riwayat"><h2>Riwayat keamanan</h2>
        <div class="table-wrap"><table><tr><th>Waktu</th><th>Kejadian</th><th>Rincian</th></tr>${history}</table></div></div>`,
    }));
  });

  app.post('/account/profile', (req, res) => {
    const c = requireUser(req, res);
    if (!c) return;
    const name = String(req.body.name || '').trim().slice(0, 60);
    if (name) c.user.name = name;
    res.redirect('/account?msg=profile');
  });

  app.post('/account/password', (req, res) => {
    const c = requireUser(req, res);
    if (!c) return;
    const { user } = c;
    if (!sec.verifyPassword(req.body.current || '', user.passwordHash)) {
      core.audit(req, user.id, 'warn', 'Gagal mengganti password', 'Password lama salah');
      return res.redirect('/account?msg=password_wrong#keamanan');
    }
    const pw = String(req.body.password || '');
    if (pw.length < 8) return res.redirect('/account?msg=password_short#keamanan');
    user.passwordHash = sec.hashPassword(pw);
    store.demo.passwords[user.id] = pw;
    core.audit(req, user.id, 'warn', 'Password diganti');
    res.redirect('/account?msg=password');
  });

  app.get('/account/2fa/add', (req, res) => {
    const c = requireUser(req, res);
    if (!c) return;
    c.bs.pending = { purpose: 'settings', stage: 'enroll', userId: c.user.id, mandatory: false };
    res.redirect('/2fa/enroll');
  });

  app.post('/account/2fa/backup-codes', (req, res) => {
    const c = requireUser(req, res);
    if (!c || !core.hasTwoFa(c.user)) return res.redirect('/account');
    const codes = sec.makeBackupCodes();
    c.user.twoFa.backupCodes = codes.map(code => ({ hash: sec.sha256(code), usedAt: null }));
    delete store.demo.backupCodes[c.user.id];
    core.audit(req, c.user.id, 'warn', 'Kode cadangan dibuat ulang', 'Kode lama tidak berlaku');
    res.html(core.view(c.bs, {
      title: 'Kode cadangan baru', narrow: true, flow: 'Alur 4 · Kelola akun → kode cadangan',
      body: `<div class="card"><h1>Kode cadangan baru</h1><p class="small muted">Kode lama tidak berlaku lagi. Simpan kode ini; tidak akan ditampilkan lagi.</p>
        <div class="codes">${codes.map(k => `<span>${k}</span>`).join('')}</div><a class="btn block" href="/account#dua-langkah">Selesai</a></div>`,
    }));
  });

  app.post('/account/2fa/disable', (req, res) => {
    const c = requireUser(req, res);
    if (!c) return;
    if (c.user.org.require2fa) return res.redirect('/account#dua-langkah');
    c.user.twoFa = null;
    c.user.trustedDevices = [];
    core.audit(req, c.user.id, 'critical', 'Verifikasi dua langkah dimatikan', 'Semua perangkat tepercaya dihapus');
    res.redirect('/account?msg=2fa_disabled#dua-langkah');
  });

  app.post('/account/devices/revoke', (req, res) => {
    const c = requireUser(req, res);
    if (!c) return;
    const d = c.user.trustedDevices.find(x => x.id === req.body.id);
    c.user.trustedDevices = c.user.trustedDevices.filter(x => x.id !== req.body.id);
    if (d) core.audit(req, c.user.id, 'warn', 'Perangkat tepercaya dihapus', d.label);
    res.redirect('/account?msg=device_revoked#perangkat');
  });

  app.post('/account/consents/revoke', (req, res) => {
    const c = requireUser(req, res);
    if (!c) return;
    const client = cfg.clients[req.body.clientId];
    delete c.user.consents[req.body.clientId];
    if (client) core.audit(req, c.user.id, 'info', `Persetujuan untuk ${client.name} dicabut`);
    res.redirect('/account?msg=consent_revoked#persetujuan');
  });

  // Keluarkan akun ini dari browser/perangkat lain (logout jarak jauh, memakai mekanisme Alur 5).
  app.post('/account/sessions/revoke', async (req, res) => {
    const c = requireUser(req, res);
    if (!c) return;
    const other = store.browserSessions.get(req.body.bsId);
    const acct = other?.accounts.find(a => a.userId === c.user.id);
    if (!acct || other.id === c.bs.id) return res.redirect('/account#sesi');
    other.accounts = other.accounts.filter(a => a !== acct);
    if (other.activeUserId === c.user.id) other.activeUserId = other.accounts[0]?.userId ?? null;
    await core.logoutAccounts(req, [acct], `Dikeluarkan dari ${core.deviceLabel(other.ua)} (jarak jauh)`);
    res.redirect('/account?msg=session_revoked#sesi');
  });

  // ===================== ALUR 5 =====================

  // D dari Alur 4 → "Keluar dari mana?"
  app.get('/logout', (req, res) => {
    const c = requireUser(req, res);
    if (!c) return;
    const { bs, user } = c;
    const n = bs.accounts.length;
    res.html(core.view(bs, {
      title: 'Keluar', narrow: true,
      flow: 'Alur 5 · Keluar dari mana?',
      body: `<div class="card"><h1>Keluar</h1>
        <form method="post" action="/logout">
          <button class="choice" name="scope" value="one"><span class="ic">${ui.avatar(user, 32)}</span><span><strong>Akun ini saja</strong><br><span class="small muted">${esc(user.email)} keluar. ${n > 1 ? `${n - 1} akun lain tetap masuk.` : ''}</span></span></button>
          ${n > 1 ? `<button class="choice" name="scope" value="all"><span class="ic">👥</span><span><strong>Semua akun (${n})</strong><br><span class="small muted">Hapus seluruh penanda pada browser ini.</span></span></button>` : ''}
        </form>
        <p class="small muted">Semua layanan yang sedang terbuka akan ditutup langsung dari server Pusat Akun, dan semua kunci akses dicabut.</p>
        <a class="small" href="/">Batal</a></div>`,
    }));
  });

  app.post('/logout', async (req, res) => {
    const c = requireUser(req, res);
    if (!c) return;
    const { bs } = c;
    const all = req.body.scope === 'all';
    const targets = all ? [...bs.accounts] : bs.accounts.filter(a => a.userId === bs.activeUserId);
    const names = targets.map(a => store.users.get(a.userId)?.email);

    // "Hapus penanda akun terpilih, akun lain tetap masuk" / "Hapus seluruh penanda pada browser ini"
    bs.accounts = bs.accounts.filter(a => !targets.includes(a));
    bs.activeUserId = bs.accounts[0]?.userId ?? null;
    bs.pending = null;
    if (!bs.accounts.length) {
      store.browserSessions.delete(bs.id);
      res.clearCookie(core.BS_COOKIE);
    }

    const { results, revoked } = await core.logoutAccounts(req, targets, all ? 'Keluar (semua akun)' : 'Keluar');

    // "Masih ada akun lain yang masuk?" — Ya → B, Tidak → mode tamu
    const remaining = bs.accounts.length ? store.users.get(bs.activeUserId) : null;
    const rows = results.map(r => `<tr><td>${esc(r.name)}</td><td>${r.ok
      ? `<span class="tag ok">Tertutup</span> <span class="small muted">${r.attempts > 1 ? `setelah ${r.attempts} percobaan` : ''}</span>`
      : `<span class="tag err">Gagal</span> <span class="small muted">${esc(r.error)} · ${r.attempts} percobaan · dicatat untuk ditindaklanjuti</span>`}</td></tr>`).join('');

    res.html(core.view(remaining ? bs : null, {
      title: 'Keluar selesai', narrow: true,
      flow: `Alur 5 · ${remaining ? 'Masih ada akun lain → B ke Alur 3' : 'Selesai → halaman kembali ke mode tamu'}`,
      body: `<div class="card"><h1>✅ Anda sudah keluar</h1>
        <p class="small">${names.map(esc).join(', ')}</p>
        <h3>Perintah keluar ke layanan (langsung antar server)</h3>
        ${rows ? `<table>${rows}</table>` : '<p class="small muted">Tidak ada layanan yang sedang terbuka.</p>'}
        <p class="small muted">${revoked} kunci akses dibatalkan. Kejadian dicatat di riwayat keamanan.
        ${results.some(r => !r.ok) ? 'Layanan yang gagal dihubungi tetap tidak bisa memakai kunci akses lama — sesinya akan berakhir saat layanan memeriksa kunci tersebut.' : ''}</p>
        ${remaining
          ? `${ui.alert('info', `Masih masuk sebagai <strong>${esc(remaining.email)}</strong>.`)}<a class="btn block" href="/">Ke Halaman Utama</a>`
          : '<a class="btn block" href="/">Selesai</a>'}
      </div>`,
    }));
  });
};
