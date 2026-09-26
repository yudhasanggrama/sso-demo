'use strict';
// Panel Admin — di luar 5 alur SSO: IdP butuh cara mengelola akun (daftar, unlock, hapus)
// tanpa harus masuk sebagai salah satu pengguna. Sesi admin terpisah dari sesi pengguna (pa_bs).
const sec = require('../lib/security');
const ui = require('../lib/ui');
const db = require('../db/mysql');
const redis = require('../db/redis');
const store = require('./store');
const core = require('./core');

const { esc } = ui;
const ADMIN_COOKIE = 'pa_admin';
const SESSION_TTL_SEC = 8 * 3600;
const BRAND = { name: 'Admin — Pusat Akun', logo: '⚙', color: '#7c3aed', home: '/admin' };

function page({ title, body, right = '', narrow = false }) {
  return ui.page({ title, brand: BRAND, body, right, narrow });
}

async function currentAdmin(req) {
  const token = req.cookies[ADMIN_COOKIE];
  if (!token) return null;
  return redis.client.get(`sso:admin_session:${token}`);
}

module.exports = function registerAdminRoutes(app) {
  const requireAdmin = async (req, res) => {
    const username = await currentAdmin(req);
    if (!username) { res.redirect('/admin/login'); return null; }
    return username;
  };

  app.get('/admin/login', (req, res) => {
    const error = req.query.error === '1';
    res.html(page({
      title: 'Masuk Admin', narrow: true,
      body: `<div class="card">
        <h1>⚙ Panel Admin</h1>
        <p class="muted small">Terpisah dari akun pengguna biasa — untuk mengelola daftar akun (unlock, hapus).</p>
        ${error ? ui.alert('error', 'Username atau password admin salah.') : ''}
        <form method="post" action="/admin/login">
          <label for="username">Username</label>
          <input id="username" name="username" type="text" autofocus required autocomplete="username">
          <label for="password">Password</label>
          <input id="password" name="password" type="password" required autocomplete="current-password">
          <div style="margin-top:16px"><button class="block">Masuk</button></div>
        </form>
        <p class="small"><a href="/">← Kembali ke Portal</a></p>
      </div>`,
    }));
  });

  app.post('/admin/login', async (req, res) => {
    const username = String(req.body.username || '').trim().toLowerCase();
    const admin = await store.getAdmin(username);
    if (!admin || !sec.verifyPassword(req.body.password || '', admin.password_hash)) {
      return res.redirect('/admin/login?error=1');
    }
    const token = sec.randomToken();
    await redis.client.set(`sso:admin_session:${token}`, username, { EX: SESSION_TTL_SEC });
    res.cookie(ADMIN_COOKIE, token, { maxAge: SESSION_TTL_SEC });
    res.redirect('/admin');
  });

  app.get('/admin/logout', async (req, res) => {
    const token = req.cookies[ADMIN_COOKIE];
    if (token) await redis.client.del(`sso:admin_session:${token}`);
    res.clearCookie(ADMIN_COOKIE);
    res.redirect('/admin/login');
  });

  const right = username => `<span class="small muted">👤 ${esc(username)}</span><a class="btn sm ghost" href="/">Portal</a><a class="btn sm secondary" href="/admin/logout">Keluar</a>`;

  // ---- Daftar akun: unlock dan hapus, sesuai yang diminta ----
  app.get('/admin', async (req, res) => {
    const username = await requireAdmin(req, res);
    if (!username) return;
    const msg = {
      deleted: ['ok', 'Akun dihapus.'], unlocked: ['ok', 'Akun dibuka kembali.'], locked: ['warn', 'Akun dikunci.'],
      disabled: ['warn', 'Akun dinonaktifkan.'], enabled: ['ok', 'Akun diaktifkan kembali.'],
    }[req.query.msg];
    const users = await store.listUsers();

    const rows = users.map(u => {
      const statusTag = u.status === 'active' ? '<span class="tag ok">Aktif</span>'
        : u.status === 'locked' ? '<span class="tag err">Terkunci</span>' : '<span class="tag">Nonaktif</span>';
      return `<tr>
        <td><strong>${esc(u.name)}</strong><br><span class="small muted mono">${esc(u.email)}</span></td>
        <td class="small">${esc(u.org?.name || '—')}<br>${(u.roles || []).map(esc).join(', ')}</td>
        <td>${statusTag}</td>
        <td class="small">${core.hasTwoFa(u) ? Object.keys(u.twoFa.methods).map(k => esc(core.METHOD_LABEL[k])).join(', ') : '—'}</td>
        <td class="small">${ui.fmtTime(u.createdAt)}</td>
        <td class="row">
          ${u.status === 'active' ? `<form method="post" action="/admin/users/${esc(u.id)}/lock" onsubmit="return confirm('Kunci akun ${esc(u.email)}? Akun tidak akan bisa masuk sampai dibuka lagi.')"><button class="sm secondary">Kunci</button></form>` : ''}
          ${u.status === 'locked' ? `<form method="post" action="/admin/users/${esc(u.id)}/unlock"><button class="sm">Buka kunci</button></form>` : ''}
          ${u.status === 'active' ? `<form method="post" action="/admin/users/${esc(u.id)}/disable" onsubmit="return confirm('Nonaktifkan akun ${esc(u.email)}? Berbeda dari Kunci — dipakai untuk keputusan permanen seperti akun yang sudah tidak dipakai lagi.')"><button class="sm ghost">Nonaktifkan</button></form>` : ''}
          ${u.status === 'disabled' ? `<form method="post" action="/admin/users/${esc(u.id)}/enable"><button class="sm">Aktifkan</button></form>` : ''}
          <form method="post" action="/admin/users/${esc(u.id)}/delete" onsubmit="return confirm('Hapus akun ${esc(u.email)} secara permanen? Semua sesi dan kunci aksesnya juga dicabut.')">
            <button class="sm danger">Hapus</button></form>
        </td></tr>`;
    }).join('');

    res.html(page({
      title: 'Panel Admin — Akun',
      right: right(username),
      body: `${msg ? ui.alert(msg[0], msg[1]) : ''}
        <h1>Akun (${users.length})</h1>
        <p class="muted small">Panel ini di luar 5 alur SSO — dipakai IdP untuk mengelola daftar akun secara langsung (unlock dan hapus).</p>
        <div class="card"><div class="table-wrap"><table>
          <tr><th>Akun</th><th>Organisasi / peran</th><th>Status</th><th>2FA</th><th>Dibuat</th><th></th></tr>
          ${rows || '<tr><td colspan="6" class="muted small">Belum ada akun.</td></tr>'}
        </table></div></div>`,
    }));
  });

  // Kunci manual — dipakai admin untuk menghentikan akun langsung (mis. dicurigai dibajak),
  // terpisah dari kunci otomatis akibat gagal 2FA berulang (Alur 2), tapi memakai status yang sama.
  app.post('/admin/users/:id/lock', async (req, res) => {
    const username = await requireAdmin(req, res);
    if (!username) return;
    const u = await store.getUser(req.params.id);
    if (u && u.status === 'active') {
      u.status = 'locked';
      await store.saveUser(u);
      await store.addAudit({ userId: u.id, level: 'critical', title: 'Akun dikunci oleh admin', detail: `Oleh ${username}` });
    }
    res.redirect('/admin?msg=locked');
  });

  app.post('/admin/users/:id/unlock', async (req, res) => {
    const username = await requireAdmin(req, res);
    if (!username) return;
    const u = await store.getUser(req.params.id);
    // Sengaja hanya berlaku untuk status 'locked' — akun 'disabled' adalah keputusan admin lain,
    // bukan hasil kunci otomatis/manual, jadi tidak boleh ikut ter-reaktivasi dari sini.
    if (u && u.status === 'locked') {
      Object.assign(u, { status: 'active', failedLogins: 0, twoFaFailures: 0, twoFaLockedUntil: 0 });
      await store.saveUser(u);
      await store.addAudit({ userId: u.id, level: 'warn', title: 'Akun dibuka oleh admin', detail: `Oleh ${username}` });
    }
    res.redirect('/admin?msg=unlocked');
  });

  // Nonaktifkan/Aktifkan — keputusan administratif yang lebih permanen daripada Kunci/Buka kunci
  // (mis. akun karyawan yang sudah keluar). Sengaja terpisah dari status 'locked': akun nonaktif
  // TIDAK bisa pulih sendiri lewat /recover (lihat komentar di routes-login.js), harus lewat sini.
  app.post('/admin/users/:id/disable', async (req, res) => {
    const username = await requireAdmin(req, res);
    if (!username) return;
    const u = await store.getUser(req.params.id);
    if (u && u.status === 'active') {
      u.status = 'disabled';
      await store.saveUser(u);
      await store.addAudit({ userId: u.id, level: 'critical', title: 'Akun dinonaktifkan oleh admin', detail: `Oleh ${username}` });
    }
    res.redirect('/admin?msg=disabled');
  });

  app.post('/admin/users/:id/enable', async (req, res) => {
    const username = await requireAdmin(req, res);
    if (!username) return;
    const u = await store.getUser(req.params.id);
    if (u && u.status === 'disabled') {
      Object.assign(u, { status: 'active', failedLogins: 0, twoFaFailures: 0, twoFaLockedUntil: 0 });
      await store.saveUser(u);
      await store.addAudit({ userId: u.id, level: 'warn', title: 'Akun diaktifkan kembali oleh admin', detail: `Oleh ${username}` });
    }
    res.redirect('/admin?msg=enabled');
  });

  app.post('/admin/users/:id/delete', async (req, res) => {
    const username = await requireAdmin(req, res);
    if (!username) return;
    const u = await store.getUser(req.params.id);
    if (u) {
      await store.deleteUser(u.id);
      await store.addAudit({ userId: null, level: 'critical', title: `Akun ${u.email} dihapus oleh admin`, detail: `Oleh ${username}` });
    }
    res.redirect('/admin?msg=deleted');
  });
};
