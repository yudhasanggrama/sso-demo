'use strict';
// Panel Demo: alat bantu untuk mencoba semua cabang flowchart. Tidak ada di sistem produksi.
const cfg = require('../config');
const sec = require('../lib/security');
const totp = require('../lib/totp');
const ui = require('../lib/ui');
const store = require('./store');
const core = require('./core');

const { esc } = ui;

async function serviceState(s) {
  try {
    const r = await fetch(`${s.url}/demo/state`, { signal: AbortSignal.timeout(800) });
    return await r.json();
  } catch {
    return null;
  }
}

module.exports = function registerDemoRoutes(app) {
  app.get('/demo', async (req, res) => {
    const bs = core.loadBS(req);
    const states = await Promise.all(cfg.services.map(serviceState));

    const users = [...store.users.values()].map(u => {
      const m = u.twoFa?.methods || {};
      const code = m.totp ? `<strong class="mono">${totp.codeAt(sec.decrypt(m.totp.secretEnc))}</strong>` : '—';
      const status = u.status === 'active' ? '<span class="tag ok">Aktif</span>' : u.status === 'locked' ? '<span class="tag err">Terkunci</span>' : '<span class="tag">Nonaktif</span>';
      return `<tr><td>${esc(u.email)}<br><span class="small muted mono">${esc(store.demo.passwords[u.id])}</span></td><td>${status}</td>
        <td class="small">${esc(u.org.name)}${u.org.require2fa ? ' <span class="tag warn">wajib 2FA</span>' : ''}<br>${u.roles.map(esc).join(', ')}</td>
        <td class="small">${Object.keys(m).map(k => esc(core.METHOD_LABEL[k])).join(', ') || '—'}</td><td>${code}</td>
        <td class="small mono">${(store.demo.backupCodes[u.id] || []).map(esc).join('<br>') || '—'}</td>
        <td><form method="post" action="/demo/reset-user" class="stack"><input type="hidden" name="userId" value="${esc(u.id)}">
          ${u.status === 'locked' ? '<button class="sm" name="what" value="unlock">Buka kunci</button>' : ''}
          ${core.hasTwoFa(u) && u.id !== 'u-andi' ? '<button class="sm ghost" name="what" value="2fa">Hapus 2FA</button>' : ''}
          ${u.trustedDevices.length ? '<button class="sm ghost" name="what" value="devices">Lupakan perangkat</button>' : ''}
          ${Object.keys(u.consents).length ? '<button class="sm ghost" name="what" value="consents">Hapus persetujuan</button>' : ''}</form></td></tr>`;
    }).join('');

    const services = cfg.services.map((s, i) => {
      const st = states[i];
      return `<tr><td>${s.icon} <a href="${s.url}/">${esc(s.name)}</a><br><span class="small muted mono">${s.url}</span></td>
        <td>${st ? '<span class="tag ok">Hidup</span>' : '<span class="tag err">Mati</span>'}</td>
        <td class="small">${st ? `${st.sessions} sesi lokal` : '—'}</td>
        <td><form method="post" action="/demo/service-fail" class="row"><input type="hidden" name="clientId" value="${s.id}">
          <input type="number" name="n" min="0" max="20" value="${st?.failNext ?? 0}" style="width:70px"><button class="sm secondary">Atur</button></form></td>
        <td><a class="btn sm ghost" href="${s.url}/demo/forged">Kirim token palsu</a></td></tr>`;
    }).join('');

    const failed = store.failedLogouts.map(f => `<tr><td class="small">${ui.fmtTime(f.at)}</td><td>${esc(cfg.clients[f.clientId].name)}</td>
      <td class="small">${esc(store.users.get(f.userId)?.email)}</td><td class="small">${esc(f.lastError)} (${f.attempts}×)</td>
      <td>${f.resolved ? '<span class="tag ok">Selesai</span>' : `<form method="post" action="/demo/failed-logouts/${esc(f.id)}/retry"><button class="sm">Coba lagi</button></form>`}</td></tr>`).join('');

    const outbox = store.outbox.slice(0, 15).map(o => `<tr><td class="small">${ui.fmtTime(o.at)}</td><td><span class="tag">${esc(o.channel)}</span></td><td class="small mono">${esc(o.to)}</td>
      <td class="small">${esc(o.text).replace(/(http:\/\/localhost:\d+\/\S+)/g, '<a href="$1">$1</a>')}</td></tr>`).join('');

    const audit = store.audit.slice(0, 60).map(e => `<tr><td class="small">${ui.fmtTime(e.at)}</td><td class="small">${esc(store.users.get(e.userId)?.email || '—')}</td>
      <td class="lvl-${e.level}">${esc(e.title)}</td><td class="small muted">${esc(e.detail)}</td></tr>`).join('');

    res.html(core.view(bs, {
      title: 'Panel Demo',
      flow: 'Alat bantu demo — bukan bagian dari flowchart',
      body: `<h1>Panel Demo</h1><p class="muted">Gunakan panel ini untuk mencoba setiap cabang flowchart. <a href="/demo">Muat ulang</a> · kode aplikasi berganti dalam ${totp.secondsLeft()} dtk.</p>
      <div class="card"><h2>Akun contoh</h2><div class="table-wrap"><table>
        <tr><th>Akun / password</th><th>Status</th><th>Organisasi / peran</th><th>2FA</th><th>Kode aplikasi</th><th>Kode cadangan</th><th></th></tr>${users}</table></div></div>
      <div class="card"><h2>Layanan</h2>
        <p class="small muted">“Gagal N kali berikutnya” membuat layanan menolak perintah keluar (HTTP 503) sebanyak N kali — untuk mencoba cabang <em>percobaan ulang dengan jeda makin panjang</em> di Alur 5. Batas percobaan: 1 + ${cfg.policy.logoutRetries} ulang. “Kirim token palsu” mencoba cabang <em>akses ditolak & dicatat sebagai insiden keamanan</em> di Alur 3.</p>
        <div class="table-wrap"><table><tr><th>Layanan</th><th>Status</th><th>Sesi</th><th>Gagal N kali berikutnya</th><th></th></tr>${services}</table></div></div>
      <div class="card"><h2>Logout gagal — perlu ditindaklanjuti</h2>
        ${failed ? `<div class="table-wrap"><table><tr><th>Waktu</th><th>Layanan</th><th>Akun</th><th>Galat</th><th></th></tr>${failed}</table></div>` : '<p class="small muted">Belum ada.</p>'}</div>
      <div class="card" id="kotak-keluar"><h2>Kotak keluar (SMS & email simulasi)</h2>
        ${outbox ? `<div class="table-wrap"><table>${outbox}</table></div>` : '<p class="small muted">Kosong.</p>'}</div>
      <div class="card"><h2>Riwayat keamanan (semua akun)</h2>
        <div class="table-wrap"><table><tr><th>Waktu</th><th>Akun</th><th>Kejadian</th><th>Rincian</th></tr>${audit}</table></div></div>`,
    }));
  });

  app.post('/demo/reset-user', (req, res) => {
    const u = store.users.get(req.body.userId);
    if (u) {
      if (req.body.what === 'unlock' && u.status === 'locked') Object.assign(u, { status: 'active', failedLogins: 0 });
      if (req.body.what === '2fa') Object.assign(u, { twoFa: null, trustedDevices: [], twoFaDeferredAt: 0 });
      if (req.body.what === 'devices') u.trustedDevices = [];
      if (req.body.what === 'consents') u.consents = {};
      store.addAudit({ userId: u.id, level: 'info', title: `Panel demo: ${req.body.what}` });
    }
    res.redirect('/demo');
  });

  app.post('/demo/service-fail', async (req, res) => {
    const s = cfg.clients[req.body.clientId];
    if (s) {
      await fetch(`${s.url}/demo/control`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ failNext: Math.max(0, Math.min(20, Number(req.body.n) || 0)) }),
        signal: AbortSignal.timeout(1000),
      }).catch(() => {});
    }
    res.redirect('/demo');
  });

  app.post('/demo/failed-logouts/:id/retry', async (req, res) => {
    const f = store.failedLogouts.find(x => x.id === req.params.id);
    if (f && !f.resolved) {
      const r = await core.backchannelLogout(f, { recordFailure: false });
      Object.assign(f, { attempts: f.attempts + r.attempts, lastError: r.ok ? '' : r.error, resolved: r.ok });
      store.addAudit({ userId: f.userId, level: r.ok ? 'info' : 'warn', title: `Tindak lanjut logout ${cfg.clients[f.clientId].name}`, detail: r.ok ? 'Berhasil ditutup' : r.error });
    }
    res.redirect('/demo');
  });
};
