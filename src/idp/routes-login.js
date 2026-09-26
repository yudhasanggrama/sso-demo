'use strict';
// Alur 1 (masuk dengan email + password) dan Alur 2 (verifikasi dua langkah).
const cfg = require('../config');
const sec = require('../lib/security');
const totp = require('../lib/totp');
const ui = require('../lib/ui');
const store = require('./store');
const core = require('./core');

const { esc } = ui;
const { policy } = cfg;
const GENERIC_ERROR = 'Email atau password salah.';

const safeReturn = r => (typeof r === 'string' && r.startsWith('/') && !r.startsWith('//') ? r : null);

function demoAccountsHint() {
  const rows = [...store.users.values()].map(u =>
    `<tr><td class="mono">${esc(u.email)}</td><td class="mono">${esc(store.demo.passwords[u.id])}</td><td class="small">${esc(accountNote(u))}</td></tr>`).join('');
  return ui.demoHint(`akun contoh:<div class="table-wrap"><table>${rows}</table></div>`);
}

function accountNote(u) {
  if (u.status === 'disabled') return 'Dinonaktifkan';
  if (u.status === 'locked') return 'Terkunci';
  if (core.hasTwoFa(u)) return 'Sudah punya 2FA';
  return u.org.require2fa ? 'Organisasi wajibkan 2FA' : '2FA opsional';
}

function lastSmsTo(phone) {
  const m = store.outbox.find(x => x.channel === 'SMS' && x.to === phone);
  return m ? ui.demoHint(`SMS terakhir ke <span class="mono">${esc(phone)}</span>: “${esc(m.text)}”`) : '';
}

module.exports = function registerLoginRoutes(app) {
  // ===================== ALUR 1 =====================

  function renderIdentifier(res, bs, { error, login = '' } = {}) {
    const p = bs.pending;
    const adding = p?.add && bs.accounts.length > 0;
    const fromService = p?.returnTo?.startsWith('/authorize');
    res.html(core.view(bs, {
      title: 'Masuk', narrow: true, hideMenu: !adding,
      flow: adding ? 'Alur 4 · Tambah akun → Alur 1' : 'Alur 1 · Halaman mode tamu → ketik email atau nama pengguna',
      body: `<div class="card">
        <h1>${adding ? 'Tambah akun' : 'Masuk'}</h1>
        <p class="muted">Satu akun untuk semua layanan.</p>
        ${adding ? ui.alert('info', 'Akun yang sudah masuk <strong>tidak dikeluarkan</strong>. Akun baru masuk daftar setelah berhasil.') : ''}
        ${fromService ? ui.alert('info', 'Sebuah layanan meminta Anda masuk melalui Pusat Akun.') : ''}
        ${error ? ui.alert('error', esc(error)) : ''}
        <form method="post" action="/login/identifier">
          <label for="login">Email atau nama pengguna</label>
          <input id="login" name="login" type="text" autocomplete="username" value="${esc(login)}" autofocus required>
          <div style="margin-top:16px"><button class="block">Lanjut</button></div>
        </form>
        <p class="small"><a href="/recover">Lupa password?</a></p>
      </div>${demoAccountsHint()}`,
    }));
  }

  // C (dari Alur 3 atau 4) → halaman tampil mode tamu, hanya ada tombol Masuk
  app.get('/login', (req, res) => {
    const bs = core.ensureBS(req, res);
    bs.pending = { purpose: 'login', stage: 'identifier', returnTo: safeReturn(req.query.return), add: req.query.add === '1' };
    renderIdentifier(res, bs);
  });

  // "Sistem mencari data akun" → "Akun ditemukan dan masih aktif?"
  app.post('/login/identifier', (req, res) => {
    const bs = core.ensureBS(req, res);
    if (bs.pending?.purpose !== 'login') bs.pending = { purpose: 'login', stage: 'identifier', returnTo: null };
    const login = String(req.body.login || '').trim();
    const user = store.findUser(login);

    if (!user) {
      // Tidak ditemukan → pesan umum agar penebak tidak tahu mana yang keliru
      core.audit(req, null, 'warn', 'Percobaan masuk dengan akun tidak dikenal', login.slice(0, 60));
      return renderIdentifier(res, bs, { error: GENERIC_ERROR, login });
    }
    if (user.status !== 'active') {
      core.audit(req, user.id, 'warn', 'Percobaan masuk ke akun yang terkunci/nonaktif');
      bs.pending = { purpose: 'login', stage: 'locked', userId: user.id };
      return res.redirect('/locked');
    }
    Object.assign(bs.pending, { userId: user.id, stage: 'password' });
    res.redirect('/login/password');
  });

  function renderPassword(res, c, error) {
    const { bs, user } = c;
    res.html(core.view(bs, {
      title: 'Password', narrow: true, hideMenu: true,
      flow: 'Alur 1 · Pengguna mengetik password',
      body: `<div class="card">
        <div class="row">${ui.avatar(user, 40)}<div><strong>${esc(user.email)}</strong><br><a class="small" href="/login">Bukan Anda?</a></div></div>
        ${error ? ui.alert('error', `${esc(error)} <a href="/recover">Lupa password?</a>`) : ''}
        <form method="post" action="/login/password">
          <label for="pw">Password</label>
          <input id="pw" name="password" type="password" autocomplete="current-password" autofocus required>
          <div style="margin-top:16px"><button class="block">Masuk</button></div>
        </form>
      </div>
      ${ui.demoHint(`password akun ini: <span class="mono">${esc(store.demo.passwords[user.id])}</span>. Salah ${policy.maxPasswordFailures}× berturut-turut → akun terkunci.`)}`,
    }));
  }

  app.get('/login/password', (req, res) => {
    const c = core.pendingCtx(req, ['password']);
    if (!c) return res.redirect('/login');
    renderPassword(res, c);
  });

  // "Password cocok?"
  app.post('/login/password', (req, res) => {
    const c = core.pendingCtx(req, ['password']);
    if (!c) return res.redirect('/login');
    const { bs, p, user } = c;

    if (!sec.verifyPassword(req.body.password || '', user.passwordHash)) {
      user.failedLogins++;
      // "Catat percobaan gagal ke riwayat keamanan"
      core.audit(req, user.id, 'warn', 'Password salah', `Percobaan gagal ke-${user.failedLogins} dari ${policy.maxPasswordFailures}`);
      // "Sudah gagal terlalu sering?"
      if (user.failedLogins >= policy.maxPasswordFailures) {
        user.status = 'locked';
        core.audit(req, user.id, 'critical', 'Akun dikunci otomatis', 'Terlalu banyak password salah');
        bs.pending = { purpose: 'login', stage: 'locked', userId: user.id };
        return res.redirect('/locked');
      }
      return renderPassword(res, c, `${GENERIC_ERROR} Sisa percobaan: ${policy.maxPasswordFailures - user.failedLogins}.`);
    }

    user.failedLogins = 0;
    p.stage = '2fa';
    res.redirect('/login/2fa'); // A → Alur 2
  });

  // Berhenti di halaman akun terkunci, arahkan ke pemulihan akun
  app.get('/locked', (req, res) => {
    const bs = core.loadBS(req);
    const user = store.users.get(bs?.pending?.userId);
    const disabled = user?.status === 'disabled';
    res.html(core.view(bs, {
      title: 'Akun terkunci', narrow: true, hideMenu: true,
      flow: 'Alur 1 · Berhenti di halaman akun terkunci',
      body: `<div class="card"><h1>🔒 Akun ${disabled ? 'dinonaktifkan' : 'terkunci'}</h1>
        ${disabled
          ? '<p>Akun ini dinonaktifkan oleh administrator. Hubungi tim TI untuk mengaktifkannya kembali.</p>'
          : `<p>Demi keamanan, akun ini dikunci setelah terlalu banyak percobaan masuk yang gagal.</p>
             <a class="btn block" href="/recover">Pulihkan akun</a>`}
        <p class="small"><a href="/login">Kembali ke halaman masuk</a></p></div>`,
    }));
  });

  // ---- Pemulihan akun / lupa password ----
  app.get('/recover', (req, res) => {
    const bs = core.loadBS(req);
    const sent = req.query.sent === '1';
    res.html(core.view(bs, {
      title: 'Pemulihan akun', narrow: true,
      flow: 'Alur 1 · Pemulihan akun',
      body: `<div class="card"><h1>Pemulihan akun</h1>
        ${sent ? ui.alert('ok', 'Jika akun terdaftar, tautan pemulihan sudah dikirim ke emailnya.') + ui.demoHint('buka <a href="/demo#kotak-keluar">Panel Demo → Kotak keluar</a> untuk melihat email pemulihan.') : ''}
        <form method="post" action="/recover">
          <label for="email">Email akun</label>
          <input id="email" name="email" type="email" required>
          <div style="margin-top:16px"><button class="block">Kirim tautan pemulihan</button></div>
        </form></div>`,
    }));
  });

  app.post('/recover', (req, res) => {
    const user = store.findUser(req.body.email);
    if (user && user.status !== 'disabled') {
      const token = sec.randomToken();
      store.recoveryTokens.set(sec.sha256(token), { userId: user.id, expiresAt: Date.now() + 15 * 60_000 });
      store.sendMessage('Email', user.email, `Tautan pemulihan akun (berlaku 15 menit): ${cfg.PORTAL}/recover/${token}`);
      core.audit(req, user.id, 'info', 'Tautan pemulihan akun dikirim');
    }
    res.redirect('/recover?sent=1'); // jawaban sama walau email tidak terdaftar
  });

  app.get('/recover/:token', (req, res) => {
    const rec = store.recoveryTokens.get(sec.sha256(req.params.token));
    if (!rec || rec.expiresAt < Date.now()) return core.errorPage(res, core.loadBS(req), 'Tautan tidak berlaku', 'Tautan pemulihan salah atau sudah kedaluwarsa.');
    const user = store.users.get(rec.userId);
    res.html(core.view(core.loadBS(req), {
      title: 'Atur ulang password', narrow: true,
      body: `<div class="card"><h1>Atur ulang password</h1><p class="muted">${esc(user.email)}</p>
        <form method="post" action="/recover/${esc(req.params.token)}">
          <label for="pw">Password baru (min. 8 karakter)</label>
          <input id="pw" name="password" type="password" minlength="8" autocomplete="new-password" required>
          <div style="margin-top:16px"><button class="block">Simpan & buka kunci akun</button></div>
        </form></div>`,
    }));
  });

  app.post('/recover/:token', (req, res) => {
    const hash = sec.sha256(req.params.token);
    const rec = store.recoveryTokens.get(hash);
    const pw = String(req.body.password || '');
    if (!rec || rec.expiresAt < Date.now()) return core.errorPage(res, core.loadBS(req), 'Tautan tidak berlaku', 'Tautan pemulihan salah atau sudah kedaluwarsa.');
    if (pw.length < 8) return core.errorPage(res, core.loadBS(req), 'Password terlalu pendek', 'Gunakan minimal 8 karakter.');
    store.recoveryTokens.delete(hash);
    const user = store.users.get(rec.userId);
    user.passwordHash = sec.hashPassword(pw);
    store.demo.passwords[user.id] = pw;
    user.failedLogins = 0;
    if (user.status === 'locked') user.status = 'active';
    core.audit(req, user.id, 'warn', 'Password diatur ulang lewat pemulihan akun', 'Kunci akun dibuka');
    res.redirect('/?msg=password_reset');
  });

  // ===================== ALUR 2 =====================

  // A dari Alur 1 → "Akun ini sudah punya verifikasi dua langkah?"
  app.get('/login/2fa', (req, res) => {
    const c = core.pendingCtx(req, ['2fa']);
    if (!c) return res.redirect('/login');
    const { bs, p, user } = c;

    if (!core.hasTwoFa(user)) {
      // "Aturan organisasi mewajibkannya?"
      if (user.org.require2fa) {
        Object.assign(p, { stage: 'enroll', mandatory: true });
        return res.redirect('/2fa/enroll');
      }
      p.stage = 'offer';
      return res.redirect('/login/2fa/offer');
    }

    // "Perangkat ini pernah ditandai tepercaya?"
    const dev = req.cookies[core.DEV_COOKIE];
    const trusted = dev && user.trustedDevices.find(d => d.deviceHash === sec.sha256(dev) && d.expiresAt > Date.now());
    if (trusted) {
      trusted.lastUsed = Date.now();
      core.audit(req, user.id, 'info', 'Perangkat tepercaya dikenali', trusted.label);
      return core.completeLogin(req, res, bs, user, { amr: ['pwd', 'trusted_device'], mfa: false });
    }
    p.stage = 'verify';
    res.redirect('/2fa/verify');
  });

  // "Pengguna mau mengaktifkan sekarang?"
  app.get('/login/2fa/offer', (req, res) => {
    const c = core.pendingCtx(req, ['offer']);
    if (!c) return res.redirect('/login');
    const { bs, user } = c;
    const deferred = user.twoFaDeferredAt ? `<p class="small muted">Anda terakhir menunda pada ${ui.fmtTime(user.twoFaDeferredAt)}.</p>` : '';
    res.html(core.view(bs, {
      title: 'Verifikasi dua langkah', narrow: true, hideMenu: true,
      flow: 'Alur 2 · Tidak wajib → pengguna mau mengaktifkan sekarang?',
      body: `<div class="card"><h1>Lindungi akun Anda</h1>
        <p>Verifikasi dua langkah membuat akun tetap aman walaupun password Anda bocor.</p>${deferred}
        <form method="post" action="/login/2fa/offer" class="stack">
          <button class="block" name="choice" value="now">Aktifkan sekarang</button>
          <button class="block secondary" name="choice" value="later">Nanti saja</button>
        </form></div>`,
    }));
  });

  app.post('/login/2fa/offer', (req, res) => {
    const c = core.pendingCtx(req, ['offer']);
    if (!c) return res.redirect('/login');
    const { bs, p, user } = c;
    if (req.body.choice === 'now') {
      Object.assign(p, { stage: 'enroll', mandatory: false });
      return res.redirect('/2fa/enroll');
    }
    // "Ingat penundaannya, tawarkan lagi lain waktu"
    user.twoFaDeferredAt = Date.now();
    core.audit(req, user.id, 'info', 'Verifikasi dua langkah ditunda');
    return core.completeLogin(req, res, bs, user, { amr: ['pwd'], mfa: false });
  });

  // ---------- Pendaftaran verifikasi dua langkah (tidak ada tombol lewati) ----------

  function enrollFlow(p) {
    if (p.purpose === 'stepup') return `Alur 3 · Layanan sensitif (${p.clientName}) butuh 2FA → pendaftaran`;
    if (p.purpose === 'settings') return 'Alur 4 · Kelola akun → tambah metode verifikasi';
    return p.mandatory ? 'Alur 2 · Wajib → pendaftaran wajib, tidak ada tombol lewati' : 'Alur 2 · Ya → pendaftaran';
  }
  const cancelLink = p => (p.purpose === 'settings' ? '<p class="small"><a href="/2fa/cancel">Batal</a></p>' : '');

  app.get('/2fa/enroll', (req, res) => {
    const c = core.pendingCtx(req, ['enroll']);
    if (!c) return res.redirect('/');
    const { bs, p, user } = c;
    const has = user.twoFa?.methods || {};
    const intro = p.purpose === 'stepup'
      ? ui.alert('warn', `Layanan <strong>${esc(p.clientName)}</strong> berisi data sensitif dan mewajibkan verifikasi dua langkah.`)
      : p.mandatory ? ui.alert('warn', `<strong>${esc(user.org.name)}</strong> mewajibkan verifikasi dua langkah. Langkah ini tidak dapat dilewati.`) : '';
    const opt = (id, icon, title, desc) => has[id]
      ? `<div class="choice" style="opacity:.6"><span class="ic">${icon}</span><div><strong>${title}</strong> <span class="tag ok">Sudah aktif</span><br><span class="small muted">${desc}</span></div></div>`
      : `<a class="choice" href="/2fa/enroll/${id}"><span class="ic">${icon}</span><div><strong>${title}</strong><br><span class="small muted">${desc}</span></div></a>`;
    res.html(core.view(bs, {
      title: 'Aktifkan verifikasi dua langkah', narrow: true, hideMenu: p.purpose === 'login',
      flow: enrollFlow(p),
      body: `<div class="card"><h1>Pilih cara verifikasi</h1>${intro}
        ${opt('totp', '📱', 'Aplikasi kode', 'Google Authenticator, Microsoft Authenticator, Authy, dll.')}
        ${opt('passkey', '👆', 'Sidik jari atau wajah', 'Kunci perangkat yang disimpan di browser ini (simulasi).')}
        ${opt('sms', '💬', 'SMS', 'Kode dikirim ke nomor ponsel Anda.')}
        ${cancelLink(p)}</div>`,
    }));
  });

  app.get('/2fa/cancel', (req, res) => {
    const c = core.pendingCtx(req, ['enroll']);
    if (c && c.p.purpose === 'settings') c.bs.pending = null;
    res.redirect('/account#dua-langkah');
  });

  // Simpan pengaturan secara terenkripsi dan terbitkan kode cadangan
  function finishEnroll(req, c, method, data) {
    const { p, user } = c;
    user.twoFa ||= { methods: {}, backupCodes: [], enrolledAt: Date.now() };
    user.twoFa.methods[method] = { ...data, addedAt: Date.now() };
    let codes = null;
    if (!user.twoFa.backupCodes.some(b => !b.usedAt)) {
      codes = sec.makeBackupCodes();
      user.twoFa.backupCodes = codes.map(code => ({ hash: sec.sha256(code), usedAt: null }));
    }
    user.twoFaDeferredAt = 0;
    user.twoFaFailures = 0;
    core.audit(req, user.id, 'info', 'Metode verifikasi dua langkah ditambahkan', core.METHOD_LABEL[method]);
    Object.assign(p, { stage: 'enrolled', enroll: null, newBackupCodes: codes, enrolledMethod: method });
    return '/2fa/enrolled';
  }

  // --- Aplikasi kode (TOTP) ---
  function renderTotpEnroll(res, c, error) {
    const { bs, p, user } = c;
    if (p.enroll?.method !== 'totp') p.enroll = { method: 'totp', secret: totp.generateSecret() };
    const { secret } = p.enroll;
    res.html(core.view(bs, {
      title: 'Aplikasi kode', narrow: true, hideMenu: p.purpose === 'login',
      flow: `${enrollFlow(p)} → aplikasi kode`,
      body: `<div class="card"><h1>📱 Aplikasi kode</h1>
        <ol class="small">
          <li>Buka aplikasi authenticator, pilih <em>Tambah akun → Masukkan kunci penyiapan</em>.</li>
          <li>Ketik kunci ini (tipe: berbasis waktu):<span class="secret">${secret.match(/.{1,4}/g).join(' ')}</span></li>
          <li>Masukkan kode 6 digit yang muncul sebagai uji coba.</li>
        </ol>
        <details class="small"><summary>URI otpauth (untuk dijadikan QR)</summary><code>${esc(totp.otpauthUri(secret, user.email, 'Pusat Akun Demo'))}</code></details>
        ${error ? ui.alert('error', esc(error)) : ''}
        <form method="post" action="/2fa/enroll/totp">
          <label for="code">Kode dari aplikasi</label>
          <input id="code" class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus required>
          <div style="margin-top:16px"><button class="block">Uji & aktifkan</button></div>
        </form>
        <p class="small"><a href="/2fa/enroll">← Pilih cara lain</a></p></div>
        ${ui.demoHint(`tanpa ponsel? kode saat ini: <strong class="mono">${totp.codeAt(secret)}</strong> (berganti dalam ${totp.secondsLeft()} dtk)`)}`,
    }));
  }

  app.get('/2fa/enroll/totp', (req, res) => {
    const c = core.pendingCtx(req, ['enroll']);
    if (!c) return res.redirect('/');
    renderTotpEnroll(res, c);
  });

  app.post('/2fa/enroll/totp', (req, res) => {
    const c = core.pendingCtx(req, ['enroll']);
    if (!c || c.p.enroll?.method !== 'totp') return res.redirect('/');
    const step = totp.verify(c.p.enroll.secret, req.body.code);
    if (step == null) return renderTotpEnroll(res, c, 'Kode tidak cocok. Pastikan jam di ponsel sudah benar lalu coba lagi.');
    res.redirect(finishEnroll(req, c, 'totp', { secretEnc: sec.encrypt(c.p.enroll.secret), lastStep: step }));
  });

  // --- SMS ---
  function renderSmsEnroll(res, c, error) {
    const { bs, p } = c;
    const sent = p.enroll?.method === 'sms' && p.enroll.codeHash;
    res.html(core.view(bs, {
      title: 'SMS', narrow: true, hideMenu: p.purpose === 'login',
      flow: `${enrollFlow(p)} → SMS`,
      body: `<div class="card"><h1>💬 SMS</h1>
        ${error ? ui.alert('error', esc(error)) : ''}
        <form method="post" action="/2fa/enroll/sms/send">
          <label for="phone">Nomor ponsel</label>
          <div class="row"><input id="phone" name="phone" type="tel" value="${esc(sent ? p.enroll.phone : '+62')}" style="flex:1" required>
          <button class="${sent ? 'secondary' : ''}">${sent ? 'Kirim ulang' : 'Kirim kode'}</button></div>
        </form>
        ${sent ? `<form method="post" action="/2fa/enroll/sms">
          <label for="code">Kode dari SMS</label>
          <input id="code" class="code" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" autofocus required>
          <div style="margin-top:16px"><button class="block">Uji & aktifkan</button></div></form>` : ''}
        <p class="small"><a href="/2fa/enroll">← Pilih cara lain</a></p></div>
        ${sent ? lastSmsTo(p.enroll.phone) : ''}`,
    }));
  }

  app.get('/2fa/enroll/sms', (req, res) => {
    const c = core.pendingCtx(req, ['enroll']);
    if (!c) return res.redirect('/');
    renderSmsEnroll(res, c);
  });

  app.post('/2fa/enroll/sms/send', (req, res) => {
    const c = core.pendingCtx(req, ['enroll']);
    if (!c) return res.redirect('/');
    const phone = String(req.body.phone || '').replace(/[\s-]/g, '');
    if (!/^\+?\d{9,15}$/.test(phone)) return renderSmsEnroll(res, c, 'Nomor ponsel tidak valid.');
    const code = sec.randomDigits();
    c.p.enroll = { method: 'sms', phone, codeHash: sec.sha256(code), expiresAt: Date.now() + policy.smsCodeTtlMs };
    store.sendMessage('SMS', phone, `Kode verifikasi Pusat Akun: ${code}. Berlaku 5 menit. Jangan berikan kepada siapa pun.`);
    res.redirect('/2fa/enroll/sms');
  });

  app.post('/2fa/enroll/sms', (req, res) => {
    const c = core.pendingCtx(req, ['enroll']);
    const e = c?.p.enroll;
    if (!c || e?.method !== 'sms' || !e.codeHash) return res.redirect('/');
    if (e.expiresAt < Date.now() || !sec.safeEqual(sec.sha256(String(req.body.code || '').trim()), e.codeHash)) {
      return renderSmsEnroll(res, c, 'Kode salah atau sudah kedaluwarsa.');
    }
    const masked = e.phone.slice(0, 3) + '•'.repeat(Math.max(0, e.phone.length - 7)) + e.phone.slice(-4);
    res.redirect(finishEnroll(req, c, 'sms', { phoneEnc: sec.encrypt(e.phone), phoneMasked: masked }));
  });

  // --- Sidik jari / wajah (simulasi: kunci ECDSA disimpan di browser, server menyimpan kunci publik) ---
  const passkeyScript = ({ mode, challenge, userId, endpoint }) => `<script>
(() => {
  const btn = document.getElementById('pk-btn'), out = document.getElementById('pk-out');
  const KEY = 'pa_passkey_' + ${JSON.stringify(userId)};
  const alg = { name: 'ECDSA', namedCurve: 'P-256' }, sigAlg = { name: 'ECDSA', hash: 'SHA-256' };
  const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
  const msg = new TextEncoder().encode(${JSON.stringify(challenge)});
  btn.addEventListener('click', async () => {
    btn.disabled = true; out.textContent = 'Memindai…';
    try {
      let payload, toSave = null;
      if (${JSON.stringify(mode)} === 'register') {
        const kp = await crypto.subtle.generateKey(alg, true, ['sign', 'verify']);
        const credId = crypto.randomUUID();
        payload = { credId, publicJwk: await crypto.subtle.exportKey('jwk', kp.publicKey), signature: b64u(await crypto.subtle.sign(sigAlg, kp.privateKey, msg)) };
        toSave = { credId, privateJwk: await crypto.subtle.exportKey('jwk', kp.privateKey) };
      } else {
        const saved = JSON.parse(localStorage.getItem(KEY) || 'null');
        if (!saved) throw new Error('Kunci sidik jari/wajah tidak ditemukan di browser ini. Gunakan cara lain.');
        const priv = await crypto.subtle.importKey('jwk', saved.privateJwk, alg, false, ['sign']);
        payload = { credId: saved.credId, signature: b64u(await crypto.subtle.sign(sigAlg, priv, msg)) };
      }
      const r = await fetch(${JSON.stringify(endpoint)}, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
      const j = await r.json();
      if (!j.ok) throw new Error(j.error || 'Gagal');
      if (toSave) localStorage.setItem(KEY, JSON.stringify(toSave));
      location.href = j.next;
    } catch (e) { out.textContent = e.message; btn.disabled = false; }
  });
})();
</script>`;

  app.get('/2fa/enroll/passkey', (req, res) => {
    const c = core.pendingCtx(req, ['enroll']);
    if (!c) return res.redirect('/');
    const { bs, p, user } = c;
    p.enroll = { method: 'passkey', challenge: sec.randomToken(24) };
    res.html(core.view(bs, {
      title: 'Sidik jari atau wajah', narrow: true, hideMenu: p.purpose === 'login',
      flow: `${enrollFlow(p)} → sidik jari / wajah`,
      body: `<div class="card"><h1>👆 Sidik jari atau wajah</h1>
        <p class="muted small">Simulasi: browser membuat pasangan kunci. Kunci privat tetap di perangkat ini; Pusat Akun hanya menyimpan kunci publik.</p>
        <button id="pk-btn" class="block">Pindai sidik jari (simulasi)</button>
        <p id="pk-out" class="small muted"></p>
        <p class="small"><a href="/2fa/enroll">← Pilih cara lain</a></p></div>
        ${passkeyScript({ mode: 'register', challenge: p.enroll.challenge, userId: user.id, endpoint: '/2fa/enroll/passkey' })}`,
    }));
  });

  app.post('/2fa/enroll/passkey', (req, res) => {
    const c = core.pendingCtx(req, ['enroll']);
    if (!c || c.p.enroll?.method !== 'passkey') return res.json({ ok: false, error: 'Sesi pendaftaran berakhir, muat ulang halaman.' });
    const { credId, publicJwk, signature } = req.body;
    if (!credId || !sec.verifyEcSignature(publicJwk, c.p.enroll.challenge, signature)) {
      return res.json({ ok: false, error: 'Uji coba tanda tangan perangkat gagal.' });
    }
    const { kty, crv, x, y } = publicJwk;
    res.json({ ok: true, next: finishEnroll(req, c, 'passkey', { credId: String(credId), publicJwk: { kty, crv, x, y } }) });
  });

  // Tampilkan kode cadangan (sekali saja)
  app.get('/2fa/enrolled', (req, res) => {
    const c = core.pendingCtx(req, ['enrolled']);
    if (!c) return res.redirect('/');
    const { bs, p } = c;
    const codes = p.newBackupCodes;
    res.html(core.view(bs, {
      title: 'Verifikasi dua langkah aktif', narrow: true, hideMenu: p.purpose === 'login',
      flow: 'Alur 2 · Simpan pengaturan terenkripsi dan terbitkan kode cadangan',
      body: `<div class="card"><h1>✅ Verifikasi dua langkah aktif</h1>
        <p>Metode: <strong>${esc(core.METHOD_LABEL[p.enrolledMethod])}</strong>. Pengaturan disimpan terenkripsi.</p>
        ${codes ? `<h3>Kode cadangan</h3><p class="small muted">Simpan di tempat aman. Setiap kode hanya bisa dipakai sekali bila ponsel/perangkat hilang. Kode ini tidak akan ditampilkan lagi.</p>
          <div class="codes">${codes.map(k => `<span>${k}</span>`).join('')}</div>` : ''}
        <form method="post" action="/2fa/enrolled"><button class="block">${codes ? 'Saya sudah menyimpannya, lanjutkan' : 'Lanjutkan'}</button></form></div>`,
    }));
  });

  app.post('/2fa/enrolled', (req, res) => {
    const c = core.pendingCtx(req, ['enrolled']);
    if (!c) return res.redirect('/');
    const { bs, p, user } = c;
    const method = p.enrolledMethod;
    if (p.purpose === 'login') return core.completeLogin(req, res, bs, user, { amr: ['pwd', method], mfa: true });
    if (p.purpose === 'stepup') {
      const acct = bs.accounts.find(a => a.userId === user.id);
      Object.assign(acct, { mfaTime: Date.now(), amr: [...new Set([...acct.amr, method])] });
      bs.pending = null;
      return res.redirect(p.returnTo || '/');
    }
    bs.pending = null;
    res.redirect('/account?msg=2fa_added#dua-langkah');
  });

  // ---------- Verifikasi (perangkat belum tepercaya, atau verifikasi ulang layanan sensitif) ----------

  function renderVerify(res, c, { error, info } = {}) {
    const { bs, p, user } = c;
    const m = user.twoFa.methods;
    const stepup = p.purpose === 'stepup';
    const lockedFor = Math.ceil((user.twoFaLockedUntil - Date.now()) / 1000);
    p.challenge = sec.randomToken(24);

    const hints = [];
    if (m.totp) hints.push(`kode aplikasi saat ini: <strong class="mono">${totp.codeAt(sec.decrypt(m.totp.secretEnc))}</strong> (${totp.secondsLeft()} dtk)`);
    if (store.demo.backupCodes[user.id]) hints.push(`kode cadangan contoh: <span class="mono">${store.demo.backupCodes[user.id].join(', ')}</span>`);
    const smsHint = m.sms && p.smsSent ? lastSmsTo(sec.decrypt(m.sms.phoneEnc)) : '';

    const body = lockedFor > 0
      ? `<div class="card"><h1>⏳ Terkunci sementara</h1>${ui.alert('error', `Terlalu banyak kode salah. Coba lagi dalam ${lockedFor} detik.`)}
          <a class="btn secondary" href="/2fa/verify">Muat ulang</a></div>`
      : `<div class="card"><h1>${stepup ? '🔐 Verifikasi ulang' : 'Verifikasi dua langkah'}</h1>
        ${stepup ? ui.alert('warn', `<strong>${esc(p.clientName)}</strong> adalah layanan sensitif. Masukkan kode lagi walaupun Anda sudah masuk.`) : ''}
        <div class="row">${ui.avatar(user, 32)}<span class="small">${esc(user.email)}</span></div>
        ${info ? ui.alert('ok', esc(info)) : ''}${error ? ui.alert('error', esc(error)) : ''}
        <form method="post" action="/2fa/verify">
          <label for="code">Kode dari ${[m.totp && 'aplikasi', m.sms && 'SMS', 'kode cadangan'].filter(Boolean).join(', ')}</label>
          <input id="code" class="code" name="code" autocomplete="one-time-code" maxlength="9" autofocus required>
          <div style="margin-top:16px"><button class="block">Verifikasi</button></div>
        </form>
        ${m.sms || m.passkey ? '<h3>Cara lain</h3>' : ''}
        ${m.sms ? `<form method="post" action="/2fa/verify/sms"><button class="choice" type="submit"><span class="ic">💬</span><span>Kirim kode SMS ke <span class="mono">${esc(m.sms.phoneMasked)}</span></span></button></form>` : ''}
        ${m.passkey ? `<button id="pk-btn" class="choice" type="button"><span class="ic">👆</span><span>Gunakan sidik jari atau wajah</span></button><p id="pk-out" class="small" style="color:var(--danger)"></p>
          ${passkeyScript({ mode: 'verify', challenge: p.challenge, userId: user.id, endpoint: '/2fa/verify/passkey' })}` : ''}
        ${stepup ? `<p class="small"><a href="/">Batal, kembali ke Halaman Utama</a></p>` : ''}
      </div>${hints.length ? ui.demoHint(hints.join('<br>')) : ''}${smsHint}`;

    res.html(core.view(bs, {
      title: 'Verifikasi', narrow: true, hideMenu: !stepup,
      flow: stepup ? `Alur 3 · Layanan sensitif → minta kode verifikasi lagi` : 'Alur 2 · Perangkat belum tepercaya → masukkan kode dari aplikasi, SMS, atau kode cadangan',
      body,
    }));
  }

  app.get('/2fa/verify', (req, res) => {
    const c = core.pendingCtx(req, ['verify']);
    if (!c) return res.redirect('/');
    renderVerify(res, c, { info: req.query.sent === '1' ? 'Kode SMS sudah dikirim.' : null });
  });

  app.post('/2fa/verify/sms', (req, res) => {
    const c = core.pendingCtx(req, ['verify']);
    if (!c || !c.user.twoFa.methods.sms) return res.redirect('/');
    const phone = sec.decrypt(c.user.twoFa.methods.sms.phoneEnc);
    const code = sec.randomDigits();
    Object.assign(c.p, { sms: { codeHash: sec.sha256(code), expiresAt: Date.now() + policy.smsCodeTtlMs, used: false }, smsSent: true });
    store.sendMessage('SMS', phone, `Kode masuk Pusat Akun: ${code}. Berlaku 5 menit.`);
    res.redirect('/2fa/verify?sent=1');
  });

  // "Kode benar, masih berlaku, dan belum pernah dipakai?"
  function checkCode(user, p, input) {
    const code = String(input || '').trim();
    const m = user.twoFa.methods;
    if (m.totp) {
      const step = totp.verify(sec.decrypt(m.totp.secretEnc), code, m.totp.lastStep);
      if (step != null) { m.totp.lastStep = step; return 'totp'; }
    }
    if (p.sms && !p.sms.used && p.sms.expiresAt > Date.now() && /^\d{6}$/.test(code) && sec.safeEqual(sec.sha256(code), p.sms.codeHash)) {
      p.sms.used = true;
      return 'sms';
    }
    const backup = user.twoFa.backupCodes.find(b => !b.usedAt && sec.safeEqual(b.hash, sec.sha256(sec.normalizeBackupCode(code))));
    if (backup) { backup.usedAt = Date.now(); return 'backup'; }
    return null;
  }

  // "Catat percobaan gagal, kunci sementara bila berulang"
  function failCode(req, user) {
    user.twoFaFailures++;
    core.audit(req, user.id, 'warn', 'Kode verifikasi salah', `Percobaan gagal ke-${user.twoFaFailures} dari ${policy.max2faFailures}`);
    if (user.twoFaFailures >= policy.max2faFailures) {
      user.twoFaFailures = 0;
      user.twoFaLockedUntil = Date.now() + policy.twoFaLockMs;
      core.audit(req, user.id, 'critical', 'Verifikasi dua langkah dikunci sementara', `${policy.twoFaLockMs / 1000} detik`);
    }
    return `Kode salah, sudah kedaluwarsa, atau sudah pernah dipakai. Sisa percobaan: ${policy.max2faFailures - user.twoFaFailures}.`;
  }

  function passCode(req, c, method) {
    const { bs, p, user } = c;
    user.twoFaFailures = 0;
    if (method === 'backup') {
      const left = user.twoFa.backupCodes.filter(b => !b.usedAt).length;
      core.audit(req, user.id, 'warn', 'Kode cadangan dipakai', `Sisa ${left} kode`);
    }
    if (p.purpose === 'stepup') {
      const acct = bs.accounts.find(a => a.userId === user.id);
      Object.assign(acct, { mfaTime: Date.now(), amr: [...new Set([...acct.amr, method])] });
      core.audit(req, user.id, 'info', `Verifikasi ulang untuk layanan sensitif ${p.clientName}`, core.METHOD_LABEL[method]);
      bs.pending = null;
      return p.returnTo || '/';
    }
    Object.assign(p, { stage: 'trust', amr: ['pwd', method] });
    return '/login/trust';
  }

  app.post('/2fa/verify', (req, res) => {
    const c = core.pendingCtx(req, ['verify']);
    if (!c) return res.redirect('/');
    if (c.user.twoFaLockedUntil > Date.now()) return res.redirect('/2fa/verify');
    const method = checkCode(c.user, c.p, req.body.code);
    if (!method) return renderVerify(res, c, { error: failCode(req, c.user) });
    res.redirect(passCode(req, c, method));
  });

  app.post('/2fa/verify/passkey', (req, res) => {
    const c = core.pendingCtx(req, ['verify']);
    if (!c) return res.json({ ok: false, error: 'Sesi berakhir, muat ulang halaman.' });
    const pk = c.user.twoFa.methods.passkey;
    if (c.user.twoFaLockedUntil > Date.now()) return res.json({ ok: false, error: 'Terkunci sementara.' });
    const ok = pk && c.p.challenge && req.body.credId === pk.credId && sec.verifyEcSignature(pk.publicJwk, c.p.challenge, req.body.signature);
    c.p.challenge = null; // tantangan sekali pakai
    if (!ok) return res.json({ ok: false, error: failCode(req, c.user) });
    res.json({ ok: true, next: passCode(req, c, 'passkey') });
  });

  // "Tawarkan: percayai perangkat ini selama 30 hari"
  app.get('/login/trust', (req, res) => {
    const c = core.pendingCtx(req, ['trust']);
    if (!c) return res.redirect('/login');
    res.html(core.view(c.bs, {
      title: 'Percayai perangkat', narrow: true, hideMenu: true,
      flow: 'Alur 2 · Kode benar → tawarkan: percayai perangkat ini selama 30 hari',
      body: `<div class="card"><h1>Percayai perangkat ini?</h1>
        <p>Perangkat: <strong>${esc(core.deviceLabel(req.ua))}</strong></p>
        <p class="muted small">Selama ${policy.trustDeviceDays} hari, Anda tidak akan diminta kode saat masuk dari perangkat ini. Layanan sensitif tetap akan meminta kode.</p>
        <form method="post" action="/login/trust" class="stack">
          <button class="block" name="trust" value="yes">Ya, percayai ${policy.trustDeviceDays} hari</button>
          <button class="block secondary" name="trust" value="no">Jangan, ini perangkat umum</button>
        </form></div>`,
    }));
  });

  app.post('/login/trust', (req, res) => {
    const c = core.pendingCtx(req, ['trust']);
    if (!c) return res.redirect('/login');
    const { bs, p, user } = c;
    if (req.body.trust === 'yes') {
      const deviceHash = sec.sha256(core.deviceId(req, res));
      user.trustedDevices = user.trustedDevices.filter(d => d.deviceHash !== deviceHash);
      const label = core.deviceLabel(req.ua);
      user.trustedDevices.push({ id: sec.randomToken(6), deviceHash, label, location: core.locationOf(req.ip), createdAt: Date.now(), lastUsed: Date.now(), expiresAt: Date.now() + policy.trustDeviceDays * 86400_000 });
      core.audit(req, user.id, 'info', 'Perangkat ditandai tepercaya', `${label} · ${policy.trustDeviceDays} hari`);
    }
    return core.completeLogin(req, res, bs, user, { amr: p.amr, mfa: true });
  });
};
