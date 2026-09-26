'use strict';
const { PORTAL } = require('../config');

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const AVATAR_COLORS = ['#4f46e5', '#0891b2', '#16a34a', '#c026d3', '#ea580c', '#0d9488', '#7c3aed', '#db2777'];
function avatar(user, size = 36) {
  const initials = String(user.name || '?').split(/\s+/).map(w => w[0]).slice(0, 2).join('').toUpperCase();
  const color = AVATAR_COLORS[[...String(user.id)].reduce((a, c) => a + c.charCodeAt(0), 0) % AVATAR_COLORS.length];
  return `<span class="avatar" style="width:${size}px;height:${size}px;font-size:${Math.round(size * 0.4)}px;background:${color}">${esc(initials)}</span>`;
}

const alert = (type, html) => `<div class="alert ${type}">${html}</div>`;
const demoHint = html => `<div class="demo-hint"><strong>Bantuan demo</strong> · ${html}</div>`;

const fmtTime = t => (t ? new Date(t).toLocaleString('id-ID', { dateStyle: 'medium', timeStyle: 'medium' }) : '—');

const css = accent => `
:root{--accent:${accent};--bg:#f5f6fa;--card:#fff;--text:#1f2937;--muted:#6b7280;--border:#e5e7eb;--danger:#dc2626;--ok:#15803d;--warn:#b45309}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text)}
a{color:var(--accent)}
header.top{background:#fff;border-bottom:1px solid var(--border);padding:10px 24px;display:flex;align-items:center;justify-content:space-between;gap:12px;position:sticky;top:0;z-index:5}
.brand{display:flex;gap:10px;align-items:center;font-weight:700;color:var(--text);text-decoration:none;font-size:17px}
.logo{width:32px;height:32px;border-radius:9px;background:var(--accent);color:#fff;display:grid;place-items:center;font-size:16px}
.right{display:flex;align-items:center;gap:12px}
main{max-width:1040px;margin:28px auto;padding:0 16px}
main.narrow{max-width:460px}
footer{text-align:center;color:var(--muted);font-size:13px;padding:24px 16px 40px}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:22px 24px;margin-bottom:16px;box-shadow:0 1px 2px rgba(0,0,0,.03)}
h1{font-size:23px;margin:0 0 6px}h2{font-size:17px;margin:0 0 12px}h3{font-size:15px;margin:16px 0 8px}
.muted{color:var(--muted)}.small{font-size:13px}
label{display:block;font-size:14px;font-weight:600;margin:14px 0 6px}
input[type=text],input[type=password],input[type=email],input[type=tel],input[type=number]{width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:8px;font-size:15px;background:#fff}
input:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:transparent}
input.code{font-family:ui-monospace,Consolas,monospace;font-size:20px;letter-spacing:4px;text-align:center}
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:10px 16px;border-radius:8px;border:1px solid var(--accent);background:var(--accent);color:#fff;font-weight:600;font-size:14px;cursor:pointer;text-decoration:none;font-family:inherit}
button:disabled{opacity:.6;cursor:wait}
.btn.secondary,button.secondary{background:#fff;color:var(--accent)}
.btn.danger,button.danger{background:var(--danger);border-color:var(--danger);color:#fff}
.btn.ghost,button.ghost{background:transparent;border-color:var(--border);color:var(--text)}
.btn.sm,button.sm{padding:6px 10px;font-size:13px}
.block{width:100%}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.stack>*+*{margin-top:10px}
.alert{padding:10px 14px;border-radius:8px;margin:12px 0;font-size:14px}
.alert.error{background:#fef2f2;color:#991b1b;border:1px solid #fecaca}
.alert.ok{background:#f0fdf4;color:#166534;border:1px solid #bbf7d0}
.alert.info{background:#eff6ff;color:#1e40af;border:1px solid #bfdbfe}
.alert.warn{background:#fffbeb;color:#92400e;border:1px solid #fde68a}
.flow{display:inline-block;font:12px ui-monospace,Consolas,monospace;background:#eef2ff;color:#3730a3;padding:3px 10px;border-radius:999px;margin-bottom:14px}
.demo-hint{border:1px dashed #d97706;background:#fffbeb;padding:10px 12px;border-radius:8px;font-size:13px;margin:14px 0;color:#78350f}
.avatar{border-radius:50%;display:inline-grid;place-items:center;color:#fff;font-weight:700;flex:none}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px;margin:18px 0}
.tile{display:flex;flex-direction:column;gap:6px;padding:18px;border-radius:14px;background:#fff;border:1px solid var(--border);text-decoration:none;color:var(--text);border-top:4px solid var(--c);transition:transform .1s,box-shadow .1s}
.tile:hover{transform:translateY(-2px);box-shadow:0 8px 20px rgba(0,0,0,.07)}
.tile-icon{font-size:28px}
.tags{display:flex;gap:6px;flex-wrap:wrap;margin-top:4px}
.tag{font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;background:#f3f4f6;color:#374151}
.tag.ok{background:#dcfce7;color:#166534}.tag.warn{background:#fef3c7;color:#92400e}.tag.err{background:#fee2e2;color:#991b1b}.tag.info{background:#dbeafe;color:#1e40af}
details.menu{position:relative}
details.menu>summary{list-style:none;cursor:pointer;border-radius:50%}
details.menu>summary::-webkit-details-marker{display:none}
details.menu>summary.waffle-btn{border-radius:8px;padding:6px;color:var(--muted);display:grid;place-items:center;width:36px;height:36px}
details.menu>summary.waffle-btn:hover{background:#f3f4f6;color:var(--text)}
details[open]>summary.waffle-btn{background:#eef2ff;color:var(--accent)}
.menu-panel{position:absolute;right:0;top:46px;width:310px;background:#fff;border:1px solid var(--border);border-radius:14px;box-shadow:0 12px 32px rgba(0,0,0,.14);padding:8px;z-index:10}
.menu-head{display:flex;gap:12px;align-items:center;padding:10px}
.menu-label{font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;padding:10px 10px 4px}
.menu-item{display:flex;gap:10px;align-items:center;width:100%;padding:9px 10px;border-radius:8px;background:none;border:0;color:var(--text);font-weight:500;text-align:left;cursor:pointer;text-decoration:none;font-size:14px}
.menu-item:hover{background:#f3f4f6}
.menu-panel form{margin:0}
.menu-panel hr{border:0;border-top:1px solid var(--border);margin:6px 0}
.apps-panel{width:264px}
.apps-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:4px;padding:6px}
.app-tile{display:flex;flex-direction:column;align-items:center;gap:5px;padding:14px 6px 10px;border-radius:10px;text-decoration:none;color:var(--text);font-size:12px;font-weight:600;text-align:center;border-top:3px solid var(--c);transition:background .1s}
.app-tile:hover{background:#f3f4f6}
.app-tile-icon{font-size:22px;line-height:1}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.03em}
.table-wrap{overflow-x:auto}
code,.mono{font-family:ui-monospace,Consolas,monospace;font-size:13px}
.secret{display:block;font:18px ui-monospace,Consolas,monospace;letter-spacing:2px;background:#f3f4f6;padding:10px 12px;border-radius:8px;word-break:break-all}
.codes{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin:12px 0}
.codes span{font:16px ui-monospace,Consolas,monospace;background:#f3f4f6;padding:8px;border-radius:6px;text-align:center}
.choice{display:flex;gap:14px;align-items:flex-start;padding:14px;border:1px solid var(--border);border-radius:12px;text-decoration:none;color:var(--text);margin-bottom:10px;background:#fff;width:100%;text-align:left;font-weight:400;font-size:15px}
.choice:hover{border-color:var(--accent);background:#fafaff}
.choice .ic{font-size:24px;line-height:1}
.lvl-critical{color:var(--danger);font-weight:700}.lvl-warn{color:var(--warn);font-weight:600}.lvl-info{color:var(--muted)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media (max-width:760px){.two{grid-template-columns:1fr}}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;font-size:14px}
.kv dt{color:var(--muted)}.kv dd{margin:0;word-break:break-all}
.toggle-row{display:flex;align-items:flex-start;gap:12px;padding:14px;border:1px solid var(--border);border-radius:12px;background:#fafafa;margin-bottom:16px}
.toggle-row input[type=checkbox]{width:20px;height:20px;accent-color:var(--accent);margin-top:2px;flex:none}
.toggle-row strong{font-size:15px}
.qr-panel{display:flex;gap:24px;align-items:center;flex-wrap:wrap;margin:16px 0}
.qr-box{flex:none;background:#fff;border:1px solid var(--border);border-radius:14px;padding:14px;box-shadow:0 1px 3px rgba(0,0,0,.06);line-height:0}
.qr-box svg{display:block;width:176px;height:176px}
.qr-steps{flex:1;min-width:220px}
.qr-steps ol{margin:0;padding-left:20px}
.qr-steps li{margin-bottom:9px}
`;

const WAFFLE_ICON = `<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor">${[5, 12, 19].flatMap(cy => [5, 12, 19].map(cx => `<circle cx="${cx}" cy="${cy}" r="2"/>`)).join('')}</svg>`;

// Header Bersama (Alur 3a) — grid 3x3 layanan. Data polos (bukan objek store) supaya bisa dipakai
// baik oleh Portal (langsung) maupun tiap Service Provider (lewat panggilan /internal/header).
function appLauncher(services, portalUrl) {
  const tiles = services.map(s => `<a class="app-tile" href="${esc(s.url)}/" style="--c:${esc(s.color)}"><span class="app-tile-icon">${s.icon}</span><span>${esc(s.name)}</span></a>`).join('');
  return `<details class="menu"><summary class="waffle-btn" title="Semua layanan">${WAFFLE_ICON}</summary><div class="menu-panel apps-panel">
    <div class="menu-label">Layanan Anda</div>
    <div class="apps-grid">${tiles || '<div class="menu-item muted small">Tidak ada layanan untuk akun ini</div>'}</div>
    <hr><a class="menu-item" href="${esc(portalUrl)}/">🏠 Portal</a>
  </div></details>`;
}

// Menu avatar (Alur 4) — markup yang sama persis dipakai di Portal dan di tiap layanan,
// hanya tujuan form/link yang berbeda (lokal di Portal, absolut lewat Pusat Akun bila dari layanan).
function avatarMenu({ user, others = [], switchAction, addHref, manageHref, logoutHref, returnTo }) {
  const switchItems = others.length
    ? others.map(o => `<form method="post" action="${esc(switchAction)}"><input type="hidden" name="userId" value="${esc(o.id)}">${returnTo ? `<input type="hidden" name="return" value="${esc(returnTo)}">` : ''}
        <button class="menu-item">${avatar(o, 28)}<span>${esc(o.name)}<br><span class="muted small">${esc(o.email)}</span></span></button></form>`).join('')
    : '<div class="menu-item muted small">Belum ada akun lain di browser ini</div>';
  return `<details class="menu"><summary title="Menu akun">${avatar(user)}</summary><div class="menu-panel">
    <div class="menu-head">${avatar(user, 44)}<div><strong>${esc(user.name)}</strong><div class="muted small">${esc(user.email)}</div></div></div>
    <hr>
    <a class="menu-item" href="${esc(addHref)}">➕ Tambah akun</a>
    <div class="menu-label">Ganti akun</div>${switchItems}
    <hr>
    ${manageHref ? `<a class="menu-item" href="${esc(manageHref)}">⚙️ Kelola akun</a>` : ''}
    <a class="menu-item" href="${esc(logoutHref)}">🚪 Keluar</a>
  </div></details>`;
}

function page({ title, brand, flow, body, right = '', narrow = false }) {
  return `<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · ${esc(brand.name)}</title><style>${css(brand.color)}</style></head>
<body>
<header class="top"><a class="brand" href="${esc(brand.home)}"><span class="logo">${brand.logo}</span>${esc(brand.name)}</a><div class="right">${right}</div></header>
<main class="${narrow ? 'narrow' : ''}">${flow ? `<div class="flow">${esc(flow)}</div>` : ''}${body}</main>
<footer>Demo SSO · <a href="${PORTAL}/">Portal</a> · <a href="${PORTAL}/demo">Panel Demo</a></footer>
</body></html>`;
}

module.exports = { esc, avatar, alert, demoHint, fmtTime, page, appLauncher, avatarMenu };
