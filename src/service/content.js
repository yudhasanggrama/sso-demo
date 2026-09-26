'use strict';
// Isi palsu tiap layanan, supaya terlihat seperti aplikasi sungguhan.
const { esc } = require('../lib/ui');

const rupiah = n => `Rp${n.toLocaleString('id-ID')}`;

module.exports = {
  surel: c => {
    const mails = [
      ['Tim TI', 'Pemeliharaan server Sabtu malam', '09.12'],
      ['Sari Wulandari', 'Laporan anggaran Q3 sudah siap', '08.47'],
      ['HRD', `Selamat datang di portal baru, ${c.name || ''}`, 'Kemarin'],
      ['Andi Pratama', 'Re: rapat koordinasi', 'Senin'],
    ];
    return `<div class="card"><h2>Kotak masuk</h2><table>${mails.map(([from, subj, t]) =>
      `<tr><td><strong>${esc(from)}</strong></td><td>${esc(subj)}</td><td class="small muted">${t}</td></tr>`).join('')}</table></div>`;
  },
  dokumen: () => {
    const files = [['Pedoman Keamanan Informasi.pdf', '1,2 MB'], ['Notulen Rapat Oktober.docx', '84 KB'], ['Rencana Kerja 2027.xlsx', '312 KB'], ['Logo Perusahaan.zip', '4,8 MB']];
    return `<div class="card"><h2>Berkas bersama</h2><table>${files.map(([f, s]) =>
      `<tr><td>📄 ${esc(f)}</td><td class="small muted">${s}</td></tr>`).join('')}</table></div>`;
  },
  keuangan: () => {
    const tx = [['Pembayaran vendor jaringan', -48_500_000], ['Penerimaan termin proyek B', 210_000_000], ['Gaji karyawan Oktober', -365_250_000], ['Pengembalian dana pajak', 12_300_000]];
    return `<div class="two">
      <div class="card"><div class="muted small">Saldo kas operasional</div><div style="font-size:28px;font-weight:700">${rupiah(1_284_530_000)}</div></div>
      <div class="card"><div class="muted small">Menunggu persetujuan Anda</div><div style="font-size:28px;font-weight:700">3 pembayaran</div></div></div>
      <div class="card"><h2>Transaksi terakhir</h2><table>${tx.map(([d, v]) =>
        `<tr><td>${esc(d)}</td><td style="text-align:right;color:${v < 0 ? 'var(--danger)' : 'var(--ok)'}">${rupiah(v)}</td></tr>`).join('')}</table></div>`;
  },
};
