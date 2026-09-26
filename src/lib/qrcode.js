'use strict';
// Pembuat gambar QR untuk kode 2FA (otpauth://) — dirender sebagai SVG langsung di server,
// tanpa pustaka pihak ketiga sebagai dependency (lihat README: "tidak ada dependensi").
// Mesin enkode QR sesungguhnya divendor apa adanya di vendor/qrcode-generator.js (MIT, Kazuhiko Arase).
const qrcodeLib = require('./vendor/qrcode-generator');

// otpauth://... untuk secret 32 karakter base32 muat di type ≈ 5-7; 0 = pilih otomatis type terkecil yang cukup.
function svgFor(text, { cellSize = 5, margin = 4 } = {}) {
  const qr = qrcodeLib(0, 'M');
  qr.addData(text);
  qr.make();
  return qr.createSvgTag(cellSize, margin);
}

module.exports = { svgFor };
