'use strict';
const { createApp } = require('../lib/http');

function createPortal() {
  const app = createApp('pusat-akun');
  require('./routes-oidc')(app);    // Mulai + Alur 3
  require('./routes-login')(app);   // Alur 1 + Alur 2
  require('./routes-account')(app); // Alur 4 + Alur 5
  require('./routes-demo')(app);    // Panel Demo
  return app;
}

module.exports = { createPortal };
