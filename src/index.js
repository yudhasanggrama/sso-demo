'use strict';
const cfg = require('./config');
const { createPortal } = require('./idp/server');
const { createService } = require('./service/server');

createPortal().listen(cfg.PORTAL_PORT, () => {
  console.log(`\n  Pusat Akun (Portal)  ${cfg.PORTAL}`);
  console.log(`  Panel Demo           ${cfg.PORTAL}/demo`);
});

for (const svc of cfg.services) {
  createService(svc).listen(svc.port, () => console.log(`  Layanan ${svc.name.padEnd(12)} ${svc.url}`));
}
