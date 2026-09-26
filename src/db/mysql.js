'use strict';
// Data yang TETAP (durable): akun pengguna, 2FA, riwayat keamanan, catatan logout gagal.
// Baris/kolom biasa dipakai untuk apa yang perlu di-query/di-tampilkan panel admin (id, email,
// status, dst); kolom JSON dipakai untuk sub-dokumen bersarang (metode 2FA, kode cadangan,
// perangkat tepercaya, consents) supaya bentuknya tetap mendekati objek lama di memori.
const mysql = require('mysql2/promise');
const cfg = require('../config');

const pool = mysql.createPool({
  host: cfg.mysql.host,
  port: cfg.mysql.port,
  user: cfg.mysql.user,
  password: cfg.mysql.password,
  database: cfg.mysql.database,
  waitForConnections: true,
  connectionLimit: 10,
  dateStrings: true,
});

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS users (
    id                  VARCHAR(40) PRIMARY KEY,
    username            VARCHAR(60) NOT NULL UNIQUE,
    email               VARCHAR(190) NOT NULL UNIQUE,
    name                VARCHAR(120) NOT NULL,
    password_hash       VARCHAR(255) NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'active',
    org                 JSON NOT NULL,
    roles               JSON NOT NULL,
    failed_logins       INT NOT NULL DEFAULT 0,
    two_fa              JSON NULL,
    two_fa_failures     INT NOT NULL DEFAULT 0,
    two_fa_locked_until BIGINT NOT NULL DEFAULT 0,
    two_fa_deferred_at  BIGINT NOT NULL DEFAULT 0,
    trusted_devices     JSON NOT NULL,
    consents            JSON NOT NULL,
    last_login          JSON NULL,
    previous_login      JSON NULL,
    created_at          BIGINT NOT NULL
  ) ENGINE=InnoDB`,
  `CREATE TABLE IF NOT EXISTS audit_log (
    id       VARCHAR(20) PRIMARY KEY,
    at       BIGINT NOT NULL,
    user_id  VARCHAR(40) NULL,
    level    VARCHAR(10) NOT NULL,
    title    VARCHAR(200) NOT NULL,
    detail   TEXT,
    ip       VARCHAR(64),
    ua       VARCHAR(255),
    INDEX idx_audit_at (at),
    INDEX idx_audit_user (user_id, at)
  ) ENGINE=InnoDB`,
  `CREATE TABLE IF NOT EXISTS failed_logouts (
    id         VARCHAR(20) PRIMARY KEY,
    at         BIGINT NOT NULL,
    client_id  VARCHAR(60) NOT NULL,
    sid        VARCHAR(60) NOT NULL,
    user_id    VARCHAR(40) NOT NULL,
    attempts   INT NOT NULL,
    last_error TEXT,
    resolved   TINYINT(1) NOT NULL DEFAULT 0
  ) ENGINE=InnoDB`,
  `CREATE TABLE IF NOT EXISTS admins (
    username      VARCHAR(60) PRIMARY KEY,
    password_hash VARCHAR(255) NOT NULL,
    created_at    BIGINT NOT NULL
  ) ENGINE=InnoDB`,
];

async function migrate() {
  for (const sql of SCHEMA) await pool.query(sql);
}

module.exports = { pool, migrate };
