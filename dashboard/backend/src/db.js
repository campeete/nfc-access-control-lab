/**
 * NFC Dashboard — Database Layer
 * Uses sql.js (pure JS SQLite) — no native bindings required
 */

const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '../data/nfc_lab.db');
let db = null;

async function getDb() {
  if (db) return db;
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    db = new SQL.Database();
  }
  initSchema();
  return db;
}

function initSchema() {
  db.run(`CREATE TABLE IF NOT EXISTS scan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    uid TEXT NOT NULL,
    phase INTEGER NOT NULL,
    result TEXT NOT NULL,
    response_time_ms REAL,
    reader_ip TEXT,
    notes TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS attack_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    uid TEXT,
    phase_target INTEGER,
    result TEXT,
    response_time_ms REAL,
    raw_payload TEXT,
    notes TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS valid_uids (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT UNIQUE NOT NULL,
    discovered_at TEXT NOT NULL,
    discovery_method TEXT,
    confirmed INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT UNIQUE NOT NULL,
    label TEXT,
    created_at TEXT NOT NULL,
    last_used TEXT
  )`);

  persist();
}

function persist() {
  if (!db) return;
  const data = db.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function run(sql, params = []) {
  db.run(sql, params);
  persist();
}

function all(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function get(sql, params = []) {
  return all(sql, params)[0] || null;
}

module.exports = { getDb, run, all, get, persist };
