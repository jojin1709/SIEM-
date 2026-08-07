const path = require('path');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');

const DATA_DIR = process.env.VERCEL_ENV
  ? '/tmp/siem-data'
  : path.join(__dirname, '..', 'data');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, 'siem.db'));
db.exec('PRAGMA journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,               -- unix ms
  source_type TEXT NOT NULL,         -- syslog | nginx | suricata | winevent | json | raw
  host TEXT,
  src_ip TEXT,
  dest_ip TEXT,
  user TEXT,
  event_id TEXT,
  severity TEXT,
  message TEXT,
  raw TEXT,
  parsed TEXT,                       -- JSON blob of extracted fields
  ingest_batch TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_source_type ON events(source_type);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);

CREATE TABLE IF NOT EXISTS rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT,
  query TEXT NOT NULL,           -- mini-DSL query string
  window_minutes INTEGER NOT NULL DEFAULT 5,
  threshold INTEGER NOT NULL DEFAULT 1,
  severity TEXT NOT NULL DEFAULT 'medium',
  enabled INTEGER NOT NULL DEFAULT 1,
  is_default INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id INTEGER NOT NULL,
  rule_name TEXT NOT NULL,
  severity TEXT NOT NULL,
  matched_count INTEGER NOT NULL,
  window_minutes INTEGER NOT NULL,
  triggered_at INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',  -- open | acknowledged | closed
  sample_event_ids TEXT,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(rule_id) REFERENCES rules(id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_triggered ON alerts(triggered_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_events_ingest_batch ON events(ingest_batch);
CREATE INDEX IF NOT EXISTS idx_events_ts_ingest ON events(ts, ingest_batch);

CREATE TABLE IF NOT EXISTS ingest_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT,
  source_type TEXT,
  event_count INTEGER,
  ingested_at INTEGER
);

CREATE TABLE IF NOT EXISTS saved_searches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  query TEXT NOT NULL,
  description TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_saved_searches_name ON saved_searches(name);

CREATE TABLE IF NOT EXISTS lookup_tables (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  key_field TEXT NOT NULL,
  value_field TEXT NOT NULL,
  data TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lookup_name ON lookup_tables(name);

CREATE TABLE IF NOT EXISTS field_extractions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_type TEXT NOT NULL,
  field_name TEXT NOT NULL,
  pattern TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
`);

module.exports = db;
