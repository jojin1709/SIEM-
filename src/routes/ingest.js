const express = require('express');
const multer = require('multer');
const db = require('../db');
const { detectSourceType, parseLine } = require('../parsers');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

const insertStmt = db.prepare(`
  INSERT INTO events (ts, source_type, host, src_ip, dest_ip, user, event_id, severity, message, raw, parsed, ingest_batch)
  VALUES (@ts, @source_type, @host, @src_ip, @dest_ip, @user, @event_id, @severity, @message, @raw, @parsed, @ingest_batch)
`);

function insertMany(events) {
  db.exec('BEGIN');
  try {
    for (const e of events) insertStmt.run(e);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

router.post('/file', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded (field name must be "file")' });

  const text = req.file.buffer.toString('utf-8');
  const lines = text.split(/\r?\n/).filter(l => l.trim().length > 0);
  if (lines.length === 0) return res.status(400).json({ error: 'File is empty' });

  let sourceType = req.body.source_type;
  if (!sourceType || sourceType === 'auto') {
    sourceType = detectSourceType(lines.slice(0, Math.min(20, lines.length)));
  }

  const batchId = `${req.file.originalname}-${Date.now()}`;
  const rows = [];
  for (const line of lines) {
    const parsed = parseLine(line, sourceType);
    rows.push({
      ts: parsed.ts || Date.now(),
      source_type: parsed.source_type || sourceType,
      host: parsed.host || null,
      src_ip: parsed.src_ip || null,
      dest_ip: parsed.dest_ip || null,
      user: parsed.user || null,
      event_id: parsed.event_id || null,
      severity: parsed.severity || 'info',
      message: parsed.message || line.slice(0, 500),
      raw: line.slice(0, 2000),
      parsed: JSON.stringify(parsed.parsed || {}),
      ingest_batch: batchId
    });
  }

  insertMany(rows);
  db.prepare(`INSERT INTO ingest_log (filename, source_type, event_count, ingested_at) VALUES (?, ?, ?, ?)`)
    .run(req.file.originalname, sourceType, rows.length, Date.now());

  res.json({ ok: true, filename: req.file.originalname, source_type: sourceType, ingested: rows.length, batch_id: batchId });
});

// Loads the bundled sample-logs/*.log|json files, but shifts each file's
// timestamps so its most recent line lands "now" (preserving relative
// spacing). That way the dashboard/alerts feel alive immediately after
// loading, regardless of what day someone actually runs this.
const fs = require('fs');
const path = require('path');
const SAMPLE_DIR = path.join(__dirname, '..', '..', 'sample-logs');
const SAMPLE_FILES = [
  { file: 'auth-syslog.log', source_type: 'syslog' },
  { file: 'access-nginx.log', source_type: 'nginx' },
  { file: 'eve.json', source_type: 'suricata' },
  { file: 'winevents.json', source_type: 'winevent' }
];

router.post('/sample', (req, res) => {
  const summary = [];
  for (const { file, source_type } of SAMPLE_FILES) {
    const fp = path.join(SAMPLE_DIR, file);
    if (!fs.existsSync(fp)) continue;
    const lines = fs.readFileSync(fp, 'utf-8').split(/\r?\n/).filter(l => l.trim());
    const parsedRows = lines.map(l => parseLine(l, source_type));
    const maxTs = Math.max(...parsedRows.map(p => p.ts || 0));
    const delta = Date.now() - maxTs;
    const batchId = `sample-${file}-${Date.now()}`;

    const rows = parsedRows.map((parsed, i) => ({
      ts: (parsed.ts || Date.now()) + delta,
      source_type: parsed.source_type || source_type,
      host: parsed.host || null,
      src_ip: parsed.src_ip || null,
      dest_ip: parsed.dest_ip || null,
      user: parsed.user || null,
      event_id: parsed.event_id || null,
      severity: parsed.severity || 'info',
      message: parsed.message || lines[i].slice(0, 500),
      raw: lines[i].slice(0, 2000),
      parsed: JSON.stringify(parsed.parsed || {}),
      ingest_batch: batchId
    }));

    insertMany(rows);
    db.prepare(`INSERT INTO ingest_log (filename, source_type, event_count, ingested_at) VALUES (?, ?, ?, ?)`)
      .run(file, source_type, rows.length, Date.now());
    summary.push({ file, ingested: rows.length });
  }
  res.json({ ok: true, summary });
});

router.get('/history', (req, res) => {
  const { page = '1', limit = '50' } = req.query;
  const pageNum = Math.max(1, parseInt(page, 10) || 1);
  const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10) || 50));
  const offset = (pageNum - 1) * limitNum;

  const total = db.prepare('SELECT COUNT(*) as c FROM ingest_log').get().c;
  const rows = db.prepare(
    'SELECT * FROM ingest_log ORDER BY ingested_at DESC LIMIT ? OFFSET ?'
  ).all(limitNum, offset);

  res.json({ entries: rows, total, page: pageNum, limit: limitNum });
});

module.exports = router;

function loadSampleData() {
  const fs = require('fs');
  const path = require('path');
  const { parseLine } = require('../parsers');

  const SAMPLE_DIR = path.join(__dirname, '..', '..', 'sample-logs');
  const SAMPLE_FILES = [
    { file: 'auth-syslog.log', source_type: 'syslog' },
    { file: 'access-nginx.log', source_type: 'nginx' },
    { file: 'eve.json', source_type: 'suricata' },
    { file: 'winevents.json', source_type: 'winevent' }
  ];

  const insertStmt = db.prepare(`
    INSERT INTO events (ts, source_type, host, src_ip, dest_ip, user, event_id, severity, message, raw, parsed, ingest_batch)
    VALUES (@ts, @source_type, @host, @src_ip, @dest_ip, @user, @event_id, @severity, @message, @raw, @parsed, @ingest_batch)
  `);

  for (const { file, source_type } of SAMPLE_FILES) {
    const fp = path.join(SAMPLE_DIR, file);
    if (!fs.existsSync(fp)) continue;
    const lines = fs.readFileSync(fp, 'utf-8').split(/\r?\n/).filter(l => l.trim());
    const parsedRows = lines.map(l => parseLine(l, source_type));
    const maxTs = Math.max(...parsedRows.map(p => p.ts || 0));
    const delta = Date.now() - maxTs;
    const batchId = `sample-${file}-${Date.now()}`;

    const rows = parsedRows.map((parsed, i) => ({
      ts: (parsed.ts || Date.now()) + delta,
      source_type: parsed.source_type || source_type,
      host: parsed.host || null,
      src_ip: parsed.src_ip || null,
      dest_ip: parsed.dest_ip || null,
      user: parsed.user || null,
      event_id: parsed.event_id || null,
      severity: parsed.severity || 'info',
      message: parsed.message || lines[i].slice(0, 500),
      raw: lines[i].slice(0, 2000),
      parsed: JSON.stringify(parsed.parsed || {}),
      ingest_batch: batchId
    }));

    db.exec('BEGIN');
    try {
      for (const e of rows) insertStmt.run(e);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
    }
    db.prepare(`INSERT INTO ingest_log (filename, source_type, event_count, ingested_at) VALUES (?, ?, ?, ?)`)
      .run(file, source_type, rows.length, Date.now());
  }
}

module.exports.loadSampleData = loadSampleData;
