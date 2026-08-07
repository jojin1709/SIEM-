const express = require('express');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const db = require('../db');
const { detectSourceType, parseLine } = require('../parsers');
const { SAMPLE_DATA } = require('../sample-data');
const { runAllRules } = require('../rules');

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

function buildEventObject(parsed, line, sourceType, batchId) {
  return {
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
  };
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
    rows.push(buildEventObject(parsed, line, sourceType, batchId));
  }

  insertMany(rows);
  db.prepare(`INSERT INTO ingest_log (filename, source_type, event_count, ingested_at) VALUES (?, ?, ?, ?)`)
    .run(req.file.originalname, sourceType, rows.length, Date.now());

  try { runAllRules(); } catch (e) { console.error('[rules] auto-eval error:', e.message); }

  res.json({ ok: true, filename: req.file.originalname, source_type: sourceType, ingested: rows.length, batch_id: batchId });
});

router.post('/sample', (req, res) => {
  const summary = [];
  const now = Date.now();

  for (const [filename, { source_type, lines }] of Object.entries(SAMPLE_DATA)) {
    const parsedRows = lines.map(l => parseLine(l, source_type));
    const maxTs = Math.max(...parsedRows.map(p => p.ts || 0));
    const delta = now - maxTs;
    const batchId = `sample-${filename}-${Date.now()}`;

    const events = parsedRows.map((parsed, i) => ({
      ...buildEventObject(parsed, lines[i], source_type, batchId),
      ts: (parsed.ts || now) + delta
    }));

    insertMany(events);
    db.prepare(`INSERT INTO ingest_log (filename, source_type, event_count, ingested_at) VALUES (?, ?, ?, ?)`)
      .run(filename, source_type, events.length, now);
    summary.push({ file: filename, ingested: events.length });
  }

  try { runAllRules(); } catch (e) { console.error('[rules] auto-eval error:', e.message); }

  res.json({ ok: true, summary });
});

function loadSampleData() {
  const now = Date.now();

  for (const [filename, { source_type, lines }] of Object.entries(SAMPLE_DATA)) {
    const parsedRows = lines.map(l => parseLine(l, source_type));
    const maxTs = Math.max(...parsedRows.map(p => p.ts || 0));
    const delta = now - maxTs;
    const batchId = `sample-${filename}-${Date.now()}`;

    const events = parsedRows.map((parsed, i) => ({
      ...buildEventObject(parsed, lines[i], source_type, batchId),
      ts: (parsed.ts || now) + delta
    }));

    db.exec('BEGIN');
    try {
      for (const e of events) insertStmt.run(e);
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
    }
    db.prepare(`INSERT INTO ingest_log (filename, source_type, event_count, ingested_at) VALUES (?, ?, ?, ?)`)
      .run(filename, source_type, events.length, now);
  }

  try { runAllRules(); } catch (e) { console.error('[rules] auto-eval error:', e.message); }
}

module.exports = router;
module.exports.loadSampleData = loadSampleData;
