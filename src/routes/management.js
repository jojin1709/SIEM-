const express = require('express');
const db = require('../db');

const router = express.Router();

router.get('/lookup-tables', (req, res) => {
  res.json(db.prepare('SELECT id, name, key_field, value_field, created_at, updated_at FROM lookup_tables ORDER BY name').all());
});

router.post('/lookup-tables', (req, res) => {
  const { name, key_field, value_field, data } = req.body || {};
  if (![name, key_field, value_field].every(v => typeof v === 'string' && v.trim())) {
    return res.status(400).json({ error: 'name, key_field, and value_field are required' });
  }
  if (!Array.isArray(data) && (!data || typeof data !== 'object')) return res.status(400).json({ error: 'data must be an object or array' });
  const now = Date.now();
  const info = db.prepare('INSERT INTO lookup_tables (name, key_field, value_field, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(name.trim(), key_field.trim(), value_field.trim(), JSON.stringify(data), now, now);
  res.status(201).json({ id: info.lastInsertRowid });
});

router.delete('/lookup-tables/:id', (req, res) => {
  const result = db.prepare('DELETE FROM lookup_tables WHERE id = ?').run(Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error: 'Lookup table not found' });
  res.json({ ok: true });
});

router.get('/field-extractions', (req, res) => {
  res.json(db.prepare('SELECT * FROM field_extractions ORDER BY source_type, field_name').all());
});

router.post('/field-extractions', (req, res) => {
  const { source_type, field_name, pattern } = req.body || {};
  if (![source_type, field_name, pattern].every(v => typeof v === 'string' && v.trim())) {
    return res.status(400).json({ error: 'source_type, field_name, and pattern are required' });
  }
  try { new RegExp(pattern); } catch { return res.status(400).json({ error: 'pattern must be a valid regular expression' }); }
  const now = Date.now();
  const info = db.prepare('INSERT INTO field_extractions (source_type, field_name, pattern, created_at, updated_at) VALUES (?, ?, ?, ?, ?)')
    .run(source_type.trim(), field_name.trim(), pattern, now, now);
  res.status(201).json({ id: info.lastInsertRowid });
});

router.delete('/field-extractions/:id', (req, res) => {
  const result = db.prepare('DELETE FROM field_extractions WHERE id = ?').run(Number(req.params.id));
  if (!result.changes) return res.status(404).json({ error: 'Field extraction not found' });
  res.json({ ok: true });
});

router.get('/runtime', (req, res) => {
  res.json({
    uptime: process.uptime(),
    syslog: { enabled: Boolean(process.env.SYSLOG_PORT), port: process.env.SYSLOG_PORT ? Number(process.env.SYSLOG_PORT) : null },
    websocket: !process.env.VERCEL,
    threat_intel: { feeds_configured: (process.env.TI_FEEDS || '').split(',').filter(Boolean).length }
  });
});

module.exports = router;
