const express = require('express');
const db = require('../db');
const { runAllRules } = require('../rules');

const router = express.Router();

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const VALID_ALERT_STATUSES = ['open', 'acknowledged', 'closed'];

function validateRuleInput(body) {
  const errors = [];
  if (!body.name || typeof body.name !== 'string' || body.name.trim().length === 0 || body.name.length > 255) {
    errors.push('name is required (1-255 chars)');
  }
  if (!body.query || typeof body.query !== 'string' || body.query.trim().length === 0) {
    errors.push('query is required');
  }
  const wm = parseInt(body.window_minutes, 10);
  if (isNaN(wm) || wm < 1 || wm > 1440) errors.push('window_minutes must be between 1 and 1440');
  const th = parseInt(body.threshold, 10);
  if (isNaN(th) || th < 1) errors.push('threshold must be >= 1');
  if (body.severity && !VALID_SEVERITIES.includes(body.severity)) errors.push('severity must be one of: ' + VALID_SEVERITIES.join(', '));
  if (body.description !== undefined && (typeof body.description !== 'string' || body.description.length > 1000)) {
    errors.push('description must be a string up to 1000 chars');
  }
  return errors;
}

router.get('/rules', (req, res) => {
  res.json(db.prepare('SELECT * FROM rules ORDER BY id DESC').all());
});

router.post('/rules', (req, res) => {
  const errors = validateRuleInput(req.body);
  if (errors.length) return res.status(400).json({ error: 'Validation failed', details: errors });

  const name = req.body.name.trim();
  const description = (req.body.description || '').trim();
  const query = req.body.query.trim();
  const window_minutes = parseInt(req.body.window_minutes, 10) || 5;
  const threshold = parseInt(req.body.threshold, 10) || 1;
  const severity = req.body.severity || 'medium';
  const now = Date.now();

  const info = db.prepare(
    `INSERT INTO rules (name, description, query, window_minutes, threshold, severity, enabled, is_default, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 1, 0, ?, ?)`
  ).run(name, description, query, window_minutes, threshold, severity, now, now);
  res.json({ id: info.lastInsertRowid });
});

router.patch('/rules/:id', (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid rule ID' });
  const existing = db.prepare('SELECT * FROM rules WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Not found' });

  const allowedFields = ['name', 'description', 'query', 'window_minutes', 'threshold', 'severity', 'enabled'];
  const updates = {};
  for (const field of allowedFields) {
    if (req.body[field] !== undefined) updates[field] = req.body[field];
  }

  const errors = [];
  if (updates.name !== undefined && (typeof updates.name !== 'string' || updates.name.trim().length === 0 || updates.name.length > 255)) {
    errors.push('name must be 1-255 chars');
  }
  if (updates.description !== undefined && (typeof updates.description !== 'string' || updates.description.length > 1000)) {
    errors.push('description must be up to 1000 chars');
  }
  if (updates.query !== undefined && (typeof updates.query !== 'string' || updates.query.trim().length === 0)) {
    errors.push('query is required');
  }
  if (updates.window_minutes !== undefined) {
    const wm = parseInt(updates.window_minutes, 10);
    if (isNaN(wm) || wm < 1 || wm > 1440) errors.push('window_minutes must be between 1 and 1440');
    updates.window_minutes = wm;
  }
  if (updates.threshold !== undefined) {
    const th = parseInt(updates.threshold, 10);
    if (isNaN(th) || th < 1) errors.push('threshold must be >= 1');
    updates.threshold = th;
  }
  if (updates.severity !== undefined && !VALID_SEVERITIES.includes(updates.severity)) {
    errors.push('severity must be one of: ' + VALID_SEVERITIES.join(', '));
  }
  if (updates.enabled !== undefined) {
    updates.enabled = updates.enabled ? 1 : 0;
  }

  if (errors.length) return res.status(400).json({ error: 'Validation failed', details: errors });

  if (Object.keys(updates).length === 0) return res.json({ ok: true, message: 'No fields to update' });

  const fields = Object.keys(updates);
  const setClause = fields.map(f => `${f} = ?`).join(', ');
  const values = fields.map(f => updates[f]);
  values.push(Date.now(), id);

  db.prepare(`UPDATE rules SET ${setClause}, updated_at = ? WHERE id = ?`).run(...values);
  res.json({ ok: true });
});

router.delete('/rules/:id', (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid rule ID' });
  const stmt = db.prepare('DELETE FROM rules WHERE id = ?');
  const result = stmt.run(id);
  if (result.changes === 0) return res.status(404).json({ error: 'Rule not found' });
  res.json({ ok: true, deleted: result.changes });
});

router.post('/rules/run', (req, res) => {
  const fired = runAllRules();
  res.json({ fired });
});

router.get('/', (req, res) => {
  const { status, page = '1', limit = '50' } = req.query;
  const pageNum = Math.max(1, parseInt(page, 10) || 1);
  const limitNum = Math.min(200, Math.max(1, parseInt(limit, 10) || 50));
  const offset = (pageNum - 1) * limitNum;

  const total = status
    ? db.prepare('SELECT COUNT(*) as c FROM alerts WHERE status = ?').get(status).c
    : db.prepare('SELECT COUNT(*) as c FROM alerts').get().c;

  const rows = status
    ? db.prepare('SELECT * FROM alerts WHERE status = ? ORDER BY triggered_at DESC LIMIT ? OFFSET ?').all(status, limitNum, offset)
    : db.prepare('SELECT * FROM alerts ORDER BY triggered_at DESC LIMIT ? OFFSET ?').all(limitNum, offset);

  res.json({ alerts: rows, total, page: pageNum, limit: limitNum });
});

router.patch('/:id', (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid alert ID' });
  const { status } = req.body;
  if (!VALID_ALERT_STATUSES.includes(status)) return res.status(400).json({ error: 'invalid status' });
  const result = db.prepare('UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?').run(status, Date.now(), id);
  if (result.changes === 0) return res.status(404).json({ error: 'Alert not found' });
  res.json({ ok: true });
});

module.exports = router;
