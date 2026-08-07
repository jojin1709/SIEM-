const express = require('express');
const db = require('../db');
const { buildWhere } = require('../query');

const router = express.Router();

router.get('/', (req, res) => {
  const rows = db.prepare('SELECT * FROM saved_searches ORDER BY name ASC').all();
  res.json(rows);
});

router.post('/', (req, res) => {
  const { name, query, description = '' } = req.body;
  if (!name || typeof name !== 'string' || name.trim().length === 0 || name.length > 100) {
    return res.status(400).json({ error: 'name is required (1-100 chars)' });
  }
  if (!query || typeof query !== 'string' || query.trim().length === 0) {
    return res.status(400).json({ error: 'query is required' });
  }
  if (description !== undefined && (typeof description !== 'string' || description.length > 500)) {
    return res.status(400).json({ error: 'description must be up to 500 chars' });
  }

  const now = Date.now();
  try {
    const info = db.prepare(
      `INSERT INTO saved_searches (name, query, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`
    ).run(name.trim(), query.trim(), description.trim(), now, now);
    res.json({ id: info.lastInsertRowid });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'A saved search with that name already exists' });
    }
    res.status(500).json({ error: 'Database error' });
  }
});

router.get('/:id/run', (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });

  const saved = db.prepare('SELECT * FROM saved_searches WHERE id = ?').get(id);
  if (!saved) return res.status(404).json({ error: 'Saved search not found' });

  const { q = saved.query, source_type, severity, from, to, page = '1', pageSize = '50' } = req.query;

  const { where, params } = buildWhere(q, {
    source_type: source_type || undefined,
    severity: severity || undefined,
    from: from ? Number(from) : undefined,
    to: to ? Number(to) : undefined
  });

  const pageNum = Math.max(1, parseInt(page, 10) || 1);
  const size = Math.min(500, Math.max(1, parseInt(pageSize, 10) || 50));
  const offset = (pageNum - 1) * size;

  try {
    const total = db.prepare(`SELECT COUNT(*) as c FROM events WHERE ${where}`).get(...params).c;
    const rows = db.prepare(
      `SELECT * FROM events WHERE ${where} ORDER BY ts DESC LIMIT ? OFFSET ?`
    ).all(...params, size, offset);

    res.json({
      saved_search: saved.name,
      total,
      page: pageNum,
      pageSize: size,
      totalPages: Math.ceil(total / size),
      results: rows.map(r => ({ ...r, parsed: safeParse(r.parsed) }))
    });
  } catch (err) {
    res.status(400).json({ error: 'Query error' });
  }
});

router.patch('/:id', (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });

  const existing = db.prepare('SELECT * FROM saved_searches WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Not found' });

  const allowedFields = ['name', 'query', 'description'];
  const updates = {};
  for (const field of allowedFields) {
    if (req.body[field] !== undefined) updates[field] = req.body[field];
  }

  if (updates.name !== undefined) {
    if (typeof updates.name !== 'string' || updates.name.trim().length === 0 || updates.name.length > 100) {
      return res.status(400).json({ error: 'name must be 1-100 chars' });
    }
    updates.name = updates.name.trim();
  }
  if (updates.query !== undefined) {
    if (typeof updates.query !== 'string' || updates.query.trim().length === 0) {
      return res.status(400).json({ error: 'query is required' });
    }
    updates.query = updates.query.trim();
  }
  if (updates.description !== undefined) {
    if (typeof updates.description !== 'string' || updates.description.length > 500) {
      return res.status(400).json({ error: 'description must be up to 500 chars' });
    }
    updates.description = updates.description.trim();
  }

  if (Object.keys(updates).length === 0) return res.json({ ok: true, message: 'No fields to update' });

  const fields = Object.keys(updates);
  const setClause = fields.map(f => `${f} = ?`).join(', ');
  const values = [...fields.map(f => updates[f]), Date.now(), id];

  try {
    db.prepare(`UPDATE saved_searches SET ${setClause}, updated_at = ? WHERE id = ?`).run(...values);
    res.json({ ok: true });
  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'A saved search with that name already exists' });
    }
    res.status(500).json({ error: 'Database error' });
  }
});

router.delete('/:id', (req, res) => {
  const id = Number(req.params.id);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid ID' });
  const result = db.prepare('DELETE FROM saved_searches WHERE id = ?').run(id);
  if (result.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true, deleted: result.changes });
});

function safeParse(s) {
  try { return JSON.parse(s); } catch { return {}; }
}

module.exports = router;
