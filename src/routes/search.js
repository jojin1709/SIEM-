const express = require('express');
const db = require('../db');
const { buildWhere } = require('../query');
const { annotateEvents } = require('../threatintel');

const router = express.Router();

const VALID_SOURCE_TYPES = ['syslog', 'nginx', 'suricata', 'winevent', 'json', 'raw', 'syslog_realtime'];
const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

router.get('/', (req, res) => {
  const { q = '', source_type, severity, from, to, page = '1', pageSize = '50', format = 'json' } = req.query;

  if (source_type && !VALID_SOURCE_TYPES.includes(source_type)) {
    return res.status(400).json({ error: 'Invalid source_type filter' });
  }
  if (severity && !VALID_SEVERITIES.includes(severity)) {
    return res.status(400).json({ error: 'Invalid severity filter' });
  }

  let fromNum, toNum;
  if (from) { fromNum = Number(from); if (isNaN(fromNum)) return res.status(400).json({ error: 'Invalid from timestamp' }); }
  if (to) { toNum = Number(to); if (isNaN(toNum)) return res.status(400).json({ error: 'Invalid to timestamp' }); }

  const { where, params } = buildWhere(q, {
    source_type: source_type || undefined,
    severity: severity || undefined,
    from: fromNum,
    to: toNum
  });

  const pageNum = Math.max(1, parseInt(page, 10) || 1);
  const size = Math.min(500, Math.max(1, parseInt(pageSize, 10) || 50));
  const offset = (pageNum - 1) * size;

  try {
    const total = db.prepare(`SELECT COUNT(*) as c FROM events WHERE ${where}`).get(...params).c;
    const rows = db.prepare(
      `SELECT * FROM events WHERE ${where} ORDER BY ts DESC LIMIT ? OFFSET ?`
    ).all(...params, size, offset);

    const annotated = annotateEvents(rows);
    const results = annotated.map(r => ({ ...r, parsed: safeParse(r.parsed) }));

    res.json({
      total,
      page: pageNum,
      pageSize: size,
      totalPages: Math.ceil(total / size),
      results,
      ti_hits: annotated.reduce((acc, e) => acc + (e.threat_intel_hit ? 1 : 0), 0)
    });
  } catch (err) {
    res.status(400).json({ error: 'Query error', message: 'Invalid search query' });
  }
});

router.get('/export', (req, res) => {
  const { q = '', source_type, severity, from, to, format = 'json' } = req.query;

  if (!['json', 'csv'].includes(format)) {
    return res.status(400).json({ error: 'format must be json or csv' });
  }

  if (source_type && !VALID_SOURCE_TYPES.includes(source_type)) {
    return res.status(400).json({ error: 'Invalid source_type filter' });
  }
  if (severity && !VALID_SEVERITIES.includes(severity)) {
    return res.status(400).json({ error: 'Invalid severity filter' });
  }

  const { where, params } = buildWhere(q, {
    source_type: source_type || undefined,
    severity: severity || undefined,
    from: from ? Number(from) : undefined,
    to: to ? Number(to) : undefined
  });

  try {
    const rows = db.prepare(`SELECT * FROM events WHERE ${where} ORDER BY ts DESC LIMIT 5000`).all(...params);

    if (format === 'csv') {
      const header = 'ts,source_type,host,src_ip,dest_ip,user,event_id,severity,message,raw';
      const csvLines = rows.map(r => {
        const fields = [
          r.ts, r.source_type, r.host, r.src_ip, r.dest_ip,
          r.user, r.event_id, r.severity, r.message, r.raw
        ];
        return fields.map(f => `"${String(f || '').replace(/"/g, '""')}"`).join(',');
      });
      const csv = [header, ...csvLines].join('\n');
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="siem-export.csv"');
      return res.send(csv);
    }

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="siem-export.json"');
    res.json(rows.map(r => ({ ...r, parsed: safeParse(r.parsed) })));
  } catch (err) {
    res.status(400).json({ error: 'Export failed', message: 'Invalid search query' });
  }
});

function safeParse(s) {
  try { return JSON.parse(s); } catch { return {}; }
}

module.exports = router;
