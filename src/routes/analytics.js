const express = require('express');
const db = require('../db');
const { buildWhere } = require('../query');

const router = express.Router();

const NUMERIC_FIELDS = new Set(['id', 'ts', 'window_minutes', 'matched_count', 'triggered_at']);
const VALID_FIELDS = ['src_ip', 'dest_ip', 'host', 'user', 'event_id', 'severity', 'source_type', 'message'];

router.get('/top', (req, res) => {
  const { q = '', field = 'src_ip', limit = '10', source_type, severity, from, to } = req.query;

  if (!VALID_FIELDS.includes(field)) {
    return res.status(400).json({ error: `Invalid field. Must be one of: ${VALID_FIELDS.join(', ')}` });
  }

  const { where, params } = buildWhere(q, {
    source_type: source_type || undefined,
    severity: severity || undefined,
    from: from ? Number(from) : undefined,
    to: to ? Number(to) : undefined
  });

  const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10) || 10));

  try {
    const rows = db.prepare(
      `SELECT ${field} as value, COUNT(*) as count FROM events WHERE ${where} AND ${field} IS NOT NULL GROUP BY ${field} ORDER BY count DESC LIMIT ?`
    ).all(...params, limitNum);

    res.json({ field, total: rows.reduce((s, r) => s + r.count, 0), top: rows });
  } catch (err) {
    res.status(400).json({ error: 'Query error' });
  }
});

router.get('/stats', (req, res) => {
  const { q = '', stat = 'count', by = '', source_type, severity, from, to } = req.query;

  const { where, params } = buildWhere(q, {
    source_type: source_type || undefined,
    severity: severity || undefined,
    from: from ? Number(from) : undefined,
    to: to ? Number(to) : undefined
  });

  const allowedStats = new Set(['count', 'dc', 'sum', 'avg', 'min', 'max']);
  const statType = allowedStats.has(stat) ? stat : 'count';
  const byField = by && VALID_FIELDS.includes(by) ? by : null;

  try {
    if (statType === 'count' && !byField) {
      const total = db.prepare(`SELECT COUNT(*) as c FROM events WHERE ${where}`).get(...params).c;
      return res.json({ stat: 'count', total });
    }

    let aggExpr;
    switch (statType) {
      case 'dc': aggExpr = `COUNT(DISTINCT ${byField}) as value`; break;
      case 'sum': aggExpr = `SUM(CAST(json_extract(parsed, '$.bytes') AS INTEGER)) as value`; break;
      case 'avg': aggExpr = `AVG(CAST(json_extract(parsed, '$.status') AS INTEGER)) as value`; break;
      case 'min': aggExpr = `MIN(ts) as value`; break;
      case 'max': aggExpr = `MAX(ts) as value`; break;
      case 'count':
      default: aggExpr = `COUNT(*) as value`; break;
    }

    if (byField) {
      const rows = db.prepare(
        `SELECT ${byField} as group_key, ${aggExpr} FROM events WHERE ${where} GROUP BY ${byField} ORDER BY value DESC LIMIT 100`
      ).all(...params);
      res.json({ stat: statType, by: byField, results: rows });
    } else {
      const row = db.prepare(`SELECT ${aggExpr} FROM events WHERE ${where}`).get(...params);
      res.json({ stat: statType, value: row.value });
    }
  } catch (err) {
    res.status(400).json({ error: 'Query error' });
  }
});

router.get('/timechart', (req, res) => {
  const { q = '', bucket = 'hour', source_type, severity, from, to } = req.query;

  const bucketMap = { minute: 60000, hour: 3600000, day: 86400000 };
  const bucketSize = bucketMap[bucket] || 3600000;

  const { where, params } = buildWhere(q, {
    source_type: source_type || undefined,
    severity: severity || undefined,
    from: from ? Number(from) : undefined,
    to: to ? Number(to) : undefined
  });

  try {
    const rows = db.prepare(
      `SELECT (ts / ?) as bucket, COUNT(*) as count FROM events WHERE ${where} GROUP BY bucket ORDER BY bucket ASC LIMIT 500`
    ).all(bucketSize, ...params);

    res.json({
      bucket_size: bucketSize,
      series: rows.map(r => ({ ts: r.bucket * bucketSize, count: r.count }))
    });
  } catch (err) {
    res.status(400).json({ error: 'Query error' });
  }
});

router.get('/threatintel/lookup', (req, res) => {
  const { query } = req.query;
  const { ipSet, domainSet, reloadIfNeeded } = require('../threatintel');
  reloadIfNeeded();

  if (!query) {
    return res.json({
      total_ips: ipSet.size,
      total_domains: domainSet.size,
      sample_ips: Array.from(ipSet).slice(0, 10),
      sample_domains: Array.from(domainSet).slice(0, 10)
    });
  }

  const clean = query.trim();
  const isIpMatch = ipSet.has(clean);
  const isDomainMatch = domainSet.has(clean.replace(/^\*\.?/, ''));

  res.json({
    query: clean,
    matched: isIpMatch || isDomainMatch,
    type: isIpMatch ? 'ip' : (isDomainMatch ? 'domain' : null),
    details: (isIpMatch || isDomainMatch) ? 'Match found in active threat intelligence blocklist' : 'No threat match found'
  });
});

module.exports = router;
