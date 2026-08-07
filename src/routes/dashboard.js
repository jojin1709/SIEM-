const express = require('express');
const db = require('../db');

const router = express.Router();

router.get('/stats', (req, res) => {
  const totalEvents = db.prepare('SELECT COUNT(*) as c FROM events').get().c;
  const totalAlerts = db.prepare(`SELECT COUNT(*) as c FROM alerts WHERE status = 'open'`).get().c;

  const bySource = db.prepare(
    `SELECT source_type, COUNT(*) as c FROM events GROUP BY source_type ORDER BY c DESC`
  ).all();

  const bySeverity = db.prepare(
    `SELECT severity, COUNT(*) as c FROM events GROUP BY severity ORDER BY c DESC`
  ).all();

  const topSrcIps = db.prepare(
    `SELECT src_ip, COUNT(*) as c FROM events WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY c DESC LIMIT 10`
  ).all();

  const topHosts = db.prepare(
    `SELECT host, COUNT(*) as c FROM events WHERE host IS NOT NULL GROUP BY host ORDER BY c DESC LIMIT 10`
  ).all();

  // events per hour bucket for last 48h (based on data present, not wall clock,
  // since demo data may be historical)
  const timeline = db.prepare(`
    SELECT (ts / 3600000) as bucket, COUNT(*) as c
    FROM events
    GROUP BY bucket
    ORDER BY bucket ASC
    LIMIT 500
  `).all().map(r => ({ hour: r.bucket * 3600000, count: r.c }));

  res.json({ totalEvents, totalAlerts, bySource, bySeverity, topSrcIps, topHosts, timeline });
});

module.exports = router;
