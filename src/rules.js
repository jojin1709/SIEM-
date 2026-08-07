const db = require('./db');
const { buildWhere } = require('./query');
const { notify } = require('./notify');

function runRule(rule) {
  const now = Date.now();
  const from = now - rule.window_minutes * 60 * 1000;
  const { where, params } = buildWhere(rule.query, { from, to: now });

  const combinedQuery = `
    SELECT id,
      COUNT(*) OVER() as total_count
    FROM events
    WHERE ${where}
    ORDER BY ts DESC
    LIMIT 20
  `;
  const rows = db.prepare(combinedQuery).all(...params);

  const count = rows.length ? rows[0].total_count : 0;
  const sampleIds = rows.slice(0, 20).map(r => r.id);

  if (count >= rule.threshold) {
    const recent = db.prepare(
      `SELECT id FROM alerts WHERE rule_id = ? AND triggered_at >= ? ORDER BY triggered_at DESC LIMIT 1`
    ).get(rule.id, now - rule.window_minutes * 60 * 1000);
    if (recent) return null;

    const info = db.prepare(
      `INSERT INTO alerts (rule_id, rule_name, severity, matched_count, window_minutes, triggered_at, status, sample_event_ids, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)`
    ).run(rule.id, rule.name, rule.severity, count, rule.window_minutes, now, JSON.stringify(sampleIds), now);

    setImmediate(() => {
      notify(info.lastInsertRowid).catch(e => console.error('[rules] notify error:', e.message));
    });

    return info.lastInsertRowid;
  }
  return null;
}

function runAllRules() {
  const rules = db.prepare('SELECT * FROM rules WHERE enabled = 1').all();
  const fired = [];
  for (const rule of rules) {
    const alertId = runRule(rule);
    if (alertId) fired.push({ ruleId: rule.id, ruleName: rule.name, alertId });
  }
  return fired;
}

function seedDefaultRules() {
  const existing = db.prepare('SELECT COUNT(*) as c FROM rules WHERE is_default = 1').get().c;
  if (existing > 0) return;

  const defaults = [
    {
      name: 'Repeated Auth Failures (possible brute force)',
      description: 'Multiple failed login/auth events from the same source within a short window.',
      query: 'fail',
      window_minutes: 5,
      threshold: 5,
      severity: 'high'
    },
    {
      name: 'HTTP 5xx Error Spike',
      description: 'Elevated server error rate on the web tier.',
      query: 'source_type:nginx severity:high',
      window_minutes: 5,
      threshold: 10,
      severity: 'medium'
    },
    {
      name: 'Suricata High-Severity Alert',
      description: 'Network IDS raised a high-severity alert.',
      query: 'source_type:suricata severity:high',
      window_minutes: 10,
      threshold: 1,
      severity: 'critical'
    },
    {
      name: 'Windows Account Lockout / Critical Event',
      description: 'Critical Windows event log entries.',
      query: 'source_type:winevent severity:critical',
      window_minutes: 15,
      threshold: 1,
      severity: 'high'
    }
  ];

  const stmt = db.prepare(
    `INSERT INTO rules (name, description, query, window_minutes, threshold, severity, enabled, is_default, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 1, 1, ?, ?)`
  );
  const now = Date.now();
  for (const r of defaults) {
    stmt.run(r.name, r.description, r.query, r.window_minutes, r.threshold, r.severity, now, now);
  }
}

module.exports = { runRule, runAllRules, seedDefaultRules };
