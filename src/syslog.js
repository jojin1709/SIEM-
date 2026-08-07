const dgram = require('dgram');
const db = require('./db');
const { parseLine } = require('./parsers');

let socket = null;
let buffer = [];
const BATCH_SIZE = 100;
const FLUSH_INTERVAL_MS = 5000;

function start() {
  if (socket) return;
  const port = process.env.SYSLOG_PORT || 514;
  socket = dgram.createSocket('udp4');

  socket.on('message', (msg, rinfo) => {
    const line = msg.toString('utf-8').replace(/\s+$/, '');
    if (!line) return;
    try {
      const parsed = parseLine(line, 'syslog');
      buffer.push({
        ts: parsed.ts,
        source_type: 'syslog_realtime',
        host: parsed.host || rinfo.address,
        src_ip: parsed.src_ip || null,
        dest_ip: parsed.dest_ip || null,
        user: parsed.user || null,
        event_id: parsed.event_id || null,
        severity: parsed.severity || 'info',
        message: parsed.message || line.slice(0, 500),
        raw: line.slice(0, 2000),
        parsed: JSON.stringify(parsed.parsed || {}),
        ingest_batch: `syslog-rt-${Date.now()}`
      });
    } catch (e) {
      console.error('[syslog] parse error:', e.message);
    }
    if (buffer.length >= BATCH_SIZE) flush();
  });

  socket.on('error', (err) => {
    console.error('[syslog] socket error:', err.message);
    socket.close();
  });

  socket.bind(port, '0.0.0.0', () => {
    console.log(`  [syslog] UDP receiver listening on :${port}`);
  });

  setInterval(flush, FLUSH_INTERVAL_MS);
}

function flush() {
  if (!buffer.length) return;
  const insertStmt = db.prepare(`
    INSERT INTO events (ts, source_type, host, src_ip, dest_ip, user, event_id, severity, message, raw, parsed, ingest_batch)
    VALUES (@ts, @source_type, @host, @src_ip, @dest_ip, @user, @event_id, @severity, @message, @raw, @parsed, @ingest_batch)
  `);
  db.exec('BEGIN');
  try {
    for (const ev of buffer) insertStmt.run(ev);
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    console.error('[syslog] batch insert error:', err.message);
  }
  buffer = [];
}

module.exports = { start, flush };
