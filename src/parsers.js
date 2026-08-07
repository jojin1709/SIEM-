// Each parser takes a single line/record of text and returns a normalized
// event object, or null if the line should be skipped (blank/unparsable).

function safeDate(d) {
  const t = new Date(d).getTime();
  return isNaN(t) ? Date.now() : t;
}

// --- Syslog (RFC3164-ish): "<Mon DD HH:MM:SS> host process[pid]: message"
const SYSLOG_RE = /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w\-.\/]+)(?:\[(\d+)\])?:\s*(.*)$/;
function parseSyslogLine(line) {
  const m = line.match(SYSLOG_RE);
  if (!m) return null;
  const [, ts, host, proc, pid, message] = m;
  const year = new Date().getFullYear();
  const ipMatch = message.match(/(?:from|src=|address)\s*[:=]?\s*(\d{1,3}(?:\.\d{1,3}){3})/i);
  return {
    ts: safeDate(`${ts} ${year}`),
    source_type: 'syslog',
    host,
    src_ip: ipMatch ? ipMatch[1] : null,
    message,
    severity: /fail|error|denied|invalid/i.test(message) ? 'medium' : 'info',
    parsed: { process: proc, pid: pid || null }
  };
}

// --- Nginx/Apache combined log format
const CLF_RE = /^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d{3}) (\S+) "([^"]*)" "([^"]*)"/;
function parseNginxLine(line) {
  const m = line.match(CLF_RE);
  if (!m) return null;
  const [, ip, ts, method, url, status, bytes, referrer, ua] = m;
  const statusNum = parseInt(status, 10);
  return {
    ts: safeDate(ts.replace(':', ' ').replace(/^(\d+)\/(\w+)\/(\d+) /, '$2 $1 $3 ')),
    source_type: 'nginx',
    src_ip: ip,
    message: `${method} ${url} -> ${status}`,
    severity: statusNum >= 500 ? 'high' : statusNum >= 400 ? 'medium' : 'info',
    parsed: { method, url, status: statusNum, bytes, referrer, user_agent: ua }
  };
}

// --- Suricata eve.json (one JSON object per line)
function looksLikeSuricata(obj) {
  return !!(obj.event_type || obj.alert || obj.flow_id || obj.in_iface);
}
function parseSuricataLine(line) {
  let obj;
  try { obj = JSON.parse(line); } catch { return null; }
  if (!obj || typeof obj !== 'object' || !looksLikeSuricata(obj)) return null;
  const sev = obj.alert && obj.alert.severity;
  return {
    ts: safeDate(obj.timestamp || Date.now()),
    source_type: 'suricata',
    host: obj.host || null,
    src_ip: obj.src_ip || null,
    dest_ip: obj.dest_ip || null,
    message: obj.alert ? obj.alert.signature : (obj.event_type || 'suricata event'),
    severity: sev === 1 ? 'high' : sev === 2 ? 'medium' : sev === 3 ? 'low' : 'info',
    event_id: obj.event_type || null,
    parsed: obj
  };
}

// --- Windows Event Log JSON export (evtx-to-json style: one JSON object per line, or array)
function looksLikeWinEvent(obj) {
  return !!(obj.EventID || obj.EventId || obj.Computer || obj.TimeCreated);
}
function parseWinEventLine(line) {
  let obj;
  try { obj = JSON.parse(line); } catch { return null; }
  if (!obj || typeof obj !== 'object' || !looksLikeWinEvent(obj)) return null;
  const level = (obj.Level || obj.level || '').toString().toLowerCase();
  const sevMap = { critical: 'critical', error: 'high', warning: 'medium', information: 'info', info: 'info' };
  return {
    ts: safeDate(obj.TimeCreated || obj.timestamp || Date.now()),
    source_type: 'winevent',
    host: obj.Computer || obj.host || null,
    user: obj.UserId || obj.User || null,
    event_id: (obj.EventID || obj.EventId || '').toString(),
    message: obj.Message || obj.message || JSON.stringify(obj).slice(0, 300),
    severity: sevMap[level] || 'info',
    parsed: obj
  };
}

// --- Generic JSON-lines fallback
function parseJsonLine(line) {
  let obj;
  try { obj = JSON.parse(line); } catch { return null; }
  return {
    ts: safeDate(obj.timestamp || obj.ts || obj.time || Date.now()),
    source_type: 'json',
    host: obj.host || null,
    src_ip: obj.src_ip || obj.ip || null,
    message: obj.message || obj.msg || JSON.stringify(obj).slice(0, 300),
    severity: obj.severity || 'info',
    parsed: obj
  };
}

// --- Raw fallback: store the line as-is
function parseRawLine(line) {
  return {
    ts: Date.now(),
    source_type: 'raw',
    message: line.slice(0, 500),
    severity: 'info',
    parsed: {}
  };
}

const PARSERS = {
  syslog: parseSyslogLine,
  nginx: parseNginxLine,
  suricata: parseSuricataLine,
  winevent: parseWinEventLine,
  json: parseJsonLine,
  raw: parseRawLine
};

// Try to auto-detect the format from the first non-blank lines of a file.
function detectSourceType(sampleLines) {
  const tries = ['suricata', 'winevent', 'json', 'nginx', 'syslog'];
  for (const type of tries) {
    let hits = 0;
    for (const line of sampleLines) {
      if (!line.trim()) continue;
      if (PARSERS[type](line)) hits++;
    }
    if (hits >= Math.max(1, Math.floor(sampleLines.length * 0.5))) return type;
  }
  return 'raw';
}

function parseLine(line, sourceType) {
  const parser = PARSERS[sourceType] || parseRawLine;
  return parser(line) || parseRawLine(line);
}

module.exports = { PARSERS, detectSourceType, parseLine };
