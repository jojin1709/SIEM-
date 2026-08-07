// Mini Splunk-ish query language:
//   field:value            -> exact match on a known column, or json_extract for others
//   field:*partial*        -> wildcard match (LIKE)
//   "quoted phrase"         -> substring match against message/raw
//   bareword                -> substring match against message/raw
//   -term / -field:value    -> negate the following token
//   space-separated terms are ANDed together
//
// Known columns: host, src_ip, dest_ip, user, event_id, severity, source_type, message

const KNOWN_COLUMNS = new Set(['host', 'src_ip', 'dest_ip', 'user', 'event_id', 'severity', 'source_type', 'message']);

function tokenize(q) {
  const tokens = [];
  const re = /-?"[^"]*"|-?\S+/g;
  let m;
  while ((m = re.exec(q)) !== null) tokens.push(m[0]);
  return tokens;
}

function buildWhere(queryStr, extra = {}) {
  const clauses = [];
  const params = [];

  if (queryStr && queryStr.trim()) {
    const tokens = tokenize(queryStr.trim());
    for (let tok of tokens) {
      let negate = false;
      if (tok.startsWith('-')) { negate = true; tok = tok.slice(1); }
      let clause;
      const colonIdx = tok.indexOf(':');
      if (colonIdx > 0) {
        const field = tok.slice(0, colonIdx);
        let value = tok.slice(colonIdx + 1).replace(/^"(.*)"$/, '$1');
        const hasWildcard = value.includes('*');
        if (hasWildcard) {
          const escaped = value.replace(/%/g, '\\%').replace(/_/g, '\\_').replace(/\*/g, '%');
          clause = `${field} LIKE ? ESCAPE '\\'`;
          params.push(escaped);
        } else {
          clause = `${field} = ?`;
          params.push(value);
        }
        if (!KNOWN_COLUMNS.has(field)) {
          clause = hasWildcard
            ? `json_extract(parsed, '$.${field.replace(/'/g, "")}') LIKE ? ESCAPE '\\'`
            : `json_extract(parsed, '$.${field.replace(/'/g, "")}') = ?`;
        }
      } else {
        const value = tok.replace(/^"(.*)"$/, '$1');
        if (value === '*') {
          clause = '1=1';
        } else {
          const needsEscape = /[\%_]/.test(value);
          const escapedVal = value.replace(/%/g, '\\%').replace(/_/g, '\\_');
          const sqlVal = `%${escapedVal}%`;
          if (needsEscape) {
            clause = `(message LIKE ? ESCAPE '\\' OR raw LIKE ? ESCAPE '\\')`;
          } else {
            clause = `(message LIKE ? OR raw LIKE ?)`;
          }
          params.push(sqlVal, sqlVal);
        }
      }
      clauses.push(negate ? `NOT (${clause})` : clause);
    }
  }

  if (extra.source_type) { clauses.push('source_type = ?'); params.push(extra.source_type); }
  if (extra.severity) { clauses.push('severity = ?'); params.push(extra.severity); }
  if (extra.from) { clauses.push('ts >= ?'); params.push(extra.from); }
  if (extra.to) { clauses.push('ts <= ?'); params.push(extra.to); }

  const where = clauses.length ? clauses.join(' AND ') : '1=1';
  return { where, params };
}

module.exports = { buildWhere };
