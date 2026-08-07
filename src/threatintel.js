const fs = require('fs');
const path = require('path');
const db = require('./db');

const TI_DIR = path.join(__dirname, '..', 'data', 'threatintel');
if (!fs.existsSync(TI_DIR)) {
  try { fs.mkdirSync(TI_DIR, { recursive: true }); } catch (e) { console.error('[ti] mkdir error:', e.message); }
}

const BLOCKLIST_FILE = path.join(TI_DIR, 'blocklist.txt');
const CUSTOM_FILE = path.join(TI_DIR, 'custom.txt');

let ipSet = new Set();
let domainSet = new Set();
let lastReload = 0;
const RELOAD_INTERVAL_MS = 60000;

function parseBlocklistFile(filePath) {
  if (!fs.existsSync(filePath)) return;
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    for (const line of lines) {
      if (line.includes('.') && /^\d{1,3}(\.\d{1,3}){3}$/.test(line)) {
        ipSet.add(line);
      } else if (line.includes('.')) {
        const host = line.replace(/^\*\.?/, '');
        if (host.length > 2) domainSet.add(host);
      }
    }
  } catch (e) {
    console.error(`[ti] error loading ${filePath}:`, e.message);
  }
}

function loadBlocklists(urls) {
  if (typeof fetch === 'undefined') return;
  for (const url of urls) {
    fetch(url, { signal: AbortSignal.timeout(10000) })
      .then(r => r.text())
      .then(text => {
        text.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#')).forEach(line => {
          if (/^\d{1,3}(\.\d{1,3}){3}$/.test(line)) ipSet.add(line);
          else if (line.includes('.')) {
            const host = line.replace(/^\*\.?/, '');
            if (host.length > 2) domainSet.add(host);
          }
        });
      })
      .catch(e => console.error(`[ti] failed to fetch ${url}:`, e.message));
  }
}

function reloadIfNeeded() {
  const now = Date.now();
  if (now - lastReload < RELOAD_INTERVAL_MS) return;
  lastReload = now;
  ipSet.clear();
  domainSet.clear();
  parseBlocklistFile(BLOCKLIST_FILE);
  parseBlocklistFile(CUSTOM_FILE);
  const urls = (process.env.TI_FEEDS || '').split(',').map(s => s.trim()).filter(Boolean);
  if (urls.length) loadBlocklists(urls);
}

function checkIocs(events) {
  reloadIfNeeded();
  const hits = [];
  for (const ev of events) {
    if (ev.src_ip && ipSet.has(ev.src_ip)) {
      hits.push({ type: 'ip', value: ev.src_ip, event_id: ev.id });
    }
    const parsed = ev.parsed;
    if (parsed && typeof parsed === 'object') {
      for (const [key, val] of Object.entries(parsed)) {
        if (key.toLowerCase().includes('domain') || key.toLowerCase().includes('host')) {
          if (typeof val === 'string' && domainSet.has(val.replace(/^\*\.?/, ''))) {
            hits.push({ type: 'domain', value: val, event_id: ev.id });
          }
        }
      }
    }
  }
  return hits;
}

function annotateEvents(events) {
  reloadIfNeeded();
  return events.map(ev => {
    let ti_hit = null;
    if (ev.src_ip && ipSet.has(ev.src_ip)) ti_hit = { type: 'ip_blocklist', value: ev.src_ip };
    if (ev.dest_ip && ipSet.has(ev.dest_ip)) {
      if (!ti_hit) ti_hit = { type: 'ip_blocklist', value: ev.dest_ip };
    }
    if (ti_hit) db.prepare(`UPDATE events SET severity = 'high' WHERE id = ?`).run(ev.id);
    return { ...ev, threat_intel_hit: ti_hit };
  });
}

module.exports = { checkIocs, annotateEvents, reloadIfNeeded, ipSet, domainSet };
