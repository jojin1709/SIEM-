const nodemailer = require('nodemailer');
const https = require('https');
const http = require('http');
const db = require('./db');

const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];

async function sendEmail(alert, rule, config) {
  if (!config || !config.host || !config.user) {
    console.warn('[notify] No SMTP config for email notification, skipping');
    return false;
  }
  const transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port || 587,
    secure: config.secure || false,
    auth: { user: config.user, pass: config.pass }
  });
  const html = `
    <h2>SIEAlarm: ${escape(rule.name)}</h2>
    <p><strong>Severity:</strong> ${escape(rule.severity)}</p>
    <p><strong>Matched events:</strong> ${alert.matched_count} in ${alert.window_minutes}m</p>
    <p><strong>Triggered:</strong> ${new Date(alert.triggered_at).toLocaleString()}</p>
    <p><strong>Details:</strong> ${escape(rule.description || 'No description')}</p>
  `;
  await transporter.sendMail({
    from: config.from || config.user,
    to: config.to,
    subject: `[SIEM] ${rule.severity.toUpperCase()} alert: ${rule.name}`,
    html
  });
  return true;
}

function sendWebhook(alert, rule, config) {
  return new Promise((resolve) => {
    if (!config || !config.url) {
      console.warn('[notify] No webhook URL configured, skipping');
      return resolve(false);
    }
    const payload = JSON.stringify({
      alert,
      rule,
      severity: rule.severity,
      triggered_at: alert.triggered_at
    });
    const url = new URL(config.url);
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname + url.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      }
    };
    Object.assign(options.headers, config.headers || {});
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(options, (res) => {
      if (config.channel) {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => resolve({ status: res.statusCode, body: data }));
      } else {
        res.resume();
        resolve({ status: res.statusCode });
      }
    });
    req.on('error', (e) => {
      console.error('[notify] webhook error:', e.message);
      resolve(false);
    });
    req.write(payload);
    req.end();
  });
}

function escape(s) {
  return String(s || '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}

async function notify(alertId) {
  const alertRow = db.prepare(`
    SELECT a.*, r.name as rule_name, r.description as rule_desc, r.severity as rule_severity,
           r.query as rule_query, r.window_minutes as rule_window, r.threshold as rule_threshold
    FROM alerts a JOIN rules r ON a.rule_id = r.id WHERE a.id = ?
  `).get(alertId);
  if (!alertRow) return;

  const rule = {
    id: alertRow.rule_id,
    name: alertRow.rule_name,
    description: alertRow.rule_desc,
    query: alertRow.rule_query,
    severity: alertRow.rule_severity,
    window_minutes: alertRow.rule_window,
    threshold: alertRow.rule_threshold
  };
  const alert = {
    id: alertRow.id,
    severity: alertRow.rule_severity,
    matched_count: alertRow.matched_count,
    window_minutes: alertRow.window_minutes,
    triggered_at: alertRow.triggered_at,
    status: alertRow.status
  };

  const config = loadConfig();
  const results = {};

  if (config.email && validSeverities.includes(rule.severity)) {
    try {
      await sendEmail(alert, rule, config.email);
      results.email = { sent: true };
    } catch (e) {
      console.error('[notify] email error:', e.message);
      results.email = { sent: false, error: e.message };
    }
  }

  if (config.webhook) {
    try {
      results.webhook = await sendWebhook(alert, rule, config.webhook);
    } catch (e) {
      console.error('[notify] webhook error:', e.message);
      results.webhook = { sent: false, error: e.message };
    }
  }

  return results;
}

function loadConfig() {
  const cfg = { email: null, webhook: null };
  if (process.env.SMTP_HOST) {
    cfg.email = {
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587', 10),
      secure: process.env.SMTP_SECURE === 'true',
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
      from: process.env.SMTP_FROM,
      to: process.env.NOTIFY_EMAIL
    };
  }
  if (process.env.WEBHOOK_URL) {
    cfg.webhook = {
      url: process.env.WEBHOOK_URL,
      headers: parseHeaders(process.env.WEBHOOK_HEADERS),
      channel: process.env.WEBHOOK_CHANNEL || false
    };
  }
  return cfg;
}

function parseHeaders(value) {
  if (!value) return {};
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch (e) {
    console.error('[notify] invalid WEBHOOK_HEADERS JSON, ignoring headers');
    return {};
  }
}

module.exports = { notify, sendEmail, sendWebhook };
