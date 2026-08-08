const express = require('express');
const path = require('path');
const fs = require('fs');
const http = require('http');
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
    if (match && !process.env[match[1]]) process.env[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
  }
}
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const db = require('./src/db');
const { seedDefaultRules, runAllRules } = require('./src/rules');
const { requireAuth, API_KEY } = require('./src/auth');
const syslog = require('./src/syslog');
const livefeed = require('./src/livefeed');

const ingestRoutes = require('./src/routes/ingest');
const searchRoutes = require('./src/routes/search');
const dashboardRoutes = require('./src/routes/dashboard');
const alertRoutes = require('./src/routes/alerts');
const analyticsRoutes = require('./src/routes/analytics');
const savedSearchRoutes = require('./src/routes/savedsearches');
const managementRoutes = require('./src/routes/management');

const app = express();
const PORT = process.env.PORT || 4000;
const RETENTION_DAYS = parseInt(process.env.RETENTION_DAYS || '90', 10);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false
}));

app.use(express.json({ limit: '10mb' }));

app.get('/', (req, res) => {
  res.setHeader('Set-Cookie', `siem_key=${API_KEY}; Path=/; SameSite=Lax`);
  const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf-8');
  res.send(html.replace(/__API_KEY__/g, API_KEY));
});

app.use(express.static(path.join(__dirname, 'public')));

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  message: { error: 'Rate limit exceeded' },
  standardHeaders: true,
  legacyHeaders: false
});

const ingestLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'Rate limit exceeded for ingestion' },
  standardHeaders: true,
  legacyHeaders: false
});

app.use('/api', apiLimiter);
app.use('/api/ingest', ingestLimiter);

app.get('/api/health', (req, res) => {
  try {
    db.prepare('SELECT 1 as test').get();
    res.json({ ok: true, time: Date.now(), db: 'connected', uptime: process.uptime() });
  } catch (err) {
    res.status(500).json({ ok: false, error: 'Database unreachable' });
  }
});

app.use('/api/ingest', requireAuth, ingestRoutes);
app.use('/api/search', requireAuth, searchRoutes);
app.use('/api/dashboard', requireAuth, dashboardRoutes);
app.use('/api/alerts', requireAuth, alertRoutes);
app.use('/api/analytics', requireAuth, analyticsRoutes);
app.use('/api/savedsearches', requireAuth, savedSearchRoutes);
app.use('/api/management', requireAuth, managementRoutes);

seedDefaultRules();

// Auto sample loading disabled - database starts clean with 0 events

if (process.env.SYSLOG_PORT && !process.env.VERCEL) {
  try { syslog.start(); } catch (e) { console.error('[syslog] failed to start:', e.message); }
}

const server = http.createServer(app);

if (!process.env.VERCEL) {
  livefeed.start(server);
} else {
  console.log('  [ws] Live feed disabled (not supported on Vercel serverless)');
}

if (!process.env.VERCEL) {
  setInterval(() => {
    try { runAllRules(); } catch (e) { console.error('[rules] eval error:', e.message); }
  }, 60 * 1000);
}

if (!process.env.VERCEL && RETENTION_DAYS > 0) {
  setInterval(() => {
    try {
      const cutoff = Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000;
      const result = db.prepare('DELETE FROM events WHERE ts < ?').run(cutoff);
      if (result.changes > 0) console.log(`[retention] deleted ${result.changes} old events (older than ${RETENTION_DAYS}d)`);
      db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    } catch (e) {
      console.error('[retention] error:', e.message);
    }
  }, 6 * 60 * 60 * 1000);
}

process.on('SIGINT', () => {
  console.log('\nShutting down...');
  try { db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); } catch (e) { console.error(e); }
  process.exit(0);
});

server.listen(PORT, () => {
  console.log(`\n  mini-SIEM running -> http://localhost:${PORT}\n  API key (X-API-Key header): ${API_KEY}\n  Live feed: ws://localhost:${PORT}/ws/events\n`);
});

module.exports = app;
