<a href="https://github.com/jojin1709/SIEM-">
  <img src="https://img.shields.io/badge/SIEM--Full%20Stack%20SIEM-000000?style=for-the-badge&logo=github&logoColor=white" alt="SIEM++">
</a>

<div align="center">

# SIEM++ — Full Stack SIEM

</div>

SIEM++ is a self-hosted Security Information and Event Management (SIEM) platform built for security practitioners who need enterprise-grade log analysis, threat detection, and incident response capabilities — all in a single Node.js process with SQLite.

> **[!NOTE]**
> **SIEM++ v1.0 is now available!** SIEM++ provides log ingestion, search, dashboards, detection rules, threat intelligence, alerts, and notifications — no cloud dependencies, no licensing fees, runs anywhere Node.js runs.

---

<div align="center">

[![GitHub Stars](https://img.shields.io/github/stars/jojin1709/SIEM-?style=social)](https://github.com/jojin1709/SIEM-/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?logo=nodedotjs&logoColor=white)](https://nodejs.org/)
[![Vercel](https://img.shields.io/badge/Deploy%20on-Vercel-000000?logo=vercel&logoColor=white)](https://vercel.com/)
[![Security](https://img.shields.io/badge/Security-Authenticated%20%7C%20CSP%20%7C%20Rate%20Limited-ff6b6b)](./README.md)

</div>

## Table of Contents

- [What is SIEM++?](#what-is-siem)
- [Key Features](#key-features)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Writing Detection Rules](#writing-detection-rules)
- [Threat Intelligence](#threat-intelligence)
- [Notifications](#notifications)
- [Environment Variables](#environment-variables)
- [Deploying to Vercel](#deploying-to-vercel)
- [Project Layout](#project-layout)
- [Safety & Limitations](#safety--limitations)
- [License](#license)
- [About the Developer](#about-the-developer)
- [Community & Support](#community--support)

## What is SIEM++?

SIEM++ (pronounced "SIEM-plus-plus") is a full-stack Security Information and Event Management system designed for security teams, SOC analysts, and penetration testers who need to collect, search, and analyze logs from diverse sources. Unlike heavyweight enterprise SIEMs (Splunk, QRadar, Microsoft Sentinel), SIEM++ runs on a single Node.js process with a local SQLite database — no infrastructure overhead, no licensing costs.

SIEM++ shines for:
- **Home labs & red team operations** — Collect and analyze logs from your test environments
- **Blue team training** — Learn SIEM concepts, detection engineering, and threat hunting
- **Small-to-medium estates** — Monitor 10-100 hosts without enterprise licensing
- **Bug bounty & pentest tooling** — Correlate findings across multiple log sources

## Key Features

### Core SIEM Capabilities
- **Log Ingestion** — Drag-and-drop file upload with auto-detection for syslog, nginx/Apache, Suricata eve.json, Windows Event JSON, JSON-lines, and raw text. Also supports real-time UDP syslog receiving.
- **Splunk-like Search** — Mini query language supporting `field:value`, `"quoted phrases"`, `wildcard:value*`, `-negation`, and AND semantics. Export results as JSON or CSV.
- **Live Dashboard** — Events-over-time pulse, source/severity breakdowns, top talkers (IPs, hosts), auto-refreshing every 60s.
- **Detection Rules** — Threshold-based correlation engine with saved searches, configurable windows, and automatic deduplication. Ships with 4 starter rules (brute-force, 5xx spike, IDS alert, Windows critical events).
- **Alert Triage** — Open/acknowledged/closed workflow with severity levels and sample event IDs.
- **Analytics** — Top-N reports, statistical aggregations (count, dc, sum, avg), and timechart bucketing.

### Security First
- **API key authentication** — All endpoints require a valid `X-API-Key` header
- **Security headers** — Helmet with strict CSP, X-Frame-Options, X-Content-Type-Options, HSTS
- **Rate limiting** — 300 req/min on API, 30/min on ingestion
- **Input validation** — All rule fields validated server-side (severity enum, threshold ≥ 1, window bounds)
- **XSS prevention** — All user-controlled output is HTML-escaped

### Enrichment & Intelligence
- **Threat intelligence** — Events annotated against IP/domain blocklists (local files + remote feeds)
- **Webhook & email notifications** — Real-time alerting via SMTP or webhooks when rules fire
- **WebSocket live feed** — Real-time event streaming at `/ws/events`

## Quick Start

Requires **Node.js 18+** (uses built-in `node:sqlite` — no native compilation, no build step).

```bash
git clone https://github.com/jojin1709/SIEM-.git
cd SIEM-
npm install
npm start
```

Open **http://localhost:4000**. The API key is printed to the console on startup.

To try it immediately:
1. Go to **Ingest Data → Load sample data** (loads SSH brute-force, nginx 5xx spike, Suricata alert, Windows lockout)
2. Go to **Alerts → Run rules now** (rules fire automatically)

<img src="https://placeholder.co/800x400?text=SIEM+Dashboard+Screenshot" alt="Dashboard screenshot" width="100%">

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │        SIEM++ (Node.js)            │
                    │                                     │
  ┌───────────┐     │  ┌──────────┐  ┌──────────┐        │
  │  Syslog   │────▶│  │  Syslog  │  │   HTTP   │        │
  │  UDP :514 │     │  │ Receiver │  │   API    │        │
  └───────────┘     │  └──────────┘  └────┬─────┘        │
                    │                    │                │
  ┌───────────┐     │                    │                │
  │  File     │────►│                    │                │
  │  Upload   │     │                    ▼                │
  └───────────┘     │              ┌──────────┐         │
                    │              │   SQLite │         │
                    │              │   Events │         │
                    │              └────┬─────┘         │
                    │                   │               │
                    │  ┌──────────┐    │    ┌─────────┐ │
                    │  │  Rules   │◄───┼───▶│ Analytics│ │
                    │  │ Engine   │    │    │  API     │ │
                    │  └──────────┘    │    └─────────┘ │
                    │       │         │                │
                    │       ▼         │   ┌──────────┐ │
                    │  ┌─────────┐    │   │   Live   │ │
                    │  │ Alerts  │    │   │  WS Feed │ │
                    │  │ & Notify│    │   └──────────┘ │
                    │  └─────────┘    │                │
                    └─────────────────┘                │
                               │                       │
                    ┌──────────┴──────────┐            │
                    │   Frontend (SSR)    │◄───────────┘
                    │  HTML/CSS/JS        │
                    └─────────────────────┘
```

## API Reference

All endpoints require `X-API-Key` header. The root page (`/`) serves the UI with the API key injected automatically.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check + DB connectivity |
| POST | `/api/ingest/file` | Upload a log file (multipart) |
| POST | `/api/ingest/sample` | Load bundled sample data |
| GET | `/api/ingest/history` | Ingestion history (paginated) |
| GET | `/api/search` | Search events with query language |
| GET | `/api/search/export` | Export search results (JSON/CSV) |
| GET | `/api/dashboard/stats` | Dashboard statistics |
| GET | `/api/alerts` | List alerts (paginated, filterable) |
| PATCH | `/api/alerts/:id` | Update alert status |
| GET | `/api/alerts/rules` | List detection rules |
| POST | `/api/alerts/rules` | Create a rule |
| PATCH | `/api/alerts/rules/:id` | Update a rule |
| DELETE | `/api/alerts/rules/:id` | Delete a rule |
| POST | `/api/alerts/rules/run` | Manually trigger rule evaluation |
| GET | `/api/analytics/top` | Top-N events by field |
| GET | `/api/analytics/stats` | Statistical aggregation |
| GET | `/api/analytics/timechart` | Time-bucketed event counts |
| GET | `/api/savedsearches` | List saved searches |
| POST | `/api/savedsearches` | Create a saved search |
| GET | `/api/savedsearches/:id/run` | Run a saved search |
| PATCH | `/api/savedsearches/:id` | Update a saved search |
| DELETE | `/api/savedsearches/:id` | Delete a saved search |
| WS | `/ws/events` | WebSocket live event feed |

## Writing Detection Rules

Go to **Detection Rules → New rule**. A rule consists of:

- **Query** — same syntax as Search, e.g. `src_ip:45.83.12.4 severity:high`
- **Window** — how far back to look (1–1440 minutes)
- **Threshold** — how many matching events trigger an alert (≥ 1)
- **Severity** — critical, high, medium, low, or info
- **Notifications** — if SMTP/webhook configured, alerts fire notifications automatically

The engine re-evaluates all enabled rules every 60 seconds and skips re-firing alerts that already exist within the same window.

## Threat Intelligence

SIEM++ automatically annotates events against IP/domain blocklists:

- Local files: `data/threatintel/blocklist.txt`, `data/threatintel/custom.txt`
- Remote feeds: configure via `TI_FEEDS` env var (comma-separated URLs)

Matching events get a `threat_intel_hit` field in search results and their severity is bumped to `high`.

## Notifications

Configure email or webhook notifications via environment variables:

```bash
# Email notifications
SMTP_HOST=smtp.gmail.com
SMTP_USER=your@email.com
SMTP_PASS=your-app-password
NOTIFY_EMAIL=soc-team@company.com

# Webhook notifications  
WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 4000 | HTTP port |
| `API_KEY` | auto-generated | API key for authentication |
| `SYSLOG_PORT` | (disabled) | UDP port for real-time syslog receiver |
| `RETENTION_DAYS` | 90 | Days to retain events before cleanup |
| `SMTP_HOST` | — | SMTP server for email notifications |
| `SMTP_PORT` | 587 | SMTP port |
| `SMTP_SECURE` | false | Use TLS for SMTP |
| `SMTP_USER` | — | SMTP username |
| `SMTP_PASS` | — | SMTP password |
| `SMTP_FROM` | SMTP_USER | Sender email address |
| `NOTIFY_EMAIL` | — | Recipient email for alerts |
| `WEBHOOK_URL` | — | Webhook URL for alert notifications |
| `TI_FEEDS` | — | Comma-separated threat intel feed URLs |

## Deploying to Vercel

```bash
npm install -g vercel
vercel
```

> [!WARNING]
> On Vercel, `/tmp` is ephemeral and UDP/WebSocket require a different architecture. Use a managed database (PostgreSQL) and Vercel Cron Jobs for production.

## Project Layout

```
server.js              Express app + security middleware + WebSocket server
src/
  db.js                SQLite schema and connection
  parsers.js           Format auto-detection + line parsers
  query.js             Mini search-query-language → SQL
  rules.js             Detection rule evaluation + default rules
  auth.js              API key authentication middleware
  syslog.js            Real-time UDP syslog receiver
  notify.js            Email/webhook notification dispatcher
  threatintel.js       IP/domain blocklist matching + enrichment
  livefeed.js          WebSocket event broadcasting
  routes/
    ingest.js          File upload + sample data loader
    search.js          Search API + JSON/CSV export
    dashboard.js       Stats for the overview page
    alerts.js          Rules CRUD + alert triage
    analytics.js       Top/stats/timechart analytics
    savedsearches.js   Saved search CRUD + execution
public/                Frontend (plain HTML/CSS/JS, no build step)
  index.html
  css/style.css
  js/app.js
  js/vendor/chart.umd.js  (vendored, works offline)
sample-logs/           Demo data for all supported formats
data/                  SQLite database (gitignored)
  threatintel/         Blocklist files (blocklist.txt, custom.txt)
vercel.json            Vercel deployment config
```

## Safety & Limitations

- **Single-node, SQLite-backed** — great for demos, home labs, and small estates (thousands to low millions of events). Not a Splunk/ELK replacement at enterprise scale.
- **Authentication** uses a single API key. For multi-user RBAC, pair with a reverse proxy.
- **Synchronous SQLite** (`DatabaseSync`) is sufficient for moderate load but not for high-volume deployments.
- **Syslog timestamp parsing** assumes the current year (RFC3164 format omits it).
- This is a personal portfolio project — see [License](#license).

## License

MIT — use it however you want for personal or commercial purposes, just don't blame the developer if something breaks.

## About the Developer

Developed by **JOJIN JOHN** — a security engineer and open-source contributor who builds tools for log analysis, threat detection, and SOC automation.

**Connect:**
- GitHub: [@jojin1709](https://github.com/jojin1709)
- Security blog: https://jojin.dev

## Community & Support

- **Found a bug?** [Open an issue](https://github.com/jojin1709/SIEM-/issues)
- **Have a feature request?** [Start a discussion](https://github.com/jojin1709/SIEM-/discussions)
- **Want to contribute?** See [CONTRIBUTING.md](./CONTRIBUTING.md)

<p align="center">
  <b>Built by <a href="https://github.com/jojin1709">JOJIN JOHN</a></b>
</p>
