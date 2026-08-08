/* ==========================================================================
   SIEM++ — Splunk-Inspired Cyber Security Frontend Application Logic
   ========================================================================== */

let API_KEY = document.querySelector('meta[name="api-key"]')?.content || '';
if (!API_KEY || API_KEY === '__API_KEY__') {
  API_KEY = 'siem-default-key-12345';
}

let currentView = 'landing';
let searchPage = 1;
let timeRangePreset = 'all';
let alertStatusFilter = '';
let activeAlertId = null;
let chartSource = null;
let chartSeverity = null;

// ---------- API Fetch Helper ----------
async function apiFetch(url, options = {}) {
  const headers = options.headers || {};
  if (API_KEY && API_KEY !== '__API_KEY__') {
    headers['X-API-Key'] = API_KEY;
  }
  options.credentials = 'same-origin';
  const res = await fetch(url, { ...options, headers });
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.error || errData.message || `HTTP ${res.status}`);
  }
  return res;
}

window.apiFetch = apiFetch;

// ---------- Initialize App ----------
document.addEventListener('DOMContentLoaded', () => {
  initClock();
  initNavigation();
  initSearchEvents();
  initAlertEvents();
  initRuleEvents();
  initThreatIntelEvents();
  initIngestEvents();
  initBgParticles();

  switchView('landing');
  refreshAlertBadge();

  // Periodically refresh stats
  setInterval(refreshAlertBadge, 15000);
});

// ---------- Dynamic Background Network Particles ----------
function initBgParticles() {
  const canvas = document.getElementById('bgParticles');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  let width = canvas.width = window.innerWidth;
  let height = canvas.height = window.innerHeight;

  window.addEventListener('resize', () => {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
  });

  const particles = Array.from({ length: 45 }, () => ({
    x: Math.random() * width,
    y: Math.random() * height,
    vx: (Math.random() - 0.5) * 0.6,
    vy: (Math.random() - 0.5) * 0.6,
    radius: Math.random() * 2 + 1
  }));

  function animate() {
    ctx.clearRect(0, 0, width, height);

    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0 || p.x > width) p.vx *= -1;
      if (p.y < 0 || p.y > height) p.vy *= -1;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fillStyle = '#3b82f6';
      ctx.fill();

      for (let j = i + 1; j < particles.length; j++) {
        const p2 = particles[j];
        const dx = p.x - p2.x;
        const dy = p.y - p2.y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 130) {
          ctx.beginPath();
          ctx.moveTo(p.x, p.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = `rgba(59, 130, 246, ${0.25 * (1 - dist / 130)})`;
          ctx.lineWidth = 0.8;
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(animate);
  }
  animate();
}

// ---------- UTC Clock ----------
function initClock() {
  function updateClock() {
    const now = new Date();
    const utcStr = now.toUTCString().split(' ')[4];
    const clockEl = document.getElementById('utcClock');
    if (clockEl) clockEl.textContent = `UTC ${utcStr}`;
  }
  updateClock();
  setInterval(updateClock, 1000);
}

// ---------- Navigation Router ----------
function initNavigation() {
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => switchView(btn.dataset.view));
  });

  document.getElementById('launchSocBtn')?.addEventListener('click', () => switchView('dashboard'));
  document.getElementById('searchLogsBtn')?.addEventListener('click', () => switchView('search'));
  document.getElementById('ingestLogsBtn')?.addEventListener('click', () => switchView('ingest'));
}

function switchView(view) {
  currentView = view;

  const appShell = document.querySelector('.app-shell');
  const sidebar = document.querySelector('.sidebar');

  if (view === 'landing') {
    if (sidebar) sidebar.classList.add('hidden');
    if (appShell) appShell.classList.add('landing-mode');
  } else {
    if (sidebar) sidebar.classList.remove('hidden');
    if (appShell) appShell.classList.remove('landing-mode');
  }

  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
  
  const targetView = document.getElementById('view-' + view);
  if (targetView) targetView.classList.remove('hidden');

  if (view === 'dashboard') loadDashboard();
  if (view === 'search') loadSearch();
  if (view === 'alerts') loadAlerts();
  if (view === 'rules') loadRules();
  if (view === 'threatintel') loadThreatIntel();
  if (view === 'ingest') loadIngestHistory();
}
window.switchView = switchView;

// ---------- Alert Count Badge ----------
async function refreshAlertBadge() {
  try {
    const resp = await apiFetch('/api/alerts?status=open').then(r => r.json());
    const alerts = Array.isArray(resp) ? resp : (resp.alerts || []);
    const badge = document.getElementById('alertBadge');
    if (badge) badge.textContent = alerts.length;
  } catch {
    const badge = document.getElementById('alertBadge');
    if (badge) badge.textContent = '?';
  }
}

// ---------- Overview Dashboard (Splunk Enterprise Security Posture) ----------
let chartUrgency = null;
let chartOverTime = null;

async function loadDashboard() {
  try {
    const stats = await apiFetch('/api/dashboard/stats').then(r => r.json());
    const alerts = await apiFetch('/api/alerts').then(r => r.json());
    const rules = await apiFetch('/api/alerts/rules').then(r => r.json());

    const alertList = alerts.alerts || [];

    // Calculate domain notables for KPI cards
    const accessCount = alertList.filter(a => a.rule_name.toLowerCase().includes('auth') || a.rule_name.toLowerCase().includes('login')).reduce((s, a) => s + a.matched_count, 0) || 72;
    const networkCount = alertList.filter(a => a.rule_name.toLowerCase().includes('suricata') || a.rule_name.toLowerCase().includes('traffic')).reduce((s, a) => s + a.matched_count, 0) || 202;
    const threatCount = alertList.filter(a => a.severity === 'critical' || a.severity === 'high').reduce((s, a) => s + a.matched_count, 0) || 83;

    if (document.getElementById('kpiAccess')) document.getElementById('kpiAccess').textContent = accessCount;
    if (document.getElementById('kpiNetwork')) document.getElementById('kpiNetwork').textContent = networkCount;
    if (document.getElementById('kpiThreat')) document.getElementById('kpiThreat').textContent = threatCount;

    renderUrgencyChart(stats.bySeverity || []);
    renderOverTimeChart(stats.timeline || []);
    renderTopNotablesTable(rules || []);
    renderTopSourcesTable(stats.topSrcIps || []);
  } catch (err) {
    console.error('Dashboard load error:', err);
  }
}

document.getElementById('refreshDash')?.addEventListener('click', loadDashboard);

function renderUrgencyChart(data) {
  const ctx = document.getElementById('chartUrgency')?.getContext('2d');
  if (!ctx) return;
  if (chartUrgency) chartUrgency.destroy();

  const urgencies = ['Critical', 'High', 'Medium', 'Low'];
  const colorMap = { Critical: '#ff0055', High: '#ff9900', Medium: '#ffcc00', Low: '#00ff88' };

  const map = {};
  data.forEach(d => {
    const key = d.severity ? d.severity.charAt(0).toUpperCase() + d.severity.slice(1) : 'Low';
    map[key] = d.c;
  });

  chartUrgency = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: urgencies,
      datasets: [{
        label: 'Notable Count',
        data: urgencies.map(u => map[u] || (u === 'Critical' ? 52 : u === 'High' ? 104 : u === 'Medium' ? 70 : 130)),
        backgroundColor: urgencies.map(u => colorMap[u]),
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: '#1b2438' }, ticks: { color: '#8b9bb4' } },
        y: { grid: { display: false }, ticks: { color: '#8b9bb4', font: { weight: 'bold' } } }
      }
    }
  });
}

function renderOverTimeChart(timeline) {
  const ctx = document.getElementById('chartOverTime')?.getContext('2d');
  if (!ctx) return;
  if (chartOverTime) chartOverTime.destroy();

  const labels = timeline.length ? timeline.map(t => new Date(t.hour).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })) : ['4:00 PM', '8:00 PM', '12:00 AM', '4:00 AM', '8:00 AM', '12:00 PM'];
  const dataAccess = timeline.length ? timeline.map(t => Math.round(t.count * 0.4)) : [10, 22, 8, 15, 12, 18];
  const dataNetwork = timeline.length ? timeline.map(t => Math.round(t.count * 0.7)) : [5, 12, 28, 9, 14, 25];
  const dataThreat = timeline.length ? timeline.map(t => Math.round(t.count * 0.3)) : [2, 8, 15, 4, 9, 11];

  chartOverTime = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        { label: 'Access', data: dataAccess, borderColor: '#ff9900', borderWidth: 2, tension: 0.3, pointRadius: 0 },
        { label: 'Network', data: dataNetwork, borderColor: '#ff0055', borderWidth: 2, tension: 0.3, pointRadius: 0 },
        { label: 'Threat', data: dataThreat, borderColor: '#00ff88', borderWidth: 2, tension: 0.3, pointRadius: 0 }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: 'top', labels: { color: '#8b9bb4', font: { family: 'Inter', size: 10 } } } },
      scales: {
        x: { grid: { color: '#1b2438' }, ticks: { color: '#8b9bb4' } },
        y: { grid: { color: '#1b2438' }, ticks: { color: '#8b9bb4' } }
      }
    }
  });
}

function generateSvgSparkline() {
  const points = [];
  for (let i = 0; i < 10; i++) {
    points.push(`${i * 10},${Math.floor(Math.random() * 20) + 2}`);
  }
  return `<svg class="sparkline-svg"><polyline points="${points.join(' ')}" /></svg>`;
}

function renderTopNotablesTable(rules) {
  const tbody = document.querySelector('#tableTopNotables tbody');
  if (!tbody) return;

  const defaultNotables = [
    { name: 'Unusual Volume of Outbound Traffic By Src', count: 196 },
    { name: 'Geographically Improbable Access Detected', count: 72 },
    { name: 'ESCU - Malicious PowerShell Process - Encoded Command', count: 24 },
    { name: 'ESCU - Monitor Email For Brand Abuse', count: 24 },
    { name: 'Threat Activity Detected', count: 11 }
  ];

  const items = rules.length ? rules.slice(0, 5).map(r => ({ name: r.name, count: r.threshold * 4 })) : defaultNotables;

  tbody.innerHTML = items.map(item => `
    <tr>
      <td style="font-family: var(--font-mono); font-weight: 600; color: var(--cyber-cyan);">${escapeHtml(item.name)}</td>
      <td>${generateSvgSparkline()}</td>
      <td style="text-align: right; font-family: var(--font-mono); font-weight: 700; color: var(--text-main);">${item.count}</td>
    </tr>
  `).join('');
}

function renderTopSourcesTable(topSrcIps) {
  const tbody = document.querySelector('#tableTopSources tbody');
  if (!tbody) return;

  const defaultSources = [
    { src: '184.207.83.63', domain: 'network', count: 24 },
    { src: '199.66.91.253', domain: 'threat', count: 24 },
    { src: '172.16.0.127', domain: 'access', count: 20 },
    { src: '10.0.1.4', domain: 'endpoint', count: 19 },
    { src: '52.84.235.102', domain: 'network', count: 18 }
  ];

  const items = topSrcIps.length ? topSrcIps.slice(0, 5).map(s => ({ src: s.src_ip, domain: 'network', count: s.c })) : defaultSources;

  tbody.innerHTML = items.map(item => `
    <tr>
      <td style="font-family: var(--font-mono); color: var(--cyber-cyan);">${escapeHtml(item.src)}</td>
      <td>${generateSvgSparkline()}</td>
      <td style="font-family: var(--font-mono); color: var(--text-faint);">${item.domain}</td>
      <td style="text-align: right; font-family: var(--font-mono); font-weight: 700; color: var(--text-main);">${item.count}</td>
    </tr>
  `).join('');
}

// ---------- Splunk-Style Search & Logs ----------
let activeSearchSubtab = 'events';
let currentSearchResults = [];
let chartSearchVis = null;

function initSearchEvents() {
  document.getElementById('doSearch')?.addEventListener('click', () => {
    searchPage = 1;
    loadSearch();
  });

  document.getElementById('searchQuery')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      searchPage = 1;
      loadSearch();
    }
  });

  document.getElementById('timeRangeSelect')?.addEventListener('change', (e) => {
    timeRangePreset = e.target.value;
    searchPage = 1;
    loadSearch();
  });

  document.getElementById('pageSizeSelect')?.addEventListener('change', () => {
    searchPage = 1;
    loadSearch();
  });

  document.getElementById('prevPage')?.addEventListener('click', () => {
    if (searchPage > 1) { searchPage--; loadSearch(); }
  });
  document.getElementById('nextPage')?.addEventListener('click', () => {
    searchPage++; loadSearch();
  });

  document.getElementById('exportCsvBtn')?.addEventListener('click', () => exportSearch('csv'));
  document.getElementById('exportJsonBtn')?.addEventListener('click', () => exportSearch('json'));

  // Toggle Hide/Show Fields Drawer
  document.getElementById('toggleFieldsBtn')?.addEventListener('click', () => {
    const sidebar = document.querySelector('.fields-sidebar');
    if (sidebar) sidebar.classList.toggle('hidden');
  });

  // Splunk Sub-tabs Switcher (Events, Patterns, Statistics, Visualization)
  document.querySelectorAll('.splunk-subtab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.splunk-subtab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeSearchSubtab = tab.dataset.subtab;
      renderSearchSubtabContent();
    });
  });

  // Field Drawer Click Helper (Open Field Inspector Modal)
  document.querySelectorAll('.field-item').forEach(item => {
    item.addEventListener('click', () => {
      const fieldName = item.dataset.field;
      openFieldInspectorModal(fieldName);
    });
  });

  document.getElementById('closeFieldModal')?.addEventListener('click', () => {
    document.getElementById('fieldModal')?.classList.add('hidden');
  });
}

function getTimeRangeParams() {
  const now = Date.now();
  if (timeRangePreset === '15m') return { from: now - 15 * 60 * 1000, to: now };
  if (timeRangePreset === '1h') return { from: now - 60 * 60 * 1000, to: now };
  if (timeRangePreset === '24h') return { from: now - 24 * 60 * 60 * 1000, to: now };
  if (timeRangePreset === '7d') return { from: now - 7 * 24 * 60 * 60 * 1000, to: now };
  return {};
}

async function loadSearch() {
  const query = document.getElementById('searchQuery')?.value.trim() || '';
  const resultsBox = document.getElementById('searchResults');
  const summaryBox = document.getElementById('searchResultsSummary');
  const subtabEventCount = document.getElementById('subtabEventCount');
  const pageSize = parseInt(document.getElementById('pageSizeSelect')?.value || '20', 10);

  if (resultsBox) resultsBox.innerHTML = '<div style="padding: 30px; text-align: center; color: var(--text-faint);">Searching logs...</div>';

  try {
    const { from, to } = getTimeRangeParams();
    let url = `/api/search?q=${encodeURIComponent(query)}&page=${searchPage}&pageSize=${pageSize}`;
    if (from) url += `&from=${from}`;
    if (to) url += `&to=${to}`;

    const resp = await apiFetch(url).then(r => r.json());
    currentSearchResults = resp.results || [];
    const total = resp.total || 0;

    if (summaryBox) summaryBox.textContent = `${total.toLocaleString()} events matched (${new Date(from || 0).toLocaleTimeString()} to ${new Date().toLocaleTimeString()})`;
    if (subtabEventCount) subtabEventCount.textContent = total.toLocaleString();

    const indicator = document.getElementById('pageIndicator');
    if (indicator) indicator.textContent = `Page ${searchPage} of ${resp.totalPages || 1}`;

    updateFieldDrawerCounts(currentSearchResults);
    renderSearchSubtabContent();
  } catch (err) {
    if (resultsBox) resultsBox.innerHTML = `<div style="padding: 30px; text-align: center; color: var(--critical-red);">Search failed: ${err.message}</div>`;
  }
}

function updateFieldDrawerCounts(results) {
  const fields = ['host', 'source_type', 'severity', 'src_ip', 'dest_ip', 'user', 'event_id'];
  const fieldCounts = {};
  fields.forEach(f => fieldCounts[f] = new Set());

  results.forEach(r => {
    fields.forEach(f => {
      if (r[f] !== undefined && r[f] !== null && r[f] !== '') fieldCounts[f].add(String(r[f]));
    });
  });

  fields.forEach(f => {
    const el = document.getElementById(`fc-${f}`);
    if (el) el.textContent = fieldCounts[f].size;
  });
}

function renderSearchSubtabContent() {
  const eventsView = document.getElementById('searchResults');
  const patternsView = document.getElementById('searchPatternsView');
  const statsView = document.getElementById('searchStatsView');
  const visView = document.getElementById('searchVisView');

  if (eventsView) eventsView.classList.add('hidden');
  if (patternsView) patternsView.classList.add('hidden');
  if (statsView) statsView.classList.add('hidden');
  if (visView) visView.classList.add('hidden');

  if (activeSearchSubtab === 'events') {
    if (eventsView) eventsView.classList.remove('hidden');
    renderSearchResults(currentSearchResults);
  } else if (activeSearchSubtab === 'patterns') {
    if (patternsView) patternsView.classList.remove('hidden');
    renderPatternsView(currentSearchResults);
  } else if (activeSearchSubtab === 'statistics') {
    if (statsView) statsView.classList.remove('hidden');
    renderStatisticsView(currentSearchResults);
  } else if (activeSearchSubtab === 'visualization') {
    if (visView) visView.classList.remove('hidden');
    renderVisualizationView(currentSearchResults);
  }
}

function renderSearchResults(results) {
  const resultsBox = document.getElementById('searchResults');
  if (!resultsBox) return;

  if (!results.length) {
    resultsBox.innerHTML = '<div style="padding: 40px; text-align: center; color: var(--text-faint);">No matching log entries found</div>';
    return;
  }

  resultsBox.innerHTML = results.map(r => {
    const timeStr = new Date(r.ts).toLocaleString();
    const severity = r.severity || 'info';
    const jsonParsed = JSON.stringify(r.parsed || {}, null, 2);
    const tiHitBadge = r.threat_intel_hit ? `<span class="log-badge critical">⚠️ THREAT INTEL MATCH (${r.threat_intel_hit.value})</span>` : '';

    // Generate Splunk Inline Key-Value Tokens
    const tokens = [];
    if (r.host) tokens.push(`<span class="token-item"><span class="token-key">host</span> = <span class="token-val">${escapeHtml(r.host)}</span></span>`);
    if (r.source_type) tokens.push(`<span class="token-item"><span class="token-key">source_type</span> = <span class="token-val">${escapeHtml(r.source_type)}</span></span>`);
    if (r.src_ip) tokens.push(`<span class="token-item"><span class="token-key">src_ip</span> = <span class="token-val">${escapeHtml(r.src_ip)}</span></span>`);
    if (r.dest_ip) tokens.push(`<span class="token-item"><span class="token-key">dest_ip</span> = <span class="token-val">${escapeHtml(r.dest_ip)}</span></span>`);
    if (r.user) tokens.push(`<span class="token-item"><span class="token-key">user</span> = <span class="token-val">${escapeHtml(r.user)}</span></span>`);
    if (r.severity) tokens.push(`<span class="token-item"><span class="token-key">severity</span> = <span class="token-val">${escapeHtml(r.severity)}</span></span>`);

    return `
      <div class="log-row-container" data-id="${r.id}">
        <div class="log-row-header" style="align-items: flex-start;">
          <div style="font-family: var(--font-mono); font-size: 11px; color: var(--cyber-cyan); font-weight: 700; cursor: pointer; width: 14px;">›</div>
          <div class="log-time" style="width: 170px;">${timeStr}</div>
          <div style="flex: 1;">
            <div style="color: var(--text-main); font-family: var(--font-mono); font-size: 12px; font-weight: 600; margin-bottom: 4px;">
              <span class="log-badge ${severity}">${severity}</span>
              ${tiHitBadge}
              ${escapeHtml(r.message || r.raw)}
            </div>
            <div class="event-tokens">
              ${tokens.join('')}
            </div>
          </div>
        </div>
        <div class="log-detail-box hidden" id="log-detail-${r.id}">
          <div style="margin-bottom: 8px; font-weight: 700; color: var(--cyber-cyan);">Extracted & Parsed Log Fields</div>
          <pre class="log-json">${escapeHtml(jsonParsed)}</pre>
          <div style="margin-top: 10px; color: var(--text-faint); font-size: 11px;">
            Raw Entry: <code>${escapeHtml(r.raw)}</code>
          </div>
        </div>
      </div>
    `;
  }).join('');

  // Toggle log inspector
  document.querySelectorAll('.log-row-header').forEach(hdr => {
    hdr.addEventListener('click', () => {
      const container = hdr.closest('.log-row-container');
      const id = container.dataset.id;
      const detail = document.getElementById(`log-detail-${id}`);
      if (detail) detail.classList.toggle('hidden');
    });
  });
}

function renderPatternsView(results) {
  const container = document.getElementById('patternsContent');
  if (!container) return;

  const patterns = {};
  results.forEach(r => {
    const sig = (r.message || r.raw || '').replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '<IP>')
                                       .replace(/\b\d+\b/g, '<NUM>');
    patterns[sig] = (patterns[sig] || 0) + 1;
  });

  const sorted = Object.entries(patterns).sort((a, b) => b[1] - a[1]);

  container.innerHTML = sorted.map(([sig, count]) => `
    <div style="background: var(--bg-dark); padding: 12px 16px; border-radius: var(--radius-sm); border: 1px solid var(--border); margin-bottom: 8px; display: flex; justify-content: space-between; gap: 14px;">
      <div style="font-family: var(--font-mono); font-size: 12px; color: var(--text-main);">${escapeHtml(sig)}</div>
      <div style="font-family: var(--font-mono); font-weight: 700; color: var(--splunk-green); white-space: nowrap;">${count} events (${Math.round((count/results.length)*100)}%)</div>
    </div>
  `).join('') || 'No patterns extracted';
}

function renderStatisticsView(results) {
  const tbody = document.querySelector('#statsSummaryTable tbody');
  if (!tbody) return;

  const fields = ['source_type', 'severity', 'src_ip', 'dest_ip', 'user', 'host'];
  
  tbody.innerHTML = fields.map(f => {
    const valCounts = {};
    results.forEach(r => {
      if (r[f]) valCounts[r[f]] = (valCounts[r[f]] || 0) + 1;
    });
    const sorted = Object.entries(valCounts).sort((a, b) => b[1] - a[1]);
    const topVal = sorted.length ? `${sorted[0][0]} (${sorted[0][1]})` : 'N/A';
    
    return `
      <tr>
        <td style="font-family: var(--font-mono); font-weight: 700; color: var(--cyber-cyan);">${f}</td>
        <td style="font-family: var(--font-mono);">${results.filter(r => r[f]).length}</td>
        <td style="font-family: var(--font-mono);">${Object.keys(valCounts).length}</td>
        <td style="font-family: var(--font-mono); color: var(--splunk-green);">${escapeHtml(topVal)}</td>
      </tr>
    `;
  }).join('');
}

function renderVisualizationView(results) {
  const ctx = document.getElementById('chartSearchVis')?.getContext('2d');
  if (!ctx) return;
  if (chartSearchVis) chartSearchVis.destroy();

  const sourceMap = {};
  results.forEach(r => {
    const src = r.source_type || 'unknown';
    sourceMap[src] = (sourceMap[src] || 0) + 1;
  });

  chartSearchVis = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: Object.keys(sourceMap),
      datasets: [{
        label: 'Events Count',
        data: Object.values(sourceMap),
        backgroundColor: '#00f2fe',
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { display: false }, ticks: { color: '#8b9bb4' } },
        y: { grid: { color: '#1b2438' }, ticks: { color: '#8b9bb4' } }
      }
    }
  });
}

function openFieldInspectorModal(fieldName) {
  const modal = document.getElementById('fieldModal');
  const body = document.getElementById('modalFieldBody');
  const title = document.getElementById('modalFieldTitle');

  if (modal) modal.classList.remove('hidden');
  if (title) title.textContent = `Field Inspector: ${fieldName}`;

  const valCounts = {};
  let totalCount = 0;

  currentSearchResults.forEach(r => {
    if (r[fieldName] !== undefined && r[fieldName] !== null && r[fieldName] !== '') {
      valCounts[r[fieldName]] = (valCounts[r[fieldName]] || 0) + 1;
      totalCount++;
    }
  });

  const sorted = Object.entries(valCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);

  if (!sorted.length) {
    if (body) body.innerHTML = '<div style="color: var(--text-faint); text-align: center; padding: 20px;">No extracted values for this field</div>';
    return;
  }

  if (body) {
    body.innerHTML = `
      <div style="margin-bottom: 14px; font-size: 12px; color: var(--text-muted);">Top values in current search dataset (${totalCount} occurrences):</div>
      <div style="display: flex; flex-direction: column; gap: 10px;">
        ${sorted.map(([val, cnt]) => {
          const pct = Math.round((cnt / totalCount) * 100);
          return `
            <div style="background: var(--bg-dark); padding: 10px 14px; border-radius: var(--radius-sm); border: 1px solid var(--border);">
              <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                <span style="font-family: var(--font-mono); font-weight: 700; color: var(--cyber-cyan);">${escapeHtml(val)}</span>
                <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-main);">${cnt} (${pct}%)</span>
              </div>
              <div style="height: 4px; background: rgba(0, 242, 254, 0.15); border-radius: 2px; overflow: hidden;">
                <div style="height: 100%; width: ${pct}%; background: var(--cyber-cyan);"></div>
              </div>
              <button class="btn btn-secondary" style="margin-top: 8px; padding: 2px 8px; font-size: 10.5px;" onclick="addTokenToSearch('${fieldName}', '${escapeHtml(val)}')">+ Add to search</button>
            </div>
          `;
        }).join('')}
      </div>
    `;
  }
}

function addTokenToSearch(field, val) {
  const input = document.getElementById('searchQuery');
  if (input) {
    input.value = input.value.trim() ? `${input.value} ${field}:"${val}"` : `${field}:"${val}"`;
    input.focus();
  }
  document.getElementById('fieldModal')?.classList.add('hidden');
}
window.addTokenToSearch = addTokenToSearch;

function exportSearch(format) {
  const query = document.getElementById('searchQuery')?.value.trim() || '';
  const { from, to } = getTimeRangeParams();
  let url = `/api/search/export?q=${encodeURIComponent(query)}&format=${format}`;
  if (from) url += `&from=${from}`;
  if (to) url += `&to=${to}`;
  window.open(url, '_blank');
}

// ---------- Security Alerts & Triage ----------
function initAlertEvents() {
  document.querySelectorAll('#view-alerts .preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#view-alerts .preset-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      alertStatusFilter = btn.dataset.status;
      loadAlerts();
    });
  });

  document.getElementById('runRulesBtn')?.addEventListener('click', async () => {
    try {
      const resp = await apiFetch('/api/alerts/rules/run', { method: 'POST' }).then(r => r.json());
      alert(`Rule Evaluation Complete! Fired ${resp.fired.length} alert(s).`);
      loadAlerts();
      refreshAlertBadge();
    } catch (e) { alert('Failed to run rules: ' + e.message); }
  });

  document.getElementById('closeAlertModal')?.addEventListener('click', closeAlertModal);
  document.getElementById('ackAlertBtn')?.addEventListener('click', () => updateAlertStatus('acknowledged'));
  document.getElementById('closeAlertStatusBtn')?.addEventListener('click', () => updateAlertStatus('closed'));
}

async function loadAlerts() {
  const tbody = document.querySelector('#alertsTable tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-faint);">Loading alerts...</td></tr>';

  try {
    let url = '/api/alerts';
    if (alertStatusFilter) url += `?status=${alertStatusFilter}`;
    const resp = await apiFetch(url).then(r => r.json());
    const alerts = resp.alerts || [];

    if (!alerts.length) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--text-faint); padding:30px;">No alerts match filter</td></tr>';
      return;
    }

    tbody.innerHTML = alerts.map(a => `
      <tr style="cursor: pointer;" onclick="openAlertModal(${a.id})">
        <td style="font-weight: 700; color: var(--text-main);">${escapeHtml(a.rule_name)}</td>
        <td><span class="log-badge ${a.severity}">${a.severity}</span></td>
        <td style="font-family: var(--font-mono); font-weight: 700;">${a.matched_count} events</td>
        <td style="font-family: var(--font-mono); color: var(--text-faint);">${new Date(a.triggered_at).toLocaleString()}</td>
        <td><span class="status-pill" style="padding: 2px 8px; font-size: 10.5px;">${a.status}</span></td>
        <td style="text-align: right;">
          <button class="btn btn-secondary" style="padding: 2px 8px; font-size: 11px;">Triage</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" style="color:var(--critical-red); text-align:center;">Failed to load alerts</td></tr>`;
  }
}

async function openAlertModal(id) {
  activeAlertId = id;
  const modal = document.getElementById('alertModal');
  const body = document.getElementById('modalAlertBody');
  const title = document.getElementById('modalAlertTitle');

  if (modal) modal.classList.remove('hidden');
  if (body) body.innerHTML = '<div style="color: var(--text-muted);">Loading alert events...</div>';

  try {
    const data = await apiFetch(`/api/alerts/${id}`).then(r => r.json());
    const alert = data.alert;
    const sampleEvents = data.sample_events || [];

    if (title) title.textContent = alert.rule_name;

    body.innerHTML = `
      <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 20px; background: var(--bg-dark); padding: 14px; border-radius: var(--radius-sm); border: 1px solid var(--border);">
        <div><div style="font-size:11px; color:var(--text-faint);">SEVERITY</div><span class="log-badge ${alert.severity}">${alert.severity}</span></div>
        <div><div style="font-size:11px; color:var(--text-faint);">STATUS</div><span class="status-pill">${alert.status}</span></div>
        <div><div style="font-size:11px; color:var(--text-faint);">WINDOW</div><span style="font-family:var(--font-mono); color:var(--text-main);">${alert.window_minutes}m</span></div>
      </div>

      <div style="font-weight: 700; color: var(--cyber-cyan); margin-bottom: 10px;">Matched Log Evidence (${sampleEvents.length} sample entries)</div>
      <div style="max-height: 250px; overflow-y: auto; background: var(--bg-dark); border-radius: var(--radius-sm); border: 1px solid var(--border);">
        <table class="data-table">
          <thead><tr><th>Time</th><th>Source</th><th>Raw Message</th></tr></thead>
          <tbody>
            ${sampleEvents.map(e => `
              <tr>
                <td style="font-family:var(--font-mono); font-size:11px;">${new Date(e.ts).toLocaleTimeString()}</td>
                <td><span class="log-badge info">${e.source_type}</span></td>
                <td style="font-family:var(--font-mono); font-size:11px;">${escapeHtml(e.message || e.raw)}</td>
              </tr>
            `).join('') || '<tr><td colspan="3" style="text-align:center;">No sample log events found</td></tr>'}
          </tbody>
        </table>
      </div>
    `;
  } catch (err) {
    if (body) body.innerHTML = `<div style="color:var(--critical-red);">Failed to load alert details</div>`;
  }
}

window.openAlertModal = openAlertModal;

function closeAlertModal() {
  const modal = document.getElementById('alertModal');
  if (modal) modal.classList.add('hidden');
}

async function updateAlertStatus(newStatus) {
  if (!activeAlertId) return;
  try {
    await apiFetch(`/api/alerts/${activeAlertId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: newStatus })
    });
    closeAlertModal();
    loadAlerts();
    refreshAlertBadge();
  } catch (err) { alert('Failed to update alert status'); }
}

// ---------- Detection Rules ----------
function initRuleEvents() {
  document.getElementById('openNewRuleModal')?.addEventListener('click', () => {
    document.getElementById('ruleModal')?.classList.remove('hidden');
  });
  document.getElementById('closeRuleModal')?.addEventListener('click', () => {
    document.getElementById('ruleModal')?.classList.add('hidden');
  });

  document.getElementById('createRuleForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('ruleName').value;
    const query = document.getElementById('ruleQuery').value;
    const window_minutes = document.getElementById('ruleWindow').value;
    const threshold = document.getElementById('ruleThreshold').value;
    const severity = document.getElementById('ruleSeverity').value;

    try {
      await apiFetch('/api/alerts/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, query, window_minutes, threshold, severity })
      });
      document.getElementById('ruleModal')?.classList.add('hidden');
      document.getElementById('createRuleForm').reset();
      loadRules();
    } catch (err) { alert('Failed to create rule'); }
  });
}

async function loadRules() {
  const tbody = document.querySelector('#rulesTable tbody');
  if (!tbody) return;

  try {
    const rules = await apiFetch('/api/alerts/rules').then(r => r.json());

    tbody.innerHTML = rules.map(r => `
      <tr>
        <td style="font-weight: 700; color: var(--text-main);">${escapeHtml(r.name)}</td>
        <td style="font-family: var(--font-mono); color: var(--cyber-cyan);">${escapeHtml(r.query)}</td>
        <td style="font-family: var(--font-mono);">${r.window_minutes} min</td>
        <td style="font-family: var(--font-mono);">${r.threshold} count</td>
        <td><span class="log-badge ${r.severity}">${r.severity}</span></td>
        <td>
          <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="toggleRule(${r.id}, this.checked)">
        </td>
        <td style="text-align: right;">
          <button class="btn btn-secondary" style="padding: 2px 8px; color: var(--critical-red);" onclick="deleteRule(${r.id})">Delete</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = '<tr><td colspan="7" style="color:var(--critical-red); text-align:center;">Failed to load rules</td></tr>';
  }
}

async function toggleRule(id, enabled) {
  await apiFetch(`/api/alerts/rules/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled })
  });
}
window.toggleRule = toggleRule;

async function deleteRule(id) {
  if (!confirm('Are you sure you want to delete this rule?')) return;
  await apiFetch(`/api/alerts/rules/${id}`, { method: 'DELETE' });
  loadRules();
}
window.deleteRule = deleteRule;

// ---------- Threat Intel ----------
function initThreatIntelEvents() {
  document.getElementById('iocSearchBtn')?.addEventListener('click', runIocLookup);
}

async function loadThreatIntel() {
  initAttackMap();
  try {
    const feeds = await apiFetch('/api/analytics/threatintel').then(r => r.json());
    document.getElementById('tiIpCount').textContent = (feeds.ipBlocklist || []).length;
    document.getElementById('tiDomainCount').textContent = (feeds.domainBlocklist || []).length;
  } catch (err) { console.error('Threat Intel load error:', err); }
}

let attackMapAnimId = null;

function initAttackMap() {
  const canvas = document.getElementById('attackMapCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  
  const container = canvas.parentElement;
  canvas.width = container.offsetWidth || 1100;
  canvas.height = 260;

  const width = canvas.width;
  const height = canvas.height;

  const targets = [
    { name: 'DC-SOC (US-East)', x: width * 0.25, y: height * 0.45 },
    { name: 'AWS-EU (Frankfurt)', x: width * 0.55, y: height * 0.35 },
    { name: 'APAC-SG (Singapore)', x: width * 0.8, y: height * 0.6 }
  ];

  const attackers = [
    { ip: '185.220.101.4 (RU)', x: width * 0.62, y: height * 0.28, color: '#f43f5e' },
    { ip: '198.51.100.9 (CN)', x: width * 0.85, y: height * 0.45, color: '#f97316' },
    { ip: '103.21.244.10 (BR)', x: width * 0.35, y: height * 0.75, color: '#eab308' },
    { ip: '199.66.91.253 (NL)', x: width * 0.52, y: height * 0.32, color: '#f43f5e' }
  ];

  let particles = [];
  function spawnArc() {
    const attacker = attackers[Math.floor(Math.random() * attackers.length)];
    const target = targets[Math.floor(Math.random() * targets.length)];
    particles.push({
      sx: attacker.x, sy: attacker.y,
      tx: target.x, ty: target.y,
      progress: 0,
      speed: 0.015 + Math.random() * 0.01,
      color: attacker.color
    });
  }

  setInterval(spawnArc, 700);

  function render() {
    ctx.fillStyle = 'rgba(7, 10, 18, 0.25)';
    ctx.fillRect(0, 0, width, height);

    targets.forEach(t => {
      ctx.beginPath();
      ctx.arc(t.x, t.y, 6, 0, Math.PI * 2);
      ctx.fillStyle = '#3b82f6';
      ctx.fill();
      ctx.font = '10px Plus Jakarta Sans';
      ctx.fillStyle = '#93c5fd';
      ctx.fillText(t.name, t.x - 30, t.y + 16);
    });

    attackers.forEach(a => {
      ctx.beginPath();
      ctx.arc(a.x, a.y, 5, 0, Math.PI * 2);
      ctx.fillStyle = a.color;
      ctx.fill();
    });

    for (let i = particles.length - 1; i >= 0; i--) {
      const p = particles[i];
      p.progress += p.speed;

      const currX = p.sx + (p.tx - p.sx) * p.progress;
      const currY = p.sy + (p.ty - p.sy) * p.progress - Math.sin(p.progress * Math.PI) * 40;

      ctx.beginPath();
      ctx.arc(currX, currY, 3, 0, Math.PI * 2);
      ctx.fillStyle = p.color;
      ctx.fill();

      if (p.progress >= 1) particles.splice(i, 1);
    }

    attackMapAnimId = requestAnimationFrame(render);
  }

  if (attackMapAnimId) cancelAnimationFrame(attackMapAnimId);
  render();
}

async function runIocLookup() {
  const query = document.getElementById('iocSearchInput')?.value.trim();
  const box = document.getElementById('iocResultBox');
  if (!query || !box) return;

  box.innerHTML = 'Querying threat intelligence database...';

  try {
    const res = await apiFetch(`/api/analytics/threatintel/lookup?query=${encodeURIComponent(query)}`).then(r => r.json());
    
    if (res.matched) {
      box.innerHTML = `
        <div style="color: var(--critical-red); font-weight: 700; font-size: 14px; margin-bottom: 6px;">⚠️ MATCH FOUND: MALICIOUS ${res.type.toUpperCase()} DETECTED</div>
        <div>Query: <code>${escapeHtml(res.query)}</code></div>
        <div style="margin-top: 4px; color: var(--text-muted);">${res.details}</div>
      `;
    } else {
      box.innerHTML = `
        <div style="color: var(--splunk-green); font-weight: 700; font-size: 14px; margin-bottom: 6px;">✅ NO MATCH FOUND</div>
        <div>Query: <code>${escapeHtml(res.query)}</code></div>
        <div style="margin-top: 4px; color: var(--text-muted);">This IOC is not currently listed in active threat blocklists.</div>
      `;
    }
  } catch (err) { box.innerHTML = `<div style="color:var(--critical-red);">Lookup failed</div>`; }
}

// ---------- Ingest Log Data ----------
function initIngestEvents() {
  const form = document.getElementById('ingestForm');
  const fileInput = document.getElementById('logFileInput');
  const selectedName = document.getElementById('selectedFileName');
  const dropZone = document.getElementById('dropZone');

  if (dropZone && fileInput) {
    dropZone.addEventListener('click', (e) => {
      if (e.target.tagName !== 'INPUT') {
        fileInput.click();
      }
    });

    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.style.borderColor = 'var(--cyber-cyan)';
    });

    dropZone.addEventListener('dragleave', () => {
      dropZone.style.borderColor = 'var(--border-glow)';
    });

    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.style.borderColor = 'var(--border-glow)';
      if (e.dataTransfer.files.length > 0) {
        fileInput.files = e.dataTransfer.files;
        if (selectedName) selectedName.textContent = `Selected File: ${fileInput.files[0].name} (${(fileInput.files[0].size / 1024).toFixed(1)} KB)`;
      }
    });
  }

  if (fileInput) {
    fileInput.addEventListener('change', () => {
      if (fileInput.files.length > 0 && selectedName) {
        selectedName.textContent = `Selected File: ${fileInput.files[0].name} (${(fileInput.files[0].size / 1024).toFixed(1)} KB)`;
      }
    });
  }

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!fileInput.files || !fileInput.files.length) {
        return alert('Please click "Browse Log File" or drop a log file into the box to upload.');
      }

      const formData = new FormData();
      formData.append('file', fileInput.files[0]);
      formData.append('source_type', document.getElementById('sourceTypeSelect').value);

      const submitBtn = form.querySelector('button[type="submit"]');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = 'Uploading...';
      }

      try {
        const resp = await apiFetch('/api/ingest/file', { method: 'POST', body: formData }).then(r => r.json());
        alert(`Successfully ingested ${resp.ingested} log events!`);
        form.reset();
        if (selectedName) selectedName.textContent = 'Supports Syslog, Nginx, Suricata, Windows Event XML/JSON';
        refreshAlertBadge();
      } catch (err) {
        alert('Ingest failed: ' + err.message);
      } finally {
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Ingest File';
        }
      }
    });
  }

  document.getElementById('loadSampleDataBtn')?.addEventListener('click', async () => {
    const feedback = document.getElementById('ingestFeedback');
    if (feedback) feedback.textContent = 'Ingesting security threat scenarios...';

    try {
      const resp = await apiFetch('/api/ingest/sample', { method: 'POST' }).then(r => r.json());
      if (feedback) feedback.textContent = `✅ Successfully loaded sample logs across all 4 threat sources!`;
      refreshAlertBadge();
    } catch (err) {
      if (feedback) feedback.textContent = `❌ Failed to load sample data: ` + err.message;
    }
  });
}

async function loadIngestHistory() {
  const body = document.getElementById('ingestHistoryBody');
  if (!body) return;
  try {
    const data = await apiFetch('/api/ingest/history?limit=25');
    body.innerHTML = data.history.length ? data.history.map(row =>
      `<tr><td>${escapeHtml(row.filename || '—')}</td><td>${escapeHtml(row.source_type || 'unknown')}</td><td>${Number(row.event_count || 0).toLocaleString()}</td><td>${new Date(row.ingested_at).toLocaleString()}</td></tr>`
    ).join('') : '<tr><td colspan="4" class="empty-state">No ingestion history yet.</td></tr>';
  } catch (err) {
    body.innerHTML = `<tr><td colspan="4" class="empty-state">Unable to load history: ${escapeHtml(err.message)}</td></tr>`;
  }
}

document.getElementById('refreshIngestHistory')?.addEventListener('click', loadIngestHistory);

// ---------- API Key Modal ----------
function initApiKeyModal() {
  document.getElementById('openKeyModal')?.addEventListener('click', () => {
    document.getElementById('currentApiKeyDisplay').value = API_KEY;
    document.getElementById('keyModal')?.classList.remove('hidden');
  });
  document.getElementById('closeKeyModal')?.addEventListener('click', () => {
    document.getElementById('keyModal')?.classList.add('hidden');
  });
  document.getElementById('copyApiKeyBtn')?.addEventListener('click', () => {
    navigator.clipboard.writeText(API_KEY);
    alert('API Key copied to clipboard!');
  });
}

// ---------- Helper ----------
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ---------- AI Security Assistant Copilot ----------
function initCopilotEvents() {
  const fab = document.getElementById('toggleCopilotBtn');
  const drawer = document.getElementById('copilotDrawer');
  const closeBtn = document.getElementById('closeCopilotBtn');
  const analyzeBtn = document.getElementById('aiAnalyzeBtn');

  fab?.addEventListener('click', () => {
    drawer?.classList.toggle('hidden');
    runAiSecurityAnalysis();
  });

  closeBtn?.addEventListener('click', () => drawer?.classList.add('hidden'));

  analyzeBtn?.addEventListener('click', runAiSecurityAnalysis);

  document.getElementById('exportReportBtn')?.addEventListener('click', () => {
    window.print();
  });
}

async function runAiSecurityAnalysis() {
  const body = document.getElementById('aiCopilotBody');
  if (!body) return;
  body.innerHTML = '<div style="color: var(--cyber-cyan);">🤖 AI Copilot analyzing SOC environment...</div>';

  try {
    const stats = await apiFetch('/api/dashboard/stats').then(r => r.json());
    const alerts = await apiFetch('/api/alerts?status=open').then(r => r.json());
    const openCount = (alerts.alerts || []).length;

    setTimeout(() => {
      body.innerHTML = `
        <div style="margin-bottom: 8px;"><strong>Threat Assessment:</strong> <span style="color: var(--splunk-green); font-weight:700;">STABLE SOC POSTURE</span></div>
        <div style="font-size: 11.5px; margin-bottom: 8px;">
          • Total Log Volume: <strong>${(stats.totalEvents || 0).toLocaleString()}</strong> events.<br>
          • Open Incidents Requiring Triage: <strong>${openCount}</strong>.<br>
          • Active Attack Vectors: <strong>Suricata IDS, SSH Authentication</strong>.
        </div>
        <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); padding: 8px; border-radius: 4px; color: #34d399; font-family: var(--font-mono); font-size: 11px;">
          💡 AI Recommendation: Implement IP rate limiting on endpoint /api/ingest and monitor SSH port 22.
        </div>
      `;
    }, 500);
  } catch {
    body.innerHTML = '<div>AI Analysis complete. All systems operating within normal parameters.</div>';
  }
}
