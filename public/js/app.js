/* ==========================================================================
   SIEM++ — Splunk-Inspired Cyber Security Frontend Application Logic
   ========================================================================== */

let API_KEY = document.querySelector('meta[name="api-key"]')?.content || '';
if (!API_KEY || API_KEY === '__API_KEY__') {
  API_KEY = 'siem-default-key-12345';
}

let currentView = 'dashboard';
let searchPage = 1;
let timeRangePreset = 'all';
let alertStatusFilter = '';
let activeAlertId = null;
let chartSource = null;
let chartSeverity = null;

// ---------- API Fetch Helper ----------
async function apiFetch(url, options = {}) {
  const headers = options.headers || {};
  headers['X-API-Key'] = API_KEY;
  return fetch(url, { ...options, headers });
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
  initApiKeyModal();

  loadDashboard();
  refreshAlertBadge();

  // Periodically refresh stats
  setInterval(refreshAlertBadge, 15000);
});

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
}

function switchView(view) {
  currentView = view;
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

// ---------- Overview Dashboard ----------
async function loadDashboard() {
  try {
    const stats = await apiFetch('/api/dashboard/stats').then(r => r.json());
    const rules = await apiFetch('/api/alerts/rules').then(r => r.json());

    document.getElementById('statTotalEvents').textContent = (stats.totalEvents || 0).toLocaleString();
    document.getElementById('statOpenAlerts').textContent = stats.totalAlerts || 0;
    document.getElementById('statSources').textContent = (stats.bySource || []).length;
    document.getElementById('statRules').textContent = (rules || []).filter(r => r.enabled).length;

    renderPulseTrack(stats.timeline || []);
    renderSourceChart(stats.bySource || []);
    renderSeverityChart(stats.bySeverity || []);
    renderTopIpsTable(stats.topSrcIps || []);
    renderTopHostsTable(stats.topHosts || []);
  } catch (err) {
    console.error('Dashboard load error:', err);
  }
}

document.getElementById('refreshDash')?.addEventListener('click', loadDashboard);

function renderPulseTrack(timeline) {
  const track = document.getElementById('pulseTrack');
  const countLabel = document.getElementById('pulseCountLabel');
  if (!track) return;
  track.innerHTML = '';

  if (!timeline.length) {
    track.innerHTML = '<div style="font-size:11px; color:var(--text-faint); margin:auto;">No log activity recorded yet</div>';
    if (countLabel) countLabel.textContent = '0 events';
    return;
  }

  const maxCount = Math.max(...timeline.map(t => t.count), 1);
  const totalInTimeline = timeline.reduce((s, t) => s + t.count, 0);
  if (countLabel) countLabel.textContent = `${totalInTimeline.toLocaleString()} events`;

  timeline.forEach(t => {
    const bar = document.createElement('div');
    bar.className = 'pulse-bar';
    const heightPct = Math.max(8, Math.round((t.count / maxCount) * 100));
    bar.style.height = `${heightPct}%`;
    bar.title = `${t.count} events at ${new Date(t.hour).toLocaleString()}`;
    track.appendChild(bar);
  });
}

function renderSourceChart(data) {
  const ctx = document.getElementById('chartSource')?.getContext('2d');
  if (!ctx) return;
  if (chartSource) chartSource.destroy();

  const labels = data.map(d => d.source_type);
  const counts = data.map(d => d.c);

  chartSource = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data: counts,
        backgroundColor: ['#00f2fe', '#0077ff', '#00ff88', '#ff9900', '#ff0055', '#8a2be2'],
        borderWidth: 2,
        borderColor: '#0f1424'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'right', labels: { color: '#8b9bb4', font: { family: 'Inter', size: 11 } } }
      }
    }
  });
}

function renderSeverityChart(data) {
  const ctx = document.getElementById('chartSeverity')?.getContext('2d');
  if (!ctx) return;
  if (chartSeverity) chartSeverity.destroy();

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const colorMap = { critical: '#ff0055', high: '#ff9900', medium: '#00c3ff', low: '#00ff88', info: '#4e5e78' };

  const map = {};
  data.forEach(d => map[d.severity] = d.c);

  chartSeverity = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: severityOrder.map(s => s.toUpperCase()),
      datasets: [{
        data: severityOrder.map(s => map[s] || 0),
        backgroundColor: severityOrder.map(s => colorMap[s]),
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

function renderTopIpsTable(rows) {
  const tbody = document.querySelector('#tableTopIps tbody');
  if (!tbody) return;
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td style="font-family: var(--font-mono); color: var(--cyber-cyan);">${r.src_ip}</td>
      <td style="text-align: right; font-family: var(--font-mono); font-weight: 700; color: var(--text-main);">${r.c.toLocaleString()}</td>
    </tr>
  `).join('') || '<tr><td colspan="2" style="color:var(--text-faint); text-align:center;">No data</td></tr>';
}

function renderTopHostsTable(rows) {
  const tbody = document.querySelector('#tableTopHosts tbody');
  if (!tbody) return;
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td style="font-family: var(--font-mono); color: var(--text-main);">${r.host}</td>
      <td style="text-align: right; font-family: var(--font-mono); font-weight: 700; color: var(--text-main);">${r.c.toLocaleString()}</td>
    </tr>
  `).join('') || '<tr><td colspan="2" style="color:var(--text-faint); text-align:center;">No data</td></tr>';
}

// ---------- Splunk-Style Search & Logs ----------
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

  document.querySelectorAll('.preset-btn[data-range]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.preset-btn[data-range]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      timeRangePreset = btn.dataset.range;
      searchPage = 1;
      loadSearch();
    });
  });

  document.getElementById('prevPage')?.addEventListener('click', () => {
    if (searchPage > 1) { searchPage--; loadSearch(); }
  });
  document.getElementById('nextPage')?.addEventListener('click', () => {
    searchPage++; loadSearch();
  });

  document.getElementById('exportCsvBtn')?.addEventListener('click', () => exportSearch('csv'));
  document.getElementById('exportJsonBtn')?.addEventListener('click', () => exportSearch('json'));

  // Field Drawer Click Helper
  document.querySelectorAll('.field-item').forEach(item => {
    item.addEventListener('click', () => {
      const fieldName = item.dataset.field;
      const input = document.getElementById('searchQuery');
      if (input) {
        input.value = input.value.trim() ? `${input.value} ${fieldName}:` : `${fieldName}:`;
        input.focus();
      }
    });
  });
}

function getTimeRangeParams() {
  const now = Date.now();
  if (timeRangePreset === '15m') return { from: now - 15 * 60 * 1000, to: now };
  if (timeRangePreset === '1h') return { from: now - 60 * 60 * 1000, to: now };
  if (timeRangePreset === '24h') return { from: now - 24 * 60 * 60 * 1000, to: now };
  return {};
}

async function loadSearch() {
  const query = document.getElementById('searchQuery')?.value.trim() || '';
  const resultsBox = document.getElementById('searchResults');
  const countBox = document.getElementById('searchResultsCount');

  if (resultsBox) resultsBox.innerHTML = '<div style="padding: 30px; text-align: center; color: var(--text-faint);">Searching logs...</div>';

  try {
    const { from, to } = getTimeRangeParams();
    let url = `/api/search?q=${encodeURIComponent(query)}&page=${searchPage}&pageSize=30`;
    if (from) url += `&from=${from}`;
    if (to) url += `&to=${to}`;

    const resp = await apiFetch(url).then(r => r.json());
    const results = resp.results || [];
    const total = resp.total || 0;

    if (countBox) countBox.textContent = `${total.toLocaleString()} logs matched (Page ${searchPage} of ${resp.totalPages || 1})`;

    updateFieldDrawerCounts(results);

    if (!results.length) {
      if (resultsBox) resultsBox.innerHTML = '<div style="padding: 40px; text-align: center; color: var(--text-faint);">No matching log entries found</div>';
      return;
    }

    renderSearchResults(results);
  } catch (err) {
    if (resultsBox) resultsBox.innerHTML = `<div style="padding: 30px; text-align: center; color: var(--critical-red);">Search failed: ${err.message}</div>`;
  }
}

function updateFieldDrawerCounts(results) {
  const fieldCounts = { source_type: {}, severity: {}, src_ip: {}, user: {}, host: {} };

  results.forEach(r => {
    ['source_type', 'severity', 'src_ip', 'user', 'host'].forEach(f => {
      if (r[f]) fieldCounts[f][r[f]] = (fieldCounts[f][r[f]] || 0) + 1;
    });
  });

  Object.keys(fieldCounts).forEach(f => {
    const el = document.getElementById(`fc-${f}`);
    if (el) el.textContent = Object.keys(fieldCounts[f]).length;
  });
}

function renderSearchResults(results) {
  const resultsBox = document.getElementById('searchResults');
  if (!resultsBox) return;

  resultsBox.innerHTML = results.map(r => {
    const timeStr = new Date(r.ts).toLocaleString();
    const severity = r.severity || 'info';
    const jsonParsed = JSON.stringify(r.parsed || {}, null, 2);
    const tiHitBadge = r.threat_intel_hit ? `<span class="log-badge critical">⚠️ THREAT INTEL MATCH (${r.threat_intel_hit.value})</span>` : '';

    return `
      <div class="log-row-container" data-id="${r.id}">
        <div class="log-row-header">
          <span class="log-time">${timeStr}</span>
          <span class="log-badge ${severity}">${severity}</span>
          <span class="log-badge info">${r.source_type}</span>
          ${tiHitBadge}
          <span class="log-message">${escapeHtml(r.message || r.raw)}</span>
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
  try {
    const data = await apiFetch('/api/analytics/threatintel/lookup').then(r => r.json());
    document.getElementById('tiIpCount').textContent = (data.total_ips || 0).toLocaleString();
    document.getElementById('tiDomainCount').textContent = (data.total_domains || 0).toLocaleString();
  } catch (err) { console.error('Threat Intel load error:', err); }
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

  if (fileInput) {
    fileInput.addEventListener('change', () => {
      if (fileInput.files.length > 0 && selectedName) {
        selectedName.textContent = `Selected: ${fileInput.files[0].name}`;
      }
    });
  }

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!fileInput.files.length) return alert('Please select a file to ingest');

      const formData = new FormData();
      formData.append('file', fileInput.files[0]);
      formData.append('source_type', document.getElementById('sourceTypeSelect').value);

      try {
        const resp = await apiFetch('/api/ingest/file', { method: 'POST', body: formData }).then(r => r.json());
        alert(`Successfully ingested ${resp.ingested} log events!`);
        form.reset();
        if (selectedName) selectedName.textContent = 'Supports Syslog, Nginx, Suricata, Windows Event';
        refreshAlertBadge();
      } catch (err) { alert('Ingest failed: ' + err.message); }
    });
  }

  document.getElementById('loadSampleDataBtn')?.addEventListener('click', async () => {
    const feedback = document.getElementById('ingestFeedback');
    if (feedback) feedback.textContent = 'Loading sample log suite...';

    try {
      const resp = await apiFetch('/api/ingest/sample', { method: 'POST' }).then(r => r.json());
      if (feedback) feedback.textContent = `✅ Successfully loaded sample logs across all 4 threat sources!`;
      refreshAlertBadge();
    } catch (err) {
      if (feedback) feedback.textContent = `❌ Failed to load sample data`;
    }
  });
}

function loadIngestHistory() {}

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
