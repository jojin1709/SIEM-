const API = '';
let API_KEY = '';
let currentView = 'dashboard';
let searchPage = 1;
let searchTotal = 0;
let alertStatusFilter = '';
let chartSource, chartSeverity;

API_KEY = document.querySelector('meta[name="api-key"]')?.content || '';

async function apiFetch(url, options = {}) {
  const headers = options.headers || {};
  headers['X-API-Key'] = API_KEY;
  return fetch(url, { ...options, headers });
}

window.apiFetch = apiFetch;

// ---------- Nav ----------
document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => switchView(btn.dataset.view));
});

function switchView(view) {
  currentView = view;
  document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === view));
  document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
  document.getElementById('view-' + view).classList.remove('hidden');
  if (view === 'dashboard') loadDashboard();
  if (view === 'alerts') loadAlerts();
  if (view === 'rules') loadRules();
  if (view === 'ingest') loadIngestHistory();
}

// ---------- Health ----------
async function checkHealth() {
  try {
    await fetch('/api/health').then(r => r.json());
    const pill = document.getElementById('healthPill');
    pill.classList.add('ok');
    pill.innerHTML = '<span class="dot"></span> live';
  } catch {
    document.getElementById('healthPill').innerHTML = '<span class="dot"></span> offline';
  }
}

async function refreshAlertBadge() {
  try {
    const resp = await apiFetch('/api/alerts?status=open').then(r => r.json());
    const alerts = Array.isArray(resp) ? resp : (resp.alerts || []);
    document.getElementById('alertBadge').textContent = alerts.length;
  } catch {
    document.getElementById('alertBadge').textContent = '?';
  }
}

// ---------- Dashboard ----------
async function loadDashboard() {
  try {
    const stats = await apiFetch('/api/dashboard/stats').then(r => r.json());
    const rules = await apiFetch('/api/alerts/rules').then(r => r.json());

    document.getElementById('statTotalEvents').textContent = stats.totalEvents.toLocaleString();
    document.getElementById('statOpenAlerts').textContent = stats.totalAlerts;
    document.getElementById('statSources').textContent = stats.bySource.length;
    document.getElementById('statRules').textContent = rules.filter(r => r.enabled).length;

    renderPulse(stats.timeline);
    renderSourceChart(stats.bySource);
    renderSeverityChart(stats.bySeverity);
    renderMiniTable('tableTopIps', stats.topSrcIps, 'src_ip');
    renderMiniTable('tableTopHosts', stats.topHosts, 'host');

    refreshAlertBadge();
  } catch (e) {
    document.getElementById('statTotalEvents').textContent = 'error';
  }
}

function renderPulse(timeline) {
  const track = document.getElementById('pulseTrack');
  track.innerHTML = '';
  if (!timeline.length) {
    track.innerHTML = '<div style="color:var(--text-faint);font-size:12px;">No events ingested yet.</div>';
    return;
  }
  const max = Math.max(...timeline.map(t => t.count), 1);
  timeline.slice(-96).forEach(t => {
    const bar = document.createElement('div');
    bar.className = 'pulse-bar';
    bar.style.height = Math.max(4, (t.count / max) * 46) + 'px';
    bar.title = `${new Date(t.hour).toLocaleString()}: ${t.count} events`;
    track.appendChild(bar);
  });
}

function renderMiniTable(id, rows, keyField) {
  const tbody = document.querySelector('#' + id + ' tbody');
  tbody.innerHTML = '';
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="2" style="color:var(--text-faint);">No data</td></tr>';
    return;
  }
  rows.forEach(r => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${escapeHtml(r[keyField] || '-')}</td><td>${r.c}</td>`;
    tbody.appendChild(tr);
  });
}

function renderSourceChart(bySource) {
  const ctx = document.getElementById('chartSource');
  if (chartSource) chartSource.destroy();
  chartSource = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: bySource.map(s => s.source_type),
      datasets: [{
        data: bySource.map(s => s.c),
        backgroundColor: ['#7C6FF0', '#4EA1F3', '#34D399', '#F0B429', '#F0546B', '#8A93A3'],
        borderColor: '#12161D',
        borderWidth: 2
      }]
    },
    options: {
      plugins: { legend: { position: 'right', labels: { color: '#8A93A3', boxWidth: 10, font: { size: 11 } } } }
    }
  });
}

function renderSeverityChart(bySeverity) {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const colors = { critical: '#F0546B', high: '#F08A99', medium: '#F0B429', low: '#4EA1F3', info: '#8A93A3' };
  const sorted = [...bySeverity].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  const ctx = document.getElementById('chartSeverity');
  if (chartSeverity) chartSeverity.destroy();
  chartSeverity = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: sorted.map(s => s.severity),
      datasets: [{ data: sorted.map(s => s.c), backgroundColor: sorted.map(s => colors[s.severity] || '#8A93A3') }]
    },
    options: {
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#8A93A3' }, grid: { display: false } },
        y: { ticks: { color: '#8A93A3' }, grid: { color: '#232935' } }
      }
    }
  });
}

document.getElementById('refreshDash').addEventListener('click', loadDashboard);

// ---------- Search ----------
async function runSearch(page = 1) {
  searchPage = page;
  const q = document.getElementById('searchInput').value;
  const source_type = document.getElementById('searchSourceType').value;
  const severity = document.getElementById('searchSeverity').value;
  const params = new URLSearchParams({ q, source_type, severity, page, pageSize: 50 });
  const res = await apiFetch('/api/search?' + params.toString()).then(r => r.json());

  if (res.error) {
    document.getElementById('searchMeta').textContent = 'Query error: ' + (res.message || res.error);
    return;
  }

  searchTotal = res.total;
  document.getElementById('searchMeta').textContent = `${res.total.toLocaleString()} events matched`;
  const tbody = document.getElementById('eventTableBody');
  tbody.innerHTML = '';
  if (!res.results.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="color:var(--text-faint);padding:20px;">No matching events. Try ingesting some data first.</td></tr>';
  }
  res.results.forEach(ev => {
    const tiHit = ev.threat_intel_hit ? '<span class="ti-hit" title="Threat Intel Hit" style="margin-left:4px;color:#F0546B;font-size:11px;">&#9888;</span>' : '';
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="mono">${new Date(ev.ts).toLocaleString()}</td>
      <td class="mono">${escapeHtml(ev.source_type)}</td>
      <td><span class="sev-pill sev-${escapeHtml(ev.severity)}">${escapeHtml(ev.severity)}</span></td>
      <td class="mono">${escapeHtml(ev.host || '-')}</td>
      <td class="mono">${escapeHtml(ev.src_ip || '-')}</td>
      <td>${escapeHtml(ev.message || '')}${tiHit}</td>
    `;
    tbody.appendChild(tr);
  });
  const totalPages = Math.max(1, Math.ceil(searchTotal / 50));
  document.getElementById('pageInfo').textContent = `Page ${searchPage} of ${totalPages}`;
}

async function exportResults(format) {
  const q = document.getElementById('searchInput').value;
  const source_type = document.getElementById('searchSourceType').value;
  const severity = document.getElementById('searchSeverity').value;
  const params = new URLSearchParams({ q, source_type, severity, format });
  try {
    const resp = await apiFetch('/api/search/export?' + params.toString());
    const blob = await resp.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `siem-export.${format}`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  } catch (e) {
    alert('Export failed: ' + e.message);
  }
}

document.getElementById('runSearch').addEventListener('click', () => runSearch(1));
document.getElementById('searchInput').addEventListener('keydown', e => { if (e.key === 'Enter') runSearch(1); });
document.getElementById('prevPage').addEventListener('click', () => { if (searchPage > 1) runSearch(searchPage - 1); });
document.getElementById('nextPage').addEventListener('click', () => {
  if (searchPage * 50 < searchTotal) runSearch(searchPage + 1);
});
document.getElementById('exportJsonBtn').addEventListener('click', () => exportResults('json'));
document.getElementById('exportCsvBtn').addEventListener('click', () => exportResults('csv'));

// ---------- Alerts ----------
async function loadAlerts() {
  const url = alertStatusFilter ? `/api/alerts?status=${alertStatusFilter}` : '/api/alerts';
  const resp = await apiFetch(url).then(r => r.json());
  const alerts = Array.isArray(resp) ? resp : (resp.alerts || []);
  const list = document.getElementById('alertList');
  list.innerHTML = '';
  if (!alerts.length) {
    list.innerHTML = '<div class="panel" style="color:var(--text-faint);">No alerts yet. They will appear here once a detection rule matches, or click "Run rules now".</div>';
    return;
  }
  alerts.forEach(a => {
    const borderClass = a.severity === 'medium' ? 'sev-medium-border' : a.severity === 'low' ? 'sev-low-border' : '';
    const card = document.createElement('div');
    card.className = `alert-card ${borderClass} status-${a.status}`;
      card.innerHTML = `
        <div>
          <div class="alert-title">${escapeHtml(a.rule_name)}</div>
          <div class="alert-meta">${a.matched_count} events in ${a.window_minutes}m &middot; ${new Date(a.triggered_at).toLocaleString()} &middot; <span class="sev-pill sev-${escapeHtml(a.severity)}">${escapeHtml(a.severity)}</span> &middot; ${a.status}</div>
        </div>
        <div class="alert-actions">
          ${a.status !== 'acknowledged' ? `<button class="btn ghost" data-action="acknowledged" data-id="${a.id}">Acknowledge</button>` : ''}
          ${a.status !== 'closed' ? `<button class="btn ghost" data-action="closed" data-id="${a.id}">Close</button>` : ''}
        </div>
      `;
    list.appendChild(card);
  });

  list.querySelectorAll('button[data-action]').forEach(btn => {
    btn.addEventListener('click', async () => {
       await apiFetch(`/api/alerts/${btn.dataset.id}`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: btn.dataset.action })
      });
      loadAlerts();
      refreshAlertBadge();
    });
  });
}

document.querySelectorAll('.chip').forEach(chip => {
  chip.addEventListener('click', () => {
    document.querySelectorAll('.chip').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    alertStatusFilter = chip.dataset.status;
    loadAlerts();
  });
});

document.getElementById('runRulesBtn').addEventListener('click', async () => {
  const btn = document.getElementById('runRulesBtn');
  btn.textContent = 'Running\u2026';
  const res = await apiFetch('/api/alerts/rules/run', { method: 'POST' }).then(r => r.json());
  btn.textContent = 'Run rules now';
  loadAlerts();
  refreshAlertBadge();
  if (res.fired.length) {
    alert(`${res.fired.length} rule(s) fired: ${res.fired.map(f => f.ruleName).join(', ')}`);
  } else {
    alert('Rules evaluated \u2014 nothing crossed threshold.');
  }
});

// ---------- Rules ----------
async function loadRules() {
  const rules = await apiFetch('/api/alerts/rules').then(r => r.json());
  const list = document.getElementById('ruleList');
  list.innerHTML = '';
  rules.forEach(r => {
    const card = document.createElement('div');
    card.className = 'rule-card';
    card.innerHTML = `
      <div class="rule-info">
        <div class="rule-name">${escapeHtml(r.name)} <span class="sev-pill sev-${escapeHtml(r.severity)}">${escapeHtml(r.severity)}</span></div>
        <div class="rule-desc">${escapeHtml(r.description || '')}</div>
        <span class="rule-query">${escapeHtml(r.query)}</span>
        <span class="rule-cond">&ge; ${r.threshold} matches / ${r.window_minutes}m</span>
      </div>
      <div class="rule-actions">
        <button class="toggle ${r.enabled ? 'on' : ''}" data-id="${r.id}" data-enabled="${r.enabled}" title="Enable/disable"></button>
        <button class="btn ghost" data-del="${r.id}">Delete</button>
      </div>
    `;
    list.appendChild(card);
  });

  list.querySelectorAll('.toggle').forEach(t => {
    t.addEventListener('click', async () => {
      const enabled = t.dataset.enabled === '1' ? 0 : 1;
       await apiFetch(`/api/alerts/rules/${t.dataset.id}`, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled })
      });
      loadRules();
    });
  });
  list.querySelectorAll('[data-del]').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm('Delete this rule?')) return;
       await apiFetch(`/api/alerts/rules/${btn.dataset.del}`, { method: 'DELETE' });
      loadRules();
    });
  });
}

const ruleModal = document.getElementById('ruleModalOverlay');
document.getElementById('newRuleBtn').addEventListener('click', () => {
  document.getElementById('ruleName').value = '';
  document.getElementById('ruleDescription').value = '';
  document.getElementById('ruleQuery').value = '';
  document.getElementById('ruleWindow').value = 5;
  document.getElementById('ruleThreshold').value = 5;
  document.getElementById('ruleSeverity').value = 'high';
  ruleModal.classList.remove('hidden');
});
document.getElementById('ruleCancelBtn').addEventListener('click', () => ruleModal.classList.add('hidden'));
document.getElementById('ruleSaveBtn').addEventListener('click', async () => {
  const body = {
    name: document.getElementById('ruleName').value.trim(),
    description: document.getElementById('ruleDescription').value.trim(),
    query: document.getElementById('ruleQuery').value.trim(),
    window_minutes: Number(document.getElementById('ruleWindow').value),
    threshold: Number(document.getElementById('ruleThreshold').value),
    severity: document.getElementById('ruleSeverity').value
  };
  if (!body.name || !body.query) { alert('Name and query are required.'); return; }
   await apiFetch('/api/alerts/rules', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  ruleModal.classList.add('hidden');
  loadRules();
});

// ---------- Ingest ----------
let selectedFile = null;
const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');

dropzone.addEventListener('click', () => fileInput.click());
dropzone.addEventListener('dragover', e => { e.preventDefault(); dropzone.classList.add('drag'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag'));
dropzone.addEventListener('drop', e => {
  e.preventDefault();
  dropzone.classList.remove('drag');
  if (e.dataTransfer.files.length) setSelectedFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', () => { if (fileInput.files.length) setSelectedFile(fileInput.files[0]); });

function setSelectedFile(file) {
  selectedFile = file;
  dropzone.querySelector('.dz-text').textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
  document.getElementById('uploadBtn').disabled = false;
}

document.getElementById('uploadBtn').addEventListener('click', async () => {
  if (!selectedFile) return;
  const btn = document.getElementById('uploadBtn');
  btn.disabled = true;
  btn.textContent = 'Ingesting\u2026';
  const fd = new FormData();
  fd.append('file', selectedFile);
  fd.append('source_type', document.getElementById('sourceTypeSelect').value);
  const resultEl = document.getElementById('ingestResult');
  try {
     const res = await apiFetch('/api/ingest/file', { method: 'POST', body: fd }).then(r => r.json());
    if (res.error) {
      resultEl.innerHTML = `<span class="err">${escapeHtml(res.error)}</span>`;
    } else {
      resultEl.innerHTML = `<span class="ok">Ingested ${res.ingested} events from ${escapeHtml(res.filename)} as "${escapeHtml(res.source_type)}".</span>`;
      loadIngestHistory();
    }
  } catch (e) {
    resultEl.innerHTML = `<span class="err">Upload failed: ${escapeHtml(e.message)}</span>`;
  }
  btn.disabled = false;
  btn.textContent = 'Ingest file';
});

document.getElementById('loadSampleBtn').addEventListener('click', async () => {
  const btn = document.getElementById('loadSampleBtn');
  const out = document.getElementById('sampleResult');
  btn.disabled = true;
  btn.textContent = 'Loading\u2026';
  try {
     const res = await apiFetch('/api/ingest/sample', { method: 'POST' }).then(r => r.json());
    out.innerHTML = `<span class="ok">Loaded: ${res.summary.map(s => `${s.file} (${s.ingested})`).join(', ')}. Run detection rules from the Alerts tab to see them fire.</span>`;
    loadIngestHistory();
  } catch (e) {
    out.innerHTML = `<span class="err">Failed: ${escapeHtml(e.message)}</span>`;
  }
  btn.disabled = false;
  btn.textContent = 'Load sample data';
});

async function loadIngestHistory() {
  const resp = await apiFetch('/api/ingest/history').then(r => r.json());
  const rows = Array.isArray(resp) ? resp : (resp.entries || []);
  const tbody = document.querySelector('#tableIngestHistory tbody');
  tbody.innerHTML = '';
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="2" style="color:var(--text-faint);">No files ingested yet</td></tr>';
    return;
  }
  rows.forEach(r => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${escapeHtml(r.filename)} <span style="color:var(--text-faint);">(${r.source_type})</span></td><td>${r.event_count}</td>`;
    tbody.appendChild(tr);
  });
}

// ---------- Utils ----------
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ---------- Init ----------
checkHealth();
loadDashboard();
setInterval(refreshAlertBadge, 20000);
setInterval(() => { if (currentView === 'dashboard') loadDashboard(); }, 60000);
