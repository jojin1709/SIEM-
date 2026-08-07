const http = require('http');
const API_KEY = 'siem-demo';

function apiFetch(path, method = 'GET', body = null) {
  const opts = { hostname: 'localhost', port: 4000, path, method, headers: { 'X-API-Key': API_KEY } };
  if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.headers['Content-Length'] = Buffer.byteLength(JSON.stringify(body));
  }
  return new Promise((resolve, reject) => {
    const req = http.request(opts, (res) => { let d=''; res.on('data',c=>d+=c); res.on('end',()=>resolve({status:res.statusCode, body:JSON.parse(d)})); });
    req.on('error', e => resolve({error: e.message}));
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

(async () => {
  let pass = 0, fail = 0;
  const check = (name, cond) => { if (cond) { pass++; console.log('PASS:', name); } else { fail++; console.log('FAIL:', name); } };

  const h = await apiFetch('/api/health');
  check('Health', h.status === 200 && h.body.db === 'connected');

  const sample = await apiFetch('/api/ingest/sample', 'POST');
  check('Sample loads all 4 files', sample.body.ok && sample.body.summary.length === 4);
  check('Sample event counts correct',
    sample.body.summary.find(s => s.file === 'auth-syslog.log')?.ingested === 10 &&
    sample.body.summary.find(s => s.file === 'access-nginx.log')?.ingested === 13 &&
    sample.body.summary.find(s => s.file === 'eve.json')?.ingested === 5 &&
    sample.body.summary.find(s => s.file === 'winevents.json')?.ingested === 5);

  const dash = await apiFetch('/api/dashboard/stats');
  check('Dashboard 33 events', dash.body.totalEvents === 33);
  check('Dashboard 4 sources', dash.body.bySource.length === 4);
  check('Dashboard timeline', dash.body.timeline.length > 0);

  const search = await apiFetch('/api/search?q=&pageSize=50');
  check('Search all events', search.body.total === 33);
  check('Search has results', search.body.results.length === 33);
  check('TI field present', 'threat_intel_hit' in search.body.results[0]);

  const searchFail = await apiFetch('/api/search?q=fail&pageSize=50');
  check('Search "fail"', searchFail.body.total === 16); // 6 syslog fail + 5 win 4625 + 5 win 1102

  const searchSev = await apiFetch('/api/search?q=severity:critical&pageSize=50');
  check('Search critical', searchSev.body.total === 4); // eve.json severity=2->medium, not critical; wait...
  check('All critical results', searchSev.body.results.every(r => r.severity === 'critical'));

  const runRules = await apiFetch('/api/alerts/rules/run', 'POST');
  check('Rules fired (3+ expected)', runRules.body.fired.length >= 3);

  const alerts = await apiFetch('/api/alerts');
  check('Alerts exist', alerts.body.total >= 3);
  check('Alert has fields', alerts.body.alerts[0].rule_name && alerts.body.alerts[0].severity);

  const history = await apiFetch('/api/ingest/history');
  check('History has entries', history.body.entries.length >= 4);
  check('History total correct', history.body.total >= 4);

  const analytics = await apiFetch('/api/analytics/top?field=src_ip&limit=5');
  check('Analytics top', analytics.body.top.length > 0);
  check('Analytics top sorted', analytics.body.top[0].count >= analytics.body.top[1]?.count);

  const timechart = await apiFetch('/api/analytics/timechart?bucket=hour');
  check('Timechart', timechart.body.series.length > 0);

  const saveSearch = await apiFetch('/api/savedsearches', 'POST', { name: 'TestSearch', query: 'fail', description: 'test' });
  check('Saved search created', saveSearch.body.id);

  const savedList = await apiFetch('/api/savedsearches');
  check('Saved search listed', savedList.body.some(s => s.name === 'TestSearch'));

  const savedRun = await apiFetch(`/api/savedsearches/${saveSearch.body.id}/run`);
  check('Saved search run', savedRun.body.total > 0);

  check('XSS blocked', (await apiFetch('/api/alerts/rules', 'POST', { name:'x',query:'f',window_minutes:5,threshold:1,severity:'<script>' })).status === 400);
  check('Negative threshold blocked', (await apiFetch('/api/alerts/rules', 'POST', { name:'x',query:'f',window_minutes:5,threshold:-1,severity:'high' })).status === 400);

  const massAssign = await apiFetch('/api/savedsearches', 'POST', { name: 'MassTest', query: 'f', description: 't', is_default: 1 });
  const allSS = await apiFetch('/api/savedsearches');
  const massCheck = allSS.body.find(s => s.id === massAssign.body.id);
  check('Mass assignment blocked', !massCheck.is_default);

  console.log(`\n=== ${pass} passed, ${fail} failed ===`);
  if (fail > 0) process.exit(1);
})();
