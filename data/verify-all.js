const http = require('http');
const fs = require('fs');
const API_KEY = 'siem-demo';

async function apiFetch(path, method = 'GET', body = null) {
  const opts = { hostname: 'localhost', port: 4000, path, method, headers: { 'X-API-Key': API_KEY } };
  if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.headers['Content-Length'] = Buffer.byteLength(JSON.stringify(body));
  }
  return new Promise((resolve, reject) => {
    const req = http.request(opts, (res) => { let d=''; res.on('data',c=>d+=c); res.on('end',()=>resolve({status:res.statusCode, body:d, headers:res.headers})); });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

(async () => {
  let pass = 0, fail = 0;
  function check(name, condition) {
    if (condition) { pass++; console.log('PASS:', name); }
    else { fail++; console.log('FAIL:', name); }
  }

  // 1. Health endpoint (no auth required, returns DB status)
  const h = await apiFetch('/api/health', 'GET', null);
  // Override to test without auth
  const hNoAuth = new Promise(resolve => {
    const req = http.request({ hostname:'localhost', port:4000, path:'/api/health', method:'GET', headers:{} }, (res) => {
      let d=''; res.on('data',c=>d+=c); res.on('end',()=>resolve({status:res.statusCode, body:d}));
    });
    req.end();
  });
  const hNo = await hNoAuth;
  check('Health no-auth status 200', hNo.status === 200);
  check('Health returns DB connectivity', JSON.parse(h.body).db === 'connected');

  // 2. Auth required on protected endpoints
  const dNoAuth = new Promise(resolve => {
    const req = http.request({ hostname:'localhost', port:4000, path:'/api/dashboard/stats', method:'GET', headers:{} }, (res) => {
      let d=''; res.on('data',c=>d+=c); res.on('end',()=>resolve({status:res.statusCode, body:d}));
    });
    req.end();
  });
  const dNo = await dNoAuth;
  check('Dashboard no-auth rejected with 401', dNo.status === 401);

  // 3. Dashboard works with key
  const dash = await apiFetch('/api/dashboard/stats');
  check('Dashboard with key returns 200', dash.status === 200);
  const dj = JSON.parse(dash.body);
  check('Dashboard has totalEvents', typeof dj.totalEvents === 'number');
  check('Dashboard has bySource array', Array.isArray(dj.bySource));
  check('Dashboard has timeline array', Array.isArray(dj.timeline));

  // 4. Security headers present
  check('CSP header present', dash.headers['content-security-policy'] !== undefined);
  check('X-Frame-Options present', dash.headers['x-frame-options'] !== undefined);
  check('X-Content-Type-Options present', dash.headers['x-content-type-options'] !== undefined);

  // 5. Rules
  const rules = await apiFetch('/api/alerts/rules');
  const rj = JSON.parse(rules.body);
  check('Rules endpoint returns array', Array.isArray(rj));
  check('Has default rules', rj.some(r => r.is_default === 1));

  // 6. XSS prevention - severity is escaped in DB (can't inject script)
  const xssAttempt = await apiFetch('/api/alerts/rules', 'POST', {
    name: 'XSS Test', query: 'fail', window_minutes: 5, threshold: 1,
    severity: '<script>alert(1)</script>'
  });
  check('XSS in severity rejected', xssAttempt.status === 400);

  // 7. Input validation
  const badThreshold = await apiFetch('/api/alerts/rules', 'POST', {
    name: 'Bad', query: 'fail', window_minutes: 5, threshold: -1, severity: 'high'
  });
  check('Negative threshold rejected', badThreshold.status === 400);

  const badWindow = await apiFetch('/api/alerts/rules', 'POST', {
    name: 'Bad', query: 'fail', window_minutes: 99999, threshold: 1, severity: 'high'
  });
  check('Invalid window_minutes rejected', badWindow.status === 400);

  // 8. Mass assignment prevention
  const created = JSON.parse((await apiFetch('/api/alerts/rules', 'POST', {
    name: 'Mass Test', query: 'fail', window_minutes: 5, threshold: 1, severity: 'high',
    is_default: 1, evil_field: 'hacked'
  })).body);
  if (created.id) {
    const allRules = JSON.parse((await apiFetch('/api/alerts/rules')).body);
    const mt = allRules.find(r => r.name === 'Mass Test');
    check('Mass assignment: is_default not set', mt.is_default === 0);
    check('Mass assignment: evil_field not present', !('evil_field' in mt));
    await apiFetch(`/api/alerts/rules/${created.id}`, 'DELETE');
  }

  // 9. LIKE wildcard escaping
  const likeTest = await apiFetch('/api/search?q=severity:high%25');
  check('LIKE wildcard escape works', likeTest.status === 200);

  // 10. Search with validation
  const badSrc = await apiFetch('/api/search?q=fail&source_type=invalid');
  check('Invalid source_type rejected', badSrc.status === 400);

  // 11. Search export CSV
  const csvExport = await apiFetch('/api/search/export?q=*&format=csv');
  check('CSV export works', csvExport.status === 200 && csvExport.body.startsWith('ts,'));

  // 12. Search export JSON
  const jsonExport = await apiFetch('/api/search/export?q=*&format=json');
  check('JSON export works', jsonExport.status === 200);

  // 13. Alerts pagination
  const alertsPage = await apiFetch('/api/alerts?page=1&limit=2');
  const aj = JSON.parse(alertsPage.body);
  check('Alerts have pagination', aj.total !== undefined && aj.page !== undefined);
  check('Alerts limit respected', aj.alerts.length <= 2);

  // 14. Non-numeric ID handling
  const badPatch = await apiFetch('/api/alerts/rules/abc', 'PATCH', { enabled: 0 });
  check('Non-numeric ID rejected', badPatch.status === 400);

  // 15. DELETE non-existent rule returns 404
  const badDelete = await apiFetch('/api/alerts/rules/99999', 'DELETE');
  check('Delete non-existent returns 404', badDelete.status === 404);

  // 16. Ingest history pagination
  const hist = await apiFetch('/api/ingest/history?page=1&limit=10');
  const hj = JSON.parse(hist.body);
  check('Ingest history has pagination', hj.total !== undefined && hj.entries !== undefined);

  // 17. Threat intel annotation (check if search results have ti_hit field)
  const tiSearch = await apiFetch('/api/search?q=*&pageSize=5');
  const sj = JSON.parse(tiSearch.body);
  check('Search returns ti_hits count', sj.ti_hits !== undefined);
  check('Results have threat_intel_hit field', sj.results.some(r => 'threat_intel_hit' in r));

  // 18. Run rules
  const run = await apiFetch('/api/alerts/rules/run', 'POST');
  const rj2 = JSON.parse(run.body);
  check('Rules run returns fired array', Array.isArray(rj2.fired));

  console.log('\n--- Results: ' + pass + ' passed, ' + fail + ' failed ---');
  if (fail > 0) process.exit(1);
})();
