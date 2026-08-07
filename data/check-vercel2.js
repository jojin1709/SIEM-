const https = require('https');
const API_KEY = 'change-me-in-vercel-env';

function get(path) {
  return new Promise(resolve => {
    const opts = {
      hostname: 'siem-swart.vercel.app', port: 443, path, method: 'GET',
      headers: { 'X-API-Key': API_KEY }
    };
    const req = https.request(opts, (res) => {
      let d=''; res.on('data',c=>d+=c); res.on('end',() => {
        try { resolve({status:res.statusCode, body:JSON.parse(d)}); }
        catch(e) { resolve({status:res.statusCode, body:d.substring(0,200)}); }
      });
    });
    req.on('error', e => resolve({error: e.message}));
    req.end();
  });
}

(async () => {
  const dash = await get('/api/dashboard/stats');
  console.log('Dashboard:', dash.status, dash.body ? `events=${dash.body.totalEvents} alerts=${dash.body.totalAlerts}` : dash.error);

  const rules = await get('/api/alerts/rules');
  console.log('Rules:', rules.status, Array.isArray(rules.body) ? `${rules.body.length} rules` : rules.body);

  const ss = await get('/api/savedsearches');
  console.log('Saved searches:', ss.status, Array.isArray(ss.body) ? `${ss.body.length} saved` : ss.body);

  const analytics = await get('/api/analytics/top?field=src_ip');
  console.log('Analytics:', analytics.status, analytics.body?.top ? `${analytics.body.top.length} results` : analytics.body?.error || 'no data');

  const search = await get('/api/search?q=fail');
  console.log('Search:', search.status, search.body?.total !== undefined ? `${search.body.total} results` : search.body?.error || 'error');
})();
