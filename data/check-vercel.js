const https = require('https');
https.get('https://siem-swart.vercel.app/', (res) => {
  let d = '';
  res.on('data', c => d += c);
  res.on('end', () => {
    console.log('Status:', res.statusCode);
    console.log('CSP header present:', !!res.headers['content-security-policy']);
    const keyMatch = d.match(/name="api-key" content="([^"]+)"/);
    console.log('API key injected:', keyMatch ? keyMatch[1].substring(0, 20) + '...' : 'NOT FOUND');
    console.log('Has SIEM++ title:', d.includes('SIEM++'));
  });
}).on('error', e => console.log('Error:', e.message));
