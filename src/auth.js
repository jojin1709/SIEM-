const API_KEY = process.env.API_KEY || 'siem-default-key-12345';

if (process.env.NODE_ENV !== 'production') {
  console.log(`\n  [auth] Default API key: ${API_KEY}\n  Set the API_KEY environment variable to override.\n`);
}

function requireAuth(req, res, next) {
  const cookieMatch = req.headers.cookie ? req.headers.cookie.match(/siem_key=([^;]+)/) : null;
  const cookieKey = cookieMatch ? cookieMatch[1] : null;
  const key = req.headers['x-api-key'] || req.headers['authorization']?.replace(/^Bearer\s+/i, '') || cookieKey;
  
  if (!key || key !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized: valid API key required' });
  }
  next();
}

module.exports = { requireAuth, API_KEY };
