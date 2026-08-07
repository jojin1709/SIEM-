const API_KEY = process.env.API_KEY || 'siem-' + Date.now().toString(36);

if (process.env.NODE_ENV !== 'production') {
  console.log(`\n  [auth] Default API key: ${API_KEY}\n  Set the API_KEY environment variable to override.\n`);
}

function requireAuth(req, res, next) {
  const key = req.headers['x-api-key'] || req.headers['authorization']?.replace(/^Bearer\s+/i, '');
  if (!key || key !== API_KEY) {
    return res.status(401).json({ error: 'Unauthorized: valid API key required' });
  }
  next();
}

module.exports = { requireAuth, API_KEY };
