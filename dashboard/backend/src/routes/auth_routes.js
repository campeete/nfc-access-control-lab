const express = require('express');
const router = express.Router();
const { generateToken, createApiKey, requireJwt } = require('../auth');

// POST /api/auth/token — get JWT for dashboard UI
// In prod this would check username/password
// For lab use: secret passphrase in env
router.post('/token', (req, res) => {
  const { passphrase } = req.body;
  const expected = process.env.DASHBOARD_PASS || 'nfclab2026';
  if (passphrase !== expected)
    return res.status(401).json({ error: 'Invalid passphrase' });

  const token = generateToken({ role: 'admin', iat: Date.now() });
  res.json({ token, expires_in: '24h' });
});

// POST /api/auth/api-key — generate new firmware API key (JWT required)
router.post('/api-key', requireJwt, async (req, res) => {
  const { label } = req.body;
  const key = await createApiKey(label || 'unnamed');
  res.status(201).json({
    key,
    message: 'Store this key securely — it will not be shown again',
    usage: 'Set as X-API-Key header in firmware HTTP requests'
  });
});

module.exports = router;
