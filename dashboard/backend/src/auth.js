/**
 * NFC Dashboard — Auth Middleware
 * API key auth for firmware POSTs + JWT for dashboard UI
 *
 * Security design:
 *   Firmware (ESP32) uses static API key in header: X-API-Key
 *   Dashboard frontend uses JWT bearer token
 *   API keys stored as bcrypt hashes — never plaintext in DB
 */

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { all, run, get } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'nfc-lab-dev-secret-change-in-prod';
const JWT_EXPIRY = '24h';

// ── JWT ────────────────────────────────────────────────────────────────────
function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

// ── API Key management ─────────────────────────────────────────────────────
function generateApiKey() {
  return `nfc_${crypto.randomBytes(24).toString('hex')}`;
}

async function createApiKey(label) {
  const key = generateApiKey();
  const hash = await bcrypt.hash(key, 10);
  run(
    'INSERT INTO api_keys (key_hash, label, created_at) VALUES (?, ?, ?)',
    [hash, label, new Date().toISOString()]
  );
  return key; // Return once — never stored in plaintext
}

async function validateApiKey(key) {
  const keys = all('SELECT * FROM api_keys');
  for (const record of keys) {
    const valid = await bcrypt.compare(key, record.key_hash);
    if (valid) {
      run('UPDATE api_keys SET last_used = ? WHERE id = ?',
        [new Date().toISOString(), record.id]);
      return record;
    }
  }
  return null;
}

// ── Middleware: require API key (for firmware endpoints) ───────────────────
async function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key) {
    return res.status(401).json({ error: 'API key required' });
  }
  const record = await validateApiKey(key);
  if (!record) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  req.apiKey = record;
  next();
}

// ── Middleware: require JWT (for dashboard UI) ─────────────────────────────
function requireJwt(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Bearer token required' });
  }
  try {
    const payload = verifyToken(auth.slice(7));
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── Dev mode: skip auth ────────────────────────────────────────────────────
function devBypass(req, res, next) {
  if (process.env.NODE_ENV === 'development' && process.env.SKIP_AUTH === 'true') {
    req.user = { role: 'dev' };
    return next();
  }
  next();
}

module.exports = {
  generateToken, verifyToken,
  createApiKey, validateApiKey,
  requireApiKey, requireJwt, devBypass
};
