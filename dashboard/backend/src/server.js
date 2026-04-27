/**
 * NFC Access Control Lab — Dashboard API Server
 * Port: 3001
 * Author: Cameron Peete
 *
 * Endpoints:
 *   POST /api/auth/token        — get JWT (dashboard login)
 *   POST /api/auth/api-key      — generate firmware API key
 *   POST /api/scans             — firmware posts scan events [X-API-Key]
 *   GET  /api/scans             — scan history [JWT]
 *   POST /api/attacks           — attack tools log events [X-API-Key]
 *   GET  /api/attacks           — attack history [JWT]
 *   GET  /api/metrics           — dashboard summary [JWT]
 *   GET  /api/metrics/valid-uids — discovered UIDs [JWT]
 *   GET  /api/health            — server health check [public]
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const { getDb } = require('./db');

const app = express();
const PORT = process.env.PORT || 3001;

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
}));
app.use(express.json({ limit: '10kb' }));
app.use(morgan('dev'));

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/api/auth', require('./routes/auth_routes'));
app.use('/api/scans', require('./routes/scans'));
app.use('/api/attacks', require('./routes/attacks'));
app.use('/api/metrics', require('./routes/metrics'));

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'nfc-dashboard-api',
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    uptime_s: process.uptime().toFixed(1)
  });
});

// ── 404 handler ───────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found` });
});

// ── Error handler ─────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Start ─────────────────────────────────────────────────────────────────────
async function start() {
  await getDb(); // Initialize DB before accepting requests
  app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════╗
║     NFC Dashboard API — Running on :${PORT}    ║
╠══════════════════════════════════════════════╣
║  POST /api/auth/token      → get JWT         ║
║  POST /api/auth/api-key    → firmware key    ║
║  POST /api/scans           → log scan        ║
║  POST /api/attacks         → log attack      ║
║  GET  /api/metrics         → dashboard data  ║
║  GET  /api/health          → health check    ║
╚══════════════════════════════════════════════╝
    `);
  });
}

start().catch(err => {
  console.error('[FATAL] Failed to start server:', err);
  process.exit(1);
});

module.exports = app;
