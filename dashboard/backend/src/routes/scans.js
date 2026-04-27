const express = require('express');
const router = express.Router();
const { run, all, get } = require('../db');
const { requireApiKey, requireJwt } = require('../auth');

// POST /api/scans — firmware posts card scan events (X-API-Key auth)
router.post('/', requireApiKey, (req, res) => {
  const { uid, phase, result, response_time_ms, notes } = req.body;
  if (!uid || !phase || !result)
    return res.status(400).json({ error: 'uid, phase, result required' });
  if (!['GRANTED', 'DENIED', 'ERROR'].includes(result))
    return res.status(400).json({ error: 'result must be GRANTED, DENIED, or ERROR' });

  const timestamp = new Date().toISOString();
  run(
    `INSERT INTO scan_events (timestamp, uid, phase, result, response_time_ms, reader_ip, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [timestamp, uid.toUpperCase(), phase, result, response_time_ms || null, req.ip, notes || null]
  );

  if (result === 'GRANTED') {
    run(`INSERT OR IGNORE INTO valid_uids (uid, discovered_at, discovery_method, confirmed)
         VALUES (?, ?, 'firmware_scan', 1)`,
      [uid.toUpperCase(), timestamp]);
  }

  console.log(`[SCAN] ${timestamp} | ${uid} | Phase ${phase} | ${result}`);
  res.status(201).json({ success: true, timestamp });
});

// GET /api/scans — paginated history with filters
router.get('/', requireJwt, (req, res) => {
  const { limit = 50, offset = 0, phase, result, uid, from, to } = req.query;
  let sql = 'SELECT * FROM scan_events WHERE 1=1';
  const params = [];
  if (phase) { sql += ' AND phase = ?'; params.push(parseInt(phase)); }
  if (result) { sql += ' AND result = ?'; params.push(result.toUpperCase()); }
  if (uid) { sql += ' AND uid LIKE ?'; params.push(`%${uid.toUpperCase()}%`); }
  if (from) { sql += ' AND timestamp >= ?'; params.push(from); }
  if (to) { sql += ' AND timestamp <= ?'; params.push(to); }
  sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));
  res.json({ data: all(sql, params), limit: parseInt(limit), offset: parseInt(offset) });
});

router.get('/:id', requireJwt, (req, res) => {
  const row = get('SELECT * FROM scan_events WHERE id = ?', [req.params.id]);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
});

module.exports = router;
