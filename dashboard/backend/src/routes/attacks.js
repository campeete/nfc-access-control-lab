const express = require('express');
const router = express.Router();
const { run, all, get } = require('../db');
const { requireApiKey, requireJwt } = require('../auth');

// POST /api/attacks — attack tools log events (X-API-Key auth)
router.post('/', requireApiKey, (req, res) => {
  const { attack_type, uid, phase_target, result, response_time_ms, raw_payload, notes } = req.body;
  if (!attack_type) return res.status(400).json({ error: 'attack_type required' });

  const timestamp = new Date().toISOString();
  run(
    `INSERT INTO attack_events 
     (timestamp, attack_type, uid, phase_target, result, response_time_ms, raw_payload, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [timestamp, attack_type, uid || null, phase_target || null,
     result || null, response_time_ms || null, raw_payload || null, notes || null]
  );

  // If attack found a valid UID, log it
  if (result === 'GRANTED' && uid) {
    run(`INSERT OR IGNORE INTO valid_uids (uid, discovered_at, discovery_method, confirmed)
         VALUES (?, ?, ?, 0)`,
      [uid.toUpperCase(), timestamp, attack_type]);
  }

  console.log(`[ATTACK] ${timestamp} | ${attack_type} | ${result || 'N/A'}`);
  res.status(201).json({ success: true, timestamp });
});

// GET /api/attacks — paginated attack event history
router.get('/', requireJwt, (req, res) => {
  const { limit = 50, offset = 0, attack_type, phase_target } = req.query;
  let sql = 'SELECT * FROM attack_events WHERE 1=1';
  const params = [];
  if (attack_type) { sql += ' AND attack_type = ?'; params.push(attack_type); }
  if (phase_target) { sql += ' AND phase_target = ?'; params.push(parseInt(phase_target)); }
  sql += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));
  res.json({ data: all(sql, params), limit: parseInt(limit), offset: parseInt(offset) });
});

router.get('/:id', requireJwt, (req, res) => {
  const row = get('SELECT * FROM attack_events WHERE id = ?', [req.params.id]);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
});

module.exports = router;
