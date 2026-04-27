const express = require('express');
const router = express.Router();
const { all, get } = require('../db');
const { requireJwt } = require('../auth');

// GET /api/metrics — dashboard summary cards
router.get('/', requireJwt, (req, res) => {
  // Scan stats
  const totalScans = get('SELECT COUNT(*) as c FROM scan_events')?.c || 0;
  const granted = get("SELECT COUNT(*) as c FROM scan_events WHERE result='GRANTED'")?.c || 0;
  const denied = get("SELECT COUNT(*) as c FROM scan_events WHERE result='DENIED'")?.c || 0;
  const grantRate = totalScans > 0 ? ((granted / totalScans) * 100).toFixed(1) : 0;

  // Attack stats
  const totalAttacks = get('SELECT COUNT(*) as c FROM attack_events')?.c || 0;
  const attacksGranted = get("SELECT COUNT(*) as c FROM attack_events WHERE result='GRANTED'")?.c || 0;
  const validUidsFound = get('SELECT COUNT(*) as c FROM valid_uids')?.c || 0;
  const confirmedUids = get('SELECT COUNT(*) as c FROM valid_uids WHERE confirmed=1')?.c || 0;

  // Attack breakdown by type
  const attacksByType = all(
    'SELECT attack_type, COUNT(*) as count FROM attack_events GROUP BY attack_type ORDER BY count DESC'
  );

  // Phase breakdown
  const scansByPhase = all(
    'SELECT phase, result, COUNT(*) as count FROM scan_events GROUP BY phase, result ORDER BY phase'
  );

  // Recent activity (last 24h)
  const since24h = new Date(Date.now() - 86400000).toISOString();
  const recentScans = get(
    'SELECT COUNT(*) as c FROM scan_events WHERE timestamp >= ?', [since24h])?.c || 0;
  const recentAttacks = get(
    'SELECT COUNT(*) as c FROM attack_events WHERE timestamp >= ?', [since24h])?.c || 0;

  // Avg response time
  const avgResponse = get(
    'SELECT AVG(response_time_ms) as avg FROM scan_events WHERE response_time_ms IS NOT NULL'
  )?.avg || 0;

  // Timeline — scans per hour (last 24h)
  const timeline = all(`
    SELECT 
      strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
      COUNT(*) as scans,
      SUM(CASE WHEN result='GRANTED' THEN 1 ELSE 0 END) as granted,
      SUM(CASE WHEN result='DENIED' THEN 1 ELSE 0 END) as denied
    FROM scan_events 
    WHERE timestamp >= ?
    GROUP BY hour 
    ORDER BY hour ASC
  `, [since24h]);

  res.json({
    summary: {
      total_scans: totalScans,
      granted,
      denied,
      grant_rate_pct: parseFloat(grantRate),
      total_attacks: totalAttacks,
      attacks_granted: attacksGranted,
      valid_uids_found: validUidsFound,
      confirmed_uids: confirmedUids,
      avg_response_ms: parseFloat(avgResponse.toFixed(2)),
      scans_last_24h: recentScans,
      attacks_last_24h: recentAttacks,
    },
    attacks_by_type: attacksByType,
    scans_by_phase: scansByPhase,
    timeline_24h: timeline,
    generated_at: new Date().toISOString()
  });
});

// GET /api/metrics/valid-uids — all discovered UIDs
router.get('/valid-uids', requireJwt, (req, res) => {
  const uids = all('SELECT * FROM valid_uids ORDER BY discovered_at DESC');
  res.json({ data: uids, total: uids.length });
});

module.exports = router;
