const http = require('http');
let jwtToken = '';
let apiKey = '';

function request(method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: 'localhost', port: 3001, path, method,
      headers: { 'Content-Type': 'application/json',
        'Content-Length': data ? Buffer.byteLength(data) : 0, ...headers }
    };
    const req = http.request(opts, res => {
      let b = '';
      res.on('data', d => b += d);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(b) }); }
        catch { resolve({ status: res.statusCode, data: b }); }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function runTests() {
  let passed = 0, failed = 0;
  function assert(name, ok, got) {
    if (ok) { console.log(`  ✓ ${name}`); passed++; }
    else { console.log(`  ✗ ${name} — got: ${JSON.stringify(got)}`); failed++; }
  }

  console.log('\n[TEST] NFC Dashboard API\n');

  console.log('── Health ──');
  const h = await request('GET', '/api/health');
  assert('GET /health 200', h.status === 200, h.status);
  assert('status ok', h.data.status === 'ok', h.data);

  console.log('\n── Auth ──');
  const bad = await request('POST', '/api/auth/token', { passphrase: 'wrong' });
  assert('bad passphrase → 401', bad.status === 401, bad.status);
  const good = await request('POST', '/api/auth/token', { passphrase: 'nfclab2026' });
  assert('good passphrase → 200', good.status === 200, good.status);
  jwtToken = good.data.token;

  console.log('\n── API Key ──');
  const k = await request('POST', '/api/auth/api-key', { label: 'test' },
    { Authorization: `Bearer ${jwtToken}` });
  assert('generate key → 201', k.status === 201, k.status);
  apiKey = k.data.key;

  console.log('\n── Scans ──');
  const s1 = await request('POST', '/api/scans',
    { uid: 'DEADBEEF', phase: 1, result: 'DENIED', response_time_ms: 45 },
    { 'X-API-Key': apiKey });
  assert('POST scan denied → 201', s1.status === 201, s1.status);

  const s2 = await request('POST', '/api/scans',
    { uid: 'AABBCCDD', phase: 3, result: 'GRANTED', response_time_ms: 12 },
    { 'X-API-Key': apiKey });
  assert('POST scan granted → 201', s2.status === 201, s2.status);

  const nokey = await request('POST', '/api/scans',
    { uid: 'TEST', phase: 1, result: 'DENIED' });
  assert('no API key → 401', nokey.status === 401, nokey.status);

  const list = await request('GET', '/api/scans', null,
    { Authorization: `Bearer ${jwtToken}` });
  assert('GET scans → 200', list.status === 200, list.status);
  assert('scans is array', Array.isArray(list.data.data), list.data);

  console.log('\n── Attacks ──');
  const a1 = await request('POST', '/api/attacks',
    { attack_type: 'uid_bruteforce', uid: 'CAFEBABE', phase_target: 1, result: 'DENIED' },
    { 'X-API-Key': apiKey });
  assert('POST attack → 201', a1.status === 201, a1.status);

  console.log('\n── Metrics ──');
  const m = await request('GET', '/api/metrics', null,
    { Authorization: `Bearer ${jwtToken}` });
  assert('GET metrics → 200', m.status === 200, m.status);
  assert('has summary', !!m.data.summary, m.data);
  assert('has timeline', Array.isArray(m.data.timeline_24h), m.data);
  assert('total_scans > 0', m.data.summary.total_scans > 0, m.data.summary);

  const uids = await request('GET', '/api/metrics/valid-uids', null,
    { Authorization: `Bearer ${jwtToken}` });
  assert('GET valid-uids → 200', uids.status === 200, uids.status);
  assert('AABBCCDD in valid uids',
    uids.data.data.some(u => u.uid === 'AABBCCDD'), uids.data);

  console.log(`\n${'─'.repeat(40)}`);
  console.log(`${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(e => { console.error(e.message); process.exit(1); });
