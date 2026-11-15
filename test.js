// End-to-end test for the Proof Gatekeeper endpoint.
// Spawns server.js on a test port with a TEST HMAC secret, then asserts:
//  1. valid task      -> approve + a proof that verifies (snarkjs groth16 verify)
//  2. trap task       -> reject + a proof that verifies (a valid rejection)
//  3. bad HMAC        -> 401, before any parsing
//  4. replayed task   -> byte-identical body AND signature (cached response)
//  5. re-used proof ref (new taskId, same proofReference) -> decision alone, no proof
//  6. preflight POST  -> 200 {status:"ok"}
//  7. missing fields  -> reject, no proof
//  8. GET /           -> 200 {status:"ok"}
// Exit 0 when all pass, 1 otherwise. Prints round-trip + proof-gen timings.
'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const snarkjs = require('snarkjs');

const TEST_SECRET = 'test-secret-123-do-not-use-in-production';
const PORT = 3456;
const DIR = __dirname;
const STORE = path.join(os.tmpdir(), 'gatekeeper-test-store-' + process.pid + '.json');
const VKEY = require(path.join(DIR, 'circuits', 'verification_key.json'));

const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const ADDR_A = '0x1111111111111111111111111111111111111111';
const ADDR_B = '0x2222222222222222222222222222222222222222';

let passed = 0, failed = 0;
function check(name, ok, extra) {
  if (ok) { passed++; console.log('  PASS', name, extra || ''); }
  else { failed++; console.log('  FAIL', name, extra || ''); }
}

function hmacHex(data) {
  return crypto.createHmac('sha256', TEST_SECRET).update(data).digest('hex');
}

function post(bodyObj, { sign = true, rawBody = null } = {}) {
  return new Promise((resolve, reject) => {
    const bodyStr = rawBody !== null ? rawBody : JSON.stringify(bodyObj);
    const headers = { 'content-type': 'application/json', 'content-length': Buffer.byteLength(bodyStr) };
    if (sign) headers['x-agent-games-signature'] = hmacHex(Buffer.from(bodyStr, 'utf8'));
    const req = http.request({ host: '127.0.0.1', port: PORT, path: '/', method: 'POST', headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject);
    req.end(bodyStr);
  });
}

function get(pathname) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: PORT, path: pathname }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    }).on('error', reject);
  });
}

function baseTask(overrides) {
  return Object.assign({
    taskId: 2026111501,
    proofReference: 'proof-ref-2026111501',
    recipient: ADDR_A,
    conditionRecipient: ADDR_A,
    amount: 500,
    maxTransfer: 1000,
    minimum: 1000,
    publicBalance: 1460,
    expiryBlock: 8430000,
    currentBlock: 8420000,
    vkHash: VK,
    registeredVkHash: VK,
    timestamp: Math.floor(Date.now() / 1000),
  }, overrides || {});
}

async function main() {
  // Start the server as a child process.
  const child = spawn(process.execPath, [path.join(DIR, 'server.js')], {
    env: Object.assign({}, process.env, {
      PORT: String(PORT),
      AGENTGAMES_HMAC_SECRET: TEST_SECRET,
      STORE_PATH: STORE,
      CIRCUITS_DIR: path.join(DIR, 'circuits'),
    }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => process.stdout.write('[server] ' + d));
  child.stderr.on('data', (d) => process.stdout.write('[server:err] ' + d));
  const stop = () => { try { child.kill('SIGTERM'); } catch {} };

  // Wait until it listens.
  let up = false;
  for (let i = 0; i < 50 && !up; i++) {
    try { const r = await get('/'); if (r.status === 200) up = true; }
    catch { await new Promise((r) => setTimeout(r, 200)); }
  }
  if (!up) { console.log('FAIL server did not start'); stop(); process.exit(1); }

  try {
    // 8. GET /
    const g = await get('/');
    check('GET / health', g.status === 200 && JSON.parse(g.body).status === 'ok');

    // 6. Preflight POST
    const pf = await post({ type: 'preflight' });
    check('preflight POST', pf.status === 200 && JSON.parse(pf.body).status === 'ok', pf.body);

    // 1. Valid task -> approve + verifiable proof
    const t0 = Date.now();
    const valid = await post(baseTask());
    const dtValid = Date.now() - t0;
    const v = JSON.parse(valid.body);
    check('valid task status 200', valid.status === 200, 'status=' + valid.status);
    check('valid task decision approve', v.decision === 'approve', 'decision=' + v.decision);
    check('valid task has proof + 13 public signals',
      !!v.proof && Array.isArray(v.publicSignals) && v.publicSignals.length === 13,
      'signals=' + (v.publicSignals || []).length);
    check('response is HMAC-signed',
      !!valid.headers['x-agent-games-signature'] &&
      valid.headers['x-agent-games-signature'] === hmacHex(Buffer.from(valid.body, 'utf8')));
    let okVerify = false;
    try { okVerify = await snarkjs.groth16.verify(VKEY, v.publicSignals, v.proof); } catch (e) { console.log('  verify error:', e.message); }
    check('valid approve proof verifies (snarkjs)', okVerify === true);
    console.log(`  valid task round trip: ${dtValid} ms (deadline 60000 ms)`);

    // 4. Replay the SAME valid task -> byte-identical body + signature
    const replay = await post(baseTask());
    check('replay returns identical body', replay.body === valid.body);
    check('replay returns identical signature',
      replay.headers['x-agent-games-signature'] === valid.headers['x-agent-games-signature']);

    // 5. Re-used proof reference, NEW taskId -> decision alone, no proof
    const reuse = await post(baseTask({ taskId: 2026111509, proofReference: 'proof-ref-2026111501' }));
    const ru = JSON.parse(reuse.body);
    check('reused proof ref: decision alone, no proof',
      reuse.status === 200 && ru.reused === true && !ru.proof && !ru.publicSignals,
      JSON.stringify(ru));

    // 2. Trap task (recipient mismatch) -> reject + a proof that verifies
    const t1 = Date.now();
    const trap = await post(baseTask({
      taskId: 2026111502, proofReference: 'proof-ref-2026111502', conditionRecipient: ADDR_B,
    }));
    const dtTrap = Date.now() - t1;
    const tr = JSON.parse(trap.body);
    check('trap task decision reject', trap.status === 200 && tr.decision === 'reject', 'decision=' + tr.decision);
    check('trap task has a rejection proof', !!tr.proof && Array.isArray(tr.publicSignals) && tr.publicSignals.length === 13);
    let okTrap = false;
    try { okTrap = await snarkjs.groth16.verify(VKEY, tr.publicSignals, tr.proof); } catch (e) { console.log('  verify error:', e.message); }
    check('trap reject proof verifies (snarkjs)', okTrap === true);
    console.log(`  trap task round trip: ${dtTrap} ms`);

    // 3. Bad HMAC -> 401
    const bad = await post(baseTask({ taskId: 2026111503 }), { sign: false });
    // (no signature header at all)
    check('missing signature -> 401', bad.status === 401, 'status=' + bad.status);
    const bad3 = await new Promise((resolve, reject) => {
      const bodyStr = JSON.stringify(baseTask({ taskId: 2026111505 }));
      const req = http.request({ host: '127.0.0.1', port: PORT, path: '/', method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(bodyStr),
          'x-agent-games-signature': '00'.repeat(32) } }, (res) => {
        const chunks = []; res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      });
      req.on('error', reject); req.end(bodyStr);
    });
    check('wrong signature -> 401', bad3.status === 401, 'status=' + bad3.status);

    // 7. Missing fields -> reject, no proof
    const mf = await post({ taskId: 2026111506, recipient: ADDR_A });
    const mfo = JSON.parse(mf.body);
    check('missing fields -> reject, no proof',
      mf.status === 200 && mfo.decision === 'reject' && !mfo.proof,
      JSON.stringify(mfo));
  } finally {
    stop();
    try { fs.unlinkSync(STORE); } catch {}
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((e) => { console.error('test crashed:', e); process.exit(1); });
