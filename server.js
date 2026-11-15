// Proof Gatekeeper agent endpoint — zkVerify Agent Games Season 01.
// Node.js, no framework (stdlib http only) + snarkjs 0.7.6.
// Handle: @ellvmx. Tournament closes 2026-11-21.
//
// Flow (per the Builder Field Guide + community documentation):
//  1. Verify HMAC-SHA256 on the RAW request body before parsing (401 on failure).
//  2. Decide DETERMINISTICALLY with a fixed checklist (never an LLM judgement).
//  3. Prove the decision with a Groth16 proof (gatekeeper circuit) and return
//     proof + public signals, signed with x-agent-games-signature.
//  4. Fail closed: any error / timeout / uncertainty => REJECT, never approve.
//  5. Remember: persist taskIds + proof references; a retried task returns the
//     byte-identical cached response; a re-used proof reference returns the
//     decision ALONE (no proof).
//
// Env:
//  AGENTGAMES_HMAC_SECRET  (required) per-agent HMAC secret from the dashboard
//                          (Rotate Secret). Never a local placeholder in prod.
//  PORT                    (default 3000)
//  CIRCUITS_DIR            (default ./circuits)
//  STORE_PATH              (default ./store.json)
//  REGISTERED_VK_HASH      (default 0x6b79c6...7b0, the tournament's gatekeeper key)
'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const snarkjs = require('snarkjs');

// ---------------------------------------------------------------- config
const PORT = Number(process.env.PORT || 3000);
const HMAC_SECRET = process.env.AGENTGAMES_HMAC_SECRET;
if (!HMAC_SECRET) {
  console.error('FATAL: AGENTGAMES_HMAC_SECRET is not set. ' +
    'Set it to the per-agent secret from the Agent Games dashboard (Rotate Secret).');
  process.exit(1);
}
const CIRCUITS_DIR = process.env.CIRCUITS_DIR || path.join(__dirname, 'circuits');
const STORE_PATH = process.env.STORE_PATH || path.join(__dirname, 'store.json');
const WASM_PATH = path.join(CIRCUITS_DIR, 'gatekeeper.wasm');
const ZKEY_PATH = path.join(CIRCUITS_DIR, 'gatekeeper_final.zkey');
const VKEY_PATH = path.join(CIRCUITS_DIR, 'verification_key.json');
const REGISTERED_VK_HASH =
  (process.env.REGISTERED_VK_HASH ||
    '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0').toLowerCase();
const RESPONSE_DEADLINE_MS = 50_000; // platform hard deadline is 60 s; stay inside it.

// ---------------------------------------------------------------- store
// { tasks: { [taskId]: { body, signature, proofReference } },
//   proofRefs: { [proofReference]: taskId } }
let store = { tasks: {}, proofRefs: {} };
function loadStore() {
  try {
    if (fs.existsSync(STORE_PATH)) store = JSON.parse(fs.readFileSync(STORE_PATH, 'utf8'));
  } catch (e) { console.error('store load failed, starting empty:', e.message); }
}
function saveStore() {
  const tmp = STORE_PATH + '.tmp-' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(store));
  fs.renameSync(tmp, STORE_PATH);
}
loadStore();

// Serialize task handling so store read-modify-write never races.
let queue = Promise.resolve();
function serialize(fn) { queue = queue.then(fn, fn); return queue; }

// ---------------------------------------------------------------- helpers
function toBigInt(v) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'number') return BigInt(Math.trunc(v));
  if (typeof v === 'string') {
    const s = v.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^-?\d+$/.test(s)) return BigInt(s);
    // Non-numeric string (e.g. a UUID taskId): hash it to an integer.
    return BigInt('0x' + crypto.createHash('sha256').update(s).digest('hex').slice(0, 16));
  }
  throw new Error('not an integer: ' + JSON.stringify(v));
}

// Deterministic per-task salt (private circuit input). Derived from the HMAC
// secret + taskId, so a retried task always produces the identical proof.
function deriveSalt(taskId) {
  const h = crypto.createHmac('sha256', HMAC_SECRET).update('salt:' + String(taskId)).digest('hex');
  return BigInt('0x' + h.slice(0, 16)); // 64-bit, safely inside the field
}

function hmacHex(secret, data) {
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

function safeEqualHex(a, b) {
  try {
    const ba = Buffer.from(String(a), 'hex');
    const bb = Buffer.from(String(b), 'hex');
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
  } catch { return false; }
}

// Pick the first present field among aliases (case-insensitive key match).
function pick(obj, names) {
  if (!obj || typeof obj !== 'object') return undefined;
  const lower = {};
  for (const k of Object.keys(obj)) lower[k.toLowerCase()] = obj[k];
  for (const n of names) {
    if (lower[n.toLowerCase()] !== undefined) return lower[n.toLowerCase()];
  }
  return undefined;
}

// The task may arrive top-level or nested under "task".
function taskFields(body) {
  const t = (body && typeof body === 'object' && body.task && typeof body.task === 'object')
    ? body.task : body;
  return {
    type: pick(body, ['type']),
    preflight: pick(body, ['preflight']),
    taskId: pick(t, ['taskId', 'task_id', 'id']),
    proofReference: pick(t, ['proofReference', 'proof_reference', 'proofRef', 'proof_ref']),
    recipient: pick(t, ['recipient', 'to']),
    conditionRecipient: pick(t, ['conditionRecipient', 'condition_recipient', 'expectedRecipient', 'expected_recipient']),
    amount: pick(t, ['amount']),
    maxTransfer: pick(t, ['maxTransfer', 'max_transfer', 'cap']),
    minimum: pick(t, ['minimum', 'minBalance', 'min_balance']),
    publicBalance: pick(t, ['publicBalance', 'public_balance', 'balance']),
    expiryBlock: pick(t, ['expiryBlock', 'expiry_block', 'expiry']),
    currentBlock: pick(t, ['currentBlock', 'current_block', 'blockNumber', 'block_number']),
    vkHash: pick(t, ['vkHash', 'proofVkHash', 'proof_vk_hash', 'verificationKeyHash', 'verification_key_hash', 'vk_hash']),
    registeredVkHash: pick(t, ['registeredVkHash', 'conditionVkHash', 'condition_vk_hash', 'registered_vk_hash']),
    timestamp: pick(t, ['timestamp', 'ts']),
  };
}

function missingFields(f) {
  const need = ['taskId', 'recipient', 'conditionRecipient', 'amount', 'maxTransfer',
    'minimum', 'publicBalance', 'expiryBlock', 'currentBlock', 'vkHash'];
  return need.filter((k) => f[k] === undefined || f[k] === null || f[k] === '');
}

// ---------------------------------------------------------------- decision
// Returns { decision: 1|0, checks: {name: bool}, reason }.
function decide(f, proofRefUsed) {
  const checks = {};
  const expectedVk = (f.registeredVkHash ? String(f.registeredVkHash) : REGISTERED_VK_HASH).toLowerCase();
  const taskVk = String(f.vkHash).toLowerCase();
  checks.vkMatches = taskVk === expectedVk;
  checks.balanceMeetsMinimum = toBigInt(f.publicBalance) >= toBigInt(f.minimum);
  checks.recipientMatches = String(f.recipient).toLowerCase() === String(f.conditionRecipient).toLowerCase();
  checks.amountWithinCap = toBigInt(f.amount) <= toBigInt(f.maxTransfer);
  checks.notExpired = toBigInt(f.currentBlock) < toBigInt(f.expiryBlock);
  checks.proofRefUnused = !proofRefUsed;
  const failed = Object.keys(checks).filter((k) => !checks[k]);
  return { decision: failed.length === 0 ? 1 : 0, checks, failed };
}

// ---------------------------------------------------------------- proof
async function proveDecision(f, decision) {
  const input = {
    registeredVkHash: toBigInt(f.registeredVkHash ? String(f.registeredVkHash) : REGISTERED_VK_HASH).toString(),
    proofVkHash: toBigInt(String(f.vkHash)).toString(),
    minimum: toBigInt(f.minimum).toString(),
    publicBalance: toBigInt(f.publicBalance).toString(),
    expiryBlock: toBigInt(f.expiryBlock).toString(),
    currentBlock: toBigInt(f.currentBlock).toString(),
    recipient: toBigInt(String(f.recipient)).toString(),
    conditionRecipient: toBigInt(String(f.conditionRecipient)).toString(),
    amount: toBigInt(f.amount).toString(),
    maxTransfer: toBigInt(f.maxTransfer).toString(),
    decision: String(decision),
    taskId: toBigInt(f.taskId).toString(),
    salt: deriveSalt(f.taskId).toString(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
  return { proof, publicSignals };
}

// ---------------------------------------------------------------- response
function signBody(bodyStr) {
  return hmacHex(HMAC_SECRET, Buffer.from(bodyStr, 'utf8'));
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json',
    'x-agent-games-signature': signBody(body),
  });
  res.end(body);
}

// Returns { status, bodyStr, signature } and records it in the store.
function buildAndRecord(taskId, proofReference, obj) {
  const bodyStr = JSON.stringify(obj);
  const signature = signBody(bodyStr);
  store.tasks[String(taskId)] = { body: bodyStr, signature, proofReference: String(proofReference) };
  if (proofReference) store.proofRefs[String(proofReference)] = String(taskId);
  saveStore();
  return { status: 200, bodyStr, signature };
}

// ---------------------------------------------------------------- handler
async function handleTask(rawBody, req, res) {
  // 1. HMAC on the RAW body, before parsing.
  const sig = req.headers['x-agent-games-signature'] ||
    req.headers['x-hmac-signature'] || req.headers['x-signature'];
  if (!sig || !safeEqualHex(sig, hmacHex(HMAC_SECRET, rawBody))) {
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'unauthorized' }));
    return;
  }

  let body;
  try { body = JSON.parse(rawBody.toString('utf8')); }
  catch { sendJson(res, 400, { error: 'invalid_json' }); return; }

  // Preflight: platform liveness check (signed). No decision, no proof.
  const f0 = taskFields(body);
  if (f0.type === 'preflight' || f0.preflight === true) {
    sendJson(res, 200, { status: 'ok', type: 'preflight', handle: '@ellvmx' });
    return;
  }

  const f = f0;
  const taskId = f.taskId;
  const proofReference = f.proofReference !== undefined ? String(f.proofReference) : (taskId !== undefined ? String(taskId) : undefined);

  // Replay: same taskId => byte-identical cached response.
  if (taskId !== undefined && store.tasks[String(taskId)]) {
    const c = store.tasks[String(taskId)];
    res.writeHead(200, { 'content-type': 'application/json', 'x-agent-games-signature': c.signature });
    res.end(c.body);
    return;
  }

  // Fail closed on missing fields: REJECT, no proof.
  const missing = missingFields(f);
  if (missing.length > 0) {
    const r = buildAndRecord(taskId ?? ('invalid-' + Date.now()), proofReference, {
      decision: 'reject', taskId: taskId ?? null, proofReference: proofReference ?? null,
      error: 'missing_fields: ' + missing.join(','),
    });
    res.writeHead(r.status, { 'content-type': 'application/json', 'x-agent-games-signature': r.signature });
    res.end(r.bodyStr);
    return;
  }

  // Timestamp sanity, only if the envelope carries one (10-minute window).
  if (f.timestamp !== undefined) {
    const ts = Number(f.timestamp);
    const now = Date.now() / 1000;
    const tsSec = ts > 1e12 ? ts / 1000 : ts; // accept ms or s
    if (!Number.isFinite(tsSec) || Math.abs(now - tsSec) > 600) {
      const r = buildAndRecord(taskId, proofReference, {
        decision: 'reject', taskId, proofReference, error: 'stale_timestamp',
      });
      res.writeHead(r.status, { 'content-type': 'application/json', 'x-agent-games-signature': r.signature });
      res.end(r.bodyStr);
      return;
    }
  }

  // 2. Deterministic decision.
  const proofRefUsed = proofReference !== undefined && store.proofRefs[String(proofReference)] !== undefined;
  let verdict;
  try { verdict = decide(f, proofRefUsed); }
  catch (e) {
    const r = buildAndRecord(taskId, proofReference, {
      decision: 'reject', taskId, proofReference, error: 'decision_error: ' + e.message,
    });
    res.writeHead(r.status, { 'content-type': 'application/json', 'x-agent-games-signature': r.signature });
    res.end(r.bodyStr);
    return;
  }

  // Re-used proof reference: return the decision ALONE (no proof), per the
  // tournament's scoring (reused proofs earn no proof bonus).
  if (proofRefUsed) {
    const r = buildAndRecord(taskId, proofReference, {
      decision: verdict.decision === 1 ? 'approve' : 'reject',
      taskId, proofReference, reused: true,
    });
    res.writeHead(r.status, { 'content-type': 'application/json', 'x-agent-games-signature': r.signature });
    res.end(r.bodyStr);
    return;
  }

  // 3. Prove the decision (fail closed: any proving error => REJECT, no proof).
  let proofOut = null;
  try {
    proofOut = await Promise.race([
      proveDecision(f, verdict.decision),
      new Promise((_, rej) => setTimeout(() => rej(new Error('proof_timeout')), RESPONSE_DEADLINE_MS)),
    ]);
  } catch (e) {
    console.error('proof failed for task', taskId, ':', e.message);
    const r = buildAndRecord(taskId, proofReference, {
      decision: 'reject', taskId, proofReference, error: 'proof_failed: ' + e.message,
    });
    res.writeHead(r.status, { 'content-type': 'application/json', 'x-agent-games-signature': r.signature });
    res.end(r.bodyStr);
    return;
  }

  const r = buildAndRecord(taskId, proofReference, {
    decision: verdict.decision === 1 ? 'approve' : 'reject',
    taskId, proofReference,
    proof: proofOut.proof,
    publicSignals: proofOut.publicSignals,
  });
  res.writeHead(r.status, { 'content-type': 'application/json', 'x-agent-games-signature': r.signature });
  res.end(r.bodyStr);
}

const server = http.createServer((req, res) => {
  // Health / preflight GET (unsigned).
  if (req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'agent-games-gatekeeper', handle: '@ellvmx' }));
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'method_not_allowed' }));
    return;
  }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const rawBody = Buffer.concat(chunks);
    // Serialize task handling (store read-modify-write must not race).
    serialize(() => handleTask(rawBody, req, res)).catch((e) => {
      console.error('handler error:', e);
      if (!res.writableEnded) {
        res.writeHead(500, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ decision: 'reject', error: 'internal_error' }));
      }
    });
  });
});

server.listen(PORT, () => {
  console.log(`gatekeeper listening on :${PORT} (handle @ellvmx)`);
  console.log(`circuits: ${CIRCUITS_DIR} | store: ${STORE_PATH}`);
});
