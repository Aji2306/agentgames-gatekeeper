# Proof Gatekeeper — Agent Games Season 01 (handle @ellvmx)

A public HTTPS endpoint that receives HMAC-signed transfer tasks, decides
APPROVE / REJECT deterministically, and proves each decision with a Groth16
proof (gatekeeper circuit, BN254 / Circom 2.x). Node.js, no framework
(stdlib `http` only) + `snarkjs` 0.7.6. Tournament closes 2026-11-21.

## Run

```sh
npm install
AGENTGAMES_HMAC_SECRET='<secret from the Agent Games dashboard — Rotate Secret>' \
  PORT=3000 node server.js
```

Required env: `AGENTGAMES_HMAC_SECRET` (the server refuses to start without
it). Optional: `PORT` (default 3000), `CIRCUITS_DIR` (default `./circuits`),
`STORE_PATH` (default `./store.json`), `REGISTERED_VK_HASH` (default the
tournament gatekeeper key `0x6b79c6…7b0`, confirmed via `/api/circuit-info`).

Circuits are vendored in `circuits/`: `gatekeeper.wasm`,
`gatekeeper_final.zkey` (SHA-256 verified against the published values) and
`verification_key.json` (exported with snarkjs, groth16 / bn128 / nPublic 13).

## Test

```sh
npm test        # node test.js — spawns the server on :3456 with a TEST secret
```

Asserts: valid task → approve + a proof that `snarkjs groth16 verify`
accepts; trap task (recipient mismatch) → reject + a proof that verifies;
missing/wrong HMAC → 401 before any parsing; replayed task → byte-identical
body and signature; re-used proof reference (new taskId) → decision alone,
no proof; preflight POST → 200; missing fields → reject, no proof; GET / → 200.

Local proof generation takes ~1.5 s; the whole round trip is ~2 s, far inside
the platform's 60-second hard deadline.

## Behaviour (implemented)

1. **HMAC first.** The raw request body is HMAC-SHA256-verified before any
   parsing. Bad or missing signature → `401 {error:"unauthorized"}`.
2. **Deterministic decision.** A fixed checklist over the task fields:
   proof vkHash == registered (condition) key; publicBalance >= minimum;
   recipient == conditionRecipient; amount <= maxTransfer;
   currentBlock < expiryBlock; proof reference not used before. One
   mismatch → REJECT. Never an LLM judgement call.
3. **Proof.** A Groth16 proof of the decision is generated with the
   tournament circuit and returned with its 13 public signals. The circuit
   itself enforces decision == (all checks pass): a wrong decision cannot
   even produce a witness (verified locally — both negative cases fail).
4. **Fail closed.** Any error, timeout (>50 s internal cap), or malformed
   task → REJECT with no proof. Never approve by default.
5. **Remember.** `store.json` persists taskIds and proof references. A
   retried taskId returns the byte-identical cached response; a re-used
   proof reference (different taskId) returns the decision alone, no proof
   (the tournament's scoring gives no proof bonus for reused proofs).
6. **Signed responses.** Every JSON response carries
   `x-agent-games-signature: HMAC-SHA256(secret, raw response body)`, hex.
7. **Salt.** The circuit's private `salt` input is derived deterministically
   as `HMAC(secret, "salt:"+taskId)` (first 64 bits), so a retried task
   always yields the identical proof.
8. **Preflight / health.** `GET /` → `200 {status:"ok",...}` (unsigned).
   A signed POST with `type:"preflight"` (or `preflight:true`) →
   `200 {status:"ok", type:"preflight"}` (signed, no decision, no proof).

## Envelope / response format (implemented)

Incoming task envelope — JSON POST. Fields are read flexibly (top-level or
nested under `"task"`; common alias spellings accepted — see `taskFields()`
in `server.js`):

| Field | Meaning |
|---|---|
| `taskId` | task identifier (number or string) |
| `proofReference` | proof reference for replay detection (defaults to taskId) |
| `recipient` / `conditionRecipient` | transfer recipient / expected recipient (0x addresses) |
| `amount` / `maxTransfer` | transfer amount / cap |
| `minimum` / `publicBalance` | balance threshold / observed balance |
| `expiryBlock` / `currentBlock` | condition expiry / current block |
| `vkHash` | the proof's verification-key hash (hex) |
| `registeredVkHash` | the condition's key (defaults to the tournament key) |
| `timestamp` | envelope timestamp (seconds or ms; checked ±10 min if present) |

Response (200):

```json
{ "decision": "approve", "taskId": 2026111501, "proofReference": "proof-ref-...",
  "proof": { "pi_a": [...], "pi_b": [[...]], "pi_c": [...], "protocol": "groth16", "curve": "bn128" },
  "publicSignals": ["13298...", "48361...", "48361...", "1000", "1460", "8430000", "8420000", "97433...", "97433...", "500", "1000", "1", "2026111501"] }
```

Public-signal order: `[Poseidon([salt, taskId]) commitment, registeredVkHash,
proofVkHash, minimum, publicBalance, expiryBlock, currentBlock, recipient,
conditionRecipient, amount, maxTransfer, decision, taskId]` (vkHash and
addresses as integers; vkHash is reduced mod the field prime by the circuit).
A rejected decision returns `"decision": "reject"` with a proof of the
rejection (decision 0); a reused proof reference returns the decision alone
with `"reused": true` and no `proof`/`publicSignals`.

## Assumptions — NOT confirmed against the official spec

The official Builder Field Guide (`agentgames.zkverify.io/build`) describes
the interface in prose but does not publish the exact JSON schema, and the
dashboard (which holds the per-agent secret and the exact envelope) needs a
login. The following were chosen from the community documentation
(Medium build reports) and must be corrected against the real spec from the
user's dashboard before going live:

- **Incoming HMAC header name.** Assumed `x-agent-games-signature`
  (the guide names this header for *responses*; the incoming header is
  likely the same). The server also accepts `x-hmac-signature` and
  `x-signature` as fallbacks.
- **HMAC scheme.** Assumed HMAC-SHA256 over the raw body, hex-encoded.
  (Not confirmed: it could be `sha256=<hex>` prefixed, base64, or over a
  canonical string instead of the raw body.)
- **Task field names.** Assumed the names in the table above (camelCase,
  matching the circuit signal names). The real envelope may nest them
  differently or use other names — the parser accepts aliases and a
  `"task"` wrapper, but an exact schema check against the dashboard is
  still needed.
- **Decision strings.** Assumed `"approve"` / `"reject"` (lowercase).
  The guide says "one deterministic decision"; the platform may expect
  `"APPROVE"` / `"REJECT"`, `1` / `0`, or a boolean.
- **Response field names.** Assumed `proof` + `publicSignals` (snarkjs
  shape). The platform may expect different keys (e.g. `public_signals`,
  a flattened proof, or a `proofReference` echo).
- **Preflight shape.** Assumed a signed POST with `type:"preflight"`.
  The real preflight may be a GET, a HEAD, or a differently-shaped POST.
- **Timestamp.** Assumed an optional `timestamp` checked within ±10 min.
  The real envelope may require a specific timestamp field or a different
  window.
- **Proof submission to zkVerify.** This endpoint proves the decision
  *locally* and returns the proof to the platform, which re-verifies it.
  The guide also describes submitting proofs to zkVerify mainnet via
  Kurier / zkVerifyJS — that is a separate step the platform may or may
  not require from the agent; it is NOT implemented here.

## Deploy (later — not done)

The tournament needs a public HTTPS URL on the standard port. This VM's
egress proxy blocks trycloudflare (403) and resets raw SSH, so the working
paths need a credential from the user: ngrok with an authtoken, a named
Cloudflare tunnel, or a free hosting account. Set the REAL secret from the
dashboard (Rotate Secret) in the deployment environment — never the test
secret, never commit a secret.
