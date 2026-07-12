/**
 * @clayseal/verify — server-side verification of Clay Seal agent credentials
 * for JavaScript/TypeScript MCP servers and tool gateways (OpenClaw plugins,
 * Node MCP servers, edge functions).
 *
 * Two checks, mirroring the Python `clayseal.identity.integrations.mcp_server`:
 *
 *   - `verifyToken`   — the JWT-SVID: who the agent is (offline, against the
 *                       tenant JWKS).
 *   - `authorizeTool` — the Biscuit capability token plus a proof-of-possession
 *                       of the bound workload key: what the agent may do, and
 *                       proof it holds the key the token is sender-constrained
 *                       to. A stolen Biscuit without the key authorizes nothing.
 *
 * Issuance stays in the Python service; this package only verifies.
 */
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";

import { AuthorizerBuilder, Biscuit, PublicKey } from "@biscuit-auth/biscuit-wasm";
import { createLocalJWKSet, jwtVerify } from "jose";

// SPIFFE JWT-SVID typ is "JWT" (or "JOSE"); "wit+jwt" is the WIMSE opt-in and
// "clayseal-svid+jwt" is the legacy Clay Seal typ, still accepted for pre-0.6 tokens.
const DEFAULT_ALLOWED_TOKEN_TYPES = ["JWT", "JOSE", "wit+jwt", "clayseal-svid+jwt"];
const POP_MAX_AGE_SECONDS = 300;

// MUST stay byte-identical to the Datalog policy in
// clayseal/identity/_capabilities.py::_AUTHORIZER_POLICY.
const AUTHORIZER_POLICY =
  "operation({resource}, {action});" +
  'allow if capability($r, $a), operation($r, $a);' +
  'allow if capability($r, "*"), operation($r, $_);' +
  "deny if true;";

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest();
}

/** base64url(sha256(utf8(token))) — matches workload_keys.token_hash. */
function tokenHash(token) {
  return b64url(sha256(Buffer.from(token, "utf8")));
}

/** RFC 7638-style JWK thumbprint of an Ed25519 SPKI PEM — matches
 * workload_keys.jwk_thumbprint_for_pem (keyhash / cnf.jkt). */
function keyhashForPem(pubkeyPem) {
  const jwk = createPublicKey(pubkeyPem).export({ format: "jwk" });
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519") {
    throw new Error("workload public key must be Ed25519");
  }
  // Canonical JSON: sorted keys, compact separators (json.dumps sort_keys=True).
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":${JSON.stringify(jwk.x)}}`;
  return b64url(sha256(Buffer.from(canonical, "utf8")));
}

/** Canonical PoP message bytes — matches workload_keys.request_pop_message
 * with operation=None (connection-level proof). Keys are emitted in sorted
 * order to match Python's json.dumps(sort_keys=True, separators=(",",":")). */
function popMessage({ ath, cnf, htm, htu, iat, jti, nonce }) {
  return Buffer.from(
    JSON.stringify({
      ath,
      cnf,
      htm: String(htm).toUpperCase(),
      htu,
      iat: Number(iat),
      jti,
      nonce,
      typ: "clayseal-pop+jwt",
    }),
    "utf8",
  );
}

function rfc3339Now() {
  return new Date().toISOString().replace(/\.\d+Z$/, "Z");
}

/**
 * Verify a Clay Seal JWT-SVID offline.
 *
 * @param {string} token
 * @param {object} opts
 * @param {object} opts.jwks    Tenant JWKS (GET /t/{tenant}/jwks.json).
 * @param {string} opts.issuer  Expected issuer/trust domain.
 * @param {string|string[]} [opts.audience]
 * @param {string[]} [opts.allowedTokenTypes]
 * @param {boolean} [opts.requireCnf=true]
 * @returns {Promise<object|null>} Verified claims, or null if invalid.
 */
export async function verifyToken(token, opts) {
  const {
    jwks,
    issuer,
    audience,
    allowedTokenTypes = DEFAULT_ALLOWED_TOKEN_TYPES,
    requireCnf = true,
  } = opts;
  const keySet = createLocalJWKSet(jwks);
  try {
    const { payload, protectedHeader } = await jwtVerify(token, keySet, {
      issuer,
      audience,
      algorithms: ["RS256"],
      typ: undefined, // checked explicitly below against our allowlist
      requiredClaims: ["exp", "iat", "sub", "jti"],
    });
    if (!allowedTokenTypes.includes(protectedHeader.typ)) return null;
    if (requireCnf && !(payload.cnf && payload.cnf.jkt)) return null;
    return payload;
  } catch {
    return null;
  }
}

/** The capability a tool requires: ("tool", <name>). Matches
 * clayseal.identity.integrations.mcp_server.default_tool_capability. */
export function defaultToolCapability(toolName) {
  return ["tool", toolName];
}

function readBoundKeys(biscuit) {
  const source = biscuit.getBlockSource(0);
  const keys = [];
  const re = /bound_key\("([^"]+)"\)/g;
  let m;
  while ((m = re.exec(source)) !== null) keys.push(m[1]);
  return keys;
}

function verifyPop(pop, { biscuitB64, serverUrl, method = "POST" }) {
  if (!pop) return { ok: false, reason: "no proof-of-possession presented" };
  let publicKey;
  try {
    publicKey = createPublicKey(pop.pubkey_pem);
  } catch {
    return { ok: false, reason: "proof-of-possession public key is unreadable" };
  }
  // Freshness.
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(pop.iat) || Math.abs(now - Number(pop.iat)) > POP_MAX_AGE_SECONDS) {
    return { ok: false, reason: "proof-of-possession is expired or not yet valid" };
  }
  // Binding: method, URL, and the biscuit's hash.
  if (String(pop.htm).toUpperCase() !== String(method).toUpperCase()) {
    return { ok: false, reason: "proof-of-possession method mismatch" };
  }
  if (serverUrl && pop.htu !== serverUrl) {
    return { ok: false, reason: "proof-of-possession endpoint mismatch" };
  }
  if (pop.ath !== tokenHash(biscuitB64)) {
    return { ok: false, reason: "proof-of-possession is not bound to this token" };
  }
  // Signature over the canonical message.
  let keyhash;
  try {
    keyhash = keyhashForPem(pop.pubkey_pem);
  } catch {
    return { ok: false, reason: "proof-of-possession key is not Ed25519" };
  }
  const message = popMessage({
    ath: pop.ath,
    cnf: keyhash,
    htm: pop.htm,
    htu: pop.htu,
    iat: pop.iat,
    jti: pop.jti,
    nonce: pop.challenge,
  });
  let signatureOk = false;
  try {
    signatureOk = edVerify(null, message, publicKey, Buffer.from(pop.signature_b64, "base64"));
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) {
    return { ok: false, reason: "proof-of-possession signature is invalid" };
  }
  return { ok: true, keyhash };
}

// Datalog evaluation budget (nanoseconds). Mirrors the Python SDK's
// _with_authorizer_limits (50ms); a little more generous here because the
// biscuit-wasm engine's first evaluation after load is slow (cold WASM/JIT)
// and would otherwise trip the default limit.
const AUTHORIZE_MAX_TIME_NANOS = 200_000_000;
// That cold first evaluation surfaces as a `RunLimit` timeout — an *incomplete*
// evaluation, not a decision — so retry it. A real policy deny is a distinct
// `FailedLogic` error and is never retried.
const AUTHORIZE_MAX_ATTEMPTS = 4;

function isRunLimitError(err) {
  return err != null && typeof err === "object" && "RunLimit" in err;
}

function authorizeAgainstRoot(biscuitB64, rootHex, operation) {
  let lastErr;
  for (let attempt = 0; attempt < AUTHORIZE_MAX_ATTEMPTS; attempt++) {
    // Re-parse per attempt: buildAuthenticated consumes the token.
    const biscuit = Biscuit.fromBase64(biscuitB64, PublicKey.fromString(rootHex));
    const ab = new AuthorizerBuilder();
    ab.addCodeWithParameters(AUTHORIZER_POLICY, { resource: operation[0], action: operation[1] }, {});
    ab.addCode("valid_pop(true);");
    ab.addCode(`time(${rfc3339Now()});`);
    try {
      ab.buildAuthenticated(biscuit).authorizeWithLimits({
        maxTimeNanos: AUTHORIZE_MAX_TIME_NANOS,
      }); // throws if denied
      return;
    } catch (err) {
      lastErr = err;
      if (!isRunLimitError(err)) throw err; // a real deny — do not retry
    }
  }
  throw lastErr;
}

/**
 * Authorize an MCP tool call against a Clay Seal capability token.
 *
 * Fail-closed: no Biscuit, no valid proof-of-possession, or a capability the
 * token does not grant all return `{ allowed: false }`.
 *
 * @param {object} opts
 * @param {string} opts.tool                 Tool name (mapped via capabilityForTool).
 * @param {string} opts.biscuit              Base64 capability token (X-ClaySeal-Biscuit).
 * @param {object|string} opts.pop           Parsed or raw-JSON X-ClaySeal-PoP header.
 * @param {string|string[]} opts.rootPublicKey  Tenant Biscuit root public key(s), hex.
 * @param {string} [opts.serverUrl]          This server's MCP endpoint (pins the proof).
 * @param {(name:string)=>[string,string]} [opts.capabilityForTool]
 * @param {{storeIfNew:(jti:string,expiresAt:number)=>boolean}|false} [opts.replayCache]
 *        Defaults to an in-process cache that makes proofs single-use within
 *        their window. Pass a shared cache for multi-worker servers, or false
 *        only when another layer already enforces single-use proofs.
 * @returns {{allowed: boolean, reason: string}}
 */
export function authorizeTool(opts) {
  const {
    tool,
    biscuit,
    pop,
    rootPublicKey,
    serverUrl,
    method = "POST",
    capabilityForTool = defaultToolCapability,
    replayCache,
  } = opts;
  if (!biscuit) {
    return { allowed: false, reason: "no capability token presented" };
  }
  const popObj = typeof pop === "string" ? safeParse(pop) : pop;
  const popResult = verifyPop(popObj, { biscuitB64: biscuit, serverUrl, method });
  if (!popResult.ok) {
    return { allowed: false, reason: popResult.reason };
  }
  const operation = capabilityForTool(tool);
  const roots = Array.isArray(rootPublicKey) ? rootPublicKey : [rootPublicKey];
  let lastReason = "capability token could not be verified";
  for (const root of roots) {
    try {
      authorizeAgainstRoot(biscuit, root, operation);
    } catch {
      lastReason = `capability ${operation[0]}:${operation[1]} not granted`;
      continue;
    }
    // Signature valid and call authorized. If single-use is on, reject a proof
    // already seen (a replay) — only now, so unsigned jti values can't fill it.
    const cache = replayCache === false ? null : replayCache || defaultReplayCache();
    if (cache && !cache.storeIfNew(popObj.jti, Number(popObj.iat) + POP_MAX_AGE_SECONDS)) {
      return { allowed: false, reason: "proof-of-possession already used (replay detected)" };
    }
    return { allowed: true, reason: "authorized" };
  }
  return { allowed: false, reason: lastReason };
}

function safeParse(s) {
  try {
    return JSON.parse(s);
  } catch {
    return null;
  }
}

/**
 * Single-process replay cache: each proof-of-possession `jti` is accepted once
 * within its freshness window (expired entries are pruned lazily). `authorizeTool`
 * uses one by default, closing same-endpoint replay for single-process servers.
 * Clients must send a fresh proof per request (`tool_headers` mints a new one
 * each call). For multi-process deployments, pass a shared store that implements
 * `storeIfNew`.
 */
export class InMemoryReplayCache {
  constructor() {
    this._seen = new Map();
  }

  storeIfNew(jti, expiresAt) {
    const now = Math.floor(Date.now() / 1000);
    for (const [key, exp] of this._seen) {
      if (exp <= now) this._seen.delete(key);
    }
    if (this._seen.has(jti)) return false;
    this._seen.set(jti, expiresAt);
    return true;
  }
}

let _defaultReplayCache;

function defaultReplayCache() {
  if (!_defaultReplayCache) {
    _defaultReplayCache = new InMemoryReplayCache();
  }
  return _defaultReplayCache;
}

export { keyhashForPem, tokenHash };
