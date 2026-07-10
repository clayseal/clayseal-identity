/**
 * Cross-language parity: verify that @clayseal/verify (JS) accepts and rejects
 * exactly what the Python SDK produced. The fixture is minted by the Python
 * backend (see js/README.md), so a pass proves the JWT, Biscuit authorization,
 * and Ed25519 proof-of-possession wire formats agree across languages.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { authorizeTool, verifyToken } from "../src/index.js";

const fx = JSON.parse(
  readFileSync(new URL("./fixture.json", import.meta.url), "utf8"),
);
const POP = fx.pop_header_name;
const call = (tool, headers, extra = {}) =>
  authorizeTool({
    tool,
    biscuit: headers[fx.biscuit_header_name],
    pop: headers[POP],
    rootPublicKey: fx.biscuit_root_public_hex,
    serverUrl: fx.server_url,
    ...extra,
  });

test("verifyToken accepts a Python-minted JWT-SVID", async () => {
  const claims = await verifyToken(fx.token, {
    jwks: fx.jwks,
    issuer: fx.issuer,
  });
  assert.ok(claims);
  assert.equal(claims.agent_id, fx.agent_id);
  assert.ok(claims.cnf.jkt);
});

test("verifyToken rejects a tampered token", async () => {
  const bad = fx.token.slice(0, -4) + "AAAA";
  assert.equal(await verifyToken(bad, { jwks: fx.jwks, issuer: fx.issuer }), null);
});

test("verifyToken rejects the wrong issuer", async () => {
  const claims = await verifyToken(fx.token, {
    jwks: fx.jwks,
    issuer: "attacker.example",
  });
  assert.equal(claims, null);
});

test("granted tools are allowed, others denied", () => {
  assert.equal(call("search_web", fx.headers).allowed, true);
  assert.equal(call("read_docs", fx.headers).allowed, true);
  assert.equal(call("delete_records", fx.headers).allowed, false);
});

test("attenuated token is held to its narrowed rights", () => {
  assert.equal(call("read_docs", fx.narrowed_headers).allowed, true);
  assert.equal(call("search_web", fx.narrowed_headers).allowed, false);
});

test("a Biscuit with no proof-of-possession is denied (sender-constraint)", () => {
  const headers = { ...fx.headers };
  delete headers[POP];
  const decision = call("search_web", headers);
  assert.equal(decision.allowed, false);
  assert.match(decision.reason, /proof-of-possession/);
});

test("a proof pinned to a different endpoint is denied", () => {
  const decision = authorizeTool({
    tool: "search_web",
    biscuit: fx.headers[fx.biscuit_header_name],
    pop: fx.headers[POP],
    rootPublicKey: fx.biscuit_root_public_hex,
    serverUrl: "https://evil.example.com/mcp",
  });
  assert.equal(decision.allowed, false);
});

test("the wrong root key denies; rotation set with the right key allows", () => {
  const wrong = "aa".repeat(32);
  assert.equal(
    call("search_web", fx.headers, { rootPublicKey: wrong }).allowed,
    false,
  );
  assert.equal(
    call("search_web", fx.headers, {
      rootPublicKey: [wrong, fx.biscuit_root_public_hex],
    }).allowed,
    true,
  );
});
