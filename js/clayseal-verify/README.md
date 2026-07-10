# @clayseal/verify

Server-side verification of [Clay Seal](https://clayseal.com) agent credentials
for JavaScript / TypeScript MCP servers and tool gateways — Node MCP servers,
[OpenClaw](https://openclaw.ai) tool plugins, edge functions.

Agents are issued short-lived, attested credentials by the Clay Seal identity
service (Python). This package is the **verifier**: it decides, offline, whether
an incoming tool call is allowed. Issuance stays server-side; nothing here needs
a private key or a network call.

```bash
npm install @clayseal/verify
```

## What it checks

A Clay Seal request carries three things, added by the client's
`tool_headers(session, server_url=...)`:

| Header | Question | Verified by |
| --- | --- | --- |
| `Authorization: Bearer <jwt>` | Who is the agent? | `verifyToken` |
| `X-ClaySeal-Biscuit` | What may it do? | `authorizeTool` |
| `X-ClaySeal-PoP` | Does it hold the bound key? | `authorizeTool` |

The Biscuit is what gets authorized, so an agent that **attenuated** its rights
mid-task is held to the narrowed token. The Biscuit is **sender-constrained**,
so a token lifted from a log is useless without the workload key that signs the
proof-of-possession.

## Use

```js
import { verifyToken, authorizeTool } from "@clayseal/verify";

// 1. Transport: is this a valid Clay Seal agent? (reject with 401 otherwise)
const claims = await verifyToken(bearer, { jwks: tenantJwks, issuer: "clayseal.io" });
if (!claims) return unauthorized();

// 2. Per tool call: does the capability token authorize *this* tool?
const decision = authorizeTool({
  tool: "search_web",
  biscuit: req.headers["x-clayseal-biscuit"],
  pop: req.headers["x-clayseal-pop"],
  rootPublicKey: tenantBiscuitRootHex,   // or an array during key rotation
  serverUrl: "https://tools.example.com/mcp",
});
if (!decision.allowed) return forbidden(decision.reason);
```

`tool` maps to the capability `("tool", <name>)` by default; pass
`capabilityForTool` to override. `verifyToken` returns the verified claims or
`null`; `authorizeTool` returns `{ allowed, reason }` and fails closed on a
missing token, a missing or stale proof, a wrong endpoint, or an ungranted
capability.

## OpenClaw

Call `authorizeTool` from a tool plugin's permission hook, so policy-approved
calls run and out-of-scope ones are refused (or escalated to a human) — see
`examples/openclaw-plugin.md` in the Clay Seal identity repo.

## Parity with the Python SDK

The Datalog authorizer policy, the Ed25519 proof-of-possession message, and the
JWK thumbprint are byte-compatible with `clayseal-identity`. `test/parity.test.mjs`
verifies a credential minted by the Python backend against this package:

```bash
python test/gen_fixture.py test/fixture.json   # needs clayseal-identity[server] on PATH
npm test
```

Run the two steps back to back — the proof-of-possession in the fixture expires
after ~5 minutes.

MIT licensed. Part of [clayseal/clayseal-identity](https://github.com/clayseal/clayseal-identity).
