#!/usr/bin/env node
/**
 * Minimal Express server that verifies a Clay Seal JWT-SVID.
 *
 * Run:
 *   cd js/clayseal-verify/examples
 *   npm install
 *   export CLAY_JWKS='{"keys":[...]}'
 *   export CLAY_ISSUER=clayseal.io
 *   export CLAY_AUDIENCE=my-tenant-id
 *   npm start
 *
 * Then call the protected endpoint with a valid token:
 *   curl http://localhost:4000/verify \
 *     -H "Authorization: Bearer <jwt>"
 *
 * An invalid or missing token gets a 401:
 *   curl http://localhost:4000/verify
 */

import express from "express";
import { verifyToken } from "@clayseal/verify";

// Config comes from the environment so the example is safe to fork.
// In a real deployment these come from your Clay Seal identity service:
//
//   CLAY_JWKS     — GET /t/{tenant}/jwks.json (the tenant's public RSA keys)
//   CLAY_ISSUER   — Your trust domain, e.g. "clayseal.io"
//   CLAY_AUDIENCE — Your tenant / customer identifier
function requireEnv(name) {
  const val = process.env[name];
  if (!val) {
    console.error(`Missing required env var: ${name}`);
    console.error(`  Set it and restart:  export ${name}=<value>`);
    process.exit(1);
  }
  return val;
}

const JWKS = JSON.parse(requireEnv("CLAY_JWKS"));
const ISSUER = requireEnv("CLAY_ISSUER");
const AUDIENCE = requireEnv("CLAY_AUDIENCE");

const app = express();

app.get("/verify", async (req, res) => {
  const header = req.headers.authorization;

  if (!header?.toLowerCase().startsWith("bearer ")) {
    return res.status(401).json({ error: "missing or invalid Authorization header" });
  }

  const claims = await verifyToken(header.slice(7), {
    jwks: JWKS,
    issuer: ISSUER,
    audience: AUDIENCE,
  });

  if (!claims) {
    return res.status(401).json({ error: "token verification failed" });
  }

  return res.json({
    sub: claims.sub,
    agent_id: claims.agent_id,
    agent_type: claims.agent_type,
  });
});

app.listen(4000, () => {
  console.log(`Clay Seal verify example listening on http://localhost:4000`);
  console.log(`  Protected: GET /verify  (requires Authorization: Bearer <jwt>)`);
});
