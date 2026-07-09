# Clay Seal Identity CLI

The CLI makes the identity layer useful from a terminal:

```bash
clayseal-identity explain token.jwt
clayseal-identity lint token.jwt
clayseal-identity status
clayseal-identity whoami token.jwt
clayseal-identity diff-token before.jwt after.jwt
clayseal-identity verify token.jwt --jwks jwks.json --issuer clayseal.io --audience acme
clayseal-identity conformance token.jwt --jwks jwks.json --issuer clayseal.io --audience acme
clayseal-identity doctor --token token.jwt --jwks jwks.json --issuer clayseal.io --audience acme
clayseal-identity preflight http://localhost:8000/tool
clayseal-identity scan-mcp mcp-config.json
clayseal-identity generate fastapi
clayseal-identity replay-lab
```

`clayseal-identity` is an alias for the same command.

## Explain

Decode a token without verifying it:

```bash
clayseal-identity explain token.jwt
```

Use this when debugging claim shape, TTL, subject, and agent metadata.

## Status

Check the local environment quickly:

```bash
clayseal-identity status
clayseal-identity status --token token.jwt --mcp mcp-config.json
```

`status` looks for common Clay Seal environment variables, summarizes the
current agent token when one is present, and can scan an MCP config in the same
run.

## Whoami

Show the agent described by a token:

```bash
clayseal-identity whoami token.jwt
clayseal-identity whoami token.jwt --json
```

This is the friendly view for humans: agent id, principal, audience, scope,
TTL, proof-of-possession, and any lint warnings.

## Diff Token

Compare identity and authority changes between two tokens:

```bash
clayseal-identity diff-token before.jwt after.jwt
```

Use this when debugging why an agent suddenly gained a broader audience, a new
scope, a longer TTL, or a different holder key.

## Lint

Check whether a token follows the Clay Seal Agent Identity Profile:

```bash
clayseal-identity lint token.jwt
clayseal-identity lint token.jwt --json
```

The linter checks `alg`, `typ`, `kid`, required claims, recommended agent
claims, `cnf.jkt`, TTL, and SPIFFE-shaped subject.

## Verify

Verify signature and claims offline from a JWKS file or URL:

```bash
clayseal-identity verify token.jwt \
  --jwks https://identity.example.com/t/acme/jwks.json \
  --issuer clayseal.io \
  --audience acme
```

Use `--claims` to print verified claims.

## Mint

Mint a demo token against a localhost identity service:

```bash
clayseal-identity mint \
  --base-url http://localhost:8000 \
  --agent-type researcher \
  --owner alice@example.com \
  --scope repo:read \
  --dev-attestation
```

`--dev-attestation` is for localhost demos/tests only.

## Conformance

Run profile linting and offline verification together:

```bash
clayseal-identity conformance token.jwt \
  --jwks jwks.json \
  --issuer clayseal.io \
  --audience acme
```

## Doctor

Diagnose a token and/or an agent identity discovery document:

```bash
clayseal-identity doctor \
  --token token.jwt \
  --jwks jwks.json \
  --issuer clayseal.io \
  --audience acme \
  --agent-identity https://identity.example.com/t/acme/.well-known/agent-identity.json
```

`doctor` combines profile linting, optional offline JWKS verification, and
metadata checks for `/.well-known/agent-identity.json`.

## Preflight

Probe a tool endpoint to see whether it rejects unsafe identity:

```bash
clayseal-identity preflight http://localhost:8000/tool
clayseal-identity preflight http://localhost:8000/tool --method POST --token token.jwt
```

It sends requests with no token and with a malformed bearer token. Endpoints
should return `401` or `403` for both.

## MCP Scan

Scan a common MCP config shape:

```bash
clayseal-identity scan-mcp mcp-config.json
```

The scanner flags remote HTTP transports, missing obvious Authorization headers,
local command servers that rely on process boundaries, and environment variables
that appear to carry secrets.

## Generate

Print starter snippets for common workflows:

```bash
clayseal-identity generate fastapi
clayseal-identity generate mcp
clayseal-identity generate gha
clayseal-identity generate express
```

The snippets are intentionally small. They give developers the first secure
shape, then point them to `preflight`, `scan-mcp`, or offline verification.

## Replay Lab

Generate a local set of signed example tokens:

```bash
clayseal-identity replay-lab
```

The lab includes a good token and common failure cases: missing
proof-of-possession, wrong audience, and long TTL. It is useful for demos,
tests, and blog posts because every run creates fresh short-lived examples.
