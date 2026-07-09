# Clay Seal Identity CLI

The CLI makes the identity layer useful from a terminal:

```bash
clayseal-identity explain token.jwt
clayseal-identity lint token.jwt
clayseal-identity verify token.jwt --jwks jwks.json --issuer agentauth.io --audience acme
clayseal-identity conformance token.jwt --jwks jwks.json --issuer agentauth.io --audience acme
```

`agentauth-identity` is an alias for the same command.

## Explain

Decode a token without verifying it:

```bash
clayseal-identity explain token.jwt
```

Use this when debugging claim shape, TTL, subject, and agent metadata.

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
  --issuer agentauth.io \
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
  --issuer agentauth.io \
  --audience acme
```
