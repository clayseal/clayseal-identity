# Federating AgentAuth identities

AgentAuth JWT-SVIDs are **RS256-signed** and published through standard,
unauthenticated discovery documents — so external systems verify them with
off-the-shelf tooling, no AgentAuth code required.

## The public surface (per tenant)

| Endpoint | What it serves |
|---|---|
| `GET /t/{tenant}/.well-known/openid-configuration` | OIDC-style discovery: `issuer`, `jwks_uri`, `RS256` |
| `GET /t/{tenant}/jwks.json` | RFC 7517 JWKS (RSA public keys) |
| `GET /t/{tenant}/spiffe-bundle.json` | Same keys as a SPIFFE bundle (`use: jwt-svid`, `spiffe_sequence`, `spiffe_refresh_hint`) for `https_web` federation |

Why RS256: it is the one algorithm accepted by every federation target — the
SPIFFE JWT-SVID allowlist (EdDSA is excluded), AWS, GCP, Azure (RS256-only),
and RFC 7523 consumers. Ed25519 remains the sender-constraining (`cnf.jkt`)
and Biscuit-root algorithm, which never crosses a federation boundary.

## Consumers that work today

**Any RFC 7517/7519 validator** (PyJWT, jose, Nimbus…): fetch
`jwks_uri`, match `kid`, verify `RS256` + `iss` (see
`backend/tests/test_federation.py::test_issued_token_verifies_with_stock_pyjwt_via_public_jwks`).

**AWS Bedrock AgentCore Identity** — `CustomJWTAuthorizer` takes an OIDC
discovery URL directly:

```json
{"customJWTAuthorizer": {
  "discoveryUrl": "https://YOUR_HOST/t/TENANT/.well-known/openid-configuration",
  "allowedAudience": ["your-gateway-audience"]}}
```

**Keycloak 26+** — create an identity provider / federated client auth using
the discovery URL, or import the JWKS as an external key source.

**SPIFFE-aware peers** — configure `https_web` federation against
`/t/{tenant}/spiffe-bundle.json`.

## Anthropic Workload Identity Federation

Anthropic's API accepts external workload identities via RFC 7523
(`urn:ietf:params:oauth:grant-type:jwt-bearer`) at `POST /v1/oauth/token`,
returning short-lived `sk-ant-oat01-…` access tokens. Requirements on the
assertion (all satisfied by AgentAuth JWT-SVIDs):

- `aud` = `https://api.anthropic.com` — pass `extra_claims={"aud": ...}` /
  audience at identify() time or mint a purpose-bound credential
- `iss` + `iat` + `exp` present; RS256/ES256 signature
- Anthropic org configured with your issuer + JWKS URL
  (`https://YOUR_HOST/t/TENANT/jwks.json`) and resource conditions
  (`svac_`/`fdis_`/`fdrl_` resources with CEL rules)

Exchange:

```bash
curl -s https://api.anthropic.com/v1/oauth/token \
  -H 'content-type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
  --data-urlencode "assertion=${AGENTAUTH_JWT_SVID}"
```

Runnable walk-through: `python examples/03_federation.py` (verifies the
public-surface flow locally; performs the live Anthropic exchange only when
`ANTHROPIC_FEDERATION_URL` is set).
