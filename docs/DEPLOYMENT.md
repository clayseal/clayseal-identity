# Clay Seal Identity — deployment

Production checklist for the **Clay Seal Identity** service (repo: `clayseal-identity`,
PyPI package: `clayseal-identity`). Deployment of the upper Clay Seal layers
(receipts, capabilities) is documented in their own repos.

## Pre-deploy

1. `alembic upgrade head` with `CLAYSEAL_MANAGE_SCHEMA=alembic`
2. `python scripts/migrate_api_keys.py --dry-run` then apply
3. Copy `.env.example` → `.env` and set all required values
4. Configure ALB/WAF rate limits (in-app limiter is advisory per instance)

## Required production env

| Variable | Purpose |
|----------|---------|
| `CLAYSEAL_ENV` | `production` |
| `CLAYSEAL_DATABASE_URL` | PostgreSQL (not SQLite) |
| `CLAYSEAL_ADMIN_API_KEY` | Gates `POST /v1/customers` |
| `CLAYSEAL_SECRET_ENCRYPTION_PROVIDER` | `aws_kms` or `local` |
| `CLAYSEAL_HTTP_ALLOWED_HOSTS` | Accepted inbound HTTP Host headers |
| `CLAYSEAL_CORS_ORIGINS` | Allowed browser-client origins (no `*`) |
| `CLAYSEAL_MANAGE_SCHEMA` | `alembic` |
| `CLAYSEAL_PUBLIC_BASE_URL` | Public Clay Seal Identity base URL used in discovery metadata |

## Node attestors

Node attestation is off until you enable the clouds/clusters this service
accepts. Each workload requests its node token with the audience
`clayseal://<tenant>/attest/<workload-key-thumbprint>`, which binds the token to
the key being presented.

| Variable | Enables | Notes |
|----------|---------|-------|
| `CLAYSEAL_ATTEST_GCP=1` | `gcp_iit` | GCP instance identity tokens (`format=full`), verified against Google's keys. No other config. |
| `CLAYSEAL_ATTEST_K8S_CLUSTER=<name>` | `k8s_psat` | Also set `CLAYSEAL_ATTEST_K8S_API` (API server URL), `CLAYSEAL_ATTEST_K8S_TOKEN` or `_TOKEN_FILE` (reviewer SA token, needs `system:auth-delegator`), and `CLAYSEAL_ATTEST_K8S_CA` (cluster CA PEM path). |
| `CLAYSEAL_ATTEST_AWS_CERTS=<region>=<pem>,...` | `aws_iid` | Map each region to AWS's regional public certificate file. `aws_iid` proves instance identity but not freshness — pair with a network boundary. |

On-prem / bare-metal with no metadata service: register a static RSA trust
anchor (`POST /v1/node-attestors`) and have the workload present a JWT signed by
it. Protect the anchor key like a root key.

## Startup guards

`validate_production_startup()` refuses to serve when:

- SQLite is configured
- Secret encryption is disabled
- Core production policy violations are present
- Unmigrated tenants lack `api_key_hash`
- `CLAYSEAL_MANAGE_SCHEMA=auto`
- `CLAYSEAL_PUBLIC_BASE_URL` is missing

---

## Recommended deployment shape: sidecar/gateway

Scoped keys reduce blast radius, but the safest pattern is to **keep tenant API keys out of the agent process entirely**.

### Which key goes where

| Component | Holds | Why |
|-----------|-------|-----|
| **Sidecar / gateway** (Envoy, nginx, or a thin proxy next to the agent) | `issuer` key | Calls `POST /v1/identify` to mint the agent's short-lived JWT-SVID. The agent never sees the API key — only the signed token. |
| **Resource server** (the service the agent calls) | `verifier` key (or offline JWKS) | Calls `POST /v1/validate` / `POST /v1/authorize` to check the agent's token. |
| **Operator workstation / CI/CD** | `admin` (bootstrap) key | Tenant setup, key rotation, audit. Never deployed into a pod. |

### Request flow

```
Agent ───(unsigned request)──▶  Sidecar
                                    │
                          (issuer key)──▶ Clay Seal Identity
                                    │        POST /v1/identify
                                    │◀─────── JWT-SVID (5min TTL)
                                    │
Sidecar ───(request + JWT)──────▶  Resource Server
                                        │
                              (verifier key)──▶ Clay Seal Identity
                                        │        POST /v1/validate
                                        │◀─────── ok / 401
                                        │
Resource Server ◀───(response)──────  Sidecar ◀───(response)── Agent
```

### Why this matters

A tenant API key inside the agent process — even an `issuer`-only key — can be exfiltrated through prompt injection or a compromised tool. With the sidecar pattern:

- The agent holds **only a short-lived, sender-constrained JWT** tied to its workload key. Compromising the agent yields a token that expires in minutes and can't be replayed from another machine.
- The sidecar holds the long-lived key but has **no LLM context, no tools, no prompt** — it's a narrow network proxy with one job.
- The admin key never touches a compute node that runs agent workloads.

### Creating the keys

See [Scoped tenant API keys in the dev guide](DEV_GUIDE.md#scoped-tenant-api-keys) for how to create `issuer` and `verifier` keys for this pattern.
