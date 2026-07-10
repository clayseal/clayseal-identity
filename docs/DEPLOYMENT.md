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
| `CLAYSEAL_HTTP_ALLOWED_HOSTS` | Outbound fetch allowlist |
| `CLAYSEAL_CORS_ORIGINS` | Dashboard origins (no `*`) |
| `CLAYSEAL_MANAGE_SCHEMA` | `alembic` |
| `CLAYSEAL_API_URL` | Clay Seal Identity base URL (required for attested receipt profiles) |

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
