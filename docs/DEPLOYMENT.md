# Clay Seal Identity — deployment

Production checklist for the **Clay Seal Identity** service (repo: `clay-seal-identity`,
PyPI package: `agentauth-identity` until the `clayseal-*` publish cutover). Cross-cutting
items (receipts, capabilities, Terraform) live in the `clay-seal-core` repo at
`docs/DEPLOYMENT.md`.

**Branding vs compatibility:** the product is **Clay Seal**. Import paths (`agentauth.*`),
environment variables (`AGENTAUTH_*`), and the `AgentAuth` SDK class name remain for
backward compatibility during the rename.

## Pre-deploy

1. `alembic upgrade head` with `AGENTAUTH_MANAGE_SCHEMA=alembic`
2. `python scripts/migrate_api_keys.py --dry-run` then apply
3. Copy `.env.example` → `.env` and set all required values
4. Configure ALB/WAF rate limits (in-app limiter is advisory per instance)

## Required production env

| Variable | Purpose |
|----------|---------|
| `AGENTAUTH_ENV` | `production` |
| `AGENTAUTH_DATABASE_URL` | PostgreSQL (not SQLite) |
| `AGENTAUTH_ADMIN_API_KEY` | Gates `POST /v1/customers` |
| `AGENTAUTH_SECRET_ENCRYPTION_PROVIDER` | `aws_kms` or `local` |
| `AGENTAUTH_HTTP_ALLOWED_HOSTS` | Outbound fetch allowlist |
| `AGENTAUTH_CORS_ORIGINS` | Dashboard origins (no `*`) |
| `AGENTAUTH_MANAGE_SCHEMA` | `alembic` |
| `AGENTAUTH_API_URL` | Clay Seal Identity base URL (required for attested receipt profiles) |

## Startup guards

`validate_production_startup()` refuses to serve when:

- SQLite is configured
- Secret encryption is disabled
- Core production policy violations are present
- Unmigrated tenants lack `api_key_hash`
- `AGENTAUTH_MANAGE_SCHEMA=auto`
