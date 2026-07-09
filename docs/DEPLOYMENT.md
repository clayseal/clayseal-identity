# Clay Seal Identity — deployment

Production checklist for the **Clay Seal Identity** service (repo: `clay-seal-identity`,
PyPI package: `clayseal-identity`). Cross-cutting items (receipts, capabilities,
Terraform) live in the `clay-seal-core` repo at `docs/DEPLOYMENT.md`.

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

## Startup guards

`validate_production_startup()` refuses to serve when:

- SQLite is configured
- Secret encryption is disabled
- Core production policy violations are present
- Unmigrated tenants lack `api_key_hash`
- `CLAYSEAL_MANAGE_SCHEMA=auto`
