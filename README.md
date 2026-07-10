# Clay Seal Identity

<img src="docs/assets/clay-seal-logo.png" alt="Clay Seal logo" width="420">

Clay Seal Identity is layer 1 of Clay Seal: cryptographically attested identity
for autonomous agents. The package is published as `clayseal-identity` and
imports from `clayseal.identity`.

Use this repo when you need to answer:

- Which agent is acting?
- Which human or service principal delegated that action?
- Is the credential short-lived, signed, and bound to the holder key?
- Can downstream systems verify the identity offline?

## Current State

Implemented today:

- JWT-SVID-style agent credentials signed with RS256 for broad federation
  compatibility.
- Ed25519 workload keys for sender-constraining (`cnf.jkt`) and offline
  proof-of-possession.
- SPIFFE-shaped agent identifiers and trust domains.
- Proof-of-possession confirmation claims for replay resistance.
- Biscuit primitives for native Clay Seal capability facts.
- A Python SDK centered on `ClaySeal`.
- An optional FastAPI identity service for centralized issuance and validation.
- SQLite-by-default development storage and Postgres-ready production storage.
- Alembic migrations, API-key hardening, and optional KMS envelope encryption.

> **Attestation model — please read.** The node/workload attestation in this repo
> is a *prototype stand-in for SPIRE*: the backend trusts an RSA anchor an
> operator registers out-of-band and does **not** yet verify live
> Kubernetes/AWS/GCP node evidence. Treat it as bring-your-own-attestation and
> front issuance with a real SPIRE agent in production. Details:
> [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md#attestation-model--read-this-first).

Layer 1 deliberately does not issue action-scoped commit tokens or write
execution receipts. Those live in the sibling layers:

| Layer | Repository | Purpose |
| --- | --- | --- |
| L1 | this repo | Agent identity and credential issuance |
| L2 | clay-seal-capabilities (private preview) | Commit tokens, mandates, leases, budgets |
| L3 | clay-seal-receipts (private preview) | Verifiable execution receipts and audit |

This package stands alone: it has no dependency on the other layers, and every
runtime dependency resolves from public PyPI.

## Install

The client SDK (`clayseal.identity`) is intentionally lightweight:

```bash
pip install clayseal-identity
```

To also run the bundled FastAPI identity service, add the `server` extra (pulls
in FastAPI, SQLAlchemy, the Postgres driver, and Alembic); `kms` adds the AWS KMS
provider:

```bash
pip install "clayseal-identity[server]"
pip install "clayseal-identity[server,kms]"
```

### From source (development)

```bash
git clone https://github.com/pberlizov/clayseal-identity.git
cd clayseal-identity
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"                 # client + server + test/lint/type tooling
pytest backend/tests sdk/python/tests -q
python examples/01_quickstart.py
```

Or run `scripts/bootstrap.sh`, which performs the steps above.

## Quickstart

The fastest path is the zero-config embedded demo. It starts a throwaway local
identity service, creates a tenant, identifies an agent, validates the token,
and revokes it:

```bash
python examples/01_quickstart.py
python examples/02_capabilities.py
```

Inspect and lint agent tokens from the terminal:

```bash
clayseal-identity explain token.jwt
clayseal-identity lint token.jwt
clayseal-identity whoami token.jwt
clayseal-identity diff-token before.jwt after.jwt
clayseal-identity doctor --token token.jwt --jwks jwks.json --issuer clayseal.io --audience acme
clayseal-identity preflight http://localhost:8000/tool
clayseal-identity scan-mcp mcp-config.json
clayseal-identity generate fastapi
clayseal-identity replay-lab
```

The current SDK flow is service-backed: create or point at a tenant, then call
`identify`. `dev_attestation=True` is only for localhost demos/tests; production
callers pass a platform-issued attestation document.

```python
from clayseal.identity import ClaySeal

tenant = ClaySeal.create_tenant("Acme AI", base_url="http://localhost:8000")
auth = ClaySeal(
    api_key=tenant["api_key"],
    base_url="http://localhost:8000",
    dev_attestation=True,  # localhost demos/tests only
)

session = auth.identify(
    agent_type="researcher",
    owner="alice@example.org",
    capabilities=[{"resource": "repo", "action": "read"}],
)

claims = session.validate().claims
assert claims["sub"].startswith("spiffe://")
```

## Hosted Service

Run the local FastAPI service:

```bash
uvicorn clayseal.backend.main:app --reload
```

Production deployments should run behind TLS, pin issuer and audience, use
Postgres, run Alembic migrations before deploy, and store signing material in a
KMS or equivalent key-management system.

## Privacy and Data Handling

Layer 1 stores and processes identity metadata: agent IDs, trust domains,
principals, credential timestamps, public keys, and operational audit metadata.
Private keys, persisted agent certificates, admin API keys, and database
credentials are secrets.

Read [docs/PRIVACY.md](docs/PRIVACY.md) before integrating with production user
or employee data.

## Documentation

- [Developer guide](docs/DEV_GUIDE.md)
- [Agent identity profile](docs/AGENT_IDENTITY_PROFILE.md)
- [CLI](docs/CLI.md)
- [Identity-only integrations](docs/INTEGRATIONS.md)
- [Agent tool integration backlog](docs/AGENT_TOOL_BACKLOG.md)
- [Federation notes](docs/FEDERATION.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Conformance guide](docs/CONFORMANCE.md)
- [Identity profiles](docs/IDENTITY_PROFILES.md)
- [Privacy and data handling](docs/PRIVACY.md)
- [Bad token zoo](bad-token-zoo/README.md)

## Compatibility Note

The public brand is Clay Seal. The package names and import paths intentionally
remain `clayseal-*` / `clayseal.*` for now so existing integrations keep
working.
