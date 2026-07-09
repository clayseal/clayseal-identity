# Clay Seal Identity

<img src="docs/assets/clay-seal-logo.png" alt="Clay Seal logo" width="420">

Clay Seal Identity is layer 1 of Clay Seal: cryptographically attested identity
for autonomous agents. The package is still published as `agentauth-identity`
and imports from `agentauth.identity` for compatibility while the product brand
is Clay Seal.

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
- A Python SDK centered on `AgentAuth`.
- An optional FastAPI identity service for centralized issuance and validation.
- SQLite-by-default development storage and Postgres-ready production storage.
- Alembic migrations, API-key hardening, and optional KMS envelope encryption.

Layer 1 deliberately does not issue action-scoped commit tokens or write
execution receipts. Those live in the sibling layers:

| Layer | Repository | Purpose |
| --- | --- | --- |
| Core | [clay-seal-core](https://github.com/pberlizov/clay-seal-core) | Shared contracts and crypto helpers |
| L1 | this repo | Agent identity and credential issuance |
| L2 | [clay-seal-capabilities](https://github.com/pberlizov/clay-seal-capabilities) | Commit tokens, mandates, leases, budgets |
| L3 | [clay-seal-receipts](https://github.com/pberlizov/clay-seal-receipts) | Verifiable execution receipts and audit |

## Install

Standalone editable development:

```bash
git clone https://github.com/pberlizov/clay-seal-identity.git
cd clay-seal-identity
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest backend/tests sdk/python/tests -q
python examples/01_quickstart.py
```

Pinned partner install:

```bash
pip install "git+https://github.com/pberlizov/clay-seal-core.git@v0.5.0"
pip install "git+https://github.com/pberlizov/clay-seal-identity.git@v0.5.0"
```

Production KMS support is optional:

```bash
pip install "agentauth-identity[kms] @ git+https://github.com/pberlizov/clay-seal-identity.git@v0.5.0"
```

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
clayseal-identity doctor --token token.jwt --jwks jwks.json --issuer agentauth.io --audience acme
clayseal-identity preflight http://localhost:8000/tool
clayseal-identity scan-mcp mcp-config.json
clayseal-identity generate fastapi
clayseal-identity replay-lab
```

The current SDK flow is service-backed: create or point at a tenant, then call
`identify`. `dev_attestation=True` is only for localhost demos/tests; production
callers pass a platform-issued attestation document.

```python
from agentauth.identity import AgentAuth

tenant = AgentAuth.create_tenant("Acme AI", base_url="http://localhost:8000")
auth = AgentAuth(
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
uvicorn agentauth.backend.main:app --reload
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
- [Federation notes](docs/FEDERATION.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Conformance guide](docs/CONFORMANCE.md)
- [Identity profiles](docs/IDENTITY_PROFILES.md)
- [Privacy and data handling](docs/PRIVACY.md)
- [Bad token zoo](bad-token-zoo/README.md)

## Compatibility Note

The public brand is Clay Seal. The package names and import paths intentionally
remain `agentauth-*` / `agentauth.*` for now so existing integrations keep
working.
