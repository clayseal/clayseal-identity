# Clay Seal Identity

<img src="docs/assets/clay-seal-logo.png" alt="Clay Seal logo" width="420">

[![PyPI](https://img.shields.io/pypi/v/clayseal-identity)](https://pypi.org/project/clayseal-identity/)
[![CI](https://github.com/clayseal/clayseal-identity/actions/workflows/ci.yml/badge.svg)](https://github.com/clayseal/clayseal-identity/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/clayseal-identity)](https://pypi.org/project/clayseal-identity/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Autonomous agents increasingly act on behalf of humans and other services:
calling tools, hitting APIs, delegating to sub-agents. Most of them do it with
no verifiable identity at all: a shared API key, a bearer token with no
holder-binding, or nothing but a name string in a prompt. Clay Seal Identity
gives agents a real, cryptographically attested identity, so the rest of your
system can answer:

- **Which agent is acting?** Every credential carries a stable, SPIFFE-shaped
  identifier.
- **Who's accountable for it?** Delegation from a human or service principal
  is baked into the credential, not just logged separately.
- **Is this credential actually theirs?** Tokens are signed and bound to a
  holder key, so a stolen token alone isn't enough to replay it.
- **Can I verify that without calling home?** Yes. Verification is offline
  and doesn't require a round trip to an issuing service.

Clay Seal Identity is layer 1 of Clay Seal. The package is published on PyPI
as [`clayseal-identity`](https://pypi.org/project/clayseal-identity/) and
imports from `clayseal.identity`.
Clay Seal Receipts is available separately as `clayseal-receipts`; the
capabilities layer remains in private preview.

## Current State

Implemented today:

- SPIFFE **JWT-SVID** agent credentials (RS256, `sub` = a per-run SPIFFE ID)
  for broad federation compatibility, and SPIFFE **X.509-SVID** certificates
  for mTLS (`identify(..., request_x509=True)`), published with a per-tenant
  trust bundle.
- Ed25519 workload keys for sender-constraining (`cnf.jkt`) and offline
  proof-of-possession.
- SPIFFE-shaped agent identifiers and trust domains.
- Proof-of-possession confirmation claims so a stolen bearer token is not
  enough.
- Scoped tenant API keys (`issuer`, `verifier`, `reader`, `revoker`, `admin`)
  so agents and gateways do not need broad standing authority.
- Biscuit primitives for native Clay Seal capability facts.
- A Python SDK centered on `ClaySeal`.
- An optional FastAPI identity service for centralized issuance and validation.
- SQLite-by-default development storage and Postgres-ready production storage.
- Alembic migrations, API-key hardening, and optional KMS envelope encryption.

> **Attestation model.** Node attestation verifies platform-signed evidence a
> workload cannot forge without controlling the node: a Google-signed GCP
> instance identity token, a Kubernetes projected service-account token (checked
> via the cluster's TokenReview API), or an AWS EC2 instance identity document
> (RSA-2048 signature against AWS's regional certificate). The node token's
> audience binds the workload key being presented, so evidence captured
> elsewhere can't be replayed to bind a different key. For on-prem and bare-metal
> there is also a static trust-anchor attestor (operator-registered key). Enable
> attestors per deployment (see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and
> [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)).

Layer 1 deliberately does not try to be a complete sandbox. Runtime capability
scoping, stateful budget checks, suspicious-sequence detection, and execution
receipts live in the sibling layers:

| Layer | Repository | Purpose |
| --- | --- | --- |
| L1 | this repo | Agent identity and credential issuance |
| L2 | Clay Seal Capabilities (private preview) | Commit tokens, mandates, leases, budgets |
| L3 | Clay Seal Receipts (`clayseal-receipts`) | Verifiable execution receipts and audit |

This package stands alone: it has no dependency on the other layers, and every
runtime dependency resolves from public PyPI.

Known boundaries are tracked in [docs/SECURITY_BACKLOG.md](docs/SECURITY_BACKLOG.md).
The short version: Identity proves who the agent run is and whether the
credential is valid. It is not, by itself, a complete runtime sandbox. For
revocation-sensitive operations, use online validation or server-side
capability authorization instead of purely offline JWT verification.

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
git clone https://github.com/clayseal/clayseal-identity.git
cd clayseal-identity
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"                 # client + server + test/lint/type tooling
pytest backend/tests sdk/python/tests -q
python examples/01_quickstart.py
```

Or run `scripts/bootstrap.sh`, which performs the steps above.

## Good First Places To Help

If you are looking at Clay Seal as an open-source project, the most useful
contributions right now are practical integrations and sharp tests:

- Add a small example for a framework you already use.
- Add a negative test showing a stolen token, wrong audience, replayed proof, or
  mis-scoped key being rejected.
- Improve the local demo path so a new developer can understand it faster.
- Review the threat model and file issues for places where the docs overclaim
  or underspecify deployment assumptions.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and
[good first issues](https://github.com/clayseal/clayseal-identity/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22good%20first%20issue%22).

## Quickstart

The fastest path is the zero-config embedded demo. It starts a throwaway local
identity service, creates a tenant, identifies an agent, validates the token,
and revokes it. The inspector example prints the token's identity fields without
trusting it:

```bash
python examples/01_quickstart.py
python examples/05_inspect_token.py
python examples/02_capabilities.py
python examples/04_mcp_server.py   # lock down an MCP server (needs the [mcp] extra)
```

### Protect an MCP server

Most MCP servers in the wild are reachable by anything that can open a
connection. With the `[mcp]` extra, a FastMCP server accepts only Clay
Seal-credentialed agents, and each tool call is authorized against the
caller's capability token: attenuation included, so an agent that narrowed
itself mid-task is held to the narrowed rights:

```python
from mcp.server.fastmcp import FastMCP
from clayseal.identity.integrations.mcp_server import (
    ClaySealTokenVerifier, ToolGuard, build_auth_settings,
)

mcp = FastMCP("tools", token_verifier=verifier, auth=auth_settings)

@mcp.tool()
@guard.require()
def search_web(query: str) -> str: ...
```

Details in [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

### Framework integrations

Native on-ramps for the frameworks agents actually run in: a JavaScript
verifier (`@clayseal/verify`) for Node MCP servers and OpenClaw tool plugins,
and an [agentskills.io](https://agentskills.io) skill for Hermes Agent. See
[integrations/](integrations).


### Inspect a token

Inspection is for humans and debug screens. It decodes claims without trusting
the token. Use `verify_offline(...)` or `session.validate()` before enforcement.

```python
from clayseal.identity import inspect_token

inspection = inspect_token(session.token)
print("\n".join(inspection.summary_lines()))
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

Start with:

- [Developer guide](docs/DEV_GUIDE.md)
- [Identity-only integrations](docs/INTEGRATIONS.md)
- [Security backlog](docs/SECURITY_BACKLOG.md)
- [Deployment checklist](docs/DEPLOYMENT.md)

Reference:

- [Agent identity profile](docs/AGENT_IDENTITY_PROFILE.md)
- [Federation notes](docs/FEDERATION.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Conformance guide](docs/CONFORMANCE.md)
- [Identity profiles](docs/IDENTITY_PROFILES.md)
- [Privacy and data handling](docs/PRIVACY.md)


## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for dev
setup, tests, and how to submit changes. Please also read our
[Code of Conduct](CODE_OF_CONDUCT.md).

Found a security issue? Do **not** open a public issue. See
[SECURITY.md](SECURITY.md) for how to report it privately.

## License

MIT. See [LICENSE](LICENSE).
