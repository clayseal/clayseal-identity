# Developer guide — Clay Seal Identity (Layer 1)

This document is written for engineers who need to **run, integrate, or extend** the identity layer of Clay Seal. It assumes you are comfortable with Python and basic PKI concepts, but not that you have read the rest of the codebase first.

---

## What this repository is for

**Clay Seal Identity** is layer 1 of the Clay Seal stack. Its package name is
still `clayseal-identity`, and its Python namespace is still
`clayseal.identity`, but the product name developers and customers should see
is Clay Seal. Its job is narrow and important: give every autonomous agent a
**cryptographically attested identity** that downstream systems can verify
offline.

Concretely, this repo provides:

- A Python SDK (`ClaySeal`) that mints and verifies **JWT-SVID-style credentials** (RS256-signed, short-lived, SPIFFE-shaped).
- Ed25519 workload keys used for sender-constraining (`cnf.jkt`) and local proof-of-possession.
- **Biscuit capability tokens** for offline, attenuatable authorization facts.
- **Proof-of-possession** binding so a stolen bearer token cannot be replayed from another machine.
- An optional **hosted FastAPI identity service** (`clayseal.backend`) for teams that want issuance and validation as a network endpoint rather than an in-process library.

What this repo deliberately does **not** include:

- Dynamic capability narrowing, commit tokens, or mandate enforcement — that is the Clay Seal Capabilities layer (layer 2, private preview).
- Execution receipts, audit logs, MCP gateways, or policy proofs — that is the Clay Seal Receipts layer (layer 3, private preview).

If you only need “who is this agent, and can I trust the credential?”, you can stop at this repo. If you need “what did the agent do, under what scope, with verifiable proof?”, you will eventually install layers 2 and 3 as well.

---

## How the three layers fit together

Think of the stack as increasing specificity:

| Layer | Repository | Question it answers |
|-------|------------|---------------------|
| L1 Identity | **this repo** | Who is acting, with what attested key? |
| L2 Capabilities | Clay Seal Capabilities (private preview) | What are they allowed to do right now (scoped, attenuated)? |
| L3 Receipts | Clay Seal Receipts (private preview) | What did they actually do, and can a third party verify it? |

Layer 1 exports facts. Layer 2 narrows them into action-scoped tokens. Layer 3 records decisions and builds tamper-evident proofs.

Import convention matters: **in this repo**, always import from the identity namespace:

```python
from clayseal.identity import ClaySeal
from clayseal.identity.session import AgentSession
```

There is intentionally **no** top-level `from clayseal import Identity` here. That unified export lives only in the receipts repo, which owns the public `clayseal` package surface for full-stack users.

---

## Installation

### Standalone (identity only)

From a clone:

```bash
git clone https://github.com/clayseal/clayseal-identity.git
cd clayseal-identity
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

From a pinned tag (recommended for partners):

```bash
pip install "git+https://github.com/clayseal/clayseal-identity.git@v0.6.0"
```

This package stands alone — no other Clay Seal layer is required. The upper
layers (capabilities, receipts) are in private preview; partners with access
install them on top, in order, from their own pinned tags.

### Python version

Supported: **3.11 through 3.13** (see `pyproject.toml`). Biscuit’s native wheel is the reason for the lower bound.

---

## Core concepts

### Clay Seal client

`ClaySeal` is the Clay Seal identity entry point. It talks to a tenant-scoped identity service, or to the embedded throwaway service used by the examples.

Typical flow:

1. **Register trust** — create a tenant, node attestor, and registration entry.
2. **Identify** — present attestation evidence and mint a short-lived credential.
3. **Use** — carry the credential on outbound calls and authorize local capabilities.
4. **Verify** — validate online with PoP or offline with issuer + JWKS.

### Credentials and JWT-SVID shape

Credentials are signed JWTs with SPIFFE-compatible claims (`sub`, `iss`, `aud`, `exp`, etc.) plus Clay Seal-specific extensions for attestation and proof-of-possession.

Design intent:

- **Short TTL** — compromise window is minutes, not days.
- **Explicit principal** — tie the agent to a named human or service account when required.
- **Key binding** — `cnf` (confirmation) claim ties the token to a holder key.

### Biscuit tokens

Biscuits provide **attenuation**: a parent token can derive child tokens that carry *fewer* rights, never more. Layer 1 includes Biscuit primitives because identity and capability facts often travel together, but **dynamic scoping logic** (commit tokens, leases, mandates) lives in layer 2.

### AuthorityBinding (shared with L2/L3)

When this package is used with the upper Clay Seal layers, `Credential.to_binding_dict()` produces the authority facts the receipts runtime consumes (its `AuthorityBinding` type normalizes them for L2/L3). This repo itself has no dependency on those layers.

---

## Operating the SDK — step by step

### Quickstart example

The fastest sanity check:

```bash
python examples/01_quickstart.py
```

This exercises identify → validate → revoke against an embedded throwaway local service, so no external service or dashboard is required.

### Minimal SDK usage

```python
from clayseal.identity import ClaySeal

tenant = ClaySeal.create_tenant("Acme AI", base_url="http://localhost:8000")
auth = ClaySeal(
    api_key=tenant["api_key"],
    base_url="http://localhost:8000",
    dev_attestation=True,  # localhost demos/tests only
)

# Mint a credential for this attested workload.
session = auth.identify(
    agent_type="researcher",
    owner="alice@example.org",
    capabilities=[{"resource": "repo", "action": "read"}],
)

# Online validation signs a one-time proof-of-possession challenge.
claims = session.validate().claims
assert claims["sub"].startswith("spiffe://")
```

For production, do not enable dev attestation. Register a node attestor and
registration entry, then call `identify_with_attestation(attestation_document)`
with evidence issued by your workload environment.

### Offline resource-server verification

Resource servers can verify a Clay Seal JWT-SVID without calling the identity
service if they have the tenant issuer and JWKS:

```python
from clayseal.identity import verify_offline

claims = verify_offline(
    token,
    jwks=tenant_jwks,
    issuer="clayseal.io",
    audience=tenant_id,
)
assert claims["cnf"]["jkt"]  # sender-constrained; not a plain bearer token
```

### Framework helpers

Identity-only helpers live under `clayseal.identity.integrations`:

```python
from clayseal.identity.integrations.langchain import identity_config
from clayseal.identity.integrations.mcp import tool_headers

runnable.invoke(input, config=identity_config(session))
headers = tool_headers(session)
```

FastAPI services can use `AgentIdentityVerifier.dependency(...)` to protect tool
endpoints with offline JWKS verification. See [INTEGRATIONS.md](INTEGRATIONS.md).

### Sessions and downstream layers

After identification, hand the issued credential to layer 2 (capabilities) or
layer 3 (receipts). A lower layer never imports a higher one, so the cross-layer
wiring lives in those packages, not here. Partners with access should use the
identity adapters those layers provide rather than hand-rolling claim dicts.

### Production attestation

The dev attestor exists to make examples runnable. Production deployments should
derive selectors from real platform evidence: Kubernetes projected service
account tokens, SPIRE, AWS instance identity, GCP identity tokens, or a node
agent that signs workload evidence. The caller does not choose its own
`agent_type` or rights; the matched registration entry does.

---

## Running the hosted identity service

For deployments where agents call a central issuer:

```bash
uvicorn clayseal.backend.main:app --host 0.0.0.0 --port 8080
```

The FastAPI app exposes issuance and validation routes used by larger integrations. Configuration is environment-driven; see `backend/` and example env files if present in your checkout.

Typical deployment pattern:

1. Run the service behind TLS termination.
2. Pin trust roots for verifiers (JWKS or configured public keys).
3. Issue credentials with TTL aligned to your agent heartbeat (often 5–15 minutes).

For local development, `--reload` is fine. For production, use a proper ASGI server layout (multiple workers only if your signing backend supports it — often you want a single signer or HSM-backed key).

---

## Testing and development workflow

### Run the test suite

```bash
pip install -e ".[dev]"
pytest backend/tests sdk/python/tests -q
```

CI runs the same suites on Python 3.11 and 3.13.

### Project layout (mental map)

| Path | Purpose |
|------|---------|
| `clayseal/identity/` | Public SDK — start here |
| `clayseal/backend/` | FastAPI identity service (the `[server]` extra) |
| `backend/tests/` | Service-level tests |
| `sdk/python/tests/` | SDK unit tests |
| `examples/` | Runnable scripts |

The small set of helpers shared with the upper layers (canonical JSON, path-scope
matching, production guards) is vendored in `clayseal/_core.py`, so this repo has
no external Clay Seal dependency.

### Editable installs and namespace gotchas

Python merges all directories named `clayseal` on `sys.path`. If you clone multiple layers into sibling folders and run tests **from inside** one repo without installing the others, you can accidentally pick up stale or partial namespace merges via the current working directory.

**Recommended practice:**

- Use a virtualenv.
- `pip install -e` only the repos you need.
- Run tests from the repo root after install, or from a neutral directory like `/tmp` with packages installed into the venv.

If imports fail with “cannot import name X from clayseal”, you almost always have a path pollution issue, not a missing release.

---

## Integrating with layer 2 and 3

Layer 2 (capabilities) and layer 3 (receipts) consume the credential this layer
issues through their own identity adapters — you do not change layer 1 code to
integrate, nor for OIDC, Auth0, SPIRE, or AWS STS. Those adapters, and the
cross-layer `IdentitySession` abstraction, live in the private-preview sibling
packages. Layer 1 remains the **native** stack when you want the full Clay Seal
attestation model.

Layer 3 (`wrap_with_identity_session`) accepts the same `IdentitySession`
abstraction. Partners with access can use the capabilities cross-layer guide and
receipts developer guide for full-stack wiring.

---

## Security and operations notes

**Key management.** Default examples generate Ed25519 keys locally. Production should use a KMS or HSM where policy requires it; the receipts layer has optional KMS providers for signing at rest.

**Clock skew.** JWT validation respects `exp`/`nbf`. Ensure NTP on agents and verifiers.

**Principal binding.** If compliance requires human-in-the-loop authorization, always set `principal` at identify time and verify it appears in downstream receipts.

**Rotation.** Plan for agent key rotation: register a new agent ID or rotate keys with overlap period where both verify.

---

## Privacy and data handling

Layer 1 handles identity metadata and secret-bearing credential material. Treat
persisted agent certificates, signing keys, admin API keys, database credentials,
and live JWT-SVIDs as secrets.

Design production integrations so identity records contain stable identifiers
and verification metadata, not prompts, source code, model outputs, or full
business payloads. Use short credential TTLs, define retention for issuance and
verification audit records, and redact credentials from logs and support
bundles.

Read [docs/PRIVACY.md](PRIVACY.md) before connecting Clay Seal Identity to
employee, customer, or regulated data.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `ModuleNotFoundError: clayseal.identity` | Package not installed | `pip install -e ".[dev]"` in this repo |
| Wrong code imported | CWD namespace merge | Install via pip; avoid running from monorepo parent |
| Verification fails immediately | Expired credential or clock skew | Re-identify; check system time |
| Biscuit errors on 3.14+ | Unsupported Python | Use 3.11–3.13 |
| Layer 2 import errors | Identity version mismatch | Pin matching tags (`v0.6.0` across stack) |

---

## Releases and versioning

This repo is tagged independently (`v0.6.0`, etc.). **Always tag identity before capabilities and receipts** — downstream `pyproject.toml` files pin this repo by git URL and tag.

Checklist for maintainers:

1. Bump `version` in `pyproject.toml`.
2. Add a `CHANGELOG.md` section.
3. Run tests locally.
4. Tag and push.
5. Only then cut dependent layer releases.

Partners should pin:

```bash
pip install "git+https://github.com/clayseal/clayseal-identity.git@v0.6.0"
```

---

## Where to go next

- **Scope and commit tokens** → Clay Seal Capabilities developer guide (private preview)
- **Receipts, audit, MCP gateway** → Clay Seal Receipts developer guide (private preview)
- **Cross-provider identity** → Capabilities cross-layer integration guide (private preview)
- **Agent identity profile** → [docs/AGENT_IDENTITY_PROFILE.md](AGENT_IDENTITY_PROFILE.md)
- **Framework integration helpers** → [docs/INTEGRATIONS.md](INTEGRATIONS.md)
- **Privacy and data handling** → [docs/PRIVACY.md](PRIVACY.md)

If something in this guide does not match the code you checked out, prefer the tagged release you installed and file an issue with the tag name and command you ran.
