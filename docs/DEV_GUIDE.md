# Developer guide — AgentAuth Identity (Layer 1)

This document is written for engineers who need to **run, integrate, or extend** the identity layer of AgentAuth. It assumes you are comfortable with Python and basic PKI concepts, but not that you have read the rest of the codebase first.

---

## What this repository is for

**agentauth-identity** is layer 1 of a three-layer stack. Its job is narrow and important: give every autonomous agent a **cryptographically attested identity** that downstream systems can verify offline.

Concretely, this repo provides:

- A Python SDK (`AgentAuth`) that mints and verifies **JWT-SVID-style credentials** (Ed25519-signed, short-lived, SPIFFE-shaped).
- **Biscuit capability tokens** for offline, attenuatable authorization facts.
- **Proof-of-possession** binding so a stolen bearer token cannot be replayed from another machine.
- An optional **hosted FastAPI identity service** (`agentauth.backend`) for teams that want issuance and validation as a network endpoint rather than an in-process library.

What this repo deliberately does **not** include:

- Dynamic capability narrowing, commit tokens, or mandate enforcement — that is [agentauth-capabilities](https://github.com/pberlizov/agentauth-capabilities) (layer 2).
- Execution receipts, audit logs, MCP gateways, or policy proofs — that is [agentauth-receipts](https://github.com/pberlizov/agentauth-receipts) (layer 3).

If you only need “who is this agent, and can I trust the credential?”, you can stop at this repo. If you need “what did the agent do, under what scope, with verifiable proof?”, you will eventually install layers 2 and 3 as well.

---

## How the three layers fit together

Think of the stack as increasing specificity:

| Layer | Repository | Question it answers |
|-------|------------|---------------------|
| L1 Identity | **this repo** | Who is acting, with what attested key? |
| L2 Capabilities | agentauth-capabilities | What are they allowed to do right now (scoped, attenuated)? |
| L3 Receipts | agentauth-receipts | What did they actually do, and can a third party verify it? |

Layer 1 exports facts. Layer 2 narrows them into action-scoped tokens. Layer 3 records decisions and builds tamper-evident proofs.

Import convention matters: **in this repo**, always import from the identity namespace:

```python
from agentauth.identity import AgentAuth
from agentauth.identity.session import Session
```

There is intentionally **no** top-level `from agentauth import AgentAuth` here. That unified export lives only in the receipts repo, which owns the public `agentauth` package surface for full-stack users.

---

## Installation

### Standalone (identity only)

From a clone:

```bash
git clone https://github.com/pberlizov/agentauth-identity.git
cd agentauth-identity
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

From a pinned tag (recommended for partners):

```bash
pip install "git+https://github.com/pberlizov/agentauth-identity.git@v0.4.0"
```

### With the full stack

Install in order — each layer depends on the one below:

```bash
pip install "git+https://github.com/pberlizov/agentauth-identity.git@v0.4.0"
pip install "git+https://github.com/pberlizov/agentauth-capabilities.git@v0.4.0"
pip install "git+https://github.com/pberlizov/agentauth-receipts.git@v0.4.0"
```

Or use the smoke script in the receipts repo: `scripts/layer_install_smoke.sh`.

### Python version

Supported: **3.10 through 3.13** (see `pyproject.toml`). Biscuit’s native wheel is the reason for the upper bound.

---

## Core concepts

### AgentAuth client

`AgentAuth` is the main entry point. You configure a trust domain (SPIFFE-style), signing keys, and optional persistence for agent certificates.

Typical flow:

1. **Register or load** an agent identity (SPIFFE ID + key pair).
2. **Identify** — mint a short-lived credential bound to the agent and optionally a human principal.
3. **Wrap** — turn the credential into a session object that layer 2/3 can consume.
4. **Verify** — offline validation of a peer’s credential.

### Credentials and JWT-SVID shape

Credentials are signed JWTs with SPIFFE-compatible claims (`sub`, `iss`, `aud`, `exp`, etc.) plus AgentAuth-specific extensions for attestation and proof-of-possession.

Design intent:

- **Short TTL** — compromise window is minutes, not days.
- **Explicit principal** — tie the agent to a named human or service account when required.
- **Key binding** — `cnf` (confirmation) claim ties the token to a holder key.

### Biscuit tokens

Biscuits provide **attenuation**: a parent token can derive child tokens that carry *fewer* rights, never more. Layer 1 includes Biscuit primitives because identity and capability facts often travel together, but **dynamic scoping logic** (commit tokens, leases, mandates) lives in layer 2.

### AuthorityBinding (shared with L2/L3)

`AuthorityBinding` (`agentauth.core.authority_binding`, from the `agentauth-core` contract package) normalizes verified credential material into an `AuthorityContext` that upper layers understand. If you integrate with capabilities or receipts, you will see this type cross repo boundaries. Layer 1's `Credential.to_binding_dict()` produces the raw claims that `AuthorityBinding.from_agentauth_credential()` consumes.

---

## Operating the SDK — step by step

### Quickstart example

The fastest sanity check:

```bash
python examples/01_quickstart.py
```

This exercises identify → wrap → basic verification without a network service.

### Minimal in-process usage

```python
from agentauth.identity import AgentAuth

auth = AgentAuth(trust_domain="example.org")
agent = auth.register_agent("engineering/devin-1")

# Mint a credential for this agent acting under a human principal
credential = auth.identify(
    agent,
    principal="alice@example.org",
    ttl_seconds=300,
)

# Verify someone else's credential (offline)
claims = auth.verify_credential(credential.to_jwt())
assert claims["sub"] == agent.spiffe_id
```

### Sessions and downstream layers

After identification, pass authority into layer 2 or 3 through the umbrella
package's cross-layer wiring — a lower layer never imports a higher one, so the
receipting convenience lives in `agentauth`, not here:

```python
import agentauth

session = auth.session(credential)
agent = agentauth.wrap(session, my_model, policy=policy)  # receipts bound to this identity
```

Do not hand-roll claim dicts for upper layers unless you are implementing a custom identity adapter in capabilities (see that repo's cross-provider guide).

### Persisting agent certificates

For long-running agents (e.g. a Devin instance that restarts), persist the agent key material:

```python
auth.register_agent("engineering/devin-1", persist_path="certs/devin-1.json")
```

On restart, load instead of re-registering. **Treat persisted cert files as secrets** — they are agent private keys.

---

## Running the hosted identity service

For deployments where agents call a central issuer:

```bash
uvicorn agentauth.backend.main:app --host 0.0.0.0 --port 8080
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
| `agentauth/identity/` | Public SDK — start here |
| `agentauth/backend/` | FastAPI identity service |
| `agentauth/core/` | Shared types (`AuthorityBinding`, signing helpers) |
| `backend/tests/` | Service-level tests |
| `sdk/python/tests/` | SDK unit tests |
| `examples/` | Runnable scripts |

### Editable installs and namespace gotchas

Python merges all directories named `agentauth` on `sys.path`. If you clone multiple layers into sibling folders and run tests **from inside** one repo without installing the others, you can accidentally pick up stale or partial namespace merges via the current working directory.

**Recommended practice:**

- Use a virtualenv.
- `pip install -e` only the repos you need.
- Run tests from the repo root after install, or from a neutral directory like `/tmp` with packages installed into the venv.

If imports fail with “cannot import name X from agentauth”, you almost always have a path pollution issue, not a missing release.

---

## Integrating with layer 2 and 3

Layer 2 accepts native AgentAuth credentials through the `agentauth` identity adapter:

```python
from agentauth.capabilities.identity_adapters import get_identity_provider

session = get_identity_provider("agentauth").build_session(credential.to_binding_dict())
```

You do not need to change layer 1 code for OIDC, Auth0, SPIRE, or AWS STS — those adapters live in capabilities. Layer 1 remains the **native** stack when you want the full AgentAuth attestation model.

Layer 3 (`wrap_with_identity_session`) accepts the same `IdentitySession` abstraction. See the capabilities doc `docs/cross_layer_integration.md` and the receipts `docs/DEV_GUIDE.md`.

---

## Security and operations notes

**Key management.** Default examples generate Ed25519 keys locally. Production should use a KMS or HSM where policy requires it; the receipts layer has optional KMS providers for signing at rest.

**Clock skew.** JWT validation respects `exp`/`nbf`. Ensure NTP on agents and verifiers.

**Principal binding.** If compliance requires human-in-the-loop authorization, always set `principal` at identify time and verify it appears in downstream receipts.

**Rotation.** Plan for agent key rotation: register a new agent ID or rotate keys with overlap period where both verify.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `ModuleNotFoundError: agentauth.identity` | Package not installed | `pip install -e ".[dev]"` in this repo |
| Wrong code imported | CWD namespace merge | Install via pip; avoid running from monorepo parent |
| Verification fails immediately | Expired credential or clock skew | Re-identify; check system time |
| Biscuit errors on 3.14+ | Unsupported Python | Use 3.10–3.13 |
| Layer 2 import errors | Identity version mismatch | Pin matching tags (`v0.4.0` across stack) |

---

## Releases and versioning

This repo is tagged independently (`v0.4.0`, etc.). **Always tag identity before capabilities and receipts** — downstream `pyproject.toml` files pin this repo by git URL and tag.

Checklist for maintainers:

1. Bump `version` in `pyproject.toml`.
2. Add a `CHANGELOG.md` section.
3. Run tests locally.
4. Tag and push.
5. Only then cut dependent layer releases.

Partners should pin:

```bash
pip install "git+https://github.com/pberlizov/agentauth-identity.git@v0.4.0"
```

---

## Where to go next

- **Scope and commit tokens** → [agentauth-capabilities](https://github.com/pberlizov/agentauth-capabilities/blob/main/docs/DEV_GUIDE.md)
- **Receipts, audit, MCP gateway** → [agentauth-receipts](https://github.com/pberlizov/agentauth-receipts/blob/main/docs/DEV_GUIDE.md)
- **Cross-provider identity** → [capabilities cross_layer_integration.md](https://github.com/pberlizov/agentauth-capabilities/blob/main/docs/cross_layer_integration.md)

If something in this guide does not match the code you checked out, prefer the tagged release you installed and file an issue with the tag name and command you ran.
