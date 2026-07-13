# Changelog

All notable changes to **clayseal-identity** are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Scoped tenant API keys for `admin`, `issuer`, `verifier`, `reader`, and
  `revoker` roles, including SDK helpers and server-side revocation.
- Registration-entry assurance tiers (`low`, `standard`, `high`) so deployments
  can require stronger attestation evidence for sensitive agent types.
- CSR-based X.509-SVID issuance: the SDK now proves possession of the TLS key
  by sending a signed CSR instead of a raw public key.
- Admin audit endpoints for reading and verifying the identity event log.
- Runnable Express.js JWT-SVID verification example
  (`js/clayseal-verify/examples/`) with env-var-driven configuration
  and startup validation.

### Changed

- Offline verifiers now require explicit audience pinning in Python and
  JavaScript helper paths.
- SPIFFE subjects are now per-run
  (`/agent/{type}/run/{agent_id}`), rather than shared by all runs of the same
  agent type.
- Production startup now requires `CLAYSEAL_PUBLIC_BASE_URL` so discovery
  metadata does not depend on inbound Host headers.
- README, deployment docs, and integration examples were tightened for
  open-source users evaluating the repo cold.

## [0.6.0] - 2026-07-10

### Changed

- **JWT-SVID `typ` is now the SPIFFE-standard `"JWT"`** (was `clayseal-svid+jwt`),
  so the default credential is a conformant SPIFFE JWT-SVID that strict
  validators accept. `wit+jwt` remains an opt-in (WIMSE). Verification still
  accepts `JWT`, `JOSE`, `wit+jwt`, and the legacy `clayseal-svid+jwt`, so
  tokens minted before this change keep validating.

### Added

- **SPIFFE X.509-SVIDs for mTLS** (`clayseal/backend/x509_svid.py`). Alongside
  the JWT-SVID, a workload can request a certificate-form SVID with
  `identify(..., request_x509=True)`: the SDK generates an EC P-256 keypair
  locally and receives a spec-conformant leaf certificate (single URI SAN = the
  SPIFFE ID, `digitalSignature` key usage, serverAuth+clientAuth EKU, CA=false)
  signed by a per-tenant EC CA. The trust bundle is published at
  `GET /t/{tenant}/x509-bundle` (PEM) and in `spiffe-bundle.json`
  (`use: x509-svid`). `session.mtls_context()` builds a ready SSLContext; a test
  drives a real mTLS handshake and recovers the peer SPIFFE ID. The JWT-SVID
  keeps its Ed25519 proof-of-possession key; the X.509-SVID uses a TLS-suitable
  EC/RSA key. New table `x509_ca_keys` (migration `a1b2c3d4e5f6`).
- **Real cloud / Kubernetes node attestation** (`clayseal/backend/node_attestors.py`).
  Node attestation now verifies platform-signed evidence a workload cannot forge
  without controlling the node: `gcp_iit` (Google-signed instance identity token,
  verified against Google's keys), `k8s_psat` (projected service-account token,
  verified by the cluster's TokenReview API), and `aws_iid` (EC2 instance
  identity document, RSA-2048 signature against AWS's regional certificate). The
  node token's audience binds the workload key being presented, so evidence
  captured elsewhere cannot bind a different key. Attestors are enabled per
  deployment via `CLAYSEAL_ATTEST_*`. The operator-registered RSA trust anchor
  remains available as static-key attestation for on-prem / bare-metal. This
  replaces the previous simulated-transport model; the trust root is now the
  cloud provider or cluster, not an out-of-band operator key.
- **Framework integrations for OpenClaw and Hermes Agent** (`integrations/`,
  `js/`). `@clayseal/verify` is a JavaScript/TypeScript verifier (offline
  JWT-SVID verification, Biscuit authorization, and Ed25519 proof-of-possession)
  for Node MCP servers and OpenClaw tool plugins — byte-compatible with the
  Python SDK, proven by a cross-language parity test that verifies a
  Python-minted credential. Ships with an OpenClaw permission-hook recipe, an
  agentskills.io skill for Hermes, and a draft proposal to back Hermes's gateway
  permission tiers with Clay Seal capabilities.
- **MCP server authorization** (`clayseal.identity.integrations.mcp_server`,
  behind the new `[mcp]` extra): `ClaySealTokenVerifier` plugs into the
  official MCP SDK's `FastMCP(token_verifier=...)` to verify agent JWT-SVIDs
  offline at the transport (401 + RFC 9728 metadata handled by the SDK), and
  `ToolGuard` authorizes every tool call against the caller's Biscuit
  capability token plus a proof-of-possession of its bound workload key —
  attenuation is honored, path-scoped tokens are enforced on file tools via
  `@guard.require(file_path_arg=...)`, and a stolen token without the key
  authorizes nothing. See `examples/04_mcp_server.py`.
- MCP client helpers now send the capability token and a connection-level
  proof-of-possession (`tool_headers(session, server_url=...)` adds
  `X-ClaySeal-Biscuit` and `X-ClaySeal-PoP` next to the JWT bearer).
- `authorize_biscuit(..., pop_binds_operation=False)` accepts a
  connection-level proof (signed without the operation tuple) while still
  binding it to the token hash, HTTP method, URL, and freshness window.
- Single-use proofs: `ToolGuard` rejects a proof-of-possession reused within
  its freshness window by default, closing same-endpoint replay.
  `InMemoryReplayCache` is provided for single-process servers; supply a
  shared-store implementation across workers, or pass `replay_cache=False` only
  when another layer already enforces replay protection. Endpoint-binding
  prevents cross-service replay.

## [0.5.0] - 2026-07-10

First public release. The open-source readiness pass below includes several
breaking changes relative to the internal 0.4.x line.

### Removed

- **Breaking:** the `clayseal-identity` command-line interface and its console
  script entry point. Token inspection/verification is now library-only via
  `clayseal.identity` (`verify_offline`, `AgentIdentityClaims`).
- Developer/debug tooling: the token profile linter and `explain_token`
  (`profile.py`), the diagnostics module (`doctor`, `preflight`, `scan-mcp`),
  the usability helpers (`whoami`, `diff-token`, `generate`), the `replay-lab`
  sample-token generator, and the `bad-token-zoo/` fixtures that fed the linter.
  These symbols are no longer exported from `clayseal.identity`.

### Added

- `clayseal/_core.py`: the small shared-helper surface (canonical JSON, path-scope
  matching, production guards) is now vendored, so the package has **no private
  dependency** — every runtime dependency resolves from public PyPI. Local
  behavior tests pin the helper semantics without checking out any sibling repo.
- Restored `Credential.to_binding_dict()` (removed in the dead-code prune): it is
  the duck-typed seam the receipts layer's `wrap_agentauth_session` consumes.
  A test now pins the contract's key set.

- Community health files: `SECURITY.md` (private vulnerability reporting),
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS`, issue/PR templates.
- `release.yml` workflow: tag-triggered `python -m build` + PyPI Trusted
  Publishing. CI now runs ruff (lint), an advisory mypy typecheck, and pytest
  with coverage; the layering contract is a dependency-free grep guard.
- `ruff` + `mypy` configuration in `pyproject.toml`.
- JWT attack tests (`alg:none`, RS256→HS256 confusion, unknown-`kid`, key-swap,
  stripped/tampered signatures) for `verify_offline`.
- Bounded exponential-backoff retries in the SDK HTTP transport for transient
  network/5xx failures (idempotent methods; connect errors for all methods).
- Fail-safe warnings when the admin gate is open in non-production and when a
  legacy plaintext API key is accepted; strict mTLS now rejects tokens missing
  `cnf.jkt`. Deployment hardening documented in the threat model.
- Prominent disclosure that the attestation layer is a SPIRE prototype stand-in
  (bring-your-own-attestation) in the README and threat model.

### Changed

- **Breaking:** the FastAPI identity service (`clayseal.backend`) and its heavy
  dependencies (`fastapi`, `uvicorn`, `SQLAlchemy`, `pydantic`, `psycopg`,
  `alembic`) moved behind a `[server]` optional extra. The client SDK
  (`clayseal.identity`) now installs only `httpx`, `biscuit-python`, `PyJWT`,
  and `cryptography`.
- **Breaking (fix):** the production guards (`refuse_dev_attestation_client`,
  `enforce_production_policy`) now key off `CLAYSEAL_ENV` and `CLAYSEAL_*`
  variables. They previously still read `AGENTAUTH_ENV`/`AGENTAUTH_*`, so after
  the env-var rename they silently no-opped under `CLAYSEAL_ENV=production`
  (dev attestation was not refused; admin-key/CORS startup checks did not run).
  Regression tests added.
- The Dockerfile installs `.[server,kms]` — after the `[server]` split it
  installed only `.[kms]` plus uvicorn/psycopg, producing an image without
  FastAPI/SQLAlchemy that could not boot.
- **Breaking:** minimum Python is now 3.11 (was 3.10): it matches the CI matrix,
  and `biscuit-python` ships no macOS wheel for CPython 3.10, which would have
  forced a Rust source build on Mac.
- **Breaking:** tenant API keys are now issued with the `cs_` prefix (was `aa_`).
  No deployed tenants exist, so no old-prefix keys are in circulation;
  `scripts/migrate_api_keys.py` continues to hash whatever plaintext keys it finds.
- Repository moved to the `clayseal` GitHub organization
  (github.com/clayseal/clayseal-identity); all in-repo URLs updated.
- `scripts/bootstrap.sh` rewritten to real setup; `.gitignore` pruned of
  monorepo leftovers; docs corrected (no more `clayseal.wrap`, `clayseal/core/`,
  or a second CLI alias).

### Removed

- **Breaking:** the never-incremented `action_count` field on the agent
  read-model (`AgentOut`) / SDK `AgentInfo`.
- The unwired `clayseal.backend.cimd` module; the non-functional mTLS "direct
  mode"; the advertised-but-rejected public `constraints` field on `Capability`
  (invalid constraints still fail closed); and dead SDK/backend helpers
  (`ClaySeal.biscuit_root_public_key`, `HttpClient.put/delete/context-manager`,
  `AgentSession.can_read_path` / `attenuate_for_task_scope`,
  `mtls.spiffe_id_from_cert`).

### Fixed

- Client-side mTLS transport passed an unsupported `ssl_context=` kwarg to
  `httpx.HTTPTransport`; it now uses `verify=`.
- Grammatical/branding residue ("an ClaySeal") in examples and error messages.

### Known follow-ups

- SDK↔backend mirrors (error hierarchy, offline JWT verify, profile/authorizer
  constants) remain duplicated, guarded by local contract tests; full
  consolidation can move to a public shared module if the layers need it.
- mypy runs advisory: ~30 type nits to burn down. `AuditEvent.customer_id` has no
  FK; timestamp helpers not yet unified.

## [0.5.0] - 2026-07-08

### Added

- `clayseal.identity.verify_offline` for local JWT-SVID verification from a
  tenant JWKS.
- Threat model, conformance guide, and identity profile documentation.
- Agent identity profile linter/explainer and `clayseal-identity` CLI.
- Identity-only FastAPI, MCP, LangChain, and LangGraph-style helpers.
- `doctor`, `preflight`, and `scan-mcp` diagnostics for token metadata,
  endpoint behavior, and MCP configs.
- `/.well-known/agent-identity.json` discovery and a bad-token zoo.
- Friendly CLI workflows: `status`, `whoami`, `diff-token`, `generate`, and
  `replay-lab`.

### Changed

- **Breaking:** renamed the package from `agentauth` to `clayseal` throughout —
  import paths (`clayseal.identity`, `clayseal.backend`, `clayseal.workload_keys`,
  `clayseal.biscuit_scope`), the `ClaySeal`/`ClaySealError` SDK classes, the
  `CLAYSEAL_*` environment variables, the `clayseal-identity` distribution name
  (the `agentauth-identity` console script alias is removed), and the default
  `clayseal-svid+jwt`/`clayseal-pop+jwt` token types and `clayseal.io` trust
  domain.
- README and developer guide now describe the current attestation-backed SDK
  flow and RS256/Ed25519 split accurately.
- Example bootstrap quiets embedded-backend logs for cleaner first-run output.

### Fixed

- SDK/backend `__version__` now matches `pyproject.toml`.

## [0.4.0] - 2026-07-05

### Added

- Repository split from the monolithic `agent-receipts` tree as **layer 1** (identity only).
- `docs/DEV_GUIDE.md` — comprehensive developer guide for operating this layer standalone or as part of the stack.
- GitHub Actions CI (`backend/tests` + `sdk/python/tests` on Python 3.11 and 3.13).
- `project.urls` in `pyproject.toml` for documentation and issue links.

### Changed

- Introduced the receipt-binding contract used by L2/L3 cross-provider integration.
- Import convention: use `from clayseal.identity import ClaySeal` (no top-level `clayseal` package in this repo).

### Fixed

- Broken `session.py` from early split script (restored in v0.3.1).
- Removed unused verifier router that belonged in the receipts layer.

## [0.3.1] - 2026-07-01

### Changed

- Cleanup release after initial three-repo split: import paths, `.gitignore`, test fixes.

## [0.3.0] - 2026-06-30

### Added

- Initial standalone release of the identity layer extracted from Clay Seal Receipts monorepo.
