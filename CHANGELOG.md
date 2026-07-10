# Changelog

All notable changes to **clayseal-identity** are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

Open-source readiness pass. Several changes are breaking and warrant a minor
version bump before release.

### Added

- `clayseal/_core.py`: the small shared-core surface (canonical JSON, path-scope
  matching, production guards) is now vendored, so the package has **no private
  dependency** — every runtime dependency resolves from public PyPI. Internal CI
  runs a `core-parity` job so the vendored helpers cannot drift from their
  `agentauth-core` originals; the parity tests skip on public checkouts.
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
  stripped/tampered signatures) for `verify_offline`, and the `bad-token-zoo`
  fixtures are now wired into the profile linter via a parametrized test.
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
  `Credential.to_binding_dict`, `AgentSession.can_read_path` /
  `attenuate_for_task_scope`, `mtls.spiffe_id_from_cert`).

### Fixed

- Client-side mTLS transport passed an unsupported `ssl_context=` kwarg to
  `httpx.HTTPTransport`; it now uses `verify=`.
- Grammatical/branding residue ("an ClaySeal") in examples and error messages.

### Known follow-ups

- SDK↔backend mirrors (error hierarchy, offline JWT verify, profile/authorizer
  constants) remain duplicated, guarded by a cross-package parity test; full
  consolidation awaits a shared module in `agentauth-core`.
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
  domain. The sibling `agentauth-core` dependency and its `agentauth.core.*`
  namespace are unaffected by this rename.
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

- `session.wrap()` imports `AuthorityBinding` from shared `agentauth.core.authority_binding` (used by L2/L3 cross-provider integration).
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
