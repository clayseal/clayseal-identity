# Changelog

All notable changes to **agentauth-identity** are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.5.0] - 2026-07-08

### Added

- `agentauth.identity.verify_offline` for local JWT-SVID verification from a
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
- Import convention: use `from agentauth.identity import AgentAuth` (no top-level `agentauth` package in this repo).

### Fixed

- Broken `session.py` from early split script (restored in v0.3.1).
- Removed unused verifier router that belonged in the receipts layer.

## [0.3.1] - 2026-07-01

### Changed

- Cleanup release after initial three-repo split: import paths, `.gitignore`, test fixes.

## [0.3.0] - 2026-06-30

### Added

- Initial standalone release of the identity layer extracted from Clay Seal Receipts monorepo.
