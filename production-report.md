# Clay Seal Identity — Production & Open-Source Readiness Report

**Package:** `clayseal-identity` v0.5.0 · **Repo:** `pberlizov/clay-seal-identity` ·
**Audit date:** 2026-07-08 · **Scope:** full repository

---

## Remediation status (updated 2026-07-09)

A remediation pass has since addressed the findings below. Summary (see
`CHANGELOG.md` → *Unreleased* for the full list):

- **Blockers:** B2 (community-health files), B3 (release workflow), B4 (examples
  install), B5 (bootstrap script) — **done**. **B1** (core dep on PyPI) is
  intentionally left to the maintainer, who will publish `agentauth-core` and
  `clayseal-identity` to PyPI; packaging/build/CI are prepared and `python -m
  build` + `twine check` pass.
- **High:** H1–H7 — **done** (attestation disclosed; `_devattest` de-alarmed;
  false doc claims removed; server split behind a `[server]` extra; env-gated
  fallbacks hardened + documented; JWT alg-confusion/downgrade tests + bad-token
  zoo wired; SDK HTTP retries). A real latent bug (client mTLS `ssl_context=`)
  was found and fixed.
- **Demoware / dead code:** deleted per the maintainer's direction (CIMD,
  `action_count`, advertised `constraints`, mTLS direct mode, dead helpers).
  Kept, with rationale: audit read/verify (validate tamper-evidence, test-backed),
  `retention.prune_expired` (real ops CLI), `AgentIdentityVerifier.dependency()`
  (documented public API), identity adapters (public extensibility surface).
- **Medium/Low:** M1 (branding residue), M4 (dead code), M5 (leftovers), M6 (CI
  lint/type/coverage), L1 (env-bool), L3 (`_scopes` helper), L6 — **done**.
- **Tracked follow-ups (not done):** full SDK↔backend de-duplication (M3, guarded
  by a parity test), physical test-tree relocation (M2, docs corrected instead),
  `AuditEvent` FK (L5), timestamp-helper unification (L2), finding-dataclass
  merge (L4), and burning down ~30 advisory mypy nits.

Current gate: **231 tests pass**, `ruff` clean, wheel/sdist build + `twine check`
pass, and the client SDK installs without the server stack.

---

## 1. Executive summary

Clay Seal Identity is **genuinely substantial, competently engineered software — not
demoware in the "fake screenshot" sense.** The backend has fail-fast production
startup guards, KMS envelope encryption, PBKDF2-hashed API keys, a hash-chained audit
log, bounded TTL caches, rate limiting, and mTLS support. The SDK is clean and the
test suite is broad (~185 backend + ~41 SDK tests with real assertions). Supply-chain
CI (CodeQL, pip-audit, gitleaks, Trivy) is already in place.

**However, it is not yet shippable as a public open-source SDK.** The blockers are not
about code *quality* — they are about **shippability, coherence, honesty of claims,
and OSS hygiene**:

- `pip install clayseal-identity` **cannot succeed** from a public index, because its
  pinned core dependency `agentauth-core` is an internal, non-PyPI wheel.
- Several documented features and claims **do not match the code** (a simulated
  attestation model sold as real attestation; docs referencing APIs that don't exist;
  a CLI alias that was removed).
- The repo is **missing every open-source-essential file** (SECURITY.md, CONTRIBUTING,
  etc.) and has **no release/publish pipeline**.
- A bounded set of **demoware, dead code, and duplication** should be cleaned up before
  outsiders read the code.

All findings are tractable. This is a "polish, prune, and be honest" release, not a
rewrite.

### Verdict

Two questions are being conflated. Separating them:

| Question | Answer |
|---|---|
| Can it run reasonably securely in a controlled production deployment? | **Mostly yes** — with the documented limits actually documented (attestation is simulated, rate-limit/caches are per-process, admin gate opens in non-prod). |
| Can an outsider `pip install`, use, and contribute to it today? | **No** — the core dependency is unresolvable from PyPI and the OSS scaffolding is absent. |

**Overall: 🔴 NOT READY for public release.** 5 blocker items; each is S–M effort.
Estimated path to a credible `v1.0-rc`: blockers + the High-severity honesty fixes.

---

## 2. Scorecard

| Dimension | Rating | One-line rationale |
|---|:---:|---|
| Installability | 🔴 Red | Core dep `agentauth-core` not on PyPI; `examples/requirements.txt` references a non-existent `[server]` extra. |
| Runtime security posture | 🟡 Yellow | Strong guards, but attestation is simulated and several fallbacks (admin gate, plaintext key path, mTLS binding) are only safe in `CLAYSEAL_ENV=production`. |
| Honesty of claims | 🔴 Red | Attestation oversold; docs reference non-existent `clayseal.wrap` / `clayseal/core/`; false CLI-alias claim. |
| Code health / duplication | 🟡 Yellow | Well-written, but SDK↔backend logic is mirrored and kept in sync only by a test. |
| Dead code | 🟡 Yellow | Bounded but real: whole modules (`clayseal/backend/cimd.py`) and several methods are unreachable at runtime. |
| Demoware | 🟡 Yellow | Persistence implied but absent (`action_count`, audit read/verify); inert features shipped. |
| Documentation | 🟡 Yellow | Much of it is excellent and code-anchored; contaminated by a few false/aspirational claims. |
| Tests | 🟡 Yellow | Broad and real, but missing JWT algorithm-confusion / downgrade negative tests for a security SDK. |
| CI / release | 🔴 Red | No publish workflow; no lint/format/type-check; no coverage; external-contributor PRs likely fail. |
| OSS hygiene | 🔴 Red | No SECURITY.md, CONTRIBUTING, CODE_OF_CONDUCT, CODEOWNERS, issue/PR templates. |
| Repo cleanliness | 🟢 Green | No committed caches/build artifacts; `.gitignore`/`.dockerignore` correct; versions consistent (0.5.0 everywhere). |

---

## 3. Findings by severity

Each finding: **evidence** (`file:line`) · **why it matters** · **recommendation**.

### 🔴 Blockers — must fix before any public release

**B1 · Core dependency is not installable from PyPI.**
`pyproject.toml:13` pins `agentauth-core>=0.5,<0.6`, but `deploy/requirements.in:1-5`
states it is "the internal `agentauth-core` distribution … installed from its built
wheel," and CI checks out `pberlizov/clay-seal-core` to build it (`.github/workflows/ci.yml:18,31`).
It is not importable in a clean environment.
*Why:* `pip install clayseal-identity` from PyPI fails to resolve its own core
dependency — the single hardest gate on an OSS SDK release.
*Recommendation:* choose one and document it: (a) publish `agentauth-core` to PyPI
(preferred), (b) vendor the small set of used helpers into this repo, or (c) ship
explicitly as a git-based install with a loud install-doc caveat and a
`pip install git+…` one-liner that actually works end-to-end.

**B2 · Missing every open-source-essential file.**
Absent: `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS`,
`.github/ISSUE_TEMPLATE/`, `.github/PULL_REQUEST_TEMPLATE.md`.
*Why:* For a **security-critical identity SDK**, a vulnerability-disclosure policy
(`SECURITY.md`) is effectively mandatory — outsiders must know how to report a flaw
privately. The rest set contribution norms.
*Recommendation:* add all six. `SECURITY.md` is itself a blocker; the others are
quick wins.

**B3 · No release / publish pipeline.**
`.github/workflows/` contains only `ci.yml`, `codeql.yml`, `security.yml`.
*Why:* Nothing builds or publishes the wheel/sdist; there is no tag-triggered release.
An "SDK release" with no release automation is incomplete (and is blocked by B1 until
the dependency is resolvable anyway).
*Recommendation:* add a tag-triggered workflow (`hatchling build` +
`pypa/gh-action-pypi-publish`, ideally Trusted Publishing) once B1 is resolved.

**B4 · Broken examples install file.**
`examples/requirements.txt:11` pins `-e ..[server]`, but **no `server` extra exists**
(`pyproject.toml:39-45` defines only `dev` and `kms`). The same file then redundantly
re-lists the backend runtime deps at lines 14-19.
*Why:* `pip install -r examples/requirements.txt` — the documented way to run the
examples — fails outright. First-run experience is broken.
*Recommendation:* create the `[server]` extra (see H4) or replace line 11 with `-e ..`;
drop the redundant lines 14-19 once the extra carries them.

**B5 · Stale `scripts/bootstrap.sh` is entirely broken.**
`scripts/bootstrap.sh` installs a non-existent `[mcp,dev]` extra (line 9), runs
`cargo build -p agent-receipts-cli` (13), `arctl doctor` (19), and points at
`examples/partner_pilot.py` (24) — none of the Rust prover, `arctl`, `crates/`, or
that example exist in this repo. It is a leftover from a different monorepo.
*Why:* A contributor running the repo's own bootstrap script hits an immediate
failure. Signals an unfinished repo split.
*Recommendation:* rewrite to the actual setup (`python -m venv`, `pip install -e ".[dev]"`,
`pytest`) or delete it.

### 🟠 High — fix before claiming "production-ready" / v1.0

**H1 · The headline "attested identity" is a simulated SPIRE stand-in.**
`clayseal/backend/attestation.py:1-26` explicitly documents that it replaces SPIRE's
two-stage node/workload attestation with a single admin-registered RSA-anchor-signed
JWT, and that "the transport is simulated." There is no live Kubernetes TokenReview,
AWS Instance Identity Document, or GCP Instance Identity Token verification.
Relatedly, the PoP-binding key is *self-asserted* inside the attestation document
(`clayseal/backend/identity.py:616` reads `workload_pubkey_pem` from the doc's
`workload` block).
*Why:* "Cryptographically attested identity for autonomous agents" (README) is the
core value proposition. Shipping a simulated attestor without prominent disclosure is
the most serious honesty-of-claims risk in the repo.
*Recommendation:* prominently disclose the current attestation model and its trust
assumptions in the README and THREAT_MODEL (which already hints at it); frame the
current path as "bring-your-own-attestation / SPIRE-shaped" and clearly mark real
node-attestor integration as roadmap.

**H2 · `clayseal/identity/_devattest.py` ships in the wheel headed `#TODO Remove in production !!!`.**
`clayseal/identity/_devattest.py:1` opens with that comment; the module self-registers
a node trust anchor + registration entry and signs its own attestation JWT
(`:127-208`). `dev_attestation=True` is the **first line a new user copies** — it
appears in the SDK quickstart docstring (`clayseal/identity/__init__.py:7`, which also
still uses the old-brand `api_key="aa_..."`).
*Mitigations that exist:* runtime is guarded to localhost and refused in production via
an external `refuse_dev_attestation_client` guard (`clayseal/identity/client.py:73-75`) plus a
localhost check (`clayseal/identity/client.py:141-165`). But an escape hatch,
`CLAYSEAL_ALLOW_REMOTE_DEV_ATTESTOR=1` (`clayseal/identity/client.py:151`), can point dev attestation at
a remote backend.
*Why:* A production-forbidden module with a self-flagged TODO, surfaced in the first
example, undermines confidence even though the runtime is guarded.
*Recommendation:* remove the alarming header comment (replace with the accurate
docstring already present below it); make the quickstart's default the *non*-dev path
and show `dev_attestation=True` only in a clearly-labeled "local demo" aside; document
or remove the remote escape hatch.

**H3 · Docs describe APIs and layout that do not exist.**
`docs/DEV_GUIDE.md:220-227` shows `import clayseal; clayseal.wrap(session, model, policy=…)`
— but no top-level `clayseal` export ships (the wheel bundles `clayseal/identity` and
`clayseal/backend` only; README:154 confirms there is no top-level export). The same
guide references `from agentauth.capabilities.identity_adapters import …` (`:297-305`,
a layer-2 package not in this repo) and lists `clayseal/core/` in the layout table
(`:276`) — that directory does not exist. Separately, `docs/DEV_GUIDE.md:187` and
`docs/CLI.md:20` claim a second CLI alias, but `pyproject.toml:36-37` defines exactly
one script and `CHANGELOG.md:28` says the alias was removed.
*Why:* Copy-pasteable docs that fail are worse than no docs; they erode trust fast in
an OSS audience.
*Recommendation:* remove or clearly mark cross-layer/aspirational snippets; fix the
layout table; delete the false alias claim.

**H4 · SDK-only users are forced to install the full server stack.**
`pyproject.toml:12-27` puts `fastapi`, `uvicorn[standard]`, `SQLAlchemy`,
`pydantic`, `psycopg[binary]`, and `alembic` in **mandatory** `dependencies`, and the
wheel bundles `clayseal/backend` (`pyproject.toml:50-56`).
*Why:* A consumer who only wants the client (`clayseal.identity`) pulls a whole web
server, a Postgres driver, and migration tooling. Heavy and surprising for an SDK.
*Recommendation:* move server-only deps and the `clayseal/backend` package behind a
`[server]` extra (which also fixes B4); keep the client's runtime deps minimal
(`httpx`, `PyJWT`, `cryptography`, `biscuit-python`, `agentauth-core`).

**H5 · Security fallbacks that are only safe in `CLAYSEAL_ENV=production`.**
Each is gated by `clayseal/backend/production.py`, but a mis-set environment silently exposes them:
- Admin endpoint open when `CLAYSEAL_ADMIN_API_KEY` unset — `require_admin` is a no-op
  outside production (`clayseal/backend/deps.py:114-125`); `POST /v1/customers`
  (which also does RSA keygen) is then unauthenticated.
- Legacy plaintext API-key acceptance: rows with `api_key_hash IS NULL` accept a raw
  string match and silently rehash (`clayseal/backend/deps.py:49-63`).
- mTLS binding is a no-op when the token lacks `cnf.jkt` (`clayseal/backend/deps.py:166-168`);
  a cert can be present-but-unbound and still pass.
*Why:* Defense-in-depth should not depend on a single env var being correct.
*Recommendation:* document these precisely in THREAT_MODEL; consider failing closed
for the admin gate whenever no key is set (regardless of env), and log a warning on
the plaintext-key path.

**H6 · No JWT algorithm-confusion / downgrade tests for a token-verification SDK.**
The test suite has no `alg:none`, RS256→HS256 confusion, `kid` confusion, or
signature-stripping cases (verified by grep). `bad-token-zoo/cases.json` (no-audience,
no-cnf, long-ttl, wrong-typ, missing-metadata) is **referenced by no test** — it is
demo-only, so those unsafe shapes are never asserted against the linter/verifier.
*Why:* Algorithm confusion is the classic JWT vulnerability class; a security identity
SDK must prove it rejects these.
*Recommendation:* add negative tests driving `verifier.verify_offline` and the backend
`validate_token` with each attack shape; wire `bad-token-zoo/cases.json` into a
parametrized test so the "zoo" is enforced, not decorative.

**H7 · No retry/backoff in the SDK HTTP layer.**
`clayseal/identity/_http.py` sets timeouts (default 30s) but has zero retry logic for
transient 5xx/network errors; CLI/diagnostics fetches likewise time-out-only.
*Why:* Production SDKs are expected to tolerate transient failures.
*Recommendation:* add bounded exponential-backoff retries for idempotent GETs and
network errors.

### 🟡 Medium — quality, maintainability, coherence

**M1 · Brand / namespace split (three names for the core).**
Brand is "Clay Seal"; package/import is `clayseal`; the core dependency is
`agentauth-core` imported as `agentauth.core.*` and sourced from repo `clay-seal-core`.
`docs/DEV_GUIDE.md` even names L2/L3 "agentauth-capabilities / agentauth-receipts" in
prose while linking `clay-seal-*` URLs. Grammatical rename residue remains
("an ClaySeal", "ClaySeal backend" in `examples/03_federation.py:1`, `examples/common.py`).
*Recommendation:* decide the end-state (finish the rename to `clayseal-core` /
`clayseal.core`, or explicitly keep and document the split), then make prose/URLs
consistent. Fix the grammatical residue.

**M2 · `sdk/python/` has tests but no source tree.**
`sdk/python/tests/` exists with 7 test files, but there is no `sdk/python/` source —
tests import from the root `clayseal.*`. `pyproject.toml:59` glues the two test trees
via `testpaths`. `docs/DEV_GUIDE.md:276` lists it as if a sibling source tree exists.
*Recommendation:* either relocate SDK tests next to `clayseal/identity/` (e.g.
`tests/sdk/`) or document why the split exists; fix the layout table.

**M3 · SDK↔backend duplication kept in sync only by a test.** (See §5 for the full
list.) The capability authorizer policy, the entire error hierarchy, offline JWT
verification, and the agent-identity profile constants are mirrored across the SDK and
backend. A parity test guards the crypto policy, but the rest can silently drift.
*Recommendation:* lift the shared contracts (error codes, profile constants, authorizer
policy string) into the `agentauth-core` (or a new shared) module and import from both.

**M4 · Dead code should be pruned before outsiders read it.** (Full inventory in §6.)
Whole module `clayseal/backend/cimd.py` and several methods are unreachable at runtime.
*Recommendation:* delete, or wire up and test, each item.

**M5 · Orphaned monorepo leftovers.**
`config/partner.example.yaml` describes a fraud-decision / receipts policy engine
(`mode: shadow|recommend|bounded_auto|prove`, `model_provenance_hash`) irrelevant to an
identity SDK; `.gitignore` carries dead rules (`crates/…`, `dashboard/`, `/receipts/`,
`/proofs/`) and ignores `SECURITY_AUDIT.md`; `scripts/migrate_api_keys.py:34` still
keys off the legacy `aa_<lookup>.<secret>` format.
*Recommendation:* remove the orphaned config and dead ignore rules; keep the migration
script (functional) but note the legacy-format handling.

**M6 · CI has no lint / format / type-check / coverage, and misstates itself.**
No `ruff`/`black`/`mypy` job anywhere; no coverage upload. `.github/workflows/security.yml:3`
comments that it is "additive to ci.yml (lint/test/layering)" — but `ci.yml` performs
no lint. External-contributor PRs likely fail because CI checks out the private
`pberlizov/clay-seal-core` and runs a `agentauth.core.layering` contract
(`ci.yml:18,31`) that forks/PRs can't authenticate.
*Recommendation:* add a `ruff` + `mypy` job and coverage; fix the inaccurate comment;
make the core checkout resilient for forks (or gate that job to internal branches).

### 🟢 Low — polish

- **L1** — Inconsistent env-bool parsing accepts different truthy sets: `clayseal/backend/config.py:12-16`
  and `clayseal/backend/secret_encryption.py:34-35` accept `{1,true,yes,on}` with `strip`, but the inline
  mTLS parsing (`clayseal/backend/config.py:122-131`) accepts `{1,true,yes}` without `on`/`strip`. So
  `CLAYSEAL_MTLS_ENABLED=on` behaves differently from `CLAYSEAL_RATE_LIMIT_ENABLED=on`.
  *Fix:* route all through one helper.
- **L2** — Three ad-hoc "UTC now / Z-suffix" timestamp conventions (`clayseal/backend/models.py:21-23`,
  `clayseal/backend/audit.py:71`, `clayseal/backend/identity.py:337`). *Fix:* one helper.
- **L3** — `_scopes()` copy-pasted across four adapters (`clayseal/identity/adapters/oidc.py:10-14`,
  `clayseal/identity/adapters/gcp.py:10-14`, `clayseal/identity/adapters/spiffe.py:10-14`, `clayseal/identity/adapters/azure.py:10-13`). *Fix:* one shared function.
- **L4** — Two identical finding dataclasses, `DiagnosticFinding` (`clayseal/identity/diagnostics.py:13-20`)
  and `LintFinding` (`clayseal/identity/profile.py:75-82`), with converter shims between them. *Fix:* merge.
- **L5** — `AuditEvent.customer_id` (`clayseal/backend/models.py:270`) is an indexed `String` with no FK
  to `customers`, unlike every other table. *Fix:* add the FK (or document the choice).
- **L6** — `clayseal/identity/verifier.py:23-24` has a redundant `keys = None` immediately overwritten.

---

## 4. Positives worth preserving (do not "clean up")

- **Fail-fast production validation** (`clayseal/backend/production.py`) refuses to
  start on SQLite, missing secret-encryption, `auto` schema management, or unmigrated
  API keys in production. This is exactly right.
- **Secret encryption at rest** with pluggable local-AES-GCM / AWS-KMS / GCP-KMS
  providers (`clayseal/backend/secret_encryption.py`), lazy-imported boto3.
- **Hash-chained, tamper-evident audit log** (`clayseal/backend/audit.py`) — the design is sound (its
  gap is exposure (§6, §7), not correctness).
- **PBKDF2 API-key hashing** with a verified-key cache to avoid re-hashing hot paths.
- **Substantive, code-anchored docs**: THREAT_MODEL, PRIVACY, FEDERATION, CONFORMANCE,
  IDENTITY_PROFILES — several cite exact tests and `conformance/token_profile.json`.
- **Broad, real test suite** (~185 backend + ~41 SDK tests) driving in-process HTTP,
  including a cross-package PoP crypto-parity test.
- **Supply-chain CI**: CodeQL + pip-audit + gitleaks + Trivy, with Dependabot.
- **Clean repo**: no committed caches/build artifacts; consistent `0.5.0` across
  `pyproject.toml`, both `__init__.py` files, and CHANGELOG.

---

## 5. Duplicate code

**SDK ↔ backend mirrors** (kept in sync by convention/tests, can drift):

| What | SDK | Backend | Guarded by |
|---|---|---|---|
| Biscuit authorizer policy string | `clayseal/identity/_capabilities.py:52-57` | `clayseal/backend/capabilities.py:93-97` | parity test only |
| PoP / attenuate / authorize primitives | `clayseal/identity/_capabilities.py:60-206` | `clayseal/backend/capabilities.py` | parity test |
| Full error hierarchy + `code` strings | `clayseal/identity/errors.py:11-108` | `clayseal/backend/errors.py:11-107` | nothing (signatures already diverge) |
| Offline JWT verification + messages | `clayseal/identity/verifier.py:88-141` | `clayseal/backend/identity.py:640-708` | nothing |
| Agent-identity profile constants | `clayseal/identity/profile.py:14-20` | `clayseal/backend/routers/federation.py:73-90` | nothing |

**Intra-repo duplication:**

- API-key SHA-256 identity: `clayseal/backend/deps.py:39` vs `clayseal/backend/rate_limit.py:97`.
- Key-lifecycle logic (create/retire/re-encrypt): `clayseal/backend/identity.py:121-172` (signing keys)
  vs `clayseal/backend/capabilities.py:195-238` (biscuit root keys).
- `verify_request_pop(...)` kwargs assembled twice: `clayseal/backend/identity.py:746-760` vs
  `clayseal/backend/capabilities.py:537-551`.
- `PopProof`-from-`body.pop` block identical: `clayseal/backend/routers/identity.py:219-228` vs `:354-363`.
- PoP-envelope construction in the SDK: `clayseal/identity/session.py:95-115` vs `:147-167`.
- Plus L1 (env-bool), L2 (timestamps), L3 (`_scopes`), L4 (finding dataclasses).

*Recommendation:* the SDK↔backend mirrors are the ones that matter — consolidate into a
shared module. The intra-repo copies are small helper extractions.

---

## 6. Dead / unnecessary code

Real code that is unreachable at runtime (consumed only by tests, or not at all):

| Symbol | Location | Reachability |
|---|---|---|
| `clayseal/backend/cimd.py` (entire module) | `clayseal/backend/cimd.py` | Imported only by `backend/tests/test_cimd.py`; no router wires CIMD in. |
| `audit.read_events`, `audit.verify_event_log` | `clayseal/backend/audit.py:104,118` | Test-only; no endpoint reads/verifies the chain. |
| `mtls.spiffe_id_from_cert` | `clayseal/backend/mtls.py:30-40` | Never called in backend code. |
| `capabilities.attenuate_biscuit` | `clayseal/backend/capabilities.py:372-409` | Dead server-side (attenuation is client-side). |
| `retention.prune_expired` | `clayseal/backend/retention.py` | Never scheduled; CLI/tests only (module admits scheduling is out of scope). |
| `ClaySeal.biscuit_root_public_key()` | `clayseal/identity/client.py:210-219` | No caller; `session` uses the credential attribute instead. Dead cache field too. |
| `HttpClient.put/delete/__enter__/__exit__` | `clayseal/identity/_http.py:50-54,101-105` | No callers. |
| `Credential.to_binding_dict` | `clayseal/identity/models.py:51-67` | No in-repo caller. |
| `session.can_read_path`, `session.attenuate_for_task_scope` | `clayseal/identity/session.py:188-192,235-243` | No callers in package/tests/examples. |
| `AgentIdentityVerifier.dependency()` + unused `Header` import | `clayseal/identity/integrations/fastapi.py:29,52-68` | Classmethod untested/unused; import unused in scope. |
| `clayseal/identity/adapters/*` (azure/gcp/oidc/spiffe/static) | `clayseal/identity/adapters/` | Real code, but nothing in the client/session/verifier flow consumes them — only re-exports + `sdk/python/tests/test_identity_adapters.py`. |

*Recommendation:* for each, **delete** or **wire up + test**. `clayseal/backend/cimd.py` and the audit
read/verify functions are the interesting ones — they look like shipped features (see §7).

---

## 7. Demoware (impressive-looking but inert, or persistence-implied-but-absent)

| Item | Evidence | Reality | Suggested disposition |
|---|---|---|---|
| `action_count` per agent | defined `clayseal/backend/models.py:249`, returned `clayseal/backend/schemas.py:198`, migrated `migrations/versions/216f3377adf5_initial_schema.py:68` | **Never incremented anywhere** — the dashboard always shows 0. | Wire up on authorize/validate, or remove the field. |
| Tamper-evident audit log | written throughout `clayseal/backend/identity.py`/`clayseal/backend/capabilities.py` | Persisted but **no read/verify endpoint** (see §6). Compliance value is implied, not exposed. | Add an admin read/verify endpoint, or scope down the claim. |
| CIMD / MCP client identification | full module `clayseal/backend/cimd.py` | **Unwired** to any route — reads as a feature, does nothing at runtime. | Integrate into the MCP/OAuth path, or remove. |
| `Capability.constraints` | `clayseal/backend/schemas.py:54-63`, rejected at `clayseal/backend/capabilities.py:124-133` | Advertised in the **public schema** only to raise "not supported yet." | Remove from the public schema until implemented. |
| mTLS "direct mode" | `clayseal/backend/mtls.py:79-84` | Reads `scope["transport"]`, a key ASGI/uvicorn never sets — non-functional. Only proxy-header mode works. | Remove direct mode or fix; correct the class docstring. |
| Agent expiry | `clayseal/backend/identity.py:692-699` | Only eventually-correct: `status="expired"` is a side effect of validating an already-expired token; no sweep, so agents can stay `active` forever. | Add a sweep job, or document the semantics. |
| CLI `generate` | `clayseal/identity/usability.py:113-216` | Prints entirely static template strings per framework; no project detection. | Fine as a snippet generator — label it as such. |
| CLI `replay-lab` | `clayseal/identity/usability.py:219-294` | Functional, but a self-contained demo over a hardcoded fixture (`cnf.jkt: "demo-thumbprint"`), not the user's tokens. | Keep, but document it as a learning fixture. |
| CLI `scan-mcp` | `clayseal/identity/diagnostics.py:147-192` | Shallow heuristic string-matching (HTTP vs HTTPS, `Bearer ` presence, `TOKEN/KEY/SECRET` substrings); does not connect to any server. | Keep; set expectations in docs. |
| Examples | `examples/common.py:120-160` boots the full backend in-process; `02_capabilities.py:21,66-69` reaches into private internals (`_capabilities`, `_workload_private_pem`) | The default demo is self-contained, not client→remote-service; `02` isn't representative public usage. | Add a "real remote service" example; keep the embedded one labeled as a demo. |

Note: `preflight` (`clayseal/identity/diagnostics.py:86-144`) is **not** demoware — it makes real
unauthenticated / malformed-token requests and asserts 401/403. (It only checks status
codes, not rejection reason — a minor enhancement.)

---

## 8. Prioritized remediation roadmap

Effort: **S** ≤ half-day · **M** ≈ 1–2 days · **L** > 2 days.

### Release blockers (do first — repo cannot ship without these)
1. **[B1, M/L]** Resolve `agentauth-core` distribution: publish to PyPI, vendor, or
   commit to a working git-install story. *Everything else depends on this.*
2. **[B2, S]** Add `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS`,
   issue/PR templates.
3. **[B4, S]** Fix `examples/requirements.txt` (`[server]` extra or `-e ..`).
4. **[B5, S]** Rewrite or delete `scripts/bootstrap.sh`.
5. **[B3, M]** Add a tag-triggered build+publish workflow (after B1).

### Before a "production-ready" / v1.0 claim
6. **[H1, S]** Disclose the simulated attestation model in README + THREAT_MODEL; reframe
   as BYO-attestation / roadmap.
7. **[H3, S]** Remove/mark false & aspirational doc claims (`clayseal.wrap`, `clayseal/core/`,
   the CLI alias, cross-layer imports).
8. **[H2, S]** De-alarm `clayseal/identity/_devattest.py`; make the quickstart default the non-dev path;
   fix the `aa_...` residue; resolve the remote escape hatch.
9. **[H4, M]** Split server deps + `clayseal/backend` behind a `[server]` extra.
10. **[H6, M]** Add JWT alg-confusion/downgrade negative tests; wire `bad-token-zoo` into tests.
11. **[H5, S]** Document (and, where cheap, harden) the env-gated security fallbacks.
12. **[H7, S]** Add retry/backoff to the SDK HTTP layer.

### Cleanup (quality — schedule after the above)
13. **[M4/§6, M]** Delete or wire-up dead code; resolve the demoware items in §7
    (especially `action_count`, `Capability.constraints`, mTLS direct mode, CIMD).
14. **[M3/§5, M]** Consolidate SDK↔backend duplication into a shared module.
15. **[M1, M]** Resolve the brand/namespace split; fix grammatical residue.
16. **[M2, S]** Fix the `sdk/python/` layout smell.
17. **[M5, S]** Remove orphaned monorepo leftovers.
18. **[M6, M]** Add ruff/mypy/coverage CI; fix the inaccurate `security.yml` comment;
    make CI resilient for external contributors.
19. **[L1–L6, S]** Minor helper extractions and the FK / redundant-line polish.

---

## 9. Appendix

**Repo stats:** 129 tracked files · 8,005 LOC Python source (`clayseal/`) · 4,182 LOC
tests · 10 docs (~1.1k lines) + logo. Largest source files: `clayseal/backend/identity.py`
(886), `clayseal/backend/capabilities.py` (589), `clayseal/backend/routers/identity.py` (378), `clayseal/identity/cli.py`
(366).

**Audit method:** static analysis only — three parallel read-only passes (backend, SDK,
supporting material) plus firsthand reads of `pyproject.toml`, `README.md`,
`clayseal/backend/config.py`, `clayseal/backend/production.py`, `clayseal/identity/_devattest.py`, `clayseal/identity/__init__.py`,
`examples/requirements.txt`, `scripts/bootstrap.sh`, and targeted greps to confirm
reachability (e.g. `action_count` mutation, `bad-token-zoo` references, `[server]`
extra, `agentauth-core` importability). All `file:line` citations were spot-verified.

**Not covered / limitations:** No code was executed — the `agentauth-core` dependency
is not installed in the audit environment, so `pip install`, `pytest`, and the example
scripts were **not** run here. Security findings are static-analysis-grounded, not
runtime-verified. No dynamic fuzzing, dependency-CVE triage beyond noting CI already
runs pip-audit/Trivy, or performance/load testing was performed. This report is a code
& repository audit, not a formal cryptographic or penetration review — an independent
security review is recommended before promoting the "attested identity" claim.
