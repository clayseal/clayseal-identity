# Clay Seal Identity Threat Model

Clay Seal Identity answers one narrow question: **which attested workload is
acting?** It is not a full agent sandbox, policy engine, or audit system by
itself.

## Attestation Model — read this first

Node attestation verifies **platform-signed evidence** a workload cannot forge
without controlling the node. Three cloud/cluster attestors verify evidence
against the provider or cluster itself (`clayseal/backend/node_attestors.py`):

- **`gcp_iit`** — a Google-signed instance identity token (JWT, RS256), verified
  against Google's published keys; selectors from the `google.compute_engine`
  block.
- **`k8s_psat`** — a Kubernetes projected service-account token, verified by the
  cluster's **TokenReview** API, which also returns the namespace, service
  account, and pod it is bound to.
- **`aws_iid`** — an EC2 instance identity document plus its RSA-2048 signature,
  verified against AWS's regional public certificate.

**Key binding.** A node token proves the *node*, not the *presenter*. The
audience the workload requests encodes the tenant and the Ed25519 workload key
being bound (`clayseal://<tenant>/attest/<key-thumbprint>`), so a token captured
elsewhere cannot be replayed to bind a different key. GCP and Kubernetes let a
workload choose its token audience, so this is enforced there. An AWS instance
identity document has no audience or expiry: it proves *which instance* is
calling but not freshness or key binding, so pair `aws_iid` with a network trust
boundary; the one-time table still prevents the same document minting twice.

**Static trust anchor (on-prem / bare-metal).** Where there is no cloud metadata
service, an operator can register an RSA trust anchor and the workload presents a
JWT signed by it (`clayseal/backend/attestation.py`) — legitimate static-key
attestation (SPIRE's `x509pop` / join-token model). Its trust root is the
operator's key management: whoever holds the anchor key can vouch for a node, so
protect it like a root key and prefer the platform attestors for cloud workloads.

**Enable per deployment.** Attestors are off until configured (`CLAYSEAL_ATTEST_*`,
see `DEPLOYMENT.md`); an identity service accepts only the clouds/clusters its
operator turns on.

`dev_attestation=True` (SDK) is a local-only convenience that plays both the node
and workload roles; it is refused in production and restricted to localhost
backends.

## Protects Against

- **Agent self-declaration.** A caller cannot choose its own identity by sending
  `agent_type=admin`; identity is derived from verified node/workload evidence
  and a matching registration entry.
- **Stolen bearer-token replay.** Issued credentials carry `cnf.jkt` and require
  proof that the presenter holds the bound Ed25519 workload key.
- **Wrong-tenant verification.** Tokens are audience- and issuer-checked, and
  JWKS keys are tenant-scoped.
- **Attestation replay.** Attestation documents carry `jti` and `exp`; a used
  attestation ID cannot mint another credential for the same tenant.
- **Ambiguous selector mapping.** Equal-specificity registration matches are
  denied instead of silently choosing the wrong identity.

## Does Not Protect Against

- **A legitimate agent doing a harmful but authorized action.** Use layer 2
  capabilities and layer 3 receipts for action-scoped enforcement.
- **Compromise of the workload private key while the credential is live.** Keep
  TTLs short and rotate workload keys.
- **A compromised static trust-anchor private key.** For the on-prem static
  attestor, whoever holds the anchor key can vouch for a node — treat it like a
  root trust anchor, rotate it, keep blast radius tenant-scoped, and prefer the
  cloud/cluster attestors where available.
- **A leaked node token replayed to bind an attacker's key.** Prevented for GCP
  and Kubernetes by the key-bound audience; not prevented for AWS `aws_iid`,
  which has no audience (pair it with a network trust boundary).
- **Prompt injection by itself.** Identity makes downstream decisions attributable
  and sender-constrained, but it does not inspect prompts or model outputs.
- **Transport security.** Run the hosted service behind TLS and use mTLS or
  equivalent network controls for issuance paths.

## Security Invariants

- Workload identity is derived from verified evidence, not caller-supplied
  labels.
- JWT-SVIDs are short-lived and RS256-signed so standard verifiers can consume
  the tenant JWKS.
- Every issued token must be sender-constrained with `cnf.jkt`.
- Online validation of sender-constrained credentials requires a fresh,
  request-bound proof-of-possession.
- Public federation endpoints expose only public key material.

## Operational Defaults

- Use TTLs of 5 to 15 minutes for production agents.
- Pin issuer and audience in every verifier.
- Refresh JWKS on `kid` miss and cache according to your deployment policy.
- Store signing material in KMS or HSM where policy requires it.
- Keep prompts, tool payloads, source code, and business data out of identity
  records; upper layers can bind sensitive payloads by hash when needed.

## Deployment Hardening

Several safeguards are gated on `CLAYSEAL_ENV=production` or a configured key. Do
not rely on a single environment variable being correct — set these explicitly:

- **Admin gate.** Tenant creation (which also generates RSA keys) is gated by
  `CLAYSEAL_ADMIN_API_KEY`. When unset it fails **closed** in production and stays
  open in development (a warning is logged on every open call). Set it for any
  internet-reachable deployment.
- **Legacy API keys.** A tenant whose stored key predates PBKDF2 hashing is
  accepted once and upgraded in place, with a logged warning. Production startup
  refuses to boot while any tenant is unmigrated — run
  `scripts/migrate_api_keys.py` first.
- **mTLS binding.** When mTLS is enabled, the presented client certificate's
  public key must equal the credential's `cnf.jkt`. In strict mode a client
  certificate is required and the credential must be sender-constrained; a token
  without `cnf.jkt` is rejected rather than accepted unbound.
- **Rate limiting and caches are per-process.** Behind multiple instances the
  app-level limiter is not authoritative; also enforce limits at the edge (WAF /
  API gateway).
