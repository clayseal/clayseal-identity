# Clay Seal Identity Threat Model

Clay Seal Identity answers one narrow question: **which attested workload is
acting?** It is not a full agent sandbox, policy engine, or audit system by
itself.

## Attestation Model — read this first

The attestation layer in this repository is a **prototype stand-in for SPIRE**,
not a production node-attestation system. The backend verifies that an
attestation document is signed by an RSA trust anchor an operator registered
**out-of-band** for the tenant, and derives workload selectors from the document.
It does **not** independently verify live platform evidence (Kubernetes
TokenReview, AWS Instance Identity Documents, GCP Instance Identity Tokens). In
SPIRE terms: the trust decision — does this document chain to a registered
anchor? — is real, but the node/workload attestation *transport* is simulated.

**Implication:** the strength of "which workload is acting" rests on how the
registered anchor's private key is protected and how registration entries are
provisioned. Treat this as **bring-your-own-attestation**: in production, front
issuance with a real SPIRE agent (or equivalent platform attestation) and
pre-register anchors and entries out-of-band. Live cloud/Kubernetes node-attestor
verification is on the roadmap, not implemented here.

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
- **A compromised node attestor private key.** Treat node attestor keys like root
  trust anchors; rotate them and keep blast radius tenant-scoped.
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
