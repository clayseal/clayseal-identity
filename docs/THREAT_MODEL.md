# Clay Seal Identity Threat Model

Clay Seal Identity answers one narrow question: **which attested workload is
acting?** It is not a full agent sandbox, policy engine, or audit system by
itself.

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
