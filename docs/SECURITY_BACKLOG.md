# Clay Seal Security Backlog

This document tracks known hardening work that does not belong entirely inside
the identity layer. Clay Seal Identity is the first released layer: it answers
"who is this agent run, and is the credential valid?" The next layers add
runtime capability scoping, policy enforcement, and receipts.

These are not ignored risks. They are the main places where we expect the stack
to keep improving.

## 1. Harmful Sequences Of Allowed Actions

**Current state.** Identity can prove that an agent run is real, short-lived,
and bound to a workload key. It can also carry simple capability facts. It does
not decide whether a sequence of individually allowed actions is suspicious.

**Example.** An agent allowed to send payments might send two `$999` transfers
to work around a `$1000` review threshold. Each action can look valid in
isolation.

**Planned work.** Layer 2 will handle runtime capability scoping: task-specific
mandates, leases, budgets, and stateful enforcement. Layer 3 will add receipts
that make decisions and actions auditable after the fact.

**What developers should do now.** Use narrow capabilities, short TTLs, and
server-side authorization for important tools. Do not treat identity alone as a
complete sandbox.

## 2. Offline Verification And Revocation

**Current state.** Offline JWT verification can check signature, issuer,
audience, expiry, and sender-constraint claims. It cannot know that a token was
revoked after it was issued.

**Why this matters.** Offline verification is useful for low-latency services,
but it is not the same as a live authorization decision.

**Planned work.** Keep JWT TTLs short by default and make the online validation
path easy for revocation-sensitive workflows. For capability tokens, keep
server-side authorization available when revocation checks matter.

**What developers should do now.** Use `/v1/validate` or server-side capability
authorization for sensitive operations. Use offline verification for lower-risk
paths where short expiry is enough.

## 3. Integration Drift Into "Identity Label Only"

**Current state.** Clay Seal provides safe integration paths that verify the
JWT, require proof-of-possession, and authorize tool calls with `ToolGuard`.
An application can still misuse the library by checking only the JWT and
ignoring proof-of-possession or capability enforcement.

**Why this matters.** A JWT by itself can become a label. The security property
comes from verifying the token and requiring the caller to prove it holds the
bound workload key.

**Planned work.** Make the safe path more obvious in every integration, add
more copy-pasteable examples, and continue adding tests that show stolen-token
and replay failures.

**What developers should do now.** In production integrations, require
proof-of-possession and use `ToolGuard` or an equivalent authorization check
before running sensitive tools.

## 4. Tenant API Key Operational Separation

**Current state.** Clay Seal supports scoped tenant API keys: `admin`,
`issuer`, `verifier`, `reader`, and `revoker`. The bootstrap key returned at
tenant creation has admin authority, but production components can use narrower
keys. Scoped-key revocation is checked on cached auth hits, so a revoked key
does not keep working until the cache TTL expires.

**Why this matters.** Even a scoped key should not live inside prompt-visible
agent context. The safer shape is a control plane, gateway, or sidecar that
keeps tenant credentials out of model-accessible tools and only exposes the
specific operation the agent needs.

**Planned work.** Add more sidecar/control-plane examples, make the scoped-key
workflow more visible in framework integrations, and document incident-response
rotation patterns for leaked issuer/verifier keys.

**What developers should do now.** Keep tenant API keys in a control plane,
gateway, sidecar, or secret store. Do not pass tenant API keys into model
context or arbitrary agent tools. Use `issuer` keys only where credentials are
minted, `verifier` keys only where online validation/authorization is needed,
and `reader` keys for dashboards or inspection surfaces.

## 5. AWS Instance Identity Weakness

**Current state.** GCP instance identity tokens and Kubernetes projected
service-account tokens can bind their audience to the tenant and workload key.
AWS EC2 instance identity documents do not have an audience or expiry in the
same way.

**Why this matters.** AWS IID proves the instance identity, but it does not
bind the evidence to the exact workload key being presented. It is weaker than
the GCP and Kubernetes paths.

**Planned work.** Treat AWS IID as a lower-assurance attestor unless it is
paired with another proof or a strong network boundary. Add deployment guidance
and tests for any stronger AWS pattern we support.

**What developers should do now.** Prefer GCP or Kubernetes attestation when
available. If using AWS IID, deploy behind a trusted network boundary and keep
attestation windows short.

## Release Bar For The Next Layers

Before the runtime capability layer is released publicly, it should be able to
show:

- Task-scoped capability grants that are narrower than the agent's standing
  authority.
- Stateful budget enforcement for cumulative actions.
- Clear handling of denied, suspicious, and review-required actions.
- Receipts that let a developer inspect why an action was allowed or denied.
- Tests that include fragmented payments, replay attempts, stolen tokens, and
  broad-to-narrow delegation.
