# Clay Seal Identity Profiles

Identity profiles are copyable deployment shapes. They all end in the same
contract: a short-lived, sender-constrained JWT-SVID plus optional Biscuit
capability facts.

## `local-dev`

Use for demos and tests only.

- SDK: `ClaySeal(..., dev_attestation=True)`
- Backend: embedded or localhost FastAPI service
- Evidence: SDK-generated dev attestation document
- Guardrail: refused for remote services unless explicitly overridden

## `k8s-service-account`

Use when an agent runs as a Kubernetes workload.

- Node evidence: Kubernetes projected service account token or node agent
  signature
- Workload selectors: namespace, service account, pod labels, image digest
- Registration entry: exact namespace/service account + expected labels
- Recommended TTL: 5 to 15 minutes

## `spiffe-spire`

Use when the environment already has SPIRE.

- Node evidence: SPIRE agent trust boundary
- Workload key: SPIFFE workload keypair
- Federation: publish `/t/{tenant}/spiffe-bundle.json`; use
  `/t/{tenant}/x509-bundle` for mTLS trust roots
- Recommended verifier: SPIFFE-aware bundle consumer or JWKS validator

## `aws-workload`

Use for EC2/ECS/EKS workloads that can prove AWS provenance.

- Node evidence: AWS instance identity / workload identity evidence
- Node selectors: account, region, instance or workload identity
- Registration entry: account + region + service selectors
- Recommended verifier: issuer + JWKS + audience pinning

## `gcp-workload`

Use for GCP workloads.

- Node evidence: GCP identity token / instance identity token
- Node selectors: project, zone, service identity
- Registration entry: project + service selectors
- Recommended verifier: issuer + JWKS + audience pinning

## `azure-workload`

Use for Azure workload identity and Entra-adjacent deployments.

- Token format: RS256 JWT-SVID for federation compatibility
- Node/workload evidence: Entra or platform-issued workload claims, normalized
  into registration selectors
- Recommended verifier: OIDC/JWKS verifier with strict issuer and audience
  checks

## Choosing A Profile

Pick the profile matching where the agent process runs. Do not create an agent
identity from prompt text, model name, or an unverified config file. The useful
security property comes from binding the credential to evidence about the actual
workload and to a holder key that must sign each presentation.
