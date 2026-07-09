# Clay Seal Agent Identity Profile

The Clay Seal Agent Identity Profile is a small JWT profile for autonomous
agents. It is meant to be useful even when a team does not use the rest of the
Clay Seal stack.

## Goal

Give every agent a token that answers:

- Which agent is this?
- Who or what owns the run?
- Which issuer/trust domain vouched for it?
- Which verifier audience is it meant for?
- Is the token short-lived?
- Is it sender-constrained rather than a plain bearer token?

## Required JOSE Header

| Field | Value |
| --- | --- |
| `alg` | `RS256` |
| `kid` | Key ID present in the tenant JWKS |
| `typ` | `clayseal-svid+jwt` or `wit+jwt` |

## Required Claims

| Claim | Purpose |
| --- | --- |
| `iss` | Issuer / trust domain |
| `sub` | SPIFFE-shaped agent subject |
| `aud` | Tenant or resource audience |
| `exp` | Expiry |
| `iat` | Issued-at timestamp |
| `jti` | Token ID |
| `cnf.jkt` | Sender-constraining workload-key thumbprint |

## Recommended Agent Claims

| Claim | Purpose |
| --- | --- |
| `agent_id` | Stable ID for this issued agent credential |
| `agent_type` | Human-readable agent type, such as `code-reviewer` |
| `owner` | Human or service principal responsible for the run |
| `scope` | Legacy readable scopes, if used |
| `selectors` | Verified workload selectors that matched registration |

## Example

```json
{
  "iss": "clayseal.io",
  "sub": "spiffe://clayseal.io/customer/acme/agent/code-reviewer",
  "aud": "tools-api",
  "iat": 1783575000,
  "exp": 1783575900,
  "jti": "01J...",
  "agent_id": "agent_123",
  "agent_type": "code-reviewer",
  "owner": "alice@example.com",
  "scope": ["repo:read"],
  "selectors": ["k8s:ns:agents", "k8s:sa:reviewer"],
  "cnf": {"jkt": "base64url-thumbprint"}
}
```

## Verification Rules

Verifiers should:

1. Fetch the tenant JWKS.
2. Match the token `kid`.
3. Verify `RS256`, `iss`, `aud`, `exp`, `iat`, and `jti`.
4. Require `cnf.jkt`.
5. Reject unexpected token types.
6. Prefer TTLs of 5 to 15 minutes.

Use `clayseal.identity.verify_offline` as the reference verifier.

## Discovery

Clay Seal Identity services publish the profile at:

```text
/t/{tenant}/.well-known/agent-identity.json
```

Example:

```json
{
  "profile": "clayseal-agent-identity-v1",
  "issuer": "clayseal.io",
  "jwks_uri": "https://identity.example.com/t/acme/jwks.json",
  "openid_configuration_uri": "https://identity.example.com/t/acme/.well-known/openid-configuration",
  "spiffe_bundle_uri": "https://identity.example.com/t/acme/spiffe-bundle.json",
  "supported_token_types": ["clayseal-svid+jwt", "wit+jwt"],
  "proof_of_possession_required": true,
  "recommended_ttl_seconds": 900
}
```
