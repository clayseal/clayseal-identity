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
| `typ` | `agentauth-svid+jwt` or `wit+jwt` |

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
  "iss": "agentauth.io",
  "sub": "spiffe://agentauth.io/customer/acme/agent/code-reviewer",
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

Use `agentauth.identity.verify_offline` as the reference verifier.
