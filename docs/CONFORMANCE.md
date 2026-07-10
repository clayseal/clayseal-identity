# Clay Seal Identity Conformance

This repo includes conformance tests for the public identity contract. They are
small on purpose: a verifier should not need Clay Seal internals to decide
whether a token is acceptable.

## Required Token Profile

| Field | Requirement |
| --- | --- |
| JOSE `alg` | `RS256` |
| JOSE `kid` | Must match a tenant JWKS key |
| JOSE `typ` | `clayseal-svid+jwt` or `wit+jwt` |
| `iss` | Expected issuer / trust domain |
| `aud` | Expected tenant or resource audience |
| `sub` | SPIFFE-shaped workload subject |
| `exp`, `iat`, `jti` | Required |
| `cnf.jkt` | Required; credential is sender-constrained |

## Current Test Matrix

| Case | Expected result | Test |
| --- | --- | --- |
| Public OIDC discovery points to tenant JWKS | Accept | `test_openid_configuration_is_public_and_points_at_jwks` |
| Stock PyJWT verifies token from public JWKS | Accept | `test_issued_token_verifies_with_stock_pyjwt_via_public_jwks` |
| SDK `verify_offline` verifies issuer, audience, JWKS, and `cnf` | Accept | `test_offline_verifier_accepts_public_jwks` |
| Wrong audience | Reject | `test_offline_verifier_rejects_wrong_audience` |
| Empty/stale JWKS | Reject | `test_offline_verifier_rejects_stale_jwks` |
| Default token type | `clayseal-svid+jwt` | `test_default_token_typ_unchanged` |
| WIMSE token type | `wit+jwt` with `cnf` | `test_wit_typ_opt_in_mints_wit_shaped_token` |
| Unknown token type | Reject | `test_unknown_token_typ_rejected` |

## How To Run

```bash
pytest backend/tests/test_federation.py -q
pytest backend/tests/test_identity.py backend/tests/test_attestation.py -q
```

For third-party implementers, use `clayseal.identity.verify_offline` as a
reference verifier. It is intentionally only a JWT/JWKS verifier; online
revocation and challenge-based proof-of-possession remain the hosted
`validate()` path.

The machine-readable profile summary lives at
`conformance/token_profile.json`. Static JWT fixtures are deliberately not
checked in because Clay Seal credentials are short-lived; the conformance tests
mint fresh credentials from the real service.
