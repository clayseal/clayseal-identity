"""Offline verification helpers for Clay Seal identity tokens.

The hosted API's ``validate`` endpoint checks revocation and proof-of-possession
online. This module covers the verifier-friendly path: a resource server that
has a tenant JWKS and issuer can validate the JWT-SVID locally with standard
JWT rules, then enforce its own sender-constrained presentation policy.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

import jwt

from .errors import InvalidTokenError, TokenExpiredError

# SPIFFE JWT-SVID typ is "JWT" (or "JOSE"); "wit+jwt" is the WIMSE opt-in and
# "clayseal-svid+jwt" is the legacy Clay Seal typ, still accepted for pre-0.6
# tokens.
DEFAULT_ALLOWED_TOKEN_TYPES = ("JWT", "JOSE", "wit+jwt", "clayseal-svid+jwt")
DEFAULT_ALGORITHMS = ("RS256",)


def _keys_from_jwks(jwks: Mapping[str, Any] | Iterable[Mapping[str, Any]]) -> list[dict]:
    if isinstance(jwks, Mapping):
        keys = jwks.get("keys")
        if keys is None and jwks.get("kty"):
            keys = [jwks]
    else:
        keys = list(jwks)
    if not isinstance(keys, list) or not all(isinstance(key, Mapping) for key in keys):
        raise InvalidTokenError(
            "JWKS must be a dict with a 'keys' list, a single JWK, or a list of JWKs.",
            code="invalid_jwks",
            suggestion="Pass the JSON returned by /t/{tenant}/jwks.json.",
        )
    return [dict(key) for key in keys]


def _select_jwk(jwks: Mapping[str, Any] | Iterable[Mapping[str, Any]], kid: str | None) -> dict:
    keys = _keys_from_jwks(jwks)
    if not kid:
        raise InvalidTokenError(
            "Token header is missing kid.",
            suggestion="Pass a Clay Seal JWT-SVID issued by the identity service.",
        )
    matches = [key for key in keys if key.get("kid") == kid]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise InvalidTokenError(
            "JWKS contains multiple keys with the token kid.",
            suggestion="Publish unique key IDs and refresh the verifier JWKS.",
            details={"kid": kid},
        )
    raise InvalidTokenError(
        "No JWKS key matches the token kid.",
        suggestion="Refresh the tenant JWKS or verify you are using the token's tenant.",
        details={"kid": kid},
    )


def verify_offline(
    token: str,
    *,
    jwks: Mapping[str, Any] | Iterable[Mapping[str, Any]],
    issuer: str,
    audience: str | Iterable[str],
    require_cnf: bool = True,
    allowed_token_types: Iterable[str] = DEFAULT_ALLOWED_TOKEN_TYPES,
    algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
    leeway: int | float = 0,
) -> dict[str, Any]:
    """Verify a Clay Seal JWT-SVID without calling the identity service.

    Args:
        token: The credential JWT returned by ``ClaySeal.identify``.
        jwks: Tenant JWKS, usually ``GET /t/{tenant}/jwks.json``.
        issuer: Expected issuer/trust domain.
        audience: Expected audience, usually the tenant/customer ID. Required:
            resource servers must pin the tenant they trust.
        require_cnf: Require a sender-constraining ``cnf.jkt`` claim.
        allowed_token_types: Accepted JOSE ``typ`` values.
        algorithms: Accepted JWT signing algorithms. Defaults to RS256 only.
        leeway: Clock-skew allowance passed to PyJWT.

    Returns:
        Verified claims.

    Raises:
        ``InvalidTokenError`` or ``TokenExpiredError`` with an actionable
        suggestion.
    """
    allowed_algs = tuple(algorithms)
    allowed_types = set(allowed_token_types)
    if audience is None:
        raise InvalidTokenError(
            "Offline verification requires an expected audience.",
            suggestion=(
                "Pass the tenant/customer ID from the token's issuer context. "
                "Audience-less verification is unsafe for resource servers."
            ),
            details={"audience_required": True},
        )
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as exc:
        raise InvalidTokenError(
            "Token is malformed and could not be parsed.",
            suggestion="Pass the full JWT string returned by ClaySeal.identify().",
        ) from exc

    if header.get("alg") not in allowed_algs:
        raise InvalidTokenError(
            "Token uses an unsupported signing algorithm.",
            suggestion=f"Expected one of {sorted(allowed_algs)}.",
            details={"alg": header.get("alg")},
        )
    if header.get("typ") not in allowed_types:
        raise InvalidTokenError(
            "Token type is not a supported Clay Seal identity token.",
            suggestion=f"Expected one of {sorted(allowed_types)}.",
            details={"typ": header.get("typ")},
        )

    jwk = _select_jwk(jwks, header.get("kid"))
    try:
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
        options = {
            "require": ["exp", "iat", "sub", "jti"],
            "verify_aud": True,
        }
        claims = jwt.decode(
            token,
            key=public_key,
            algorithms=list(allowed_algs),
            issuer=issuer,
            audience=audience,
            options=options,
            leeway=leeway,
        )
    except jwt.ExpiredSignatureError as exc:
        raise TokenExpiredError(
            "Token has expired.",
            suggestion="Call identify() again to mint a fresh credential.",
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise InvalidTokenError(
            f"Token failed offline verification: {exc}",
            suggestion="Check issuer, audience, JWKS freshness, and the token's tenant.",
        ) from exc

    if require_cnf and not ((claims.get("cnf") or {}).get("jkt")):
        raise InvalidTokenError(
            "Token is not sender-constrained to a workload key.",
            suggestion="Require Clay Seal credentials minted with workload_pubkey_pem.",
        )
    return claims
