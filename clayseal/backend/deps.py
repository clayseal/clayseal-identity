"""Shared FastAPI dependencies."""
from __future__ import annotations

import hmac
import logging
from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .api_keys import api_key_lookup_prefix, hash_api_key, verify_api_key
from .cache import TTLCache
from .config import get_settings
from .db import get_db
from .errors import APIKeyScopeError, InvalidAPIKeyError, InvalidTokenError
from .fingerprints import sensitive_fingerprint
from .models import Customer, TenantApiKey

_logger = logging.getLogger("clayseal.backend.auth")
ALL_TENANT_KEY_SCOPES = frozenset({"admin", "issuer", "verifier", "reader", "revoker"})


@dataclass(frozen=True)
class AuthContext:
    customer: Customer
    scopes: frozenset[str]
    key_id: str
    key_kind: str

# Verified-API-key cache: process-local fingerprint(api_key) -> auth metadata.
# Authenticating a request runs PBKDF2 (200k iterations) against the stored hash,
# which is deliberately slow; doing it on *every* call is wasteful when the same
# key is presented over and over. Only keys that already passed full PBKDF2
# verification are cached, and on a hit we re-check the customer's or scoped key's
# *current* api_key_hash with a constant-time compare, so a rotated/rehashed key
# falls out of the fast path immediately (bounded further by a short TTL). The
# cache key is a process-local PBKDF2 fingerprint of the raw key, never the key
# itself.
_settings = get_settings()
_verified_key_cache: TTLCache[str, tuple[str, str, str, tuple[str, ...], str]] = TTLCache(
    max_size=_settings.api_key_cache_max_size,
    ttl_seconds=_settings.api_key_cache_ttl_seconds,
)


def clear_api_key_cache() -> None:
    """Drop all cached API-key verifications (test/ops helper)."""
    _verified_key_cache.clear()


def _cache_key(api_key: str) -> str:
    return sensitive_fingerprint(api_key)


def _authenticate_customer(db: Session, x_api_key: str) -> AuthContext:
    """Full authentication path (runs PBKDF2). Raises on failure."""
    lookup = api_key_lookup_prefix(x_api_key)
    scoped_candidates: list[TenantApiKey] = []
    customer_candidates: list[Customer] = []
    if lookup is not None:
        scoped_candidates = list(
            db.scalars(
                select(TenantApiKey).where(
                    TenantApiKey.api_key == lookup,
                    TenantApiKey.status == "active",
                )
            ).all()
        )
        customer_candidates = list(
            db.scalars(select(Customer).where(Customer.api_key == lookup)).all()
        )

    for key in scoped_candidates:
        if verify_api_key(x_api_key, key.api_key_hash):
            customer = db.get(Customer, key.customer_id)
            if customer is None:
                break
            return AuthContext(
                customer=customer,
                scopes=frozenset(str(scope) for scope in (key.scopes or [])),
                key_id=key.id,
                key_kind="scoped",
            )

    if not customer_candidates:
        legacy = db.scalar(select(Customer).where(Customer.api_key == x_api_key))
        if legacy is not None:
            if legacy.api_key_hash and verify_api_key(x_api_key, legacy.api_key_hash):
                return AuthContext(
                    customer=legacy,
                    scopes=ALL_TENANT_KEY_SCOPES,
                    key_id=legacy.id,
                    key_kind="bootstrap",
                )
            if legacy.api_key_hash:
                raise InvalidAPIKeyError(
                    "API key is not recognised.",
                    suggestion="Check the API key returned when the tenant was created.",
                )
            _logger.warning(
                "Accepting a legacy plaintext API key for customer %s and "
                "upgrading it to a PBKDF2 hash. Run scripts/migrate_api_keys.py to "
                "migrate all tenants before production traffic.",
                legacy.id,
            )
            legacy.api_key_hash = hash_api_key(x_api_key)
            legacy.api_key = lookup or legacy.id[:16]
            db.add(legacy)
            db.commit()
            db.refresh(legacy)
            return AuthContext(
                customer=legacy,
                scopes=ALL_TENANT_KEY_SCOPES,
                key_id=legacy.id,
                key_kind="bootstrap",
            )
    for customer in customer_candidates:
        if verify_api_key(x_api_key, customer.api_key_hash):
            return AuthContext(
                customer=customer,
                scopes=ALL_TENANT_KEY_SCOPES,
                key_id=customer.id,
                key_kind="bootstrap",
            )
    raise InvalidAPIKeyError(
        "API key is not recognised.",
        suggestion="Check the API key returned when the tenant was created.",
    )


def get_current_auth(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> AuthContext:
    """Resolve the calling tenant from the ``X-API-Key`` header."""
    if not x_api_key:
        raise InvalidAPIKeyError(
            "Missing X-API-Key header.",
            suggestion="Send your ClaySeal API key in the 'X-API-Key' header.",
        )

    cache_key = _cache_key(x_api_key)
    cached = _verified_key_cache.get(cache_key)
    if cached is not None:
        customer_id, verified_hash, key_id, scopes, key_kind = cached
        if key_kind == "bootstrap":
            customer = db.get(Customer, customer_id)
            if (
                customer is not None
                and customer.api_key_hash
                and hmac.compare_digest(customer.api_key_hash, verified_hash)
            ):
                return AuthContext(
                    customer=customer,
                    scopes=frozenset(scopes),
                    key_id=key_id,
                    key_kind=key_kind,
                )
        elif key_kind == "scoped":
            scoped_key = db.get(TenantApiKey, key_id)
            if (
                scoped_key is not None
                and scoped_key.status == "active"
                and scoped_key.customer_id == customer_id
                and hmac.compare_digest(scoped_key.api_key_hash, verified_hash)
            ):
                customer = db.get(Customer, scoped_key.customer_id)
                if customer is not None:
                    return AuthContext(
                        customer=customer,
                        scopes=frozenset(str(scope) for scope in (scoped_key.scopes or [])),
                        key_id=key_id,
                        key_kind=key_kind,
                    )
        _verified_key_cache.invalidate(cache_key)

    auth = _authenticate_customer(db, x_api_key)
    if auth.key_kind == "bootstrap":
        verified_hash = auth.customer.api_key_hash
    else:
        scoped_key = db.get(TenantApiKey, auth.key_id)
        verified_hash = scoped_key.api_key_hash if scoped_key is not None else None
    if verified_hash:
        _verified_key_cache.set(
            cache_key,
            (
                auth.customer.id,
                verified_hash,
                auth.key_id,
                tuple(sorted(auth.scopes)),
                auth.key_kind,
            ),
        )
    return auth


def get_current_customer(auth: AuthContext = Depends(get_current_auth)) -> Customer:
    return auth.customer


def require_scope(scope: str) -> Callable[[AuthContext], Customer]:
    def dependency(auth: AuthContext = Depends(get_current_auth)) -> Customer:
        if "admin" not in auth.scopes and scope not in auth.scopes:
            raise APIKeyScopeError(
                f"API key does not have the required {scope!r} scope.",
                suggestion=(
                    "Use a tenant key with that scope, or create a scoped key from "
                    "an admin key at POST /v1/api-keys."
                ),
                required_scope=scope,
                key_scopes=sorted(auth.scopes),
            )
        return auth.customer

    return dependency


def require_admin(
    x_admin_key: str | None = Header(default=None, alias="X-Admin-Key"),
) -> None:
    """Gate privileged bootstrap operations (e.g. tenant creation).

    When ``CLAYSEAL_ADMIN_API_KEY`` is configured, the caller must present a
    matching ``X-Admin-Key`` header (constant-time compared). When it is *not*
    configured we fail closed in production (an unauthenticated tenant-creation
    endpoint that also does RSA keygen is a DoS/abuse vector) but stay open in
    development so the local/test flow needs no extra setup.
    """
    settings = get_settings()
    admin_key = settings.admin_api_key
    if not admin_key:
        if settings.is_production:
            raise InvalidAPIKeyError(
                "Administrative API key is not configured on this server.",
                suggestion=(
                    "Set CLAYSEAL_ADMIN_API_KEY on the server to enable admin-gated "
                    "operations such as tenant creation."
                ),
            )
        _logger.warning(
            "Admin-gated endpoint reached with no CLAYSEAL_ADMIN_API_KEY configured; "
            "allowing because CLAYSEAL_ENV is not 'production'. Set CLAYSEAL_ADMIN_API_KEY "
            "to require an X-Admin-Key header (fails closed automatically in production)."
        )
        return
    if not x_admin_key or not hmac.compare_digest(x_admin_key, admin_key):
        raise InvalidAPIKeyError(
            "Missing or invalid administrative API key.",
            suggestion="Send the CLAYSEAL_ADMIN_API_KEY value in the 'X-Admin-Key' header.",
        )


def verify_mtls_binding(request: Request, claims: dict | None = None) -> None:
    """When mTLS is enabled, verify the client cert's public key matches the token's cnf.jkt.

    Reuses keyhash_for_pem from clayseal.workload_keys — same thumbprint scheme as PoP.
    Gracefully degrades (no-op) when mtls_enabled is False.
    """
    settings = get_settings()
    if not settings.mtls_enabled:
        return

    cert_der: bytes | None = getattr(request.state, "client_cert_der", None)
    if cert_der is None:
        if settings.mtls_strict:
            raise InvalidTokenError(
                "mTLS client certificate is required but was not presented.",
                suggestion=(
                    "Configure your client with the SPIRE-managed X.509 SVID "
                    "as the mTLS client certificate."
                ),
            )
        return

    from clayseal.workload_keys import keyhash_for_pem

    from .mtls import cert_public_key_pem

    try:
        cert_keyhash = keyhash_for_pem(cert_public_key_pem(cert_der))
    except Exception as exc:
        raise InvalidTokenError(
            "mTLS client certificate public key could not be extracted.",
            suggestion="Ensure the client certificate is a valid X.509 cert.",
        ) from exc

    expected = (claims or {}).get("cnf", {}).get("jkt")
    if claims is not None and not expected and settings.mtls_strict:
        # Clay Seal credentials are always sender-constrained (cnf.jkt). Under
        # strict mTLS, a token with no bound key would let a presented cert go
        # unchecked — fail closed instead of silently accepting it.
        raise InvalidTokenError(
            "Token is not sender-constrained (missing cnf.jkt) but strict mTLS is enabled.",
            suggestion="Present a Clay Seal credential whose cnf.jkt binds the workload key.",
        )
    if expected and cert_keyhash != expected:
        raise InvalidTokenError(
            "mTLS client certificate public key does not match the token's bound key (cnf.jkt).",
            suggestion=(
                "The presented client certificate does not correspond to the workload key "
                "that was bound to this credential."
            ),
        )
