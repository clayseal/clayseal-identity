"""Shared FastAPI dependencies."""
from __future__ import annotations

import hashlib
import hmac

from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .api_keys import api_key_lookup_prefix, hash_api_key, verify_api_key
from .cache import TTLCache
from .config import get_settings
from .db import get_db
from .errors import InvalidAPIKeyError, InvalidTokenError
from .models import Customer

# Verified-API-key cache: sha256(api_key) -> (customer_id, verified_api_key_hash).
# Authenticating a request runs PBKDF2 (200k iterations) against the stored hash,
# which is deliberately slow; doing it on *every* call is wasteful when the same
# key is presented over and over. Only keys that already passed full PBKDF2
# verification are cached, and on a hit we re-check the customer's *current*
# api_key_hash with a constant-time compare, so a rotated/rehashed key falls out
# of the fast path immediately (bounded further by a short TTL). The cache key is
# a SHA-256 of the raw key, never the key itself.
_settings = get_settings()
_verified_key_cache: TTLCache[str, tuple[str, str]] = TTLCache(
    max_size=_settings.api_key_cache_max_size,
    ttl_seconds=_settings.api_key_cache_ttl_seconds,
)


def clear_api_key_cache() -> None:
    """Drop all cached API-key verifications (test/ops helper)."""
    _verified_key_cache.clear()


def _cache_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def _authenticate_customer(db: Session, x_api_key: str) -> Customer:
    """Full authentication path (runs PBKDF2). Raises on failure."""
    lookup = api_key_lookup_prefix(x_api_key)
    candidates: list[Customer] = []
    if lookup is not None:
        candidates = list(db.scalars(select(Customer).where(Customer.api_key == lookup)).all())
    if not candidates:
        legacy = db.scalar(select(Customer).where(Customer.api_key == x_api_key))
        if legacy is not None:
            if legacy.api_key_hash and verify_api_key(x_api_key, legacy.api_key_hash):
                return legacy
            if legacy.api_key_hash:
                raise InvalidAPIKeyError(
                    "API key is not recognised.",
                    suggestion="Double-check the key from your ClaySeal dashboard.",
                )
            legacy.api_key_hash = hash_api_key(x_api_key)
            legacy.api_key = lookup or legacy.id[:16]
            db.add(legacy)
            db.commit()
            db.refresh(legacy)
            return legacy
    for customer in candidates:
        if verify_api_key(x_api_key, customer.api_key_hash):
            return customer
    raise InvalidAPIKeyError(
        "API key is not recognised.",
        suggestion="Double-check the key from your ClaySeal dashboard.",
    )


def get_current_customer(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> Customer:
    """Resolve the calling tenant from the ``X-API-Key`` header."""
    if not x_api_key:
        raise InvalidAPIKeyError(
            "Missing X-API-Key header.",
            suggestion="Send your ClaySeal API key in the 'X-API-Key' header.",
        )

    cache_key = _cache_key(x_api_key)
    cached = _verified_key_cache.get(cache_key)
    if cached is not None:
        customer_id, verified_hash = cached
        customer = db.get(Customer, customer_id)
        if (
            customer is not None
            and customer.api_key_hash
            and hmac.compare_digest(customer.api_key_hash, verified_hash)
        ):
            return customer
        _verified_key_cache.invalidate(cache_key)

    customer = _authenticate_customer(db, x_api_key)
    if customer.api_key_hash:
        _verified_key_cache.set(cache_key, (customer.id, customer.api_key_hash))
    return customer


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

    from .mtls import cert_public_key_pem
    from clayseal.workload_keys import keyhash_for_pem

    try:
        cert_keyhash = keyhash_for_pem(cert_public_key_pem(cert_der))
    except Exception as exc:
        raise InvalidTokenError(
            "mTLS client certificate public key could not be extracted.",
            suggestion="Ensure the client certificate is a valid X.509 cert.",
        ) from exc

    expected = (claims or {}).get("cnf", {}).get("jkt")
    if expected and cert_keyhash != expected:
        raise InvalidTokenError(
            "mTLS client certificate public key does not match the token's bound key (cnf.jkt).",
            suggestion=(
                "The presented client certificate does not correspond to the workload key "
                "that was bound to this credential."
            ),
        )
