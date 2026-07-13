"""Process-local fingerprints for sensitive request identifiers.

These values are for in-memory caches and rate-limit buckets only. They are not
password hashes, database identifiers, audit facts, or cross-process stable IDs.
"""
from __future__ import annotations

import hmac
import secrets

_PROCESS_FINGERPRINT_KEY = secrets.token_bytes(32)


def sensitive_fingerprint(value: str, *, length: int | None = None) -> str:
    """Return a keyed, non-reversible fingerprint for a sensitive string."""
    digest = hmac.new(
        _PROCESS_FINGERPRINT_KEY,
        value.encode("utf-8"),
        digestmod="sha256",
    ).hexdigest()
    return digest[:length] if length is not None else digest
