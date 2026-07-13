"""Process-local fingerprints for sensitive request identifiers.

These values are for in-memory caches and rate-limit buckets only. They are not
password hashes, database identifiers, audit facts, or cross-process stable IDs.
"""
from __future__ import annotations

import hashlib
import secrets

_PROCESS_FINGERPRINT_KEY = secrets.token_bytes(32)
_FINGERPRINT_ITERATIONS = 50_000


def sensitive_fingerprint(value: str, *, length: int | None = None) -> str:
    """Return a keyed, non-reversible fingerprint for a sensitive string."""
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        value.encode("utf-8"),
        _PROCESS_FINGERPRINT_KEY,
        _FINGERPRINT_ITERATIONS,
        dklen=32,
    ).hex()
    return digest[:length] if length is not None else digest
