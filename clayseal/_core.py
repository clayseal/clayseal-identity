"""Vendored shared-core helpers, so `clayseal-identity` has no private dependency.

This is the complete surface this package used from the internal `agentauth-core`
contracts distribution, copied in so `pip install clayseal-identity` resolves
entirely from public PyPI:

- canonical JSON encoding (hashing/signing/audit linkage),
- path-scope matching (the semantics upper Clay Seal layers evaluate identically),
- the identity-layer production guards, keyed to ``CLAYSEAL_*`` env vars.

The hash and path-matching functions must stay behaviorally identical to their
`agentauth.core` originals — capability and receipt layers evaluate the same
facts, and a drift here would make layers disagree about what a token allows.
Internal CI runs a parity test against a core checkout to enforce this
(see ``sdk/python/tests/test_vendored_core.py``; it skips when core is absent).
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import posixpath
from collections.abc import Callable
from typing import Any

# --- canonical JSON (parity: agentauth.core.hash_util) ---------------------- #


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: Any, *, default: Callable[[Any], Any] | None = None) -> bytes:
    """Canonical JSON encoding (sorted keys, tight separators) as UTF-8 bytes.

    The single canonicalization used across layers for hashing, signing, and audit
    linkage. ``default`` is forwarded to ``json.dumps`` for non-JSON-native values
    (e.g. ``default=str`` to stringify datetimes)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=default
    ).encode("utf-8")


# --- path-scope matching (parity: agentauth.core.path_matching) -------------- #


def normalize_path(path: str) -> str:
    """Canonicalize a path for scope matching: unify separators and collapse ``.`` /
    ``..`` / ``//``. Without this, a denied/allowed pattern can be evaded by a
    non-canonical spelling of the same path (``./secrets/x``, ``a//b``) or escaped with
    traversal (``src/../secrets/x`` matches ``src/*`` but resolves elsewhere)."""
    return posixpath.normpath(path.strip().replace("\\", "/"))


def path_escapes_root(path: str) -> bool:
    """True if the (normalized) path is absolute or climbs above the permitted root."""
    norm = normalize_path(path)
    return norm.startswith("/") or norm == ".." or norm.startswith("../")


def path_matches_any(path: str, patterns: list[str]) -> bool:
    normalized = normalize_path(path)
    for pattern in patterns:
        if fnmatch.fnmatchcase(normalized, pattern.strip()):
            return True
    return False


def evaluate_path_scope(
    file_path: str | None,
    *,
    allowed_paths: list[str],
    denied_paths: list[str],
) -> tuple[bool, str]:
    """Return ``(allowed, reason)`` for a file path against token path facts."""
    if file_path is None:
        return True, "no file path presented"
    # A path that resolves outside the permitted root is never in scope, whatever the
    # allow/deny patterns say.
    if path_escapes_root(file_path):
        return False, f"path {file_path!r} escapes the permitted root"
    if denied_paths and path_matches_any(file_path, denied_paths):
        return False, f"path {file_path!r} matches a denied_path pattern"
    if allowed_paths and not path_matches_any(file_path, allowed_paths):
        return False, f"path {file_path!r} is outside allowed_path patterns"
    return True, "path scope satisfied"


# --- production guards (identity layer, CLAYSEAL_* env) ---------------------- #

DEV_ATTESTOR_ENV = "CLAYSEAL_DEV_ATTESTOR"
UNSAFE_DEV_ATTESTOR_ENV = "CLAYSEAL_ALLOW_REMOTE_DEV_ATTESTOR"

_PRODUCTION_VALUES = frozenset({"production", "prod"})

# Truthy in production => refuse startup.
_PRODUCTION_DENY = (UNSAFE_DEV_ATTESTOR_ENV, DEV_ATTESTOR_ENV)


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def deployment_env() -> str:
    return os.environ.get("CLAYSEAL_ENV", "").strip().lower()


def is_production() -> bool:
    return deployment_env() in _PRODUCTION_VALUES


def production_violations() -> list[str]:
    """Human-readable production policy violations for the identity layer."""
    if not is_production():
        return []

    violations: list[str] = []
    for name in _PRODUCTION_DENY:
        if _env_truthy(name):
            violations.append(f"{name}={os.environ.get(name)}")
    if not os.environ.get("CLAYSEAL_ADMIN_API_KEY", "").strip():
        violations.append("CLAYSEAL_ADMIN_API_KEY is unset")
    cors = os.environ.get("CLAYSEAL_CORS_ORIGINS", "").strip()
    if not cors:
        violations.append("CLAYSEAL_CORS_ORIGINS must be set in production")
    elif "*" in cors.split(","):
        violations.append("CLAYSEAL_CORS_ORIGINS must not include '*' in production")
    return violations


def enforce_production_policy() -> None:
    violations = production_violations()
    if violations:
        raise RuntimeError(
            "production deployment refused to start: " + "; ".join(sorted(violations))
        )


def refuse_dev_attestation_client(*, dev_attestation_enabled: bool) -> None:
    """SDK entrypoints call this when dev attestation is requested."""
    if is_production() and dev_attestation_enabled:
        raise RuntimeError(
            "dev_attestation is not permitted when CLAYSEAL_ENV=production; "
            "use a real attestation path or a non-production environment"
        )
    if is_production() and _env_truthy(UNSAFE_DEV_ATTESTOR_ENV):
        raise RuntimeError(
            f"{UNSAFE_DEV_ATTESTOR_ENV} must be unset in production"
        )
