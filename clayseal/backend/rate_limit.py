"""Lightweight in-memory rate limiting (per client IP and per API key).

This is a *defense-in-depth* limiter, not the authoritative one. Behind multiple
instances each process keeps its own counters, so the effective global limit is
roughly ``N_instances * configured_limit``. In production the authoritative
throttle belongs at the edge -- AWS WAF rate-based rules or the API gateway --
which sees every request regardless of which instance handles it. This limiter
still usefully caps a single instance and covers single-instance/dev deploys.

Two budgets, both env-tunable (see config):

* ``rate_limit_default``  -- ordinary reads.
* ``rate_limit_mutating`` -- stricter; applied to writes (POST/PUT/PATCH/DELETE),
  which is where tenant creation and the RSA/Ed25519 keygen endpoints live.

Disabled by default; on automatically when ``CLAYSEAL_ENV=production`` (or via
``CLAYSEAL_RATE_LIMIT_ENABLED=1``).
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .config import get_settings

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# Liveness/readiness probes must never be throttled -- an orchestrator/ALB polls
# them steadily and a 429 would needlessly flap the instance out of rotation.
_EXEMPT_PATHS = {"/health", "/ready"}


class FixedWindowRateLimiter:
    """A per-key fixed-window counter. Not distributed; see module docstring."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key -> (window_start_epoch, count)
        self._buckets: dict[str, tuple[float, int]] = {}

    def check(self, key: str, *, limit: int, window_seconds: int) -> bool:
        """Record a hit for ``key``; return True if still within ``limit``."""
        if limit <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            window_start, count = self._buckets.get(key, (now, 0))
            if now - window_start >= window_seconds:
                window_start, count = now, 0
            count += 1
            self._buckets[key] = (window_start, count)
            # Opportunistic cleanup so the dict can't grow without bound.
            if len(self._buckets) > 100_000:
                self._evict_stale(now, window_seconds)
            return count <= limit

    def _evict_stale(self, now: float, window_seconds: int) -> None:
        stale = [
            k for k, (start, _c) in self._buckets.items()
            if now - start >= window_seconds
        ]
        for k in stale:
            self._buckets.pop(k, None)

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


# Process-wide limiter instance.
_limiter = FixedWindowRateLimiter()


def reset_rate_limiter() -> None:
    """Clear all counters (test/ops helper)."""
    _limiter.reset()


def _client_ip(request: Request) -> str:
    settings = get_settings()
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return request.client.host if request.client else "unknown"


def _api_key_id(request: Request) -> str | None:
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return None
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]


def _too_many() -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={
            "error": {
                "code": "rate_limited",
                "message": "Too many requests.",
                "suggestion": "Slow down and retry after a short delay.",
            }
        },
    )


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        settings = get_settings()
        if not settings.rate_limit_enabled or request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        limit = (
            settings.rate_limit_mutating
            if request.method in _MUTATING_METHODS
            else settings.rate_limit_default
        )
        window = settings.rate_limit_window_seconds
        scope = "w" if request.method in _MUTATING_METHODS else "r"

        keys = [f"ip:{scope}:{_client_ip(request)}"]
        api_key_id = _api_key_id(request)
        if api_key_id is not None:
            keys.append(f"key:{scope}:{api_key_id}")

        for key in keys:
            if not _limiter.check(key, limit=limit, window_seconds=window):
                return _too_many()
        return await call_next(request)
