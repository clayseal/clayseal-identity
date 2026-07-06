"""In-memory rate limiting (Blocker 4b): disabled by default, per-IP/per-key,
stricter budget for mutating endpoints."""
from __future__ import annotations

import pytest

from agentauth.backend import rate_limit
from agentauth.backend.config import get_settings
from agentauth.backend.rate_limit import FixedWindowRateLimiter


@pytest.fixture(autouse=True)
def _reset():
    get_settings.cache_clear()
    rate_limit.reset_rate_limiter()
    yield
    get_settings.cache_clear()
    rate_limit.reset_rate_limiter()


def test_fixed_window_limiter_counts_and_resets():
    limiter = FixedWindowRateLimiter()
    assert limiter.check("k", limit=2, window_seconds=60) is True
    assert limiter.check("k", limit=2, window_seconds=60) is True
    assert limiter.check("k", limit=2, window_seconds=60) is False
    # A different key has its own budget.
    assert limiter.check("other", limit=2, window_seconds=60) is True
    # limit<=0 disables.
    assert limiter.check("k", limit=0, window_seconds=60) is True


def test_disabled_by_default(client, customer):
    h = customer["headers"]
    codes = [client.get("/v1/agents", headers=h).status_code for _ in range(10)]
    assert set(codes) == {200}


def test_reads_are_rate_limited_when_enabled(client, customer, monkeypatch):
    h = customer["headers"]
    monkeypatch.setenv("AGENTAUTH_RATE_LIMIT_ENABLED", "1")
    monkeypatch.setenv("AGENTAUTH_RATE_LIMIT_DEFAULT", "3")
    get_settings.cache_clear()
    rate_limit.reset_rate_limiter()

    codes = [client.get("/v1/agents", headers=h).status_code for _ in range(5)]
    assert codes.count(200) == 3
    assert codes[-1] == 429


def test_mutating_endpoints_use_stricter_bucket(client, customer, monkeypatch):
    h = customer["headers"]
    monkeypatch.setenv("AGENTAUTH_RATE_LIMIT_ENABLED", "1")
    monkeypatch.setenv("AGENTAUTH_RATE_LIMIT_MUTATING", "2")
    monkeypatch.setenv("AGENTAUTH_RATE_LIMIT_DEFAULT", "1000")
    get_settings.cache_clear()
    rate_limit.reset_rate_limiter()

    # POST /v1/challenge is a write -> stricter bucket (limit 2).
    write_codes = [client.post("/v1/challenge", headers=h).status_code for _ in range(4)]
    assert 429 in write_codes
    assert write_codes.count(200) == 2

    # Reads are still fine under the generous read budget (separate bucket).
    assert client.get("/v1/agents", headers=h).status_code == 200


def test_health_and_ready_are_exempt(client, monkeypatch):
    monkeypatch.setenv("AGENTAUTH_RATE_LIMIT_ENABLED", "1")
    monkeypatch.setenv("AGENTAUTH_RATE_LIMIT_DEFAULT", "1")
    get_settings.cache_clear()
    rate_limit.reset_rate_limiter()

    # Probes must never be throttled or the orchestrator will flap the instance.
    assert client.get("/health").status_code == 200
    assert client.get("/health").status_code == 200
    assert client.get("/ready").status_code == 200
    assert client.get("/ready").status_code == 200
