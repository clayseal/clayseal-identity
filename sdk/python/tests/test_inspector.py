from __future__ import annotations

from datetime import UTC, datetime

import jwt

from clayseal.identity import TokenInspection, inspect_token


def _token(claims: dict, *, headers: dict | None = None) -> str:
    merged_headers = {"kid": "kid-1", "typ": "JWT"}
    merged_headers.update(headers or {})
    return jwt.encode(
        claims,
        "demo-secret-with-enough-bytes-for-hs256-tests",
        algorithm="HS256",
        headers=merged_headers,
    )


def test_inspect_token_returns_readable_identity_view():
    now = 1_800_000_000
    token = _token(
        {
            "iss": "clayseal.io",
            "sub": "spiffe://clayseal.io/customer/acme/agent/docs-writer",
            "aud": "tools-api",
            "iat": now,
            "exp": now + 900,
            "jti": "jti-1",
            "agent_id": "agent_123",
            "agent_type": "docs-writer",
            "owner": "alice@acme.ai",
            "scope": ["repo:read"],
            "selectors": ["k8s:sa:docs"],
            "cnf": {"jkt": "thumb"},
        }
    )

    inspection = inspect_token(
        token,
        now=datetime.fromtimestamp(now, tz=UTC),
    )

    assert isinstance(inspection, TokenInspection)
    assert inspection.identity.agent_id == "agent_123"
    assert inspection.identity.agent_type == "docs-writer"
    assert inspection.identity.principal == "alice@acme.ai"
    assert inspection.identity.subject.startswith("spiffe://")
    assert inspection.is_sender_constrained is True
    assert inspection.is_expired is False
    assert inspection.expires_in_seconds == 900
    assert inspection.to_dict()["verified"] is False
    assert any("not verification" in warning for warning in inspection.warnings)


def test_inspect_token_warns_on_missing_sender_constraint_and_expiry():
    now = 1_800_000_000
    token = _token(
        {
            "iss": "clayseal.io",
            "sub": "spiffe://clayseal.io/customer/acme/agent/docs-writer",
            "iat": now - 1000,
            "exp": now - 1,
            "jti": "jti-1",
        }
    )

    inspection = inspect_token(
        token,
        now=datetime.fromtimestamp(now, tz=UTC),
    )

    assert inspection.is_sender_constrained is False
    assert inspection.is_expired is True
    assert "missing cnf.jkt sender constraint" in inspection.warnings
    assert "token is expired" in inspection.warnings
