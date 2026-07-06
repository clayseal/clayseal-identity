"""Tenant creation is admin-gated (Blocker 4a)."""
from __future__ import annotations

import pytest

from agentauth.backend.config import get_settings


@pytest.fixture(autouse=True)
def _reset_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_customer_creation_open_in_dev_without_admin_key(client):
    resp = client.post("/v1/customers", json={"name": "Open Dev"})
    assert resp.status_code == 201, resp.text


def test_customer_creation_requires_admin_key_when_configured(client, monkeypatch):
    monkeypatch.setenv("AGENTAUTH_ADMIN_API_KEY", "s3cret-bootstrap")
    get_settings.cache_clear()

    missing = client.post("/v1/customers", json={"name": "No Key"})
    assert missing.status_code == 401

    wrong = client.post(
        "/v1/customers", json={"name": "Wrong Key"}, headers={"X-Admin-Key": "nope"}
    )
    assert wrong.status_code == 401

    ok = client.post(
        "/v1/customers",
        json={"name": "Right Key"},
        headers={"X-Admin-Key": "s3cret-bootstrap"},
    )
    assert ok.status_code == 201, ok.text


def test_customer_creation_refused_in_production_without_admin_key(client, monkeypatch):
    monkeypatch.setenv("AGENTAUTH_ENV", "production")
    monkeypatch.delenv("AGENTAUTH_ADMIN_API_KEY", raising=False)
    get_settings.cache_clear()

    resp = client.post("/v1/customers", json={"name": "Prod No Admin"})
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "invalid_api_key"
