from __future__ import annotations

from fastapi.testclient import TestClient

from clayseal.backend.config import get_settings
from clayseal.backend.main import create_app


def test_configured_trusted_hosts_reject_unexpected_host(monkeypatch):
    monkeypatch.setenv("CLAYSEAL_HTTP_ALLOWED_HOSTS", "identity.example.com")
    get_settings.cache_clear()
    try:
        client = TestClient(create_app(), base_url="http://identity.example.com")
        assert client.get("/health").status_code == 200
        assert client.get("/health", headers={"host": "evil.example.com"}).status_code == 400
    finally:
        get_settings.cache_clear()
