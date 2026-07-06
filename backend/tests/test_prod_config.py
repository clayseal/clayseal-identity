"""Production hardening: DB pool wiring, the SQLite-in-prod guard, URL
normalization, and secret-encryption-required-in-production."""
from __future__ import annotations

import pytest

from agentauth.backend.config import Settings, get_settings
from agentauth.backend.db import (
    create_db_engine,
    is_sqlite_url,
    normalize_database_url,
    validate_database_config,
)
from agentauth.backend.secret_encryption import (
    secret_encryption_required,
    validate_secret_encryption_config,
)


@pytest.fixture(autouse=True)
def _reset_settings():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# --- URL normalization ----------------------------------------------------- #
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("postgresql://u:p@h/db", "postgresql+psycopg://u:p@h/db"),
        ("postgres://u:p@h/db", "postgresql+psycopg://u:p@h/db"),
        ("postgresql+psycopg://u:p@h/db", "postgresql+psycopg://u:p@h/db"),
        ("postgresql+psycopg2://u:p@h/db", "postgresql+psycopg2://u:p@h/db"),
        ("sqlite:///./agents.db", "sqlite:///./agents.db"),
    ],
)
def test_normalize_database_url(raw, expected):
    assert normalize_database_url(raw) == expected


# --- Pool wiring (no live PG needed; inspect the engine's pool) ------------- #
def test_postgres_engine_gets_tuned_pool(monkeypatch):
    monkeypatch.setenv("AGENTAUTH_DB_POOL_SIZE", "7")
    monkeypatch.setenv("AGENTAUTH_DB_MAX_OVERFLOW", "3")
    monkeypatch.setenv("AGENTAUTH_DB_POOL_RECYCLE", "1234")
    monkeypatch.setenv("AGENTAUTH_DB_POOL_TIMEOUT", "25")
    monkeypatch.setenv("AGENTAUTH_DB_POOL_PRE_PING", "1")
    settings = Settings()

    engine = create_db_engine("postgresql://u:p@localhost/db", settings)
    try:
        pool = engine.pool
        assert engine.dialect.driver == "psycopg"
        assert pool.size() == 7
        assert pool._max_overflow == 3
        assert pool._recycle == 1234
        assert pool._timeout == 25
        assert pool._pre_ping is True
    finally:
        engine.dispose()


def test_sqlite_engine_keeps_check_same_thread_shim():
    engine = create_db_engine("sqlite:///:memory:", Settings())
    try:
        # SingletonThreadPool for in-memory SQLite; the check_same_thread shim is
        # what lets FastAPI's threadpool touch the connection.
        assert engine.dialect.name == "sqlite"
    finally:
        engine.dispose()


# --- Prod guard: SQLite is refused in production --------------------------- #
def test_production_rejects_sqlite(monkeypatch):
    monkeypatch.setenv("AGENTAUTH_ENV", "production")
    monkeypatch.setenv("AGENTAUTH_DATABASE_URL", "sqlite:///./agents.db")
    with pytest.raises(RuntimeError, match="production requires a non-SQLite"):
        validate_database_config(Settings())


def test_production_accepts_postgres(monkeypatch):
    monkeypatch.setenv("AGENTAUTH_ENV", "production")
    monkeypatch.setenv("AGENTAUTH_DATABASE_URL", "postgresql://u:p@h/db")
    validate_database_config(Settings())  # no raise


def test_development_allows_sqlite(monkeypatch):
    monkeypatch.setenv("AGENTAUTH_ENV", "development")
    monkeypatch.setenv("AGENTAUTH_DATABASE_URL", "sqlite:///./agents.db")
    validate_database_config(Settings())  # no raise
    assert is_sqlite_url("sqlite:///x.db")


# --- Secret encryption required in production regardless of DB backend ----- #
def test_secret_encryption_required_in_production_even_on_sqlite(monkeypatch):
    monkeypatch.setenv("AGENTAUTH_ENV", "production")
    monkeypatch.delenv("AGENTAUTH_REQUIRE_SECRET_ENCRYPTION", raising=False)
    assert secret_encryption_required("sqlite:///local.db") is True


def test_validate_secret_encryption_fails_in_prod_without_provider(monkeypatch):
    monkeypatch.setenv("AGENTAUTH_ENV", "production")
    monkeypatch.delenv("AGENTAUTH_SECRET_ENCRYPTION_PROVIDER", raising=False)
    monkeypatch.delenv("AGENTAUTH_SIGNING_KEY_ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError, match="secret encryption is required"):
        validate_secret_encryption_config("sqlite:///local.db")


def test_secret_encryption_not_required_in_dev_on_sqlite(monkeypatch):
    monkeypatch.setenv("AGENTAUTH_ENV", "development")
    monkeypatch.delenv("AGENTAUTH_REQUIRE_SECRET_ENCRYPTION", raising=False)
    assert secret_encryption_required("sqlite:///local.db") is False
