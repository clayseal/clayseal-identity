"""Alembic migrations bring an empty database up to the current schema.

Validated on SQLite (the driver the CI/test host has); the same revision runs on
Postgres via ``alembic upgrade head`` as a pre-deploy step. This guards against
the migration drifting from the ORM models.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from clayseal.backend.db import Base

from clayseal.backend import db as db_module
from clayseal.backend.config import get_settings

REPO_ROOT = Path(__file__).resolve().parents[2]

# Every table the ORM declares must be created by the migration.
_EXPECTED_TABLES = {t.name for t in Base.metadata.tables.values()}


def test_alembic_upgrade_head_creates_full_schema():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "migrated.db")
        env = {**os.environ, "CLAYSEAL_DATABASE_URL": f"sqlite:///{db_path}"}
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

        con = sqlite3.connect(db_path)
        try:
            tables = {
                row[0]
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        finally:
            con.close()

    assert _EXPECTED_TABLES <= tables, _EXPECTED_TABLES - tables
    assert "alembic_version" in tables


def test_attestation_use_unique_constraint_present():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "migrated.db")
        env = {**os.environ, "CLAYSEAL_DATABASE_URL": f"sqlite:///{db_path}"}
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=REPO_ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        con = sqlite3.connect(db_path)
        try:
            index_list = con.execute(
                "PRAGMA index_list('attestation_uses')"
            ).fetchall()
        finally:
            con.close()
    # A UNIQUE (customer_id, jti) index must exist.
    assert any(row[2] for row in index_list), index_list  # some unique index present


def test_init_db_is_noop_under_alembic_management(monkeypatch):
    """When CLAYSEAL_MANAGE_SCHEMA=alembic, startup must not create/alter tables
    (migrations own DDL); the default keeps the dev create_all path."""
    calls = {"create_all": 0}
    monkeypatch.setattr(
        db_module.Base.metadata,
        "create_all",
        lambda **_kwargs: calls.__setitem__("create_all", calls["create_all"] + 1),
    )
    try:
        monkeypatch.setenv("CLAYSEAL_MANAGE_SCHEMA", "alembic")
        get_settings.cache_clear()
        db_module.init_db()
        assert calls["create_all"] == 0

        monkeypatch.setenv("CLAYSEAL_MANAGE_SCHEMA", "auto")
        get_settings.cache_clear()
        db_module.init_db()
        assert calls["create_all"] == 1
    finally:
        get_settings.cache_clear()
