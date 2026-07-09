"""Alembic migration environment for clayseal-identity.

The database URL comes from ``CLAYSEAL_DATABASE_URL`` (the same setting the app
uses), normalized to the psycopg driver for Postgres, so ``alembic upgrade head``
always targets the deployment's real database. ``target_metadata`` is the app's
declarative ``Base.metadata`` with every model imported, so autogenerate sees the
full schema.
"""
from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from clayseal.backend import models  # noqa: F401  (register models on Base)
from clayseal.backend.config import get_settings
from clayseal.backend.db import Base, normalize_database_url

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    return normalize_database_url(get_settings().database_url)


def run_migrations_offline() -> None:
    """Emit SQL without a DB connection (``alembic upgrade --sql``)."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live connection."""
    section = config.get_section(config.config_ini_section) or {}
    section["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=connection.dialect.name == "sqlite",
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
