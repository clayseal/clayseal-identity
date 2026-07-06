"""Database engine + session management (SQLAlchemy 2.0).

SQLite is the zero-config default for dev and the test suite. Any other backend
(Postgres in production) is configured via ``AGENTAUTH_DATABASE_URL`` and gets a
tuned connection pool. See :func:`create_db_engine` for the pool knobs.
"""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import Settings, get_settings


class Base(DeclarativeBase):
    pass


def normalize_database_url(url: str) -> str:
    """Pin bare Postgres URLs to the psycopg (v3) driver.

    SQLAlchemy resolves a bare ``postgresql://`` (or ``postgres://``) to
    psycopg2, which we do not depend on. We ship ``psycopg[binary]`` (v3), so
    rewrite those schemes to ``postgresql+psycopg://`` unless the caller already
    named a driver.
    """
    for prefix in ("postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix):]
    return url


def is_sqlite_url(url: str) -> bool:
    return url.startswith("sqlite")


def validate_database_config(settings: Settings | None = None) -> None:
    """Fail fast in production when the DB URL is SQLite.

    SQLite is a single-file, single-writer store with no durability or
    concurrency guarantees suitable for a multi-instance production service.
    """
    settings = settings or get_settings()
    if settings.is_production and is_sqlite_url(normalize_database_url(settings.database_url)):
        raise RuntimeError(
            "AGENTAUTH_ENV=production requires a non-SQLite AGENTAUTH_DATABASE_URL "
            "(e.g. postgresql://user:pass@host/db). SQLite is not a supported "
            "production backend."
        )


def create_db_engine(url: str, settings: Settings | None = None) -> Engine:
    """Build a SQLAlchemy engine with backend-appropriate pooling.

    SQLite keeps the ``check_same_thread`` shim and its default pool. Every other
    backend gets ``pool_pre_ping`` + ``pool_recycle`` + sized ``pool_size`` /
    ``max_overflow`` (all env-overridable) so a long-lived pool survives RDS
    failovers and idle-connection reaping.
    """
    settings = settings or get_settings()
    url = normalize_database_url(url)
    if is_sqlite_url(url):
        return create_engine(
            url,
            connect_args={"check_same_thread": False},
            future=True,
        )
    return create_engine(
        url,
        future=True,
        pool_pre_ping=settings.db_pool_pre_ping,
        pool_recycle=settings.db_pool_recycle,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout,
    )


_settings = get_settings()
engine = create_db_engine(_settings.database_url, _settings)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def init_db() -> None:
    """Create/repair the schema for dev, SQLite, and the test suite.

    When ``AGENTAUTH_MANAGE_SCHEMA=alembic`` this is a no-op: migrations are
    applied out-of-band by ``alembic upgrade head`` and the app must not race to
    create or alter tables at startup. Otherwise we create all tables and add any
    columns the ORM knows about but an existing table lacks.

    Import models so they register on the metadata first.
    """
    from . import models  # noqa: F401

    if get_settings().manage_schema == "alembic":
        return

    Base.metadata.create_all(bind=engine)
    _add_missing_columns()


def _add_missing_columns() -> None:
    """Non-destructive schema sync for the prototype's SQLite store.

    ``create_all`` adds new *tables* but never new *columns* to a table that
    already exists, so a DB created before a model gained a column (e.g. the v2
    identity work added ``agents.spiffe_id`` / ``agents.selectors``) would fail
    on insert with "no such column". For the create_all path (dev/SQLite) we add
    any column the ORM knows about but the table lacks. Existing rows take the
    column's default (NULL, or ``'[]'`` for JSON lists). Columns are only ever
    added — never dropped or altered — so this can't lose data. Production uses
    Alembic instead (see :func:`init_db`).
    """
    from sqlalchemy import inspect, text
    from sqlalchemy.types import JSON

    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    # Order is irrelevant for ADD COLUMN (tables already exist), so iterate the
    # plain table map rather than sorted_tables (which warns on FK cycles).
    for table in Base.metadata.tables.values():
        if table.name not in existing_tables:
            continue  # freshly created by create_all
        existing_cols = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in existing_cols:
                continue
            col_type = col.type.compile(dialect=engine.dialect)
            default = " DEFAULT '[]'" if isinstance(col.type, JSON) else ""
            with engine.begin() as conn:
                conn.execute(
                    text(
                        f'ALTER TABLE "{table.name}" '
                        f'ADD COLUMN "{col.name}" {col_type}{default}'
                    )
                )


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
