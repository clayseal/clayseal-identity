"""Production startup validation for the identity backend."""

from __future__ import annotations

import os

from clayseal._core import enforce_production_policy

from .config import Settings, get_settings
from .db import validate_database_config
from .secret_encryption import validate_secret_encryption_config


def validate_production_startup(settings: Settings | None = None) -> None:
    """Fail fast before serving traffic in production."""
    settings = settings or get_settings()
    validate_database_config(settings)
    validate_secret_encryption_config(settings.database_url)
    if not settings.is_production:
        return
    enforce_production_policy()
    extra = _identity_specific_violations(settings)
    if extra:
        raise RuntimeError(
            "identity production deployment refused to start: " + "; ".join(sorted(extra))
        )


def _identity_specific_violations(settings: Settings) -> list[str]:
    violations: list[str] = []
    if settings.mtls_enabled and not settings.tls_ca_bundle:
        violations.append(
            "CLAYSEAL_MTLS_ENABLED=1 requires CLAYSEAL_TLS_CA_BUNDLE for client verification"
        )
    if settings.secret_encryption_provider.strip().lower() == "aws_kms" and not settings.aws_kms_key_id:
        violations.append("CLAYSEAL_AWS_KMS_KEY_ID is required when using aws_kms encryption")
    if not os.environ.get("CLAYSEAL_HTTP_ALLOWED_HOSTS", "").strip():
        violations.append(
            "CLAYSEAL_HTTP_ALLOWED_HOSTS must list accepted HTTP Host headers"
        )
    if settings.is_production and settings.manage_schema.strip().lower() == "auto":
        violations.append(
            "CLAYSEAL_MANAGE_SCHEMA must be 'alembic' in production (run alembic upgrade head pre-deploy)"
        )
    violations.extend(_unmigrated_api_key_violations())
    return violations


def _unmigrated_api_key_violations() -> list[str]:
    from sqlalchemy import func, select

    from .db import SessionLocal
    from .models import Customer

    with SessionLocal() as session:
        count = session.scalar(
            select(func.count()).select_from(Customer).where(Customer.api_key_hash.is_(None))
        )
    if count:
        return [
            f"{count} tenant(s) lack PBKDF2 api_key_hash; run scripts/migrate_api_keys.py before production traffic"
        ]
    return []
