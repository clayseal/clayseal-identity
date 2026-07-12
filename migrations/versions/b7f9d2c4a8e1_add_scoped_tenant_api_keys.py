"""add scoped tenant api keys

Revision ID: b7f9d2c4a8e1
Revises: a1b2c3d4e5f6
Create Date: 2026-07-12 23:05:00.000000+00:00

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "b7f9d2c4a8e1"
down_revision: str | None = "a1b2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("registration_entries", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("min_assurance", sa.String(), nullable=False, server_default="standard")
        )
    op.create_table(
        "tenant_api_keys",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("customer_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("api_key", sa.String(), nullable=False),
        sa.Column("api_key_hash", sa.Text(), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["customer_id"], ["customers.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    with op.batch_alter_table("tenant_api_keys", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_tenant_api_keys_api_key"), ["api_key"], unique=True
        )
        batch_op.create_index(
            batch_op.f("ix_tenant_api_keys_customer_id"), ["customer_id"], unique=False
        )
        batch_op.create_index(
            batch_op.f("ix_tenant_api_keys_status"), ["status"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("tenant_api_keys", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_tenant_api_keys_status"))
        batch_op.drop_index(batch_op.f("ix_tenant_api_keys_customer_id"))
        batch_op.drop_index(batch_op.f("ix_tenant_api_keys_api_key"))
    op.drop_table("tenant_api_keys")
    with op.batch_alter_table("registration_entries", schema=None) as batch_op:
        batch_op.drop_column("min_assurance")
