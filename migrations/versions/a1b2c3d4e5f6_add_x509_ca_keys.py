"""add x509_ca_keys (per-tenant X.509-SVID certificate authority)

Revision ID: a1b2c3d4e5f6
Revises: 216f3377adf5
Create Date: 2026-07-10

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: str | None = "216f3377adf5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "x509_ca_keys",
        sa.Column("kid", sa.String(), nullable=False),
        sa.Column("customer_id", sa.String(), nullable=False),
        sa.Column("cert_pem", sa.Text(), nullable=False),
        sa.Column("private_pem", sa.Text(), nullable=False),
        sa.Column("algorithm", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("retired_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["customer_id"], ["customers.id"]),
        sa.PrimaryKeyConstraint("kid"),
    )
    with op.batch_alter_table("x509_ca_keys", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_x509_ca_keys_customer_id"), ["customer_id"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("x509_ca_keys", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_x509_ca_keys_customer_id"))
    op.drop_table("x509_ca_keys")
