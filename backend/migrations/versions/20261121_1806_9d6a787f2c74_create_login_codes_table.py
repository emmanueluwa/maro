"""create login codes table

Revision ID: 9d6a787f2c74
Revises: 1765c5c47a07
Create Date: 2026-11-21 18:06:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9d6a787f2c74"
down_revision: str | None = "1765c5c47a07"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "login_codes",
        sa.Column(
            "id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("code_hash", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "attempts", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.CheckConstraint(
            "attempts >= 0", name=op.f("ck_login_codes_attempts_not_negative")
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name=op.f("ck_login_codes_expires_after_creation"),
        ),
        sa.CheckConstraint(
            "length(code_hash) = 32",
            name=op.f("ck_login_codes_code_hash_is_hmac_sha256"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_login_codes_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_login_codes")),
    )
    op.create_index(
        op.f("ix_login_codes_user_id"), "login_codes", ["user_id"], unique=False
    )
    # At most one unused code per user, enforced by the database itself.
    op.create_index(
        "uq_login_codes_one_live_code_per_user",
        "login_codes",
        ["user_id"],
        unique=True,
        postgresql_where=sa.text("consumed_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_login_codes_one_live_code_per_user",
        table_name="login_codes",
        postgresql_where=sa.text("consumed_at IS NULL"),
    )
    op.drop_index(op.f("ix_login_codes_user_id"), table_name="login_codes")
    op.drop_table("login_codes")
