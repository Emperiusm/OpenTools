"""Add chain_calibration_state table.

Revision ID: 007
Revises: 006
"""
import sqlalchemy as sa
from alembic import op

revision = "007"
down_revision = "006"


def upgrade() -> None:
    op.create_table(
        "chain_calibration_state",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("user.id"), nullable=False, index=True),
        sa.Column("rule", sa.String(), nullable=False, index=True),
        sa.Column("alpha", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("beta_param", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("observations", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_calibrated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", "rule", name="uq_calibration_state"),
    )


def downgrade() -> None:
    op.drop_table("chain_calibration_state")
