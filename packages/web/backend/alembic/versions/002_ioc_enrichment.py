"""Add IOC enrichment table.

Revision ID: 002
Revises: 001
Create Date: 2026-04-09
"""
from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "ioc_enrichment",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("ioc_type", sa.String(), nullable=False),
        sa.Column("ioc_value", sa.String(), nullable=False),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("data", sa.String(), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=True),
        sa.Column("tags", sa.String(), nullable=True),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ttl_seconds", sa.Integer(), nullable=False, server_default="86400"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.UniqueConstraint("user_id", "ioc_type", "ioc_value", "provider", name="uq_enrichment"),
    )
    op.create_index("idx_enrichment_user_ioc", "ioc_enrichment", ["user_id", "ioc_type", "ioc_value"])
    op.create_index("idx_enrichment_lookup", "ioc_enrichment", ["ioc_type", "ioc_value"])


def downgrade():
    op.drop_index("idx_enrichment_lookup", "ioc_enrichment")
    op.drop_index("idx_enrichment_user_ioc", "ioc_enrichment")
    op.drop_table("ioc_enrichment")
