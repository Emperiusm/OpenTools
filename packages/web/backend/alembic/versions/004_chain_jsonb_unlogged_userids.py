"""Chain JSONB conversion, UNLOGGED caches, and user_id columns on caches.

Revision ID: 004
Revises: 003
Create Date: 2026-04-11
"""
from alembic import op
import sqlalchemy as sa

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    # chain_extraction_cache — create if not present, else add user_id column.
    if "chain_extraction_cache" not in existing_tables:
        op.create_table(
            "chain_extraction_cache",
            sa.Column("cache_key", sa.String(), nullable=False),
            sa.Column("provider", sa.String(), nullable=False),
            sa.Column("model", sa.String(), nullable=False),
            sa.Column("schema_version", sa.Integer(), nullable=False),
            sa.Column("result_json", sa.LargeBinary(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("user_id", sa.Uuid(), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
            sa.PrimaryKeyConstraint("cache_key"),
        )
        op.create_index(
            "ix_chain_extraction_cache_user_id",
            "chain_extraction_cache",
            ["user_id"],
        )
    else:
        existing_cols = {
            col["name"]
            for col in inspector.get_columns("chain_extraction_cache")
        }
        if "user_id" not in existing_cols:
            op.add_column(
                "chain_extraction_cache",
                sa.Column(
                    "user_id",
                    sa.Uuid(),
                    nullable=True,
                ),
            )

    # chain_llm_link_cache — create if not present, else add user_id column.
    if "chain_llm_link_cache" not in existing_tables:
        op.create_table(
            "chain_llm_link_cache",
            sa.Column("cache_key", sa.String(), nullable=False),
            sa.Column("provider", sa.String(), nullable=False),
            sa.Column("model", sa.String(), nullable=False),
            sa.Column("schema_version", sa.Integer(), nullable=False),
            sa.Column("classification_json", sa.LargeBinary(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("user_id", sa.Uuid(), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
            sa.PrimaryKeyConstraint("cache_key"),
        )
        op.create_index(
            "ix_chain_llm_link_cache_user_id",
            "chain_llm_link_cache",
            ["user_id"],
        )
    else:
        existing_cols = {
            col["name"]
            for col in inspector.get_columns("chain_llm_link_cache")
        }
        if "user_id" not in existing_cols:
            op.add_column(
                "chain_llm_link_cache",
                sa.Column(
                    "user_id",
                    sa.Uuid(),
                    nullable=True,
                ),
            )

    # Postgres-only: convert JSON TEXT columns to JSONB, mark caches UNLOGGED
    # (spec O17). JSONB is a strict superset of JSON TEXT for our use case —
    # orjson-produced bytes round-trip losslessly.
    if dialect == "postgresql":
        op.execute(
            "ALTER TABLE chain_finding_relation "
            "ALTER COLUMN reasons_json TYPE JSONB USING reasons_json::jsonb"
        )
        op.execute(
            "ALTER TABLE chain_finding_relation "
            "ALTER COLUMN confirmed_at_reasons_json TYPE JSONB "
            "USING confirmed_at_reasons_json::jsonb"
        )
        op.execute(
            "ALTER TABLE chain_linker_run "
            "ALTER COLUMN rule_stats_json TYPE JSONB "
            "USING rule_stats_json::jsonb"
        )
        op.execute("ALTER TABLE chain_extraction_cache SET UNLOGGED")
        op.execute("ALTER TABLE chain_llm_link_cache SET UNLOGGED")


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        op.execute("ALTER TABLE chain_llm_link_cache SET LOGGED")
        op.execute("ALTER TABLE chain_extraction_cache SET LOGGED")
        op.execute(
            "ALTER TABLE chain_linker_run "
            "ALTER COLUMN rule_stats_json TYPE TEXT "
            "USING rule_stats_json::text"
        )
        op.execute(
            "ALTER TABLE chain_finding_relation "
            "ALTER COLUMN confirmed_at_reasons_json TYPE TEXT "
            "USING confirmed_at_reasons_json::text"
        )
        op.execute(
            "ALTER TABLE chain_finding_relation "
            "ALTER COLUMN reasons_json TYPE TEXT "
            "USING reasons_json::text"
        )

    # Drop cache tables created by this migration. These did not exist
    # before 004 (they were CLI-only prior) so dropping is correct.
    op.drop_index(
        "ix_chain_llm_link_cache_user_id", "chain_llm_link_cache"
    )
    op.drop_table("chain_llm_link_cache")
    op.drop_index(
        "ix_chain_extraction_cache_user_id", "chain_extraction_cache"
    )
    op.drop_table("chain_extraction_cache")
