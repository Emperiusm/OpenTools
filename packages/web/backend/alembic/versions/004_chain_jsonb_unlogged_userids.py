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

    # Postgres-only: mark cache tables UNLOGGED (spec O17) for faster
    # writes since their contents are regenerable. The earlier draft of
    # this migration also converted reasons_json / confirmed_at_reasons_json
    # / rule_stats_json from TEXT to JSONB, but the SQLModel table
    # declarations still use ``Column(Text)`` and ``PostgresChainStore``
    # writes already-serialized orjson strings, which asyncpg rejects
    # against a JSONB column with ``DatatypeMismatchError: column is of
    # type jsonb but expression is of type character varying``. The
    # columns stay TEXT on Postgres, matching SQLite behavior. No code
    # path uses JSONB-specific operators on these columns, so the
    # conversion was a nice-to-have rather than a requirement.
    if dialect == "postgresql":
        op.execute("ALTER TABLE chain_extraction_cache SET UNLOGGED")
        op.execute("ALTER TABLE chain_llm_link_cache SET UNLOGGED")


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        op.execute("ALTER TABLE chain_llm_link_cache SET LOGGED")
        op.execute("ALTER TABLE chain_extraction_cache SET LOGGED")

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
