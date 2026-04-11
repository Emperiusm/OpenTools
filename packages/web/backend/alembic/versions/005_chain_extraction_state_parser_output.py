"""Chain finding_extraction_state and finding_parser_output web tables.

Mirrors the CLI-only SQLite tables of the same shape (see
``packages/cli/src/opentools/engagement/schema.py`` migration v3):

* ``chain_finding_extraction_state`` — change detection for
  re-extraction. Stores the latest input hash + extractor set seen per
  finding so the pipeline can skip findings whose inputs have not
  changed.
* ``chain_finding_parser_output`` — structured parser output rows keyed
  on ``(finding_id, parser_name)``. Feeds parser-aware extractors.

Both tables are user-scoped via a nullable FK to ``user.id`` so a
PostgresChainStore instance can isolate rows the same way the chain
cache tables already do (spec G37).

Revision ID: 005
Revises: 004
Create Date: 2026-04-11
"""
from alembic import op
import sqlalchemy as sa

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    if "chain_finding_extraction_state" not in existing_tables:
        op.create_table(
            "chain_finding_extraction_state",
            sa.Column("finding_id", sa.String(), nullable=False),
            sa.Column("extraction_input_hash", sa.String(), nullable=False),
            sa.Column(
                "last_extracted_at",
                sa.DateTime(timezone=True),
                nullable=False,
            ),
            sa.Column(
                "last_extractor_set_json",
                sa.LargeBinary(),
                nullable=False,
            ),
            sa.Column(
                "user_id",
                sa.Uuid(),
                nullable=True,
            ),
            sa.ForeignKeyConstraint(["finding_id"], ["finding.id"]),
            sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
            sa.PrimaryKeyConstraint("finding_id"),
        )
        op.create_index(
            "ix_chain_finding_extraction_state_user_id",
            "chain_finding_extraction_state",
            ["user_id"],
        )

    if "chain_finding_parser_output" not in existing_tables:
        op.create_table(
            "chain_finding_parser_output",
            sa.Column("finding_id", sa.String(), nullable=False),
            sa.Column("parser_name", sa.String(), nullable=False),
            sa.Column("data_json", sa.LargeBinary(), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
            ),
            sa.Column(
                "user_id",
                sa.Uuid(),
                nullable=True,
            ),
            sa.ForeignKeyConstraint(["finding_id"], ["finding.id"]),
            sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
            sa.PrimaryKeyConstraint("finding_id", "parser_name"),
        )
        op.create_index(
            "ix_chain_finding_parser_output_user_id",
            "chain_finding_parser_output",
            ["user_id"],
        )


def downgrade() -> None:
    op.drop_index(
        "ix_chain_finding_parser_output_user_id",
        "chain_finding_parser_output",
    )
    op.drop_table("chain_finding_parser_output")
    op.drop_index(
        "ix_chain_finding_extraction_state_user_id",
        "chain_finding_extraction_state",
    )
    op.drop_table("chain_finding_extraction_state")
