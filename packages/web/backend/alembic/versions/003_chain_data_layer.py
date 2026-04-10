"""Chain data layer tables.

Revision ID: 003
Revises: 002
Create Date: 2026-04-10
"""
from alembic import op
import sqlalchemy as sa
import sqlmodel

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # chain_entity
    op.create_table(
        "chain_entity",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sqlmodel.sql.sqltypes.GUID(), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("canonical_value", sa.String(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("mention_count", sa.Integer(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("type", "canonical_value", "user_id", name="uq_chain_entity"),
    )
    op.create_index("ix_chain_entity_user_id", "chain_entity", ["user_id"])
    op.create_index("ix_chain_entity_type", "chain_entity", ["type"])

    # chain_entity_mention
    op.create_table(
        "chain_entity_mention",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sqlmodel.sql.sqltypes.GUID(), nullable=False),
        sa.Column("entity_id", sa.String(), nullable=False),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("field", sa.String(), nullable=False),
        sa.Column("raw_value", sa.String(), nullable=False),
        sa.Column("offset_start", sa.Integer(), nullable=True),
        sa.Column("offset_end", sa.Integer(), nullable=True),
        sa.Column("extractor", sa.String(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["entity_id"], ["chain_entity.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entity_id", "finding_id", "field", "offset_start", name="uq_chain_mention"),
    )
    op.create_index("ix_chain_mention_user_id", "chain_entity_mention", ["user_id"])
    op.create_index("ix_chain_mention_entity_id", "chain_entity_mention", ["entity_id"])
    op.create_index("ix_chain_mention_finding_id", "chain_entity_mention", ["finding_id"])
    op.create_index("ix_chain_mention_entity_finding", "chain_entity_mention", ["entity_id", "finding_id"])

    # chain_finding_relation
    op.create_table(
        "chain_finding_relation",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sqlmodel.sql.sqltypes.GUID(), nullable=False),
        sa.Column("source_finding_id", sa.String(), nullable=False),
        sa.Column("target_finding_id", sa.String(), nullable=False),
        sa.Column("weight", sa.Float(), nullable=False),
        sa.Column("weight_model_version", sa.String(), nullable=False, server_default="additive_v1"),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("symmetric", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("reasons_json", sa.Text(), nullable=True),
        sa.Column("llm_rationale", sa.Text(), nullable=True),
        sa.Column("llm_relation_type", sa.String(), nullable=True),
        sa.Column("llm_confidence", sa.Float(), nullable=True),
        sa.Column("confirmed_at_reasons_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["source_finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_finding_id"], ["finding.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source_finding_id", "target_finding_id", "user_id", name="uq_chain_relation"),
    )
    op.create_index("ix_chain_relation_user_id", "chain_finding_relation", ["user_id"])
    op.create_index("ix_chain_relation_source", "chain_finding_relation", ["source_finding_id"])
    op.create_index("ix_chain_relation_target", "chain_finding_relation", ["target_finding_id"])
    op.create_index("ix_chain_relation_status", "chain_finding_relation", ["status"])

    # chain_linker_run
    op.create_table(
        "chain_linker_run",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sqlmodel.sql.sqltypes.GUID(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("scope_id", sa.String(), nullable=True),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("llm_provider", sa.String(), nullable=True),
        sa.Column("findings_processed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("entities_extracted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("relations_created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("relations_updated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("relations_skipped_sticky", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("extraction_cache_hits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("extraction_cache_misses", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("llm_calls_made", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("llm_cache_hits", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("llm_cache_misses", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rule_stats_json", sa.Text(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("generation", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status_text", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_chain_run_user_id", "chain_linker_run", ["user_id"])
    op.create_index("ix_chain_run_generation", "chain_linker_run", ["generation"])


def downgrade() -> None:
    op.drop_index("ix_chain_run_generation", "chain_linker_run")
    op.drop_index("ix_chain_run_user_id", "chain_linker_run")
    op.drop_table("chain_linker_run")
    op.drop_index("ix_chain_relation_status", "chain_finding_relation")
    op.drop_index("ix_chain_relation_target", "chain_finding_relation")
    op.drop_index("ix_chain_relation_source", "chain_finding_relation")
    op.drop_index("ix_chain_relation_user_id", "chain_finding_relation")
    op.drop_table("chain_finding_relation")
    op.drop_index("ix_chain_mention_entity_finding", "chain_entity_mention")
    op.drop_index("ix_chain_mention_finding_id", "chain_entity_mention")
    op.drop_index("ix_chain_mention_entity_id", "chain_entity_mention")
    op.drop_index("ix_chain_mention_user_id", "chain_entity_mention")
    op.drop_table("chain_entity_mention")
    op.drop_index("ix_chain_entity_type", "chain_entity")
    op.drop_index("ix_chain_entity_user_id", "chain_entity")
    op.drop_table("chain_entity")
