"""Initial schema: all tables, indexes, FTS trigger.

Revision ID: 001
Revises: None
Create Date: 2026-04-09
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- user ---
    op.create_table(
        "user",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("email", sqlmodel.sql.sqltypes.AutoString(length=320), nullable=False),
        sa.Column("hashed_password", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_superuser", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_verified", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_user_email", "user", ["email"], unique=True)

    # --- engagement ---
    op.create_table(
        "engagement",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("target", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("type", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("scope", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("status", sqlmodel.sql.sqltypes.AutoString(), nullable=False, server_default="active"),
        sa.Column("skills_used", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_engagement_user_id", "engagement", ["user_id"])

    # --- finding ---
    op.create_table(
        "finding",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("engagement_id", sqlmodel.sql.sqltypes.AutoString(), sa.ForeignKey("engagement.id"), nullable=False),
        sa.Column("tool", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("corroborated_by", sa.JSON(), nullable=True),
        sa.Column("cwe", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("severity", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("severity_by_tool", sa.JSON(), nullable=True),
        sa.Column("status", sqlmodel.sql.sqltypes.AutoString(), nullable=False, server_default="discovered"),
        sa.Column("phase", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("title", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("description", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("file_path", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("line_start", sa.Integer(), nullable=True),
        sa.Column("line_end", sa.Integer(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("false_positive", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("dedup_confidence", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_finding_user_id", "finding", ["user_id"])

    # --- timeline_event ---
    op.create_table(
        "timeline_event",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("engagement_id", sqlmodel.sql.sqltypes.AutoString(), sa.ForeignKey("engagement.id"), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("source", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("event", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("details", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("confidence", sqlmodel.sql.sqltypes.AutoString(), nullable=False, server_default="medium"),
        sa.Column("finding_id", sqlmodel.sql.sqltypes.AutoString(), sa.ForeignKey("finding.id"), nullable=True),
    )
    op.create_index("ix_timeline_event_user_id", "timeline_event", ["user_id"])

    # --- ioc ---
    op.create_table(
        "ioc",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("engagement_id", sqlmodel.sql.sqltypes.AutoString(), sa.ForeignKey("engagement.id"), nullable=False),
        sa.Column("ioc_type", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("value", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("context", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("source_finding_id", sqlmodel.sql.sqltypes.AutoString(), sa.ForeignKey("finding.id"), nullable=True),
    )
    op.create_index("ix_ioc_user_id", "ioc", ["user_id"])

    # --- artifact ---
    op.create_table(
        "artifact",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("engagement_id", sqlmodel.sql.sqltypes.AutoString(), sa.ForeignKey("engagement.id"), nullable=False),
        sa.Column("file_path", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("artifact_type", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("description", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("source_tool", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_artifact_user_id", "artifact", ["user_id"])

    # --- audit_entry ---
    op.create_table(
        "audit_entry",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("user.id"), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("command", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("args", sa.JSON(), nullable=True),
        sa.Column("engagement_id", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("result", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("details", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    )
    op.create_index("ix_audit_entry_user_id", "audit_entry", ["user_id"])

    # ── Full-text search: add tsvector column to finding ──
    op.execute(
        "ALTER TABLE finding ADD COLUMN search_vector tsvector"
    )

    # GIN index on search_vector
    op.execute(
        "CREATE INDEX ix_finding_search_vector ON finding USING gin (search_vector)"
    )

    # Trigger function to auto-update search_vector
    op.execute("""
        CREATE FUNCTION finding_search_vector_update() RETURNS trigger AS $$
        BEGIN
            NEW.search_vector :=
                setweight(to_tsvector('english', coalesce(NEW.title, '')), 'A') ||
                setweight(to_tsvector('english', coalesce(NEW.description, '')), 'B') ||
                setweight(to_tsvector('english', coalesce(NEW.evidence, '')), 'C') ||
                setweight(to_tsvector('english', coalesce(NEW.remediation, '')), 'D');
            RETURN NEW;
        END
        $$ LANGUAGE plpgsql;
    """)

    # Attach trigger
    op.execute("""
        CREATE TRIGGER finding_search_vector_trigger
            BEFORE INSERT OR UPDATE ON finding
            FOR EACH ROW
            EXECUTE FUNCTION finding_search_vector_update();
    """)

    # ── Compound indexes ──

    # Finding: user + engagement (common filter)
    op.create_index(
        "ix_finding_user_engagement",
        "finding",
        ["user_id", "engagement_id"],
    )

    # Finding: user + severity (dashboard severity breakdown)
    op.create_index(
        "ix_finding_user_severity",
        "finding",
        ["user_id", "severity"],
    )

    # Finding: dedup lookup (engagement + tool + cwe + file_path + line_start)
    op.create_index(
        "ix_finding_dedup",
        "finding",
        ["engagement_id", "tool", "cwe", "file_path", "line_start"],
    )

    # Finding: user + status (filter active/triaged findings)
    op.create_index(
        "ix_finding_user_status",
        "finding",
        ["user_id", "status"],
    )

    # TimelineEvent: user + engagement + timestamp (timeline view)
    op.create_index(
        "ix_timeline_event_user_engagement_ts",
        "timeline_event",
        ["user_id", "engagement_id", "timestamp"],
    )

    # IOC: unique constraint for upsert (engagement + ioc_type + value)
    op.create_unique_constraint(
        "uq_ioc_engagement_type_value",
        "ioc",
        ["engagement_id", "ioc_type", "value"],
    )

    # Artifact: user + engagement (list artifacts per engagement)
    op.create_index(
        "ix_artifact_user_engagement",
        "artifact",
        ["user_id", "engagement_id"],
    )

    # AuditEntry: user + timestamp (audit log pagination)
    op.create_index(
        "ix_audit_entry_user_timestamp",
        "audit_entry",
        ["user_id", "timestamp"],
    )

    # Engagement: user + status (dashboard listing)
    op.create_index(
        "ix_engagement_user_status",
        "engagement",
        ["user_id", "status"],
    )


def downgrade() -> None:
    # Drop trigger and function first
    op.execute("DROP TRIGGER IF EXISTS finding_search_vector_trigger ON finding")
    op.execute("DROP FUNCTION IF EXISTS finding_search_vector_update()")

    # Drop tables in reverse FK order
    op.drop_table("audit_entry")
    op.drop_table("artifact")
    op.drop_table("ioc")
    op.drop_table("timeline_event")
    op.drop_table("finding")
    op.drop_table("engagement")
    op.drop_table("user")
