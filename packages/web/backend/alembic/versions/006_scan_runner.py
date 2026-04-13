# packages/web/backend/alembic/versions/006_scan_runner.py
"""Scan runner tables.

Adds tables for scan orchestration: scans, tasks, raw findings,
dedup findings, events, suppression rules, FP memory, output cache,
tool effectiveness, and scan metrics.

Follows the spec section 6.1 table definitions.

Revision ID: 006
Revises: 005
Create Date: 2026-04-12
"""
from alembic import op
import sqlalchemy as sa

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    # -- scan --
    if "scan" not in existing_tables:
        op.create_table(
            "scan",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("engagement_id", sa.String(), nullable=False),
            sa.Column("target", sa.String(), nullable=False),
            sa.Column("target_type", sa.String(), nullable=False),
            sa.Column("resolved_path", sa.String(), nullable=True),
            sa.Column("target_metadata", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("profile", sa.String(), nullable=True),
            sa.Column("profile_snapshot", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("mode", sa.String(), nullable=False, server_default="auto"),
            sa.Column("status", sa.String(), nullable=False, server_default="pending"),
            sa.Column("config", sa.Text(), nullable=True),
            sa.Column("baseline_scan_id", sa.String(), nullable=True),
            sa.Column("tools_planned", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("tools_completed", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("tools_failed", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("finding_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("estimated_duration_seconds", sa.Integer(), nullable=True),
            sa.Column("metrics", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("user_id", sa.Uuid(), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_scan_engagement_id", "scan", ["engagement_id"])
        op.create_index("ix_scan_status", "scan", ["status"])
        op.create_index("ix_scan_user_id", "scan", ["user_id"])

    # -- scan_task --
    if "scan_task" not in existing_tables:
        op.create_table(
            "scan_task",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("scan_id", sa.String(), nullable=False),
            sa.Column("name", sa.String(), nullable=False),
            sa.Column("tool", sa.String(), nullable=False),
            sa.Column("task_type", sa.String(), nullable=False),
            sa.Column("command", sa.Text(), nullable=True),
            sa.Column("mcp_server", sa.String(), nullable=True),
            sa.Column("mcp_tool", sa.String(), nullable=True),
            sa.Column("mcp_args", sa.Text(), nullable=True),
            sa.Column("depends_on", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("reactive_edges", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("status", sa.String(), nullable=False, server_default="pending"),
            sa.Column("priority", sa.Integer(), nullable=False, server_default="50"),
            sa.Column("tier", sa.String(), nullable=False, server_default="normal"),
            sa.Column("resource_group", sa.String(), nullable=True),
            sa.Column("retry_policy", sa.Text(), nullable=True),
            sa.Column("cache_key", sa.String(), nullable=True),
            sa.Column("parser", sa.String(), nullable=True),
            sa.Column("tool_version", sa.String(), nullable=True),
            sa.Column("exit_code", sa.Integer(), nullable=True),
            sa.Column("stdout", sa.Text(), nullable=True),
            sa.Column("stderr", sa.Text(), nullable=True),
            sa.Column("output_hash", sa.String(), nullable=True),
            sa.Column("duration_ms", sa.Integer(), nullable=True),
            sa.Column("cached", sa.Boolean(), nullable=False, server_default="0"),
            sa.Column("isolation", sa.String(), nullable=False, server_default="none"),
            sa.Column("spawned_by", sa.String(), nullable=True),
            sa.Column("spawned_reason", sa.String(), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["scan_id"], ["scan.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_scan_task_scan_id", "scan_task", ["scan_id"])
        op.create_index("ix_scan_task_status", "scan_task", ["status"])

    # -- raw_finding --
    if "raw_finding" not in existing_tables:
        op.create_table(
            "raw_finding",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("scan_task_id", sa.String(), nullable=False),
            sa.Column("scan_id", sa.String(), nullable=False),
            sa.Column("tool", sa.String(), nullable=False),
            sa.Column("raw_severity", sa.String(), nullable=False),
            sa.Column("title", sa.String(), nullable=False),
            sa.Column("canonical_title", sa.String(), nullable=True),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("file_path", sa.String(), nullable=True),
            sa.Column("line_start", sa.Integer(), nullable=True),
            sa.Column("line_end", sa.Integer(), nullable=True),
            sa.Column("url", sa.String(), nullable=True),
            sa.Column("evidence", sa.Text(), nullable=True),
            sa.Column("evidence_quality", sa.String(), nullable=False),
            sa.Column("evidence_hash", sa.String(), nullable=False),
            sa.Column("cwe", sa.String(), nullable=True),
            sa.Column("location_fingerprint", sa.String(), nullable=False),
            sa.Column("location_precision", sa.String(), nullable=False),
            sa.Column("parser_version", sa.String(), nullable=False),
            sa.Column("parser_confidence", sa.Float(), nullable=False),
            sa.Column("raw_output_excerpt", sa.Text(), nullable=True),
            sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("causal_chain", sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(["scan_id"], ["scan.id"]),
            sa.ForeignKeyConstraint(["scan_task_id"], ["scan_task.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_raw_finding_scan_id", "raw_finding", ["scan_id"])
        op.create_index("ix_raw_finding_scan_task_id", "raw_finding", ["scan_task_id"])
        op.create_index("ix_raw_finding_tool", "raw_finding", ["tool"])

    # -- dedup_finding --
    if "dedup_finding" not in existing_tables:
        op.create_table(
            "dedup_finding",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("engagement_id", sa.String(), nullable=False),
            sa.Column("finding_id", sa.String(), nullable=True),
            sa.Column("fingerprint", sa.String(), nullable=False),
            sa.Column("raw_finding_ids", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("tools", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("corroboration_count", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("confidence_score", sa.Float(), nullable=False),
            sa.Column("severity_consensus", sa.String(), nullable=False),
            sa.Column("canonical_title", sa.String(), nullable=False),
            sa.Column("cwe", sa.String(), nullable=True),
            sa.Column("location_fingerprint", sa.String(), nullable=False),
            sa.Column("location_precision", sa.String(), nullable=False),
            sa.Column("evidence_quality_best", sa.String(), nullable=False),
            sa.Column("previously_marked_fp", sa.Boolean(), nullable=False, server_default="0"),
            sa.Column("suppressed", sa.Boolean(), nullable=False, server_default="0"),
            sa.Column("suppression_rule_id", sa.String(), nullable=True),
            sa.Column("status", sa.String(), nullable=False, server_default="discovered"),
            sa.Column("last_confirmed_scan_id", sa.String(), nullable=True),
            sa.Column("last_confirmed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("first_seen_scan_id", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_dedup_finding_engagement_id", "dedup_finding", ["engagement_id"])
        op.create_index("ix_dedup_finding_first_seen_scan", "dedup_finding", ["first_seen_scan_id"])
        op.create_index("ix_dedup_finding_fingerprint", "dedup_finding", ["fingerprint"])
        op.create_index("ix_dedup_finding_cwe", "dedup_finding", ["cwe"])

    # -- finding_correlation --
    if "finding_correlation" not in existing_tables:
        op.create_table(
            "finding_correlation",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("engagement_id", sa.String(), nullable=False),
            sa.Column("scan_id", sa.String(), nullable=False),
            sa.Column("finding_ids", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("correlation_type", sa.String(), nullable=False),
            sa.Column("narrative", sa.Text(), nullable=False),
            sa.Column("severity", sa.String(), nullable=False),
            sa.Column("kill_chain_phases", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["scan_id"], ["scan.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_finding_correlation_engagement", "finding_correlation", ["engagement_id"])
        op.create_index("ix_finding_correlation_scan", "finding_correlation", ["scan_id"])

    # -- remediation_group --
    if "remediation_group" not in existing_tables:
        op.create_table(
            "remediation_group",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("engagement_id", sa.String(), nullable=False),
            sa.Column("scan_id", sa.String(), nullable=False),
            sa.Column("action", sa.Text(), nullable=False),
            sa.Column("action_type", sa.String(), nullable=False),
            sa.Column("finding_ids", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("findings_count", sa.Integer(), nullable=False),
            sa.Column("max_severity", sa.String(), nullable=False),
            sa.Column("effort_estimate", sa.String(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["scan_id"], ["scan.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_remediation_group_engagement", "remediation_group", ["engagement_id"])

    # -- suppression_rule --
    if "suppression_rule" not in existing_tables:
        op.create_table(
            "suppression_rule",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("scope", sa.String(), nullable=False),
            sa.Column("engagement_id", sa.String(), nullable=True),
            sa.Column("rule_type", sa.String(), nullable=False),
            sa.Column("pattern", sa.String(), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("created_by", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_suppression_rule_scope", "suppression_rule", ["scope"])
        op.create_index("ix_suppression_rule_engagement", "suppression_rule", ["engagement_id"])

    # -- fp_memory --
    if "fp_memory" not in existing_tables:
        op.create_table(
            "fp_memory",
            sa.Column("target", sa.String(), nullable=False),
            sa.Column("fingerprint", sa.String(), nullable=False),
            sa.Column("cwe", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.PrimaryKeyConstraint("target", "fingerprint", "cwe"),
        )

    # -- finding_annotation --
    if "finding_annotation" not in existing_tables:
        op.create_table(
            "finding_annotation",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("finding_fingerprint", sa.String(), nullable=False),
            sa.Column("engagement_id", sa.String(), nullable=True),
            sa.Column("annotation_type", sa.String(), nullable=False),
            sa.Column("value", sa.Text(), nullable=False),
            sa.Column("created_by", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_finding_annotation_fingerprint", "finding_annotation", ["finding_fingerprint"])

    # -- scan_event --
    if "scan_event" not in existing_tables:
        op.create_table(
            "scan_event",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("scan_id", sa.String(), nullable=False),
            sa.Column("type", sa.String(), nullable=False),
            sa.Column("sequence", sa.Integer(), nullable=False),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
            sa.Column("task_id", sa.String(), nullable=True),
            sa.Column("data", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("tasks_total", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("tasks_completed", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("tasks_running", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("findings_total", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("elapsed_seconds", sa.Float(), nullable=False, server_default="0"),
            sa.Column("estimated_remaining_seconds", sa.Float(), nullable=True),
            sa.ForeignKeyConstraint(["scan_id"], ["scan.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_scan_event_scan_seq", "scan_event", ["scan_id", "sequence"])

    # -- steering_log_entry --
    if "steering_log_entry" not in existing_tables:
        op.create_table(
            "steering_log_entry",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("scan_id", sa.String(), nullable=False),
            sa.Column("sequence", sa.Integer(), nullable=False),
            sa.Column("action", sa.String(), nullable=False),
            sa.Column("reasoning", sa.Text(), nullable=False),
            sa.Column("context_snapshot", sa.Text(), nullable=True),
            sa.Column("new_tasks", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["scan_id"], ["scan.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_steering_log_scan", "steering_log_entry", ["scan_id"])

    # -- scan_attestation --
    if "scan_attestation" not in existing_tables:
        op.create_table(
            "scan_attestation",
            sa.Column("scan_id", sa.String(), nullable=False),
            sa.Column("findings_hash", sa.String(), nullable=False),
            sa.Column("profile_hash", sa.String(), nullable=False),
            sa.Column("tool_versions", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("signature", sa.String(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["scan_id"], ["scan.id"]),
            sa.PrimaryKeyConstraint("scan_id"),
        )

    # -- output_cache --
    if "output_cache" not in existing_tables:
        op.create_table(
            "output_cache",
            sa.Column("cache_key", sa.String(), nullable=False),
            sa.Column("data", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_hit_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
            sa.PrimaryKeyConstraint("cache_key"),
        )

    # -- tool_effectiveness --
    if "tool_effectiveness" not in existing_tables:
        op.create_table(
            "tool_effectiveness",
            sa.Column("tool", sa.String(), nullable=False),
            sa.Column("target_type", sa.String(), nullable=False),
            sa.Column("total_findings", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("confirmed_findings", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("false_positive_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("false_positive_rate", sa.Float(), nullable=False, server_default="0"),
            sa.Column("avg_duration_seconds", sa.Float(), nullable=False, server_default="0"),
            sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("tool", "target_type"),
        )

    # -- scan_batch --
    if "scan_batch" not in existing_tables:
        op.create_table(
            "scan_batch",
            sa.Column("id", sa.String(), nullable=False),
            sa.Column("scan_ids", sa.Text(), nullable=False, server_default="[]"),
            sa.Column("max_parallel_scans", sa.Integer(), nullable=False, server_default="2"),
            sa.Column("status", sa.String(), nullable=False, server_default="pending"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("user_id", sa.Uuid(), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    # -- scan_metrics --
    if "scan_metrics" not in existing_tables:
        op.create_table(
            "scan_metrics",
            sa.Column("scan_id", sa.String(), nullable=False),
            sa.Column("data", sa.Text(), nullable=False),
            sa.ForeignKeyConstraint(["scan_id"], ["scan.id"]),
            sa.PrimaryKeyConstraint("scan_id"),
        )


def downgrade() -> None:
    # Drop in reverse dependency order
    for table in [
        "scan_metrics",
        "scan_batch",
        "tool_effectiveness",
        "output_cache",
        "scan_attestation",
        "steering_log_entry",
        "scan_event",
        "finding_annotation",
        "fp_memory",
        "suppression_rule",
        "remediation_group",
        "finding_correlation",
        "dedup_finding",
        "raw_finding",
        "scan_task",
        "scan",
    ]:
        op.drop_table(table)
