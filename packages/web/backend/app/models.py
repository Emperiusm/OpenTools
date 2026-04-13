"""SQLModel table definitions for the web dashboard.

Architecture note
-----------------
Domain types imported from ``opentools.models``; ORM tables below are
SQLModel projections of the same schema with additional web-specific
columns (``user_id``, foreign-key constraints, TZ-aware datetime
handling, JSON/Text column overrides).

The canonical field list for each domain object lives in the CLI
package (``packages/cli/src/opentools/models.py``).  When a field is
added there it should be mirrored here in the corresponding ORM table.
Enum types (Severity, EngagementType, etc.) are imported directly from
the CLI package so both layers share a single source of truth for
allowed values.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi_users import schemas as fu_schemas
from sqlalchemy import Column, Index, Text, JSON, UniqueConstraint
from sqlalchemy.types import TypeDecorator, DateTime
from sqlmodel import Field, SQLModel

# -- Domain enums (single source of truth in the CLI package) ----------------
from opentools.models import (  # noqa: F401 – re-exported for web consumers
    Severity,
    EngagementType,
    EngagementStatus,
    FindingStatus,
    Confidence,
    IOCType,
    ArtifactType,
)


class TZAwareDateTime(TypeDecorator):
    """DateTime that coerces naive values to UTC on bind and result.

    SQLModel's default `datetime` type inference produces
    ``DateTime(timezone=False)``. When those fields bind against a
    PostgreSQL ``TIMESTAMPTZ`` column (every Alembic migration in this
    project declares ``sa.DateTime(timezone=True)``), asyncpg raises
    ``DataError: can't subtract offset-naive and offset-aware datetimes``
    because SQLAlchemy strips tz info before handing the value to the
    DBAPI. This TypeDecorator plugs the gap: it tells SQLAlchemy the
    column is ``DateTime(timezone=True)`` AND stamps UTC on any naive
    value that slips through. Idempotent on already-aware values.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and getattr(value, "tzinfo", None) is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    def process_result_value(self, value, dialect):
        if value is not None and getattr(value, "tzinfo", None) is None:
            return value.replace(tzinfo=timezone.utc)
        return value


# Keyword args shared by every SQLModel datetime Field() below.
_TZ_KW = {"sa_type": TZAwareDateTime}


# --- User -----------------------------------------------------------------

class User(SQLModel, table=True):
    __tablename__ = "user"
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    email: str = Field(unique=True, index=True, max_length=320)
    hashed_password: str = Field(default="")
    is_active: bool = Field(default=True)
    is_superuser: bool = Field(default=False)
    is_verified: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), **_TZ_KW)


class UserRead(fu_schemas.BaseUser[uuid.UUID]):
    pass


class UserCreate(fu_schemas.BaseUserCreate):
    pass


# --- Engagement -----------------------------------------------------------
# ORM projection of opentools.models.Engagement; adds user_id FK.

class Engagement(SQLModel, table=True):
    __tablename__ = "engagement"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    name: str
    target: str
    type: str
    scope: Optional[str] = None
    status: str = Field(default="active")
    skills_used: Optional[str] = Field(default=None, sa_column=Column(JSON))
    created_at: datetime = Field(**_TZ_KW)
    updated_at: datetime = Field(**_TZ_KW)


# --- Finding --------------------------------------------------------------
# ORM projection of opentools.models.Finding; adds user_id FK, JSON/Text columns.

class Finding(SQLModel, table=True):
    __tablename__ = "finding"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    engagement_id: str = Field(foreign_key="engagement.id")
    tool: str
    corroborated_by: Optional[str] = Field(default=None, sa_column=Column(JSON))
    cwe: Optional[str] = None
    severity: str
    severity_by_tool: Optional[str] = Field(default=None, sa_column=Column(JSON))
    status: str = Field(default="discovered")
    phase: Optional[str] = None
    title: str
    description: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    evidence: Optional[str] = Field(default=None, sa_column=Column(Text))
    remediation: Optional[str] = Field(default=None, sa_column=Column(Text))
    cvss: Optional[float] = None
    false_positive: bool = Field(default=False)
    dedup_confidence: Optional[str] = None
    created_at: datetime = Field(**_TZ_KW)
    deleted_at: Optional[datetime] = Field(default=None, **_TZ_KW)

    # Note: search_vector (tsvector) added via migration, not SQLModel field


# --- TimelineEvent --------------------------------------------------------
# ORM projection of opentools.models.TimelineEvent; adds user_id FK.

class TimelineEvent(SQLModel, table=True):
    __tablename__ = "timeline_event"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    engagement_id: str = Field(foreign_key="engagement.id")
    timestamp: datetime = Field(**_TZ_KW)
    source: str
    event: str
    details: Optional[str] = None
    confidence: str = Field(default="medium")
    finding_id: Optional[str] = Field(default=None, foreign_key="finding.id")


# --- IOC ------------------------------------------------------------------
# ORM projection of opentools.models.IOC; adds user_id FK.

class IOC(SQLModel, table=True):
    __tablename__ = "ioc"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    engagement_id: str = Field(foreign_key="engagement.id")
    ioc_type: str
    value: str
    context: Optional[str] = None
    first_seen: Optional[datetime] = Field(default=None, **_TZ_KW)
    last_seen: Optional[datetime] = Field(default=None, **_TZ_KW)
    source_finding_id: Optional[str] = Field(default=None, foreign_key="finding.id")


# --- Artifact -------------------------------------------------------------
# ORM projection of opentools.models.Artifact; adds user_id FK.

class Artifact(SQLModel, table=True):
    __tablename__ = "artifact"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    engagement_id: str = Field(foreign_key="engagement.id")
    file_path: str
    artifact_type: str
    description: Optional[str] = None
    source_tool: Optional[str] = None
    created_at: datetime = Field(**_TZ_KW)


# --- AuditEntry -----------------------------------------------------------
# ORM projection of opentools.models.AuditEntry; adds user_id FK, JSON column.

class AuditEntry(SQLModel, table=True):
    __tablename__ = "audit_entry"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    timestamp: datetime = Field(**_TZ_KW)
    command: str
    args: Optional[str] = Field(default=None, sa_column=Column(JSON))
    engagement_id: Optional[str] = None
    result: str
    details: Optional[str] = None


# --- IOCEnrichment --------------------------------------------------------
# ORM projection of opentools.models.IOCEnrichmentRecord; adds user_id FK.

class IOCEnrichment(SQLModel, table=True):
    __tablename__ = "ioc_enrichment"
    __table_args__ = (
        UniqueConstraint("user_id", "ioc_type", "ioc_value", "provider", name="uq_enrichment"),
    )
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    ioc_type: str = Field(index=True)
    ioc_value: str = Field(index=True)
    provider: str
    data: Optional[str] = None  # JSON string
    risk_score: Optional[int] = None
    tags: Optional[str] = None  # JSON array
    fetched_at: datetime = Field(**_TZ_KW)
    ttl_seconds: int = 86400


# --- Scan runner tables (migration 006) -----------------------------------


class ScanRecord(SQLModel, table=True):
    """ORM projection for the scan table."""
    __tablename__ = "scan"
    id: str = Field(primary_key=True)
    user_id: Optional[uuid.UUID] = Field(default=None, foreign_key="user.id", index=True)
    engagement_id: str = Field(index=True)
    target: str
    target_type: str
    resolved_path: Optional[str] = None
    target_metadata: str = Field(default="{}", sa_column=Column(Text))
    profile: Optional[str] = None
    profile_snapshot: str = Field(default="{}", sa_column=Column(Text))
    mode: str = Field(default="auto")
    status: str = Field(default="pending")
    config: Optional[str] = Field(default=None, sa_column=Column(Text))
    baseline_scan_id: Optional[str] = None
    tools_planned: str = Field(default="[]", sa_column=Column(Text))
    tools_completed: str = Field(default="[]", sa_column=Column(Text))
    tools_failed: str = Field(default="[]", sa_column=Column(Text))
    finding_count: int = Field(default=0)
    estimated_duration_seconds: Optional[int] = None
    metrics: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: datetime = Field(**_TZ_KW)
    started_at: Optional[datetime] = Field(default=None, **_TZ_KW)
    completed_at: Optional[datetime] = Field(default=None, **_TZ_KW)


class ScanTaskRecord(SQLModel, table=True):
    """ORM projection for the scan_task table."""
    __tablename__ = "scan_task"
    id: str = Field(primary_key=True)
    scan_id: str = Field(foreign_key="scan.id", index=True)
    name: str
    tool: str
    task_type: str
    command: Optional[str] = Field(default=None, sa_column=Column(Text))
    mcp_server: Optional[str] = None
    mcp_tool: Optional[str] = None
    mcp_args: Optional[str] = Field(default=None, sa_column=Column(Text))
    depends_on: str = Field(default="[]", sa_column=Column(Text))
    reactive_edges: str = Field(default="[]", sa_column=Column(Text))
    status: str = Field(default="pending")
    priority: int = Field(default=50)
    tier: str = Field(default="normal")
    resource_group: Optional[str] = None
    retry_policy: Optional[str] = Field(default=None, sa_column=Column(Text))
    cache_key: Optional[str] = None
    parser: Optional[str] = None
    tool_version: Optional[str] = None
    exit_code: Optional[int] = None
    stdout: Optional[str] = Field(default=None, sa_column=Column(Text))
    stderr: Optional[str] = Field(default=None, sa_column=Column(Text))
    output_hash: Optional[str] = None
    duration_ms: Optional[int] = None
    cached: bool = Field(default=False)
    isolation: str = Field(default="none")
    spawned_by: Optional[str] = None
    spawned_reason: Optional[str] = None
    # Approval gate fields
    approval_ticket_id: Optional[str] = None
    approval_expires_at: Optional[datetime] = Field(default=None, **_TZ_KW)
    started_at: Optional[datetime] = Field(default=None, **_TZ_KW)
    completed_at: Optional[datetime] = Field(default=None, **_TZ_KW)


class ScanEventRecord(SQLModel, table=True):
    """ORM projection for the scan_event table."""
    __tablename__ = "scan_event"
    id: str = Field(primary_key=True)
    scan_id: str = Field(foreign_key="scan.id")
    type: str
    sequence: int
    timestamp: datetime = Field(**_TZ_KW)
    task_id: Optional[str] = None
    data: str = Field(default="{}", sa_column=Column(Text))
    tasks_total: int = Field(default=0)
    tasks_completed: int = Field(default=0)
    tasks_running: int = Field(default=0)
    findings_total: int = Field(default=0)
    elapsed_seconds: float = Field(default=0)
    estimated_remaining_seconds: Optional[float] = None

    __table_args__ = (
        Index("ix_scan_event_scan_seq", "scan_id", "sequence"),
    )


# --- Chain data layer (Phase 3C.1) ---------------------------------------

class ChainEntity(SQLModel, table=True):
    """Canonical entity (host, CVE, user, etc.) extracted from findings."""
    __tablename__ = "chain_entity"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    type: str = Field(index=True)
    canonical_value: str
    first_seen_at: datetime = Field(**_TZ_KW)
    last_seen_at: datetime = Field(**_TZ_KW)
    mention_count: int = Field(default=0)

    __table_args__ = (
        UniqueConstraint("type", "canonical_value", "user_id", name="uq_chain_entity"),
    )


class ChainEntityMention(SQLModel, table=True):
    """One occurrence of an entity in a finding."""
    __tablename__ = "chain_entity_mention"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    entity_id: str = Field(foreign_key="chain_entity.id", index=True)
    finding_id: str = Field(foreign_key="finding.id", index=True)
    field: str
    raw_value: str
    offset_start: Optional[int] = None
    offset_end: Optional[int] = None
    extractor: str
    confidence: float
    created_at: datetime = Field(**_TZ_KW)

    __table_args__ = (
        UniqueConstraint("entity_id", "finding_id", "field", "offset_start", name="uq_chain_mention"),
    )


class ChainFindingRelation(SQLModel, table=True):
    """Directed edge in the attack chain graph."""
    __tablename__ = "chain_finding_relation"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    source_finding_id: str = Field(foreign_key="finding.id")
    target_finding_id: str = Field(foreign_key="finding.id")
    weight: float
    weight_model_version: str = Field(default="additive_v1")
    status: str
    symmetric: bool = Field(default=False)
    reasons_json: Optional[str] = Field(default=None, sa_column=Column(Text))
    llm_rationale: Optional[str] = None
    llm_relation_type: Optional[str] = None
    llm_confidence: Optional[float] = None
    confirmed_at_reasons_json: Optional[str] = Field(default=None, sa_column=Column(Text))
    created_at: datetime = Field(**_TZ_KW)
    updated_at: datetime = Field(**_TZ_KW)

    __table_args__ = (
        UniqueConstraint(
            "source_finding_id", "target_finding_id", "user_id",
            name="uq_chain_relation",
        ),
    )


class ChainLinkerRun(SQLModel, table=True):
    """Audit trail for linker invocations."""
    __tablename__ = "chain_linker_run"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    started_at: datetime = Field(**_TZ_KW)
    finished_at: Optional[datetime] = Field(default=None, **_TZ_KW)
    scope: str
    scope_id: Optional[str] = None
    mode: str
    llm_provider: Optional[str] = None
    findings_processed: int = Field(default=0)
    entities_extracted: int = Field(default=0)
    relations_created: int = Field(default=0)
    relations_updated: int = Field(default=0)
    relations_skipped_sticky: int = Field(default=0)
    extraction_cache_hits: int = Field(default=0)
    extraction_cache_misses: int = Field(default=0)
    llm_calls_made: int = Field(default=0)
    llm_cache_hits: int = Field(default=0)
    llm_cache_misses: int = Field(default=0)
    rule_stats_json: Optional[str] = Field(default=None, sa_column=Column(Text))
    duration_ms: Optional[int] = None
    error: Optional[str] = None
    generation: int = Field(default=0)
    status_text: Optional[str] = Field(default=None)


class ChainExtractionCache(SQLModel, table=True):
    """LLM extraction cache entries, user-scoped (spec G37)."""
    __tablename__ = "chain_extraction_cache"
    cache_key: str = Field(primary_key=True)
    provider: str
    model: str
    schema_version: int
    result_json: bytes
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), **_TZ_KW
    )
    user_id: Optional[uuid.UUID] = Field(
        default=None, foreign_key="user.id", index=True, nullable=True
    )


class ChainLlmLinkCache(SQLModel, table=True):
    """LLM link-classification cache entries, user-scoped (spec G37)."""
    __tablename__ = "chain_llm_link_cache"
    cache_key: str = Field(primary_key=True)
    provider: str
    model: str
    schema_version: int
    classification_json: bytes
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), **_TZ_KW
    )
    user_id: Optional[uuid.UUID] = Field(
        default=None, foreign_key="user.id", index=True, nullable=True
    )


class ChainFindingExtractionState(SQLModel, table=True):
    """Change detection for re-extraction (mirrors CLI finding_extraction_state).

    Stores the latest extraction input hash and extractor set seen per
    finding so the pipeline can skip findings whose inputs have not
    changed. User-scoped via nullable FK (spec G37).
    """
    __tablename__ = "chain_finding_extraction_state"
    finding_id: str = Field(
        primary_key=True, foreign_key="finding.id"
    )
    extraction_input_hash: str
    last_extracted_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), **_TZ_KW
    )
    last_extractor_set_json: bytes
    user_id: Optional[uuid.UUID] = Field(
        default=None, foreign_key="user.id", index=True, nullable=True
    )


class ChainFindingParserOutput(SQLModel, table=True):
    """Structured parser output, keyed on (finding_id, parser_name).

    Feeds parser-aware extractors that consume already-parsed tool
    output rather than re-parsing raw finding descriptions.
    """
    __tablename__ = "chain_finding_parser_output"
    finding_id: str = Field(
        primary_key=True, foreign_key="finding.id"
    )
    parser_name: str = Field(primary_key=True)
    data_json: bytes
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), **_TZ_KW
    )
    user_id: Optional[uuid.UUID] = Field(
        default=None, foreign_key="user.id", index=True, nullable=True
    )


class ChainCalibrationState(SQLModel, table=True):
    """Per-rule Bayesian calibration state for a user."""
    __tablename__ = "chain_calibration_state"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    rule: str = Field(index=True)
    alpha: float = Field(default=1.0)
    beta_param: float = Field(default=1.0)
    observations: int = Field(default=0)
    last_calibrated_at: datetime = Field(**_TZ_KW)

    __table_args__ = (
        UniqueConstraint("user_id", "rule", name="uq_calibration_state"),
    )
