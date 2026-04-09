"""Pydantic data models for the OpenTools CLI toolkit.

This module defines the complete data contract for all domain objects,
configuration models, and result/report types used across the CLI.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EngagementType(StrEnum):
    PENTEST = "pentest"
    REVERSE_ENGINEERING = "reverse-engineering"
    HARDWARE_RE = "hardware-re"
    FORENSICS = "forensics"
    CLOUD_SECURITY = "cloud-security"
    MOBILE = "mobile"
    COMBINED = "combined"


class EngagementStatus(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETE = "complete"


class FindingStatus(StrEnum):
    DISCOVERED = "discovered"
    CONFIRMED = "confirmed"
    REPORTED = "reported"
    REMEDIATED = "remediated"
    VERIFIED = "verified"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IOCType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"
    FILE_PATH = "file_path"
    REGISTRY = "registry"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    EMAIL = "email"


class ArtifactType(StrEnum):
    SCREENSHOT = "screenshot"
    PCAP = "pcap"
    BINARY = "binary"
    SOURCE = "source"
    DUMP = "dump"
    REPORT = "report"
    OTHER = "other"


class StepType(StrEnum):
    SHELL = "shell"
    MCP_TOOL = "mcp_tool"
    MANUAL = "manual"


class FailureAction(StrEnum):
    CONTINUE = "continue"
    ABORT = "abort"


class ToolStatus(StrEnum):
    AVAILABLE = "available"
    MISSING = "missing"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    NOT_CONFIGURED = "not_configured"
    UNRESOLVED = "unresolved"


# ---------------------------------------------------------------------------
# Core domain models
# ---------------------------------------------------------------------------


class Engagement(BaseModel):
    id: str
    name: str
    target: str
    type: EngagementType
    scope: Optional[str] = None
    status: EngagementStatus
    skills_used: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class Finding(BaseModel):
    id: str
    engagement_id: str
    tool: str
    corroborated_by: list[str] = Field(default_factory=list)
    cwe: Optional[str] = None
    severity: Severity
    severity_by_tool: dict[str, str] = Field(default_factory=dict)
    status: FindingStatus = FindingStatus.DISCOVERED
    phase: Optional[str] = None
    title: str
    description: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cvss: Optional[float] = None
    false_positive: bool = False
    dedup_confidence: Optional[Confidence] = None
    created_at: datetime
    deleted_at: Optional[datetime] = None


class TimelineEvent(BaseModel):
    id: str
    engagement_id: str
    timestamp: datetime
    source: str
    event: str
    details: Optional[str] = None
    confidence: Confidence
    finding_id: Optional[str] = None


class IOC(BaseModel):
    id: str
    engagement_id: str
    ioc_type: IOCType
    value: str
    context: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source_finding_id: Optional[str] = None


class Artifact(BaseModel):
    id: str
    engagement_id: str
    file_path: str
    artifact_type: ArtifactType
    description: Optional[str] = None
    source_tool: Optional[str] = None
    created_at: datetime


class AuditEntry(BaseModel):
    id: str
    timestamp: datetime
    command: str
    args: Optional[dict[str, Any]] = None
    engagement_id: Optional[str] = None
    result: str
    details: Optional[str] = None


# ---------------------------------------------------------------------------
# Config models
# ---------------------------------------------------------------------------


class ToolConfig(BaseModel):
    name: str
    type: str
    path_or_command: str
    health_check: Optional[str] = None
    profiles: list[str] = Field(default_factory=list)
    env_required: list[str] = Field(default_factory=list)
    version: Optional[str] = None
    status: ToolStatus = ToolStatus.UNRESOLVED


class RecipeVariable(BaseModel):
    description: str
    required: bool
    default: Optional[str] = None


class RecipeStep(BaseModel):
    name: str
    tool: str
    command: str
    timeout: int = 300
    step_type: StepType = StepType.SHELL
    on_failure: FailureAction = FailureAction.CONTINUE
    depends_on: Optional[list[str]] = None


class Recipe(BaseModel):
    id: str
    name: str
    description: str
    requires: list[str] = Field(default_factory=list)
    variables: dict[str, RecipeVariable] = Field(default_factory=dict)
    steps: list[RecipeStep] = Field(default_factory=list)
    parallel: bool = False
    output: str = "consolidated-findings-table"


# ---------------------------------------------------------------------------
# Result / report models
# ---------------------------------------------------------------------------


class EngagementSummary(BaseModel):
    engagement: Engagement
    finding_counts: dict[str, int] = Field(default_factory=dict)
    finding_counts_by_status: dict[str, int] = Field(default_factory=dict)
    finding_counts_by_phase: dict[str, int] = Field(default_factory=dict)
    ioc_counts_by_type: dict[str, int] = Field(default_factory=dict)
    artifact_count: int = 0
    timeline_event_count: int = 0
    false_positive_count: int = 0
    severity_conflicts: list[dict[str, Any]] = Field(default_factory=list)


class DeduplicationReport(BaseModel):
    merged: int = 0
    distinct: int = 0
    merge_details: list[dict[str, Any]] = Field(default_factory=list)


class StepResult(BaseModel):
    step_name: str
    status: str
    exit_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    duration_ms: int = 0
    log_path: Optional[str] = None


class RecipeResult(BaseModel):
    recipe_id: str
    recipe_name: str
    status: str
    steps: list[StepResult] = Field(default_factory=list)
    duration_ms: int = 0
    output_dir: Optional[str] = None
    findings_added: int = 0


# ---------------------------------------------------------------------------
# Preflight models
# ---------------------------------------------------------------------------


class ToolCheckResult(BaseModel):
    name: str
    category: str
    status: ToolStatus
    required_by: list[str] = Field(default_factory=list)
    message: str = ""
    health_check_ms: Optional[int] = None


class PreflightSummary(BaseModel):
    total: int = 0
    available: int = 0
    missing: int = 0
    errors: int = 0
    skills_fully_available: list[str] = Field(default_factory=list)
    skills_partially_available: list[str] = Field(default_factory=list)
    skills_unavailable: list[str] = Field(default_factory=list)


class PreflightReport(BaseModel):
    timestamp: datetime
    platform: str
    docker_available: bool = False
    skill: Optional[str] = None
    tools: list[ToolCheckResult] = Field(default_factory=list)
    summary: PreflightSummary = Field(default_factory=PreflightSummary)


class ContainerStatus(BaseModel):
    name: str
    state: str
    health: Optional[str] = None
    profile: list[str] = Field(default_factory=list)
    uptime: Optional[str] = None
    exit_code: Optional[int] = None


class ContainerResult(BaseModel):
    success: bool = False
    started: list[str] = Field(default_factory=list)
    failed: list[str] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Config aggregate
# ---------------------------------------------------------------------------


class ToolkitConfig(BaseModel):
    mcp_servers: dict[str, ToolConfig] = Field(default_factory=dict)
    containers: dict[str, ToolConfig] = Field(default_factory=dict)
    cli_tools: dict[str, ToolConfig] = Field(default_factory=dict)
    docker_hub_path: Optional[Path] = None
    plugin_dir: Optional[Path] = None
    api_keys: dict[str, bool] = Field(default_factory=dict)
