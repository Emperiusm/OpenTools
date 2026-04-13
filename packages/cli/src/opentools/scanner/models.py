"""Pydantic data models for the scanner orchestration engine.

This module defines all domain objects for scan lifecycle management,
task execution, finding deduplication, and progress reporting.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Optional

from pydantic import BaseModel, Field

from opentools.models import FindingStatus, Severity


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanMode(StrEnum):
    AUTO = "auto"
    ASSISTED = "assisted"


class TargetType(StrEnum):
    SOURCE_CODE = "source_code"
    URL = "url"
    BINARY = "binary"
    DOCKER_IMAGE = "docker_image"
    APK = "apk"
    NETWORK = "network"


class TaskType(StrEnum):
    SHELL = "shell"
    DOCKER_EXEC = "docker_exec"
    MCP_CALL = "mcp_call"
    PREFLIGHT = "preflight"
    PROVISION = "provision"


class TaskStatus(StrEnum):
    PENDING = "pending"
    BLOCKED = "blocked"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ExecutionTier(StrEnum):
    FAST = "fast"
    NORMAL = "normal"
    HEAVY = "heavy"


class TaskIsolation(StrEnum):
    NONE = "none"
    CONTAINER = "container"
    NETWORK_ISOLATED = "network_isolated"


class EvidenceQuality(StrEnum):
    PROVEN = "proven"
    TRACED = "traced"
    STRUCTURED = "structured"
    PATTERN = "pattern"
    HEURISTIC = "heuristic"


class LocationPrecision(StrEnum):
    EXACT_LINE = "exact_line"
    LINE_RANGE = "line_range"
    FUNCTION = "function"
    FILE = "file"
    ENDPOINT = "endpoint"
    HOST = "host"


class SteeringAction(StrEnum):
    CONTINUE = "continue"
    ADD_TASKS = "add_tasks"
    PAUSE = "pause"
    ABORT = "abort"


# ---------------------------------------------------------------------------
# Core configuration models
# ---------------------------------------------------------------------------


class TargetRateLimit(BaseModel):
    max_requests_per_second: int = 50
    max_concurrent_connections: int = 10
    backoff_on_429: bool = True
    backoff_on_timeout: bool = True


class NotificationChannel(BaseModel):
    type: str
    url: Optional[str] = None
    events: list[str] = Field(
        default_factory=lambda: [
            "scan_completed",
            "scan_failed",
            "critical_finding_discovered",
        ]
    )


class ScanNotification(BaseModel):
    channels: list[NotificationChannel] = Field(default_factory=list)


class RetryPolicy(BaseModel):
    max_retries: int = 2
    backoff_seconds: float = 5.0
    retry_on: list[str] = Field(
        default_factory=lambda: ["timeout", "connection_error"]
    )


class ScanConfig(BaseModel):
    severity_threshold: Severity = Severity.INFO
    max_concurrent_tasks: int = 8
    max_duration_seconds: Optional[int] = None
    timeout_override: Optional[int] = None
    tool_args: dict[str, Any] = Field(default_factory=dict)
    notifications: Optional[ScanNotification] = None
    steering_frequency: str = "phase_boundary"
    target_rate_limit: Optional[TargetRateLimit] = None


class ScanMetrics(BaseModel):
    tasks_total: int = 0
    tasks_pending: int = 0
    tasks_blocked: int = 0
    tasks_running: int = 0
    tasks_completed: int = 0
    tasks_failed: int = 0
    tasks_skipped: int = 0
    tasks_cached: int = 0
    tasks_retried: int = 0
    edges_fired: int = 0
    edges_suppressed: int = 0
    raw_findings_total: int = 0
    raw_findings_deduplicated: int = 0
    false_positives_suppressed: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    steering_calls: int = 0
    mcp_calls: int = 0
    shell_commands: int = 0
    docker_execs: int = 0
    total_duration_ms: int = 0
    tool_errors: int = 0


class GraphSnapshot(BaseModel):
    """A snapshot of the task graph state for steering decisions."""

    tasks_total: int = 0
    tasks_completed: int = 0
    tasks_running: int = 0
    tasks_pending: int = 0
    tasks_failed: int = 0
    tasks_skipped: int = 0
    phases_completed: list[str] = Field(default_factory=list)
    current_phase: Optional[str] = None
    finding_count: int = 0


class ReactiveEdge(BaseModel):
    id: str
    trigger_task_id: str
    evaluator: str
    condition: Optional[str] = None
    spawns: Optional[list[Any]] = None
    max_spawns: int = 20
    max_spawns_per_trigger: int = 5
    cooldown_seconds: int = 0
    budget_group: Optional[str] = None
    min_upstream_confidence: float = 0.5


class ScanTask(BaseModel):
    id: str
    scan_id: str
    name: str
    tool: str
    task_type: TaskType
    command: Optional[str] = None
    mcp_server: Optional[str] = None
    mcp_tool: Optional[str] = None
    mcp_args: Optional[dict[str, Any]] = None
    depends_on: list[str] = Field(default_factory=list)
    reactive_edges: list[ReactiveEdge] = Field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    priority: int = 50
    tier: ExecutionTier = ExecutionTier.NORMAL
    resource_group: Optional[str] = None
    retry_policy: Optional[RetryPolicy] = None
    cache_key: Optional[str] = None
    parser: Optional[str] = None
    tool_version: Optional[str] = None
    exit_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    output_hash: Optional[str] = None
    duration_ms: Optional[int] = None
    cached: bool = False
    isolation: TaskIsolation = TaskIsolation.NONE
    spawned_by: Optional[str] = None
    spawned_reason: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class Scan(BaseModel):
    id: str
    engagement_id: str
    target: str
    target_type: TargetType
    resolved_path: Optional[str] = None
    target_metadata: dict[str, Any] = Field(default_factory=dict)
    profile: Optional[str] = None
    profile_snapshot: dict[str, Any] = Field(default_factory=dict)
    mode: ScanMode = ScanMode.AUTO
    status: ScanStatus = ScanStatus.PENDING
    config: Optional[ScanConfig] = None
    baseline_scan_id: Optional[str] = None
    tools_planned: list[str] = Field(default_factory=list)
    tools_completed: list[str] = Field(default_factory=list)
    tools_failed: list[str] = Field(default_factory=list)
    finding_count: int = 0
    estimated_duration_seconds: Optional[int] = None
    metrics: Optional[ScanMetrics] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


# ---------------------------------------------------------------------------
# Finding models
# ---------------------------------------------------------------------------


class RawFinding(BaseModel):
    id: str
    scan_task_id: str
    scan_id: str
    tool: str
    raw_severity: str
    title: str
    canonical_title: Optional[str] = None
    description: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    url: Optional[str] = None
    evidence: Optional[str] = None
    evidence_quality: EvidenceQuality
    evidence_hash: str
    cwe: Optional[str] = None
    location_fingerprint: str
    location_precision: LocationPrecision
    parser_version: str
    parser_confidence: float
    raw_output_excerpt: Optional[str] = None
    discovered_at: datetime
    causal_chain: Optional[list[str]] = None


class DeduplicatedFinding(BaseModel):
    id: str
    engagement_id: str
    finding_id: Optional[str] = None
    fingerprint: str
    raw_finding_ids: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    corroboration_count: int = 1
    confidence_score: float
    severity_consensus: str
    canonical_title: str
    cwe: Optional[str] = None
    location_fingerprint: str
    location_precision: LocationPrecision
    evidence_quality_best: EvidenceQuality
    previously_marked_fp: bool = False
    suppressed: bool = False
    suppression_rule_id: Optional[str] = None
    status: FindingStatus = FindingStatus.DISCOVERED
    last_confirmed_scan_id: Optional[str] = None
    last_confirmed_at: Optional[datetime] = None
    first_seen_scan_id: str
    created_at: datetime
    updated_at: datetime


class FindingCorrelation(BaseModel):
    id: str
    engagement_id: str
    scan_id: str
    finding_ids: list[str]
    correlation_type: str
    narrative: str
    severity: str
    kill_chain_phases: Optional[list[str]] = None
    created_at: datetime


class RemediationGroup(BaseModel):
    id: str
    engagement_id: str
    scan_id: str
    action: str
    action_type: str
    finding_ids: list[str]
    findings_count: int
    max_severity: str
    effort_estimate: Optional[str] = None
    created_at: datetime


class SuppressionRule(BaseModel):
    id: str
    scope: str
    engagement_id: Optional[str] = None
    rule_type: str
    pattern: str
    reason: str
    created_by: str
    created_at: datetime
    expires_at: Optional[datetime] = None


class FindingAnnotation(BaseModel):
    id: str
    finding_fingerprint: str
    engagement_id: Optional[str] = None
    annotation_type: str
    value: str
    created_by: str
    created_at: datetime


class ScanAttestation(BaseModel):
    scan_id: str
    findings_hash: str
    profile_hash: str
    tool_versions: dict[str, str]
    signature: str
    created_at: datetime


class ToolEffectiveness(BaseModel):
    tool: str
    target_type: str
    total_findings: int = 0
    confirmed_findings: int = 0
    false_positive_count: int = 0
    false_positive_rate: float = 0.0
    avg_duration_seconds: float = 0.0
    sample_count: int = 0
    updated_at: datetime


class ScanBatch(BaseModel):
    id: str
    scan_ids: list[str] = Field(default_factory=list)
    max_parallel_scans: int = 2
    status: str = "pending"
    created_at: datetime
    completed_at: Optional[datetime] = None


class ScanQuota(BaseModel):
    max_concurrent_scans: int = 3
    max_scans_per_day: int = 20
    max_scan_duration_seconds: int = 3600
    max_assisted_mode_calls: int = 50
    max_batch_size: int = 10


class EnrichedContext(BaseModel):
    code_snippet: str
    function_name: Optional[str] = None
    file_imports: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Progress event models
# ---------------------------------------------------------------------------


class ProgressEventType(StrEnum):
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_PAUSED = "scan_paused"
    SCAN_RESUMED = "scan_resumed"
    TASK_QUEUED = "task_queued"
    TASK_STARTED = "task_started"
    TASK_PROGRESS = "task_progress"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    TASK_SKIPPED = "task_skipped"
    TASK_CACHED = "task_cached"
    TASK_RETRYING = "task_retrying"
    FINDING_DISCOVERED = "finding_discovered"
    FINDING_CORRELATED = "finding_correlated"
    EDGE_FIRED = "edge_fired"
    STEERING_DECISION = "steering_decision"
    THREAT_SUMMARY_UPDATED = "threat_summary_updated"
    RESOURCE_WARNING = "resource_warning"


class ProgressEvent(BaseModel):
    id: str
    type: ProgressEventType
    timestamp: datetime
    scan_id: str
    sequence: int
    task_id: Optional[str] = None
    data: dict[str, Any] = Field(default_factory=dict)
    tasks_total: int
    tasks_completed: int
    tasks_running: int
    findings_total: int
    elapsed_seconds: float
    estimated_remaining_seconds: Optional[float] = None
