# Scan Runner Plan 1: Foundation — Models + Store + Shared Infrastructure

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish all data models, the persistence layer, shared infrastructure modules, and static data files that the scan-runner engine (Plan 2+) will build on.

**Architecture:** Bottom-up — models first, then store protocol + SQLite implementation, then shared infra modules (async subprocess, EventBus, retry, resource pool, cancellation). Static data files (CWE hierarchy, severity maps) bundled as JSON. RecipeRunner refactored to use new shared subprocess module.

**Tech Stack:** Python 3.12, Pydantic v2, aiosqlite, asyncio, pytest + pytest-asyncio

**Spec Reference:** `docs/superpowers/specs/2026-04-12-scan-runner-design.md`

**Decomposition Note:** This is Plan 1 of 5. Plans 2-5 (engine, planner, pipeline, surfaces) build on this foundation. See spec Section 2.1 for full package layout.

---

## File Map

### New Files

| File | Responsibility |
|------|---------------|
| `packages/cli/src/opentools/scanner/__init__.py` | Package init |
| `packages/cli/src/opentools/scanner/models.py` | All scan-specific Pydantic models (Scan, ScanTask, RawFinding, DeduplicatedFinding, etc.) |
| `packages/cli/src/opentools/scanner/store.py` | `ScanStoreProtocol` + `SqliteScanStore` implementation |
| `packages/cli/src/opentools/scanner/cancellation.py` | `CancellationToken` — cooperative cancellation |
| `packages/cli/src/opentools/scanner/cwe.py` | `CWEHierarchy` — loads and queries CWE parent/child relationships |
| `packages/cli/src/opentools/scanner/data/cwe_hierarchy.json` | CWE parent/child relationships (subset of MITRE catalog) |
| `packages/cli/src/opentools/scanner/data/cwe_aliases.json` | Common aliases → canonical CWE IDs |
| `packages/cli/src/opentools/scanner/data/cwe_owasp_map.json` | CWE → OWASP Top 10 2021 categories |
| `packages/cli/src/opentools/scanner/data/severity_maps.json` | Per-tool severity → canonical severity mapping |
| `packages/cli/src/opentools/scanner/data/title_normalization.json` | Regex patterns → canonical finding titles |
| `packages/cli/src/opentools/scanner/data/parser_confidence.json` | Tool → base confidence tier |
| `packages/cli/src/opentools/shared/__init__.py` | Package init |
| `packages/cli/src/opentools/shared/subprocess.py` | `run_streaming()` — async subprocess with streaming + timeout + cancellation |
| `packages/cli/src/opentools/shared/progress.py` | `ProgressEvent`, `ProgressEventType`, `EventBus` |
| `packages/cli/src/opentools/shared/retry.py` | `RetryPolicy` execution with exponential backoff |
| `packages/cli/src/opentools/shared/resource_pool.py` | `AdaptiveResourcePool` with priority heap |
| `packages/cli/tests/test_scanner/__init__.py` | Test package init |
| `packages/cli/tests/test_scanner/test_models.py` | Unit tests for all models |
| `packages/cli/tests/test_scanner/test_store.py` | Integration tests for SqliteScanStore |
| `packages/cli/tests/test_scanner/test_cancellation.py` | Unit tests for CancellationToken |
| `packages/cli/tests/test_scanner/test_cwe.py` | Unit tests for CWEHierarchy |
| `packages/cli/tests/test_scanner/test_shared_subprocess.py` | Tests for shared subprocess module |
| `packages/cli/tests/test_scanner/test_shared_progress.py` | Tests for EventBus |
| `packages/cli/tests/test_scanner/test_shared_retry.py` | Tests for retry logic |
| `packages/cli/tests/test_scanner/test_shared_resource_pool.py` | Tests for AdaptiveResourcePool |

### Modified Files

| File | Change |
|------|--------|
| `packages/cli/src/opentools/models.py` | Add `scan_id: str \| None = None` to `Finding` model |
| `packages/cli/src/opentools/recipes.py` | Refactor `_run_step` to use `shared.subprocess.run_streaming()` |

---

### Task 1: Scanner Package Init + Enums

**Files:**
- Create: `packages/cli/src/opentools/scanner/__init__.py`
- Create: `packages/cli/src/opentools/scanner/models.py`
- Test: `packages/cli/tests/test_scanner/__init__.py`
- Test: `packages/cli/tests/test_scanner/test_models.py`

- [ ] **Step 1: Create package directories**

```bash
mkdir -p packages/cli/src/opentools/scanner
mkdir -p packages/cli/src/opentools/scanner/data
mkdir -p packages/cli/src/opentools/scanner/executor
mkdir -p packages/cli/src/opentools/scanner/parsing
mkdir -p packages/cli/src/opentools/shared
mkdir -p packages/cli/tests/test_scanner
```

- [ ] **Step 2: Write the failing test for enums**

```python
# packages/cli/tests/test_scanner/__init__.py
# (empty)

# packages/cli/tests/test_scanner/test_models.py
"""Unit tests for scanner data models."""

from opentools.scanner.models import (
    ScanStatus, ScanMode, TargetType, TaskType, TaskStatus,
    ExecutionTier, TaskIsolation, EvidenceQuality, LocationPrecision,
)


class TestEnums:
    def test_scan_status_values(self):
        assert ScanStatus.PENDING == "pending"
        assert ScanStatus.RUNNING == "running"
        assert ScanStatus.PAUSED == "paused"
        assert ScanStatus.COMPLETED == "completed"
        assert ScanStatus.FAILED == "failed"
        assert ScanStatus.CANCELLED == "cancelled"

    def test_scan_mode_values(self):
        assert ScanMode.AUTO == "auto"
        assert ScanMode.ASSISTED == "assisted"

    def test_target_type_values(self):
        assert TargetType.SOURCE_CODE == "source_code"
        assert TargetType.URL == "url"
        assert TargetType.BINARY == "binary"
        assert TargetType.DOCKER_IMAGE == "docker_image"
        assert TargetType.APK == "apk"
        assert TargetType.NETWORK == "network"

    def test_task_type_values(self):
        assert TaskType.SHELL == "shell"
        assert TaskType.DOCKER_EXEC == "docker_exec"
        assert TaskType.MCP_CALL == "mcp_call"
        assert TaskType.PREFLIGHT == "preflight"
        assert TaskType.PROVISION == "provision"

    def test_task_status_values(self):
        assert TaskStatus.PENDING == "pending"
        assert TaskStatus.BLOCKED == "blocked"
        assert TaskStatus.RUNNING == "running"
        assert TaskStatus.COMPLETED == "completed"
        assert TaskStatus.FAILED == "failed"
        assert TaskStatus.SKIPPED == "skipped"

    def test_execution_tier_values(self):
        assert ExecutionTier.FAST == "fast"
        assert ExecutionTier.NORMAL == "normal"
        assert ExecutionTier.HEAVY == "heavy"

    def test_task_isolation_values(self):
        assert TaskIsolation.NONE == "none"
        assert TaskIsolation.CONTAINER == "container"
        assert TaskIsolation.NETWORK_ISOLATED == "network_isolated"

    def test_evidence_quality_values(self):
        assert EvidenceQuality.PROVEN == "proven"
        assert EvidenceQuality.TRACED == "traced"
        assert EvidenceQuality.STRUCTURED == "structured"
        assert EvidenceQuality.PATTERN == "pattern"
        assert EvidenceQuality.HEURISTIC == "heuristic"

    def test_location_precision_values(self):
        assert LocationPrecision.EXACT_LINE == "exact_line"
        assert LocationPrecision.LINE_RANGE == "line_range"
        assert LocationPrecision.FUNCTION == "function"
        assert LocationPrecision.FILE == "file"
        assert LocationPrecision.ENDPOINT == "endpoint"
        assert LocationPrecision.HOST == "host"
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_models.py::TestEnums -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'opentools.scanner'`

- [ ] **Step 4: Write minimal implementation — enums only**

```python
# packages/cli/src/opentools/scanner/__init__.py
"""Security scan orchestration engine."""

# packages/cli/src/opentools/scanner/models.py
"""Pydantic data models for the scan-runner engine.

This module defines all domain objects for scans, tasks, findings,
and supporting types. See spec: docs/superpowers/specs/2026-04-12-scan-runner-design.md
"""

from __future__ import annotations

from enum import StrEnum


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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_models.py::TestEnums -v`
Expected: All 9 tests PASS

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/scanner/ packages/cli/src/opentools/shared/ packages/cli/tests/test_scanner/
git commit -m "feat(scanner): add scanner package with all enum types"
```

---

### Task 2: Core Pydantic Models — Scan, ScanConfig, ScanTask

**Files:**
- Modify: `packages/cli/src/opentools/scanner/models.py`
- Test: `packages/cli/tests/test_scanner/test_models.py`

- [ ] **Step 1: Write the failing test for core models**

Append to `test_models.py`:

```python
from datetime import datetime, timezone
from opentools.scanner.models import (
    Scan, ScanConfig, ScanTask, RetryPolicy, ReactiveEdge,
    TargetRateLimit, ScanNotification, NotificationChannel,
    ScanStatus, ScanMode, TargetType, TaskType, TaskStatus,
    ExecutionTier, TaskIsolation,
)


class TestScanModel:
    def test_scan_minimal(self):
        now = datetime.now(timezone.utc)
        scan = Scan(
            id="scan-1",
            engagement_id="eng-1",
            target="https://example.com",
            target_type=TargetType.URL,
            profile="web-full",
            profile_snapshot={"id": "web-full"},
            mode=ScanMode.AUTO,
            status=ScanStatus.PENDING,
            created_at=now,
        )
        assert scan.id == "scan-1"
        assert scan.finding_count == 0
        assert scan.tools_planned == []
        assert scan.metrics is None
        assert scan.baseline_scan_id is None

    def test_scan_config_defaults(self):
        config = ScanConfig()
        assert config.max_concurrent_tasks == 8
        assert config.max_duration_seconds is None
        assert config.steering_frequency == "phase_boundary"
        assert config.target_rate_limit is None

    def test_target_rate_limit_defaults(self):
        limit = TargetRateLimit()
        assert limit.max_requests_per_second == 50
        assert limit.max_concurrent_connections == 10
        assert limit.backoff_on_429 is True


class TestScanTaskModel:
    def test_scan_task_minimal(self):
        task = ScanTask(
            id="task-1",
            scan_id="scan-1",
            name="nmap-port-scan",
            tool="nmap",
            task_type=TaskType.SHELL,
            command="nmap -sV 192.168.1.1",
        )
        assert task.status == TaskStatus.PENDING
        assert task.priority == 50
        assert task.tier == ExecutionTier.NORMAL
        assert task.isolation == TaskIsolation.NONE
        assert task.depends_on == []
        assert task.cached is False

    def test_scan_task_mcp(self):
        task = ScanTask(
            id="task-2",
            scan_id="scan-1",
            name="codebadger-cpg",
            tool="codebadger",
            task_type=TaskType.MCP_CALL,
            mcp_server="codebadger",
            mcp_tool="generate_cpg",
            mcp_args={"path": "/src"},
            resource_group="mcp:codebadger",
        )
        assert task.mcp_server == "codebadger"
        assert task.command is None

    def test_retry_policy_defaults(self):
        policy = RetryPolicy()
        assert policy.max_retries == 2
        assert policy.backoff_seconds == 5.0
        assert policy.retry_on == ["timeout", "connection_error"]

    def test_reactive_edge(self):
        edge = ReactiveEdge(
            id="edge-1",
            trigger_task_id="task-1",
            evaluator="builtin:open_ports_to_nuclei",
        )
        assert edge.max_spawns == 20
        assert edge.max_spawns_per_trigger == 5
        assert edge.min_upstream_confidence == 0.5
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_models.py::TestScanModel -v`
Expected: FAIL — `ImportError: cannot import name 'Scan'`

- [ ] **Step 3: Write implementation — core models**

Append to `packages/cli/src/opentools/scanner/models.py`:

```python
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field

from opentools.models import Severity, FindingStatus


# ---------------------------------------------------------------------------
# Config models
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
        default_factory=lambda: ["scan_completed", "scan_failed", "critical_finding_discovered"]
    )


class ScanNotification(BaseModel):
    channels: list[NotificationChannel] = Field(default_factory=list)


class RetryPolicy(BaseModel):
    max_retries: int = 2
    backoff_seconds: float = 5.0
    retry_on: list[str] = Field(default_factory=lambda: ["timeout", "connection_error"])


class ScanConfig(BaseModel):
    severity_threshold: Severity = Severity.INFO
    max_concurrent_tasks: int = 8
    max_duration_seconds: Optional[int] = None
    timeout_override: Optional[int] = None
    tool_args: dict[str, dict] = Field(default_factory=dict)
    notifications: Optional[ScanNotification] = None
    steering_frequency: str = "phase_boundary"
    target_rate_limit: Optional[TargetRateLimit] = None


class ScanMetrics(BaseModel):
    total_tasks: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    cache_hit_rate: float = 0.0
    dedup_merges: int = 0
    dedup_new: int = 0
    dedup_rate: float = 0.0
    avg_task_duration_ms: float = 0.0
    max_task_duration_ms: float = 0.0
    p95_task_duration_ms: float = 0.0
    reactive_edges_fired: int = 0
    tasks_spawned_by_edges: int = 0
    tasks_spawned_by_claude: int = 0
    steering_calls: int = 0
    steering_avg_latency_ms: float = 0.0
    resource_pool_waits: int = 0
    resource_pool_avg_wait_ms: float = 0.0
    adaptive_adjustments: int = 0
    retries: int = 0
    fp_flags: int = 0
    suppressed_count: int = 0
    trend_alerts: int = 0
    corroboration_rate: float = 0.0
    parser_errors: int = 0
    output_validation_failures: int = 0


# ---------------------------------------------------------------------------
# Core domain models
# ---------------------------------------------------------------------------


class ReactiveEdge(BaseModel):
    id: str
    trigger_task_id: str
    evaluator: str
    condition: Optional[str] = None
    spawns: Optional[list[Any]] = None  # list[ScanTask] — forward ref
    max_spawns: int = 20
    max_spawns_per_trigger: int = 5
    cooldown_seconds: float = 0
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
    mcp_args: Optional[dict] = None
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
    target_metadata: dict = Field(default_factory=dict)
    profile: Optional[str] = None
    profile_snapshot: dict = Field(default_factory=dict)
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_models.py -v`
Expected: All tests PASS (both TestEnums and TestScanModel, TestScanTaskModel)

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/models.py packages/cli/tests/test_scanner/test_models.py
git commit -m "feat(scanner): core Pydantic models — Scan, ScanConfig, ScanTask"
```

---

### Task 3: Finding Models — RawFinding, DeduplicatedFinding, Supporting Types

**Files:**
- Modify: `packages/cli/src/opentools/scanner/models.py`
- Test: `packages/cli/tests/test_scanner/test_models.py`

- [ ] **Step 1: Write the failing test for finding models**

Append to `test_models.py`:

```python
from opentools.scanner.models import (
    RawFinding, DeduplicatedFinding, FindingCorrelation,
    RemediationGroup, SuppressionRule, FindingAnnotation,
    ScanAttestation, ToolEffectiveness, ScanBatch, ScanQuota,
    EnrichedContext, EvidenceQuality, LocationPrecision,
)
from opentools.models import FindingStatus


class TestRawFinding:
    def test_raw_finding_creation(self):
        now = datetime.now(timezone.utc)
        rf = RawFinding(
            id="rf-1",
            scan_task_id="task-1",
            scan_id="scan-1",
            tool="semgrep",
            raw_severity="ERROR",
            title="SQL injection via string format",
            evidence_quality=EvidenceQuality.STRUCTURED,
            evidence_hash="abc123",
            location_fingerprint="src/api/users.py:42",
            location_precision=LocationPrecision.EXACT_LINE,
            parser_version="semgrep:1.0.0",
            parser_confidence=0.9,
            discovered_at=now,
        )
        assert rf.tool == "semgrep"
        assert rf.cwe is None
        assert rf.canonical_title is None
        assert rf.causal_chain is None

    def test_raw_finding_with_cwe(self):
        now = datetime.now(timezone.utc)
        rf = RawFinding(
            id="rf-2",
            scan_task_id="task-1",
            scan_id="scan-1",
            tool="codebadger",
            raw_severity="high",
            title="Taint flow: user input to SQL query",
            cwe="CWE-89",
            evidence_quality=EvidenceQuality.TRACED,
            evidence_hash="def456",
            location_fingerprint="src/api/users.py:42",
            location_precision=LocationPrecision.LINE_RANGE,
            parser_version="codebadger:1.0.0",
            parser_confidence=0.7,
            discovered_at=now,
            causal_chain=["task-0"],
        )
        assert rf.cwe == "CWE-89"
        assert rf.causal_chain == ["task-0"]


class TestDeduplicatedFinding:
    def test_dedup_finding_creation(self):
        now = datetime.now(timezone.utc)
        df = DeduplicatedFinding(
            id="df-1",
            engagement_id="eng-1",
            fingerprint="CWE-89:src/api/users.py:42",
            raw_finding_ids=["rf-1", "rf-2"],
            tools=["semgrep", "codebadger"],
            corroboration_count=2,
            confidence_score=0.85,
            severity_consensus="high",
            canonical_title="SQL Injection",
            cwe="CWE-89",
            location_fingerprint="src/api/users.py:42",
            location_precision=LocationPrecision.EXACT_LINE,
            evidence_quality_best=EvidenceQuality.TRACED,
            first_seen_scan_id="scan-1",
            created_at=now,
            updated_at=now,
        )
        assert df.corroboration_count == 2
        assert df.status == FindingStatus.DISCOVERED
        assert df.previously_marked_fp is False
        assert df.suppressed is False


class TestSupportingModels:
    def test_suppression_rule(self):
        now = datetime.now(timezone.utc)
        rule = SuppressionRule(
            id="sr-1",
            scope="engagement",
            engagement_id="eng-1",
            rule_type="path_pattern",
            pattern="vendor/**",
            reason="Third-party code, not in scope",
            created_by="user:cli",
            created_at=now,
        )
        assert rule.expires_at is None

    def test_finding_annotation(self):
        now = datetime.now(timezone.utc)
        ann = FindingAnnotation(
            id="ann-1",
            finding_fingerprint="CWE-89:src/api/users.py:42",
            annotation_type="false_positive",
            value="Parameterized query used, FP",
            created_by="user:web",
            created_at=now,
        )
        assert ann.engagement_id is None

    def test_scan_attestation(self):
        now = datetime.now(timezone.utc)
        att = ScanAttestation(
            scan_id="scan-1",
            findings_hash="sha256:abc",
            profile_hash="sha256:def",
            tool_versions={"semgrep": "1.60.0", "nmap": "7.94"},
            signature="hmac:ghi",
            created_at=now,
        )
        assert att.tool_versions["semgrep"] == "1.60.0"

    def test_tool_effectiveness(self):
        now = datetime.now(timezone.utc)
        te = ToolEffectiveness(
            tool="semgrep",
            target_type="source_code",
            total_findings=100,
            confirmed_findings=85,
            false_positive_rate=0.15,
            updated_at=now,
        )
        assert te.sample_count == 0

    def test_scan_batch(self):
        now = datetime.now(timezone.utc)
        batch = ScanBatch(
            id="batch-1",
            scan_ids=["scan-1", "scan-2"],
            created_at=now,
        )
        assert batch.max_parallel_scans == 2
        assert batch.status == "pending"

    def test_scan_quota_defaults(self):
        quota = ScanQuota()
        assert quota.max_concurrent_scans == 3
        assert quota.max_scans_per_day == 20

    def test_enriched_context(self):
        ctx = EnrichedContext(
            code_snippet="    query = f'SELECT * FROM users WHERE id = {user_id}'",
            function_name="get_user",
            file_imports=["import sqlite3"],
        )
        assert ctx.function_name == "get_user"

    def test_finding_correlation(self):
        now = datetime.now(timezone.utc)
        corr = FindingCorrelation(
            id="corr-1",
            engagement_id="eng-1",
            scan_id="scan-1",
            finding_ids=["df-1", "df-2"],
            correlation_type="attack_chain",
            narrative="Port 80 open → Apache Struts detected → CVE-2017-5638 confirmed",
            severity="critical",
            created_at=now,
        )
        assert corr.kill_chain_phases is None

    def test_remediation_group(self):
        now = datetime.now(timezone.utc)
        rg = RemediationGroup(
            id="rg-1",
            engagement_id="eng-1",
            scan_id="scan-1",
            action="Upgrade lodash from 4.17.15 to 4.17.21",
            action_type="dependency_upgrade",
            finding_ids=["df-3", "df-4", "df-5"],
            findings_count=3,
            max_severity="high",
            created_at=now,
        )
        assert rg.effort_estimate is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_models.py::TestRawFinding -v`
Expected: FAIL — `ImportError: cannot import name 'RawFinding'`

- [ ] **Step 3: Write implementation — finding + supporting models**

Append to `packages/cli/src/opentools/scanner/models.py`:

```python
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


# ---------------------------------------------------------------------------
# Supporting models
# ---------------------------------------------------------------------------


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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_models.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/models.py packages/cli/tests/test_scanner/test_models.py
git commit -m "feat(scanner): finding + supporting Pydantic models"
```

---

### Task 4: Progress Event Models

**Files:**
- Modify: `packages/cli/src/opentools/scanner/models.py`
- Test: `packages/cli/tests/test_scanner/test_models.py`

- [ ] **Step 1: Write the failing test**

Append to `test_models.py`:

```python
from opentools.scanner.models import ProgressEvent, ProgressEventType


class TestProgressEvent:
    def test_progress_event_type_values(self):
        assert ProgressEventType.SCAN_STARTED == "scan_started"
        assert ProgressEventType.FINDING_DISCOVERED == "finding_discovered"
        assert ProgressEventType.EDGE_FIRED == "edge_fired"
        assert ProgressEventType.STEERING_DECISION == "steering_decision"

    def test_progress_event_creation(self):
        now = datetime.now(timezone.utc)
        event = ProgressEvent(
            id="evt-1",
            type=ProgressEventType.TASK_COMPLETED,
            timestamp=now,
            scan_id="scan-1",
            sequence=1,
            task_id="task-1",
            data={"exit_code": 0},
            tasks_total=10,
            tasks_completed=1,
            tasks_running=2,
            findings_total=0,
            elapsed_seconds=5.2,
        )
        assert event.estimated_remaining_seconds is None
        assert event.sequence == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_models.py::TestProgressEvent -v`
Expected: FAIL — `ImportError`

- [ ] **Step 3: Write implementation**

Append to `packages/cli/src/opentools/scanner/models.py`:

```python
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
    data: dict = Field(default_factory=dict)
    tasks_total: int
    tasks_completed: int
    tasks_running: int
    findings_total: int
    elapsed_seconds: float
    estimated_remaining_seconds: Optional[float] = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_models.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/models.py packages/cli/tests/test_scanner/test_models.py
git commit -m "feat(scanner): ProgressEvent + ProgressEventType models"
```

---

### Task 5: CancellationToken

**Files:**
- Create: `packages/cli/src/opentools/scanner/cancellation.py`
- Test: `packages/cli/tests/test_scanner/test_cancellation.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/cli/tests/test_scanner/test_cancellation.py
"""Tests for CancellationToken."""

import asyncio
import pytest
from opentools.scanner.cancellation import CancellationToken


class TestCancellationToken:
    def test_initial_state(self):
        token = CancellationToken()
        assert token.is_cancelled is False
        assert token.reason is None

    @pytest.mark.asyncio
    async def test_cancel(self):
        token = CancellationToken()
        await token.cancel("user requested")
        assert token.is_cancelled is True
        assert token.reason == "user requested"

    @pytest.mark.asyncio
    async def test_cancel_is_idempotent(self):
        token = CancellationToken()
        await token.cancel("first")
        await token.cancel("second")
        assert token.reason == "first"

    @pytest.mark.asyncio
    async def test_wait_for_cancellation(self):
        token = CancellationToken()

        async def cancel_after_delay():
            await asyncio.sleep(0.05)
            await token.cancel("timeout")

        asyncio.create_task(cancel_after_delay())
        await token.wait_for_cancellation()
        assert token.is_cancelled is True

    @pytest.mark.asyncio
    async def test_wait_returns_immediately_if_already_cancelled(self):
        token = CancellationToken()
        await token.cancel("done")
        # Should return immediately, not hang
        await asyncio.wait_for(token.wait_for_cancellation(), timeout=0.1)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_cancellation.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/scanner/cancellation.py
"""Cooperative cancellation token for scan engine."""

from __future__ import annotations

import asyncio


class CancellationToken:
    """Thread-safe, async-aware cancellation signal.

    Create one per scan. Pass it to all executors and the engine.
    Call ``cancel()`` to signal cancellation. All waiters wake up.
    """

    def __init__(self) -> None:
        self._event = asyncio.Event()
        self._reason: str | None = None

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str | None:
        return self._reason

    async def cancel(self, reason: str) -> None:
        """Signal cancellation. Idempotent — first reason wins."""
        if not self._event.is_set():
            self._reason = reason
            self._event.set()

    async def wait_for_cancellation(self) -> None:
        """Block until cancellation is signalled."""
        await self._event.wait()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_cancellation.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/cancellation.py packages/cli/tests/test_scanner/test_cancellation.py
git commit -m "feat(scanner): CancellationToken — cooperative async cancellation"
```

---

### Task 6: Static Data Files — CWE Hierarchy, Aliases, Severity Maps

**Files:**
- Create: `packages/cli/src/opentools/scanner/data/cwe_hierarchy.json`
- Create: `packages/cli/src/opentools/scanner/data/cwe_aliases.json`
- Create: `packages/cli/src/opentools/scanner/data/cwe_owasp_map.json`
- Create: `packages/cli/src/opentools/scanner/data/severity_maps.json`
- Create: `packages/cli/src/opentools/scanner/data/title_normalization.json`
- Create: `packages/cli/src/opentools/scanner/data/parser_confidence.json`

- [ ] **Step 1: Create CWE hierarchy data (focused subset for security scanning)**

```json
// packages/cli/src/opentools/scanner/data/cwe_hierarchy.json
{
  "_comment": "CWE parent/child relationships. Subset relevant to security scanning tools.",
  "CWE-20": { "name": "Improper Input Validation", "children": ["CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-77", "CWE-94"] },
  "CWE-74": { "name": "Injection", "children": ["CWE-89", "CWE-79", "CWE-78", "CWE-77", "CWE-94", "CWE-917"] },
  "CWE-89": { "name": "SQL Injection", "parent": "CWE-74", "children": ["CWE-564"] },
  "CWE-564": { "name": "SQL Injection: Hibernate", "parent": "CWE-89", "children": [] },
  "CWE-79": { "name": "Cross-site Scripting (XSS)", "parent": "CWE-74", "children": ["CWE-80", "CWE-83", "CWE-87"] },
  "CWE-80": { "name": "Basic XSS", "parent": "CWE-79", "children": [] },
  "CWE-83": { "name": "XSS in Attribute", "parent": "CWE-79", "children": [] },
  "CWE-87": { "name": "XSS in IMG Tag", "parent": "CWE-79", "children": [] },
  "CWE-78": { "name": "OS Command Injection", "parent": "CWE-74", "children": [] },
  "CWE-77": { "name": "Command Injection", "parent": "CWE-74", "children": ["CWE-78"] },
  "CWE-94": { "name": "Code Injection", "parent": "CWE-74", "children": ["CWE-95", "CWE-96"] },
  "CWE-95": { "name": "Eval Injection", "parent": "CWE-94", "children": [] },
  "CWE-96": { "name": "Static Code Injection", "parent": "CWE-94", "children": [] },
  "CWE-22": { "name": "Path Traversal", "parent": "CWE-20", "children": ["CWE-23", "CWE-36"] },
  "CWE-23": { "name": "Relative Path Traversal", "parent": "CWE-22", "children": [] },
  "CWE-36": { "name": "Absolute Path Traversal", "parent": "CWE-22", "children": [] },
  "CWE-119": { "name": "Buffer Overflow", "children": ["CWE-120", "CWE-122", "CWE-121", "CWE-787"] },
  "CWE-120": { "name": "Classic Buffer Overflow", "parent": "CWE-119", "children": [] },
  "CWE-121": { "name": "Stack-based Buffer Overflow", "parent": "CWE-119", "children": [] },
  "CWE-122": { "name": "Heap-based Buffer Overflow", "parent": "CWE-119", "children": [] },
  "CWE-787": { "name": "Out-of-bounds Write", "parent": "CWE-119", "children": [] },
  "CWE-190": { "name": "Integer Overflow", "children": [] },
  "CWE-200": { "name": "Information Exposure", "children": ["CWE-209", "CWE-532"] },
  "CWE-209": { "name": "Error Message Information Leak", "parent": "CWE-200", "children": [] },
  "CWE-532": { "name": "Log File Information Leak", "parent": "CWE-200", "children": [] },
  "CWE-250": { "name": "Execution with Unnecessary Privileges", "children": [] },
  "CWE-276": { "name": "Incorrect Default Permissions", "children": [] },
  "CWE-287": { "name": "Improper Authentication", "children": ["CWE-306", "CWE-798"] },
  "CWE-306": { "name": "Missing Authentication", "parent": "CWE-287", "children": [] },
  "CWE-798": { "name": "Hardcoded Credentials", "parent": "CWE-287", "children": [] },
  "CWE-311": { "name": "Missing Encryption", "children": ["CWE-319"] },
  "CWE-319": { "name": "Cleartext Transmission", "parent": "CWE-311", "children": [] },
  "CWE-327": { "name": "Weak Cryptographic Algorithm", "children": [] },
  "CWE-352": { "name": "Cross-Site Request Forgery (CSRF)", "children": [] },
  "CWE-362": { "name": "Race Condition (TOCTOU)", "children": ["CWE-367"] },
  "CWE-367": { "name": "TOCTOU Race Condition", "parent": "CWE-362", "children": [] },
  "CWE-400": { "name": "Uncontrolled Resource Consumption", "children": [] },
  "CWE-416": { "name": "Use After Free", "children": [] },
  "CWE-434": { "name": "Unrestricted File Upload", "children": [] },
  "CWE-502": { "name": "Deserialization of Untrusted Data", "children": [] },
  "CWE-601": { "name": "Open Redirect", "children": [] },
  "CWE-611": { "name": "XXE", "children": [] },
  "CWE-676": { "name": "Use of Potentially Dangerous Function", "children": [] },
  "CWE-732": { "name": "Incorrect Permission Assignment", "children": [] },
  "CWE-918": { "name": "Server-Side Request Forgery (SSRF)", "children": [] },
  "CWE-917": { "name": "Expression Language Injection", "parent": "CWE-74", "children": [] },
  "CWE-1021": { "name": "Missing CSP", "children": [] },
  "CWE-457": { "name": "Use of Uninitialized Variable", "children": [] },
  "CWE-415": { "name": "Double Free", "children": [] },
  "CWE-476": { "name": "NULL Pointer Dereference", "children": [] },
  "CWE-134": { "name": "Use of Externally-Controlled Format String", "children": [] }
}
```

- [ ] **Step 2: Create CWE aliases**

```json
// packages/cli/src/opentools/scanner/data/cwe_aliases.json
{
  "_comment": "Common aliases/shorthand → canonical CWE IDs",
  "sqli": "CWE-89",
  "sql injection": "CWE-89",
  "sql-injection": "CWE-89",
  "xss": "CWE-79",
  "cross-site scripting": "CWE-79",
  "cross site scripting": "CWE-79",
  "rce": "CWE-78",
  "command injection": "CWE-78",
  "os command injection": "CWE-78",
  "path traversal": "CWE-22",
  "directory traversal": "CWE-22",
  "lfi": "CWE-22",
  "buffer overflow": "CWE-119",
  "stack overflow": "CWE-121",
  "heap overflow": "CWE-122",
  "integer overflow": "CWE-190",
  "use after free": "CWE-416",
  "double free": "CWE-415",
  "null pointer": "CWE-476",
  "null dereference": "CWE-476",
  "format string": "CWE-134",
  "hardcoded password": "CWE-798",
  "hardcoded credential": "CWE-798",
  "hardcoded secret": "CWE-798",
  "csrf": "CWE-352",
  "ssrf": "CWE-918",
  "xxe": "CWE-611",
  "open redirect": "CWE-601",
  "deserialization": "CWE-502",
  "file upload": "CWE-434",
  "weak crypto": "CWE-327",
  "weak cipher": "CWE-327",
  "missing encryption": "CWE-311",
  "cleartext": "CWE-319",
  "race condition": "CWE-362",
  "toctou": "CWE-367",
  "missing csp": "CWE-1021",
  "eval injection": "CWE-95",
  "code injection": "CWE-94"
}
```

- [ ] **Step 3: Create OWASP mapping**

```json
// packages/cli/src/opentools/scanner/data/cwe_owasp_map.json
{
  "_comment": "CWE → OWASP Top 10 2021 categories",
  "CWE-287": "A07:2021 Identification and Authentication Failures",
  "CWE-306": "A07:2021 Identification and Authentication Failures",
  "CWE-798": "A07:2021 Identification and Authentication Failures",
  "CWE-327": "A02:2021 Cryptographic Failures",
  "CWE-311": "A02:2021 Cryptographic Failures",
  "CWE-319": "A02:2021 Cryptographic Failures",
  "CWE-89": "A03:2021 Injection",
  "CWE-564": "A03:2021 Injection",
  "CWE-79": "A03:2021 Injection",
  "CWE-78": "A03:2021 Injection",
  "CWE-77": "A03:2021 Injection",
  "CWE-94": "A03:2021 Injection",
  "CWE-917": "A03:2021 Injection",
  "CWE-611": "A05:2021 Security Misconfiguration",
  "CWE-1021": "A05:2021 Security Misconfiguration",
  "CWE-276": "A05:2021 Security Misconfiguration",
  "CWE-502": "A08:2021 Software and Data Integrity Failures",
  "CWE-352": "A01:2021 Broken Access Control",
  "CWE-22": "A01:2021 Broken Access Control",
  "CWE-601": "A01:2021 Broken Access Control",
  "CWE-918": "A10:2021 Server-Side Request Forgery",
  "CWE-200": "A01:2021 Broken Access Control",
  "CWE-434": "A04:2021 Insecure Design",
  "CWE-119": "A06:2021 Vulnerable and Outdated Components",
  "CWE-416": "A06:2021 Vulnerable and Outdated Components",
  "CWE-190": "A06:2021 Vulnerable and Outdated Components"
}
```

- [ ] **Step 4: Create severity maps, title normalization, parser confidence**

```json
// packages/cli/src/opentools/scanner/data/severity_maps.json
{
  "_comment": "Per-tool severity labels → canonical severity",
  "semgrep": {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "info"
  },
  "nuclei": {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info"
  },
  "trivy": {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info"
  },
  "codebadger": {
    "high": "high",
    "medium": "medium",
    "low": "low"
  },
  "gitleaks": {
    "secret": "high"
  },
  "nikto": {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "info"
  },
  "nmap": {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low"
  },
  "sqlmap": {
    "critical": "critical",
    "high": "high"
  }
}
```

```json
// packages/cli/src/opentools/scanner/data/title_normalization.json
{
  "_comment": "Regex patterns → canonical finding titles. Patterns are case-insensitive.",
  "patterns": [
    { "regex": "sql\\s*inject", "title": "SQL Injection" },
    { "regex": "cross.site.script|\\bxss\\b", "title": "Cross-Site Scripting (XSS)" },
    { "regex": "command\\s*inject|os\\s*inject|\\brce\\b", "title": "OS Command Injection" },
    { "regex": "path\\s*travers|directory\\s*travers|\\blfi\\b", "title": "Path Traversal" },
    { "regex": "hardcoded\\s*(password|secret|key|credential|token)", "title": "Hardcoded Credential" },
    { "regex": "missing\\s*(csp|content.security.policy)", "title": "Missing Content-Security-Policy" },
    { "regex": "weak\\s*(cipher|crypto|algorithm|hash)", "title": "Weak Cryptographic Algorithm" },
    { "regex": "open\\s*redirect", "title": "Open Redirect" },
    { "regex": "ssrf|server.side.request", "title": "Server-Side Request Forgery (SSRF)" },
    { "regex": "deseriali[sz]", "title": "Insecure Deserialization" },
    { "regex": "\\bcsrf\\b|cross.site.request.forg", "title": "Cross-Site Request Forgery (CSRF)" },
    { "regex": "\\bxxe\\b|xml.external.entit", "title": "XML External Entity (XXE)" },
    { "regex": "buffer\\s*overflow", "title": "Buffer Overflow" },
    { "regex": "stack.*(overflow|buffer)", "title": "Stack-based Buffer Overflow" },
    { "regex": "heap.*(overflow|buffer)", "title": "Heap-based Buffer Overflow" },
    { "regex": "use.after.free", "title": "Use After Free" },
    { "regex": "double.free", "title": "Double Free" },
    { "regex": "null.*(pointer|deref|dereference)", "title": "NULL Pointer Dereference" },
    { "regex": "integer.*(overflow|underflow|wrap)", "title": "Integer Overflow" },
    { "regex": "format.string", "title": "Format String Vulnerability" },
    { "regex": "taint.*(flow|source|sink)", "title": "Taint Flow Vulnerability" },
    { "regex": "uninitialized.*(var|read|memory|use)", "title": "Use of Uninitialized Variable" },
    { "regex": "race.condition|toctou", "title": "Race Condition (TOCTOU)" },
    { "regex": "file.upload|unrestricted.upload", "title": "Unrestricted File Upload" },
    { "regex": "missing.auth|no.auth|unauthenticated", "title": "Missing Authentication" }
  ]
}
```

```json
// packages/cli/src/opentools/scanner/data/parser_confidence.json
{
  "_comment": "Tool → base parser confidence tier (0.0-1.0)",
  "semgrep": 0.9,
  "trivy": 0.9,
  "nuclei": 0.7,
  "codebadger": 0.7,
  "nmap": 0.5,
  "nikto": 0.5,
  "gitleaks": 0.9,
  "sqlmap": 0.85,
  "hashcat": 0.5,
  "capa": 0.7,
  "arkana": 0.7
}
```

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/data/
git commit -m "feat(scanner): static data files — CWE hierarchy, aliases, severity maps, title normalization"
```

---

### Task 7: CWE Hierarchy Module

**Files:**
- Create: `packages/cli/src/opentools/scanner/cwe.py`
- Test: `packages/cli/tests/test_scanner/test_cwe.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/cli/tests/test_scanner/test_cwe.py
"""Tests for CWE hierarchy and alias resolution."""

from opentools.scanner.cwe import CWEHierarchy


class TestCWEHierarchy:
    def setup_method(self):
        self.cwe = CWEHierarchy()

    def test_get_name(self):
        assert self.cwe.get_name("CWE-89") == "SQL Injection"

    def test_get_name_unknown(self):
        assert self.cwe.get_name("CWE-99999") is None

    def test_get_parent(self):
        assert self.cwe.get_parent("CWE-564") == "CWE-89"

    def test_get_parent_root(self):
        assert self.cwe.get_parent("CWE-190") is None

    def test_get_children(self):
        children = self.cwe.get_children("CWE-89")
        assert "CWE-564" in children

    def test_is_related_parent_child(self):
        assert self.cwe.is_related("CWE-89", "CWE-564") is True

    def test_is_related_siblings(self):
        # CWE-89 and CWE-79 share parent CWE-74
        assert self.cwe.is_related("CWE-89", "CWE-79") is True

    def test_is_related_unrelated(self):
        assert self.cwe.is_related("CWE-89", "CWE-416") is False

    def test_resolve_alias(self):
        assert self.cwe.resolve_alias("sqli") == "CWE-89"
        assert self.cwe.resolve_alias("xss") == "CWE-79"
        assert self.cwe.resolve_alias("use after free") == "CWE-416"

    def test_resolve_alias_canonical_passthrough(self):
        assert self.cwe.resolve_alias("CWE-89") == "CWE-89"

    def test_resolve_alias_unknown(self):
        assert self.cwe.resolve_alias("unknown-thing") is None

    def test_get_owasp_category(self):
        assert "Injection" in self.cwe.get_owasp_category("CWE-89")

    def test_get_owasp_category_unknown(self):
        assert self.cwe.get_owasp_category("CWE-99999") is None

    def test_get_owasp_category_via_parent(self):
        # CWE-564 (Hibernate SQLi) should resolve via parent CWE-89
        result = self.cwe.get_owasp_category("CWE-564")
        assert result is not None
        assert "Injection" in result
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_cwe.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/scanner/cwe.py
"""CWE hierarchy, alias resolution, and OWASP Top 10 mapping."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path


_DATA_DIR = Path(__file__).parent / "data"


class CWEHierarchy:
    """Loads and queries CWE parent/child relationships, aliases, and OWASP mapping."""

    def __init__(self) -> None:
        self._hierarchy = _load_json("cwe_hierarchy.json")
        self._aliases = _load_json("cwe_aliases.json")
        self._owasp = _load_json("cwe_owasp_map.json")

    def get_name(self, cwe_id: str) -> str | None:
        entry = self._hierarchy.get(cwe_id)
        return entry["name"] if entry else None

    def get_parent(self, cwe_id: str) -> str | None:
        entry = self._hierarchy.get(cwe_id)
        if entry:
            return entry.get("parent")
        return None

    def get_children(self, cwe_id: str) -> list[str]:
        entry = self._hierarchy.get(cwe_id)
        if entry:
            return entry.get("children", [])
        return []

    def is_related(self, cwe_a: str, cwe_b: str) -> bool:
        """True if CWEs share a parent or one is ancestor of the other."""
        if cwe_a == cwe_b:
            return True
        # Check direct parent/child
        if self.get_parent(cwe_a) == cwe_b or self.get_parent(cwe_b) == cwe_a:
            return True
        # Check shared parent (siblings)
        parent_a = self.get_parent(cwe_a)
        parent_b = self.get_parent(cwe_b)
        if parent_a and parent_b and parent_a == parent_b:
            return True
        # Check grandparent relationships (one level up)
        if parent_a and self.get_parent(parent_a) == cwe_b:
            return True
        if parent_b and self.get_parent(parent_b) == cwe_a:
            return True
        if parent_a and parent_b:
            gp_a = self.get_parent(parent_a)
            gp_b = self.get_parent(parent_b)
            if gp_a and gp_a == gp_b:
                return True
            if gp_a and gp_a == parent_b:
                return True
            if gp_b and gp_b == parent_a:
                return True
        return False

    def resolve_alias(self, alias: str) -> str | None:
        """Resolve an alias or shorthand to a canonical CWE ID."""
        # Already canonical
        if alias in self._hierarchy:
            return alias
        # Try alias lookup (case-insensitive)
        lower = alias.lower().strip()
        if lower in self._aliases:
            return self._aliases[lower]
        return None

    def get_owasp_category(self, cwe_id: str) -> str | None:
        """Map CWE to OWASP Top 10 2021 category. Walks up the hierarchy."""
        if cwe_id in self._owasp:
            return self._owasp[cwe_id]
        # Try parent
        parent = self.get_parent(cwe_id)
        if parent and parent in self._owasp:
            return self._owasp[parent]
        return None


@lru_cache(maxsize=None)
def _load_json(filename: str) -> dict:
    path = _DATA_DIR / filename
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    # Strip _comment keys
    return {k: v for k, v in data.items() if k != "_comment"}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_cwe.py -v`
Expected: All 12 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/cwe.py packages/cli/tests/test_scanner/test_cwe.py
git commit -m "feat(scanner): CWEHierarchy — parent/child, alias resolution, OWASP mapping"
```

---

### Task 8: Shared Subprocess Module

**Files:**
- Create: `packages/cli/src/opentools/shared/__init__.py`
- Create: `packages/cli/src/opentools/shared/subprocess.py`
- Test: `packages/cli/tests/test_scanner/test_shared_subprocess.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/cli/tests/test_scanner/test_shared_subprocess.py
"""Tests for shared async subprocess execution."""

import asyncio
import sys
import pytest
from opentools.shared.subprocess import run_streaming, SubprocessResult
from opentools.scanner.cancellation import CancellationToken


class TestRunStreaming:
    @pytest.mark.asyncio
    async def test_successful_command(self):
        result = await run_streaming(
            [sys.executable, "-c", "print('hello')"],
            on_output=lambda chunk: None,
        )
        assert result.exit_code == 0
        assert "hello" in result.stdout
        assert result.duration_ms > 0

    @pytest.mark.asyncio
    async def test_failed_command(self):
        result = await run_streaming(
            [sys.executable, "-c", "import sys; sys.exit(1)"],
            on_output=lambda chunk: None,
        )
        assert result.exit_code == 1

    @pytest.mark.asyncio
    async def test_streaming_output(self):
        chunks: list[bytes] = []
        result = await run_streaming(
            [sys.executable, "-c", "print('line1'); print('line2')"],
            on_output=lambda chunk: chunks.append(chunk),
        )
        assert result.exit_code == 0
        combined = b"".join(chunks).decode()
        assert "line1" in combined
        assert "line2" in combined

    @pytest.mark.asyncio
    async def test_timeout(self):
        result = await run_streaming(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            on_output=lambda chunk: None,
            timeout=1,
        )
        assert result.exit_code is None or result.exit_code != 0
        assert result.timed_out is True

    @pytest.mark.asyncio
    async def test_cancellation(self):
        token = CancellationToken()
        asyncio.get_event_loop().call_later(0.1, lambda: asyncio.ensure_future(token.cancel("test")))
        result = await run_streaming(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            on_output=lambda chunk: None,
            cancellation=token,
        )
        assert result.cancelled is True

    @pytest.mark.asyncio
    async def test_stderr_capture(self):
        result = await run_streaming(
            [sys.executable, "-c", "import sys; print('err', file=sys.stderr)"],
            on_output=lambda chunk: None,
        )
        assert "err" in result.stderr
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_shared_subprocess.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/shared/__init__.py
"""Shared infrastructure modules used by scanner and recipe engines."""

# packages/cli/src/opentools/shared/subprocess.py
"""Async subprocess execution with streaming output, timeout, and cancellation."""

from __future__ import annotations

import asyncio
import sys
import time
from typing import Callable, Optional

from pydantic import BaseModel


class SubprocessResult(BaseModel):
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    timed_out: bool = False
    cancelled: bool = False


async def run_streaming(
    args: list[str],
    on_output: Callable[[bytes], None],
    timeout: int = 300,
    cancellation: Optional[object] = None,  # CancellationToken
) -> SubprocessResult:
    """Run a subprocess with streaming stdout, timeout, and optional cancellation.

    Parameters
    ----------
    args:
        Command and arguments.
    on_output:
        Called with each chunk of stdout bytes as they arrive.
    timeout:
        Seconds before the process is killed.
    cancellation:
        Optional CancellationToken. If cancelled, the process is killed.
    """
    start = time.monotonic()
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as e:
        return SubprocessResult(
            exit_code=-1,
            stderr=f"Command not found: {e}",
            duration_ms=int((time.monotonic() - start) * 1000),
        )

    async def _read_stdout():
        assert proc.stdout is not None
        while True:
            chunk = await proc.stdout.read(4096)
            if not chunk:
                break
            stdout_chunks.append(chunk)
            on_output(chunk)

    async def _read_stderr():
        assert proc.stderr is not None
        while True:
            chunk = await proc.stderr.read(4096)
            if not chunk:
                break
            stderr_chunks.append(chunk)

    async def _check_cancellation():
        if cancellation is None:
            return
        await cancellation.wait_for_cancellation()

    reader_stdout = asyncio.create_task(_read_stdout())
    reader_stderr = asyncio.create_task(_read_stderr())
    cancel_waiter = asyncio.create_task(_check_cancellation()) if cancellation else None

    timed_out = False
    cancelled = False

    try:
        wait_tasks = [reader_stdout, reader_stderr]
        if cancel_waiter:
            wait_tasks.append(cancel_waiter)

        done, pending = await asyncio.wait(
            wait_tasks,
            timeout=timeout,
            return_when=asyncio.FIRST_EXCEPTION if not cancel_waiter else asyncio.FIRST_COMPLETED,
        )

        # Check if cancellation fired
        if cancel_waiter and cancel_waiter in done:
            cancelled = True
            proc.kill()
            await proc.wait()
        elif pending:
            # Timeout — not all readers finished
            if reader_stdout in pending or reader_stderr in pending:
                timed_out = True
                proc.kill()
                await proc.wait()
        else:
            # Both readers finished — wait for process exit
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()

    except Exception:
        proc.kill()
        await proc.wait()
        raise
    finally:
        # Clean up tasks
        for task in [reader_stdout, reader_stderr, cancel_waiter]:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

    duration_ms = int((time.monotonic() - start) * 1000)

    return SubprocessResult(
        exit_code=proc.returncode,
        stdout=b"".join(stdout_chunks).decode(errors="replace"),
        stderr=b"".join(stderr_chunks).decode(errors="replace"),
        duration_ms=duration_ms,
        timed_out=timed_out,
        cancelled=cancelled,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_shared_subprocess.py -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/shared/ packages/cli/tests/test_scanner/test_shared_subprocess.py
git commit -m "feat(shared): async subprocess with streaming, timeout, cancellation"
```

---

### Task 9: EventBus — Progress Event Fan-Out

**Files:**
- Create: `packages/cli/src/opentools/shared/progress.py`
- Test: `packages/cli/tests/test_scanner/test_shared_progress.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/cli/tests/test_scanner/test_shared_progress.py
"""Tests for EventBus progress event fan-out."""

import asyncio
from datetime import datetime, timezone
import pytest
from opentools.shared.progress import EventBus
from opentools.scanner.models import ProgressEvent, ProgressEventType


def _make_event(scan_id: str, seq: int, event_type: ProgressEventType = ProgressEventType.TASK_COMPLETED) -> ProgressEvent:
    return ProgressEvent(
        id=f"evt-{seq}",
        type=event_type,
        timestamp=datetime.now(timezone.utc),
        scan_id=scan_id,
        sequence=seq,
        data={},
        tasks_total=10,
        tasks_completed=seq,
        tasks_running=1,
        findings_total=0,
        elapsed_seconds=float(seq),
    )


class TestEventBus:
    @pytest.mark.asyncio
    async def test_publish_and_subscribe(self):
        bus = EventBus()
        events_received: list[ProgressEvent] = []

        async def consumer():
            async for event in bus.subscribe("scan-1"):
                events_received.append(event)
                if event.type == ProgressEventType.SCAN_COMPLETED:
                    break

        consumer_task = asyncio.create_task(consumer())
        # Give consumer time to subscribe
        await asyncio.sleep(0.01)

        await bus.publish(_make_event("scan-1", 1))
        await bus.publish(_make_event("scan-1", 2, ProgressEventType.SCAN_COMPLETED))

        await asyncio.wait_for(consumer_task, timeout=1.0)
        assert len(events_received) == 2
        assert events_received[0].sequence == 1
        assert events_received[1].type == ProgressEventType.SCAN_COMPLETED

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self):
        bus = EventBus()
        events_a: list[ProgressEvent] = []
        events_b: list[ProgressEvent] = []

        async def consumer(target: list):
            async for event in bus.subscribe("scan-1"):
                target.append(event)
                if event.type == ProgressEventType.SCAN_COMPLETED:
                    break

        task_a = asyncio.create_task(consumer(events_a))
        task_b = asyncio.create_task(consumer(events_b))
        await asyncio.sleep(0.01)

        await bus.publish(_make_event("scan-1", 1, ProgressEventType.SCAN_COMPLETED))

        await asyncio.wait_for(asyncio.gather(task_a, task_b), timeout=1.0)
        assert len(events_a) == 1
        assert len(events_b) == 1

    @pytest.mark.asyncio
    async def test_different_scan_ids_isolated(self):
        bus = EventBus()
        events: list[ProgressEvent] = []

        async def consumer():
            async for event in bus.subscribe("scan-1"):
                events.append(event)
                if event.type == ProgressEventType.SCAN_COMPLETED:
                    break

        task = asyncio.create_task(consumer())
        await asyncio.sleep(0.01)

        # Publish to different scan — should not be received
        await bus.publish(_make_event("scan-2", 1))
        # Publish to our scan
        await bus.publish(_make_event("scan-1", 1, ProgressEventType.SCAN_COMPLETED))

        await asyncio.wait_for(task, timeout=1.0)
        assert len(events) == 1
        assert events[0].scan_id == "scan-1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_shared_progress.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/shared/progress.py
"""EventBus for progress event fan-out to multiple subscribers."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import AsyncIterator

from opentools.scanner.models import ProgressEvent, ProgressEventType


class EventBus:
    """Fan-out progress events to multiple async subscribers.

    Each subscriber gets its own queue. Slow subscribers drop oldest
    events (backpressure) rather than blocking the publisher.
    """

    def __init__(self, max_queue_size: int = 1000) -> None:
        self._subscribers: dict[str, list[asyncio.Queue[ProgressEvent]]] = defaultdict(list)
        self._max_queue_size = max_queue_size

    async def publish(self, event: ProgressEvent) -> None:
        """Publish an event to all subscribers for this scan."""
        for queue in self._subscribers.get(event.scan_id, []):
            if queue.full():
                # Backpressure: drop oldest event
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

    async def subscribe(
        self, scan_id: str, from_sequence: int | None = None,
    ) -> AsyncIterator[ProgressEvent]:
        """Subscribe to events for a scan. Yields events until scan completes/fails."""
        queue: asyncio.Queue[ProgressEvent] = asyncio.Queue(maxsize=self._max_queue_size)
        self._subscribers[scan_id].append(queue)

        _terminal_types = {
            ProgressEventType.SCAN_COMPLETED,
            ProgressEventType.SCAN_FAILED,
        }

        try:
            while True:
                event = await queue.get()
                yield event
                if event.type in _terminal_types:
                    break
        finally:
            self._subscribers[scan_id].remove(queue)
            if not self._subscribers[scan_id]:
                del self._subscribers[scan_id]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_shared_progress.py -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/shared/progress.py packages/cli/tests/test_scanner/test_shared_progress.py
git commit -m "feat(shared): EventBus — async progress event fan-out with backpressure"
```

---

### Task 10: Shared Retry Module

**Files:**
- Create: `packages/cli/src/opentools/shared/retry.py`
- Test: `packages/cli/tests/test_scanner/test_shared_retry.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/cli/tests/test_scanner/test_shared_retry.py
"""Tests for retry with exponential backoff."""

import asyncio
import pytest
from opentools.shared.retry import execute_with_retry
from opentools.scanner.models import RetryPolicy


class TestRetry:
    @pytest.mark.asyncio
    async def test_success_no_retry(self):
        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            return "ok"

        result = await execute_with_retry(fn, RetryPolicy(max_retries=3))
        assert result == "ok"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retry_on_failure(self):
        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise TimeoutError("timeout")
            return "ok"

        result = await execute_with_retry(
            fn,
            RetryPolicy(max_retries=3, backoff_seconds=0.01, retry_on=["timeout"]),
        )
        assert result == "ok"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_exhausted_retries_raises(self):
        async def fn():
            raise TimeoutError("timeout")

        with pytest.raises(TimeoutError):
            await execute_with_retry(
                fn,
                RetryPolicy(max_retries=2, backoff_seconds=0.01, retry_on=["timeout"]),
            )

    @pytest.mark.asyncio
    async def test_non_retryable_error_raises_immediately(self):
        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            raise ValueError("not retryable")

        with pytest.raises(ValueError):
            await execute_with_retry(
                fn,
                RetryPolicy(max_retries=3, retry_on=["timeout"]),
            )
        assert call_count == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_shared_retry.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/shared/retry.py
"""Retry execution with exponential backoff."""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Coroutine

from opentools.scanner.models import RetryPolicy


def _is_retryable(error: Exception, retry_on: list[str]) -> bool:
    """Check if an error matches any of the retryable error type names."""
    error_type = type(error).__name__.lower()
    error_str = str(error).lower()
    for pattern in retry_on:
        pattern_lower = pattern.lower()
        if pattern_lower in error_type or pattern_lower in error_str:
            return True
    return False


async def execute_with_retry(
    fn: Callable[[], Coroutine[Any, Any, Any]],
    policy: RetryPolicy,
) -> Any:
    """Execute an async function with retry on matching errors.

    Retries up to ``policy.max_retries`` times with exponential backoff.
    Only retries errors matching ``policy.retry_on`` patterns.
    Non-matching errors propagate immediately.
    """
    last_error: Exception | None = None
    for attempt in range(1 + policy.max_retries):
        try:
            return await fn()
        except Exception as e:
            last_error = e
            if not _is_retryable(e, policy.retry_on):
                raise
            if attempt >= policy.max_retries:
                raise
            backoff = policy.backoff_seconds * (2 ** attempt)
            await asyncio.sleep(backoff)
    raise last_error  # unreachable, but satisfies type checker
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_shared_retry.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/shared/retry.py packages/cli/tests/test_scanner/test_shared_retry.py
git commit -m "feat(shared): retry with exponential backoff and error pattern matching"
```

---

### Task 11: ScanStore Protocol + SQLite Implementation (Core Methods)

**Files:**
- Create: `packages/cli/src/opentools/scanner/store.py`
- Test: `packages/cli/tests/test_scanner/test_store.py`

- [ ] **Step 1: Write the failing test for store basics**

```python
# packages/cli/tests/test_scanner/test_store.py
"""Integration tests for SqliteScanStore."""

from datetime import datetime, timezone
import pytest
import pytest_asyncio
from opentools.scanner.store import SqliteScanStore
from opentools.scanner.models import (
    Scan, ScanTask, ScanStatus, ScanMode, TargetType, TaskType, TaskStatus,
)


@pytest_asyncio.fixture
async def store(tmp_path):
    db_path = tmp_path / "test_scans.db"
    s = SqliteScanStore(db_path)
    await s.initialize()
    yield s
    await s.close()


class TestScanCRUD:
    @pytest.mark.asyncio
    async def test_save_and_get_scan(self, store):
        now = datetime.now(timezone.utc)
        scan = Scan(
            id="scan-1",
            engagement_id="eng-1",
            target="https://example.com",
            target_type=TargetType.URL,
            profile="web-full",
            profile_snapshot={"id": "web-full"},
            mode=ScanMode.AUTO,
            status=ScanStatus.PENDING,
            created_at=now,
        )
        await store.save_scan(scan)
        retrieved = await store.get_scan("scan-1")
        assert retrieved is not None
        assert retrieved.id == "scan-1"
        assert retrieved.target == "https://example.com"
        assert retrieved.target_type == TargetType.URL

    @pytest.mark.asyncio
    async def test_get_scan_not_found(self, store):
        result = await store.get_scan("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_update_scan_status(self, store):
        now = datetime.now(timezone.utc)
        scan = Scan(
            id="scan-2",
            engagement_id="eng-1",
            target="./src",
            target_type=TargetType.SOURCE_CODE,
            profile_snapshot={},
            mode=ScanMode.AUTO,
            status=ScanStatus.PENDING,
            created_at=now,
        )
        await store.save_scan(scan)
        await store.update_scan_status("scan-2", ScanStatus.RUNNING, started_at=now)
        updated = await store.get_scan("scan-2")
        assert updated.status == ScanStatus.RUNNING
        assert updated.started_at is not None

    @pytest.mark.asyncio
    async def test_list_scans(self, store):
        now = datetime.now(timezone.utc)
        for i in range(3):
            await store.save_scan(Scan(
                id=f"scan-{i}",
                engagement_id="eng-1",
                target=f"target-{i}",
                target_type=TargetType.URL,
                profile_snapshot={},
                mode=ScanMode.AUTO,
                status=ScanStatus.PENDING,
                created_at=now,
            ))
        scans = await store.list_scans()
        assert len(scans) == 3

    @pytest.mark.asyncio
    async def test_list_scans_filter_by_engagement(self, store):
        now = datetime.now(timezone.utc)
        await store.save_scan(Scan(
            id="s-a", engagement_id="eng-1", target="t",
            target_type=TargetType.URL, profile_snapshot={},
            mode=ScanMode.AUTO, status=ScanStatus.PENDING, created_at=now,
        ))
        await store.save_scan(Scan(
            id="s-b", engagement_id="eng-2", target="t",
            target_type=TargetType.URL, profile_snapshot={},
            mode=ScanMode.AUTO, status=ScanStatus.PENDING, created_at=now,
        ))
        scans = await store.list_scans(engagement_id="eng-1")
        assert len(scans) == 1
        assert scans[0].id == "s-a"


class TestTaskCRUD:
    @pytest.mark.asyncio
    async def test_save_and_get_tasks(self, store):
        now = datetime.now(timezone.utc)
        await store.save_scan(Scan(
            id="scan-1", engagement_id="eng-1", target="t",
            target_type=TargetType.URL, profile_snapshot={},
            mode=ScanMode.AUTO, status=ScanStatus.RUNNING, created_at=now,
        ))
        task = ScanTask(
            id="task-1", scan_id="scan-1", name="nmap-scan",
            tool="nmap", task_type=TaskType.SHELL,
            command="nmap -sV 192.168.1.1",
        )
        await store.save_task(task)
        tasks = await store.get_scan_tasks("scan-1")
        assert len(tasks) == 1
        assert tasks[0].id == "task-1"
        assert tasks[0].tool == "nmap"

    @pytest.mark.asyncio
    async def test_update_task_status(self, store):
        now = datetime.now(timezone.utc)
        await store.save_scan(Scan(
            id="scan-1", engagement_id="eng-1", target="t",
            target_type=TargetType.URL, profile_snapshot={},
            mode=ScanMode.AUTO, status=ScanStatus.RUNNING, created_at=now,
        ))
        await store.save_task(ScanTask(
            id="task-1", scan_id="scan-1", name="nmap-scan",
            tool="nmap", task_type=TaskType.SHELL,
        ))
        await store.update_task_status(
            "task-1", TaskStatus.COMPLETED,
            exit_code=0, duration_ms=5000, stdout="output here",
        )
        tasks = await store.get_scan_tasks("scan-1")
        assert tasks[0].status == TaskStatus.COMPLETED
        assert tasks[0].exit_code == 0
        assert tasks[0].duration_ms == 5000
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_store.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/scanner/store.py
"""Scan store protocol and SQLite implementation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

import aiosqlite

from opentools.scanner.models import (
    Scan, ScanTask, ScanStatus, TaskStatus,
)


@runtime_checkable
class ScanStoreProtocol(Protocol):
    """Abstract storage for scan data."""

    async def save_scan(self, scan: Scan) -> None: ...
    async def get_scan(self, scan_id: str) -> Scan | None: ...
    async def update_scan_status(self, scan_id: str, status: ScanStatus, **fields) -> None: ...
    async def list_scans(self, engagement_id: str | None = None) -> list[Scan]: ...
    async def save_task(self, task: ScanTask) -> None: ...
    async def get_scan_tasks(self, scan_id: str) -> list[ScanTask]: ...
    async def update_task_status(self, task_id: str, status: TaskStatus, **fields) -> None: ...


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_task (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_scan_task_scan ON scan_task(scan_id);
"""


class SqliteScanStore:
    """SQLite-backed scan store for CLI usage."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._db_path))
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    def _conn(self) -> aiosqlite.Connection:
        assert self._db is not None, "Store not initialized. Call initialize() first."
        return self._db

    # ── Scan CRUD ────────────────────────────────────────────────────────

    async def save_scan(self, scan: Scan) -> None:
        data = scan.model_dump_json()
        await self._conn().execute(
            "INSERT OR REPLACE INTO scan (id, data) VALUES (?, ?)",
            (scan.id, data),
        )
        await self._conn().commit()

    async def get_scan(self, scan_id: str) -> Scan | None:
        cursor = await self._conn().execute(
            "SELECT data FROM scan WHERE id = ?", (scan_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return Scan.model_validate_json(row[0])

    async def update_scan_status(self, scan_id: str, status: ScanStatus, **fields) -> None:
        scan = await self.get_scan(scan_id)
        if scan is None:
            return
        scan.status = status
        for key, value in fields.items():
            if hasattr(scan, key):
                setattr(scan, key, value)
        await self.save_scan(scan)

    async def list_scans(self, engagement_id: str | None = None) -> list[Scan]:
        if engagement_id:
            cursor = await self._conn().execute("SELECT data FROM scan")
            rows = await cursor.fetchall()
            return [
                s for s in (Scan.model_validate_json(r[0]) for r in rows)
                if s.engagement_id == engagement_id
            ]
        cursor = await self._conn().execute("SELECT data FROM scan")
        rows = await cursor.fetchall()
        return [Scan.model_validate_json(r[0]) for r in rows]

    # ── Task CRUD ────────────────────────────────────────────────────────

    async def save_task(self, task: ScanTask) -> None:
        data = task.model_dump_json()
        await self._conn().execute(
            "INSERT OR REPLACE INTO scan_task (id, scan_id, data) VALUES (?, ?, ?)",
            (task.id, task.scan_id, data),
        )
        await self._conn().commit()

    async def get_scan_tasks(self, scan_id: str) -> list[ScanTask]:
        cursor = await self._conn().execute(
            "SELECT data FROM scan_task WHERE scan_id = ?", (scan_id,),
        )
        rows = await cursor.fetchall()
        return [ScanTask.model_validate_json(r[0]) for r in rows]

    async def update_task_status(self, task_id: str, status: TaskStatus, **fields) -> None:
        cursor = await self._conn().execute(
            "SELECT data FROM scan_task WHERE id = ?", (task_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return
        task = ScanTask.model_validate_json(row[0])
        task.status = status
        for key, value in fields.items():
            if hasattr(task, key):
                setattr(task, key, value)
        await self._conn().execute(
            "UPDATE scan_task SET data = ? WHERE id = ?",
            (task.model_dump_json(), task_id),
        )
        await self._conn().commit()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_store.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/store.py packages/cli/tests/test_scanner/test_store.py
git commit -m "feat(scanner): ScanStoreProtocol + SqliteScanStore — scan and task CRUD"
```

---

### Task 12: Modify Existing Finding Model

**Files:**
- Modify: `packages/cli/src/opentools/models.py`
- Test: `packages/cli/tests/test_models.py`

- [ ] **Step 1: Write the failing test**

Add to `packages/cli/tests/test_models.py`:

```python
def test_finding_has_scan_id():
    from datetime import datetime, timezone
    from opentools.models import Finding, Severity
    now = datetime.now(timezone.utc)
    f = Finding(
        id="f-1", engagement_id="eng-1", tool="semgrep",
        severity=Severity.HIGH, title="SQLi", created_at=now,
        scan_id="scan-1",
    )
    assert f.scan_id == "scan-1"


def test_finding_scan_id_defaults_none():
    from datetime import datetime, timezone
    from opentools.models import Finding, Severity
    now = datetime.now(timezone.utc)
    f = Finding(
        id="f-1", engagement_id="eng-1", tool="semgrep",
        severity=Severity.HIGH, title="SQLi", created_at=now,
    )
    assert f.scan_id is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_models.py::test_finding_has_scan_id -v`
Expected: FAIL — `ValidationError` (unexpected field `scan_id`)

- [ ] **Step 3: Add scan_id to Finding model**

In `packages/cli/src/opentools/models.py`, add to the `Finding` class:

```python
    scan_id: Optional[str] = None
```

Place it after the `deleted_at` field.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_models.py::test_finding_has_scan_id tests/test_models.py::test_finding_scan_id_defaults_none -v`
Expected: Both PASS

- [ ] **Step 5: Run full test suite to verify no regressions**

Run: `cd packages/cli && python -m pytest tests/ -v --tb=short`
Expected: All existing tests still PASS

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/models.py packages/cli/tests/test_models.py
git commit -m "feat(models): add scan_id field to Finding for scan-runner integration"
```

---

### Task 13: Refactor RecipeRunner to Use Shared Subprocess

**Files:**
- Modify: `packages/cli/src/opentools/recipes.py`
- Test: `packages/cli/tests/test_recipes.py` (run existing tests)

- [ ] **Step 1: Run existing recipe tests to establish baseline**

Run: `cd packages/cli && python -m pytest tests/test_recipes.py -v`
Expected: All existing tests PASS (baseline)

- [ ] **Step 2: Refactor `_run_step` to use `run_streaming`**

In `packages/cli/src/opentools/recipes.py`, replace the shell execution block in `_run_step` (the `StepType.SHELL` branch starting around line 257) with:

```python
    async def _run_step(self, step: RecipeStep, command: str, quiet: bool) -> StepResult:
        """Execute a single recipe step."""
        if step.step_type == StepType.MANUAL:
            return StepResult(step_name=step.name, status="manual", stdout=command)

        if step.step_type == StepType.MCP_TOOL:
            return StepResult(step_name=step.name, status="manual",
                            stdout=f"MCP tool step (execute in Claude): {command}")

        # Shell step — delegate to shared subprocess
        from opentools.shared.subprocess import run_streaming

        args = shlex.split(command, posix=(sys.platform != "win32"))
        result = await run_streaming(
            args,
            on_output=lambda chunk: None if quiet else None,
            timeout=step.timeout,
        )

        if result.timed_out:
            return StepResult(
                step_name=step.name, status="timeout",
                duration_ms=result.duration_ms,
                stderr=f"Timed out after {step.timeout}s",
            )

        status = "success" if result.exit_code == 0 else "error"
        return StepResult(
            step_name=step.name,
            status=status,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_ms=result.duration_ms,
        )
```

- [ ] **Step 3: Run existing recipe tests to verify no regressions**

Run: `cd packages/cli && python -m pytest tests/test_recipes.py -v`
Expected: All existing tests still PASS

- [ ] **Step 4: Commit**

```bash
git add packages/cli/src/opentools/recipes.py
git commit -m "refactor(recipes): use shared.subprocess.run_streaming in RecipeRunner"
```

---

### Task 14: Shared Resource Pool (Basic Version)

**Files:**
- Create: `packages/cli/src/opentools/shared/resource_pool.py`
- Test: `packages/cli/tests/test_scanner/test_shared_resource_pool.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/cli/tests/test_scanner/test_shared_resource_pool.py
"""Tests for AdaptiveResourcePool."""

import asyncio
import pytest
from opentools.shared.resource_pool import AdaptiveResourcePool


class TestResourcePool:
    @pytest.mark.asyncio
    async def test_acquire_and_release(self):
        pool = AdaptiveResourcePool(global_limit=2)
        await pool.acquire("task-1", priority=50, resource_group="shell")
        await pool.acquire("task-2", priority=50, resource_group="shell")
        # Pool is full — release one
        pool.release("shell")
        # Now we can acquire again
        await asyncio.wait_for(
            pool.acquire("task-3", priority=50, resource_group="shell"),
            timeout=0.5,
        )
        pool.release("shell")
        pool.release("shell")

    @pytest.mark.asyncio
    async def test_priority_ordering(self):
        pool = AdaptiveResourcePool(global_limit=1)
        order: list[str] = []

        await pool.acquire("task-1", priority=50, resource_group="shell")

        async def waiter(task_id: str, priority: int):
            await pool.acquire(task_id, priority, "shell")
            order.append(task_id)
            pool.release("shell")

        # Queue two waiters with different priorities
        t_low = asyncio.create_task(waiter("low-pri", 80))
        t_high = asyncio.create_task(waiter("high-pri", 10))
        await asyncio.sleep(0.05)  # let both waiters queue up

        # Release — highest priority (lowest number) should go first
        pool.release("shell")
        await asyncio.wait_for(asyncio.gather(t_low, t_high), timeout=1.0)
        assert order[0] == "high-pri"
        assert order[1] == "low-pri"

    @pytest.mark.asyncio
    async def test_group_limits(self):
        pool = AdaptiveResourcePool(global_limit=10, group_limits={"mcp:codebadger": 1})
        await pool.acquire("task-1", priority=50, resource_group="mcp:codebadger")

        # Second acquire on same group should block
        acquired = False

        async def try_acquire():
            nonlocal acquired
            await pool.acquire("task-2", priority=50, resource_group="mcp:codebadger")
            acquired = True

        task = asyncio.create_task(try_acquire())
        await asyncio.sleep(0.05)
        assert acquired is False

        pool.release("mcp:codebadger")
        await asyncio.wait_for(task, timeout=0.5)
        assert acquired is True
        pool.release("mcp:codebadger")

    @pytest.mark.asyncio
    async def test_active_count(self):
        pool = AdaptiveResourcePool(global_limit=5)
        await pool.acquire("task-1", priority=50, resource_group="shell")
        await pool.acquire("task-2", priority=50, resource_group="docker")
        assert pool.active_count == 2
        pool.release("shell")
        assert pool.active_count == 1
        pool.release("docker")
        assert pool.active_count == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_shared_resource_pool.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/shared/resource_pool.py
"""Adaptive resource pool with priority-based scheduling."""

from __future__ import annotations

import asyncio
import heapq
from collections import defaultdict


class AdaptiveResourcePool:
    """Priority-aware concurrency pool with per-group limits.

    Tasks acquire a slot before executing. When the pool is full,
    tasks wait in a priority heap — lowest priority number goes first.
    """

    def __init__(
        self,
        global_limit: int = 8,
        group_limits: dict[str, int] | None = None,
    ) -> None:
        self._global_limit = global_limit
        self._current_limit = global_limit
        self._group_limits = group_limits or {}
        self._active: dict[str, int] = defaultdict(int)
        self._total_active = 0
        # Priority heap of (priority, counter, future, group)
        self._waiters: list[tuple[int, int, asyncio.Future, str]] = []
        self._counter = 0  # tiebreaker for equal priorities

    @property
    def active_count(self) -> int:
        return self._total_active

    async def acquire(self, task_id: str, priority: int, resource_group: str) -> None:
        """Wait until a slot is available. Higher priority (lower number) goes first."""
        while not self._can_acquire(resource_group):
            future = asyncio.get_event_loop().create_future()
            self._counter += 1
            heapq.heappush(self._waiters, (priority, self._counter, future, resource_group))
            await future
            # After waking, re-check — another waiter might have grabbed the slot

        self._active[resource_group] += 1
        self._total_active += 1

    def release(self, resource_group: str) -> None:
        """Release a slot and wake the highest-priority waiter."""
        if self._active[resource_group] > 0:
            self._active[resource_group] -= 1
            self._total_active -= 1

        # Wake waiters that can now acquire
        self._wake_eligible()

    def _can_acquire(self, resource_group: str) -> bool:
        if self._total_active >= self._current_limit:
            return False
        group_limit = self._group_limits.get(resource_group)
        if group_limit is not None and self._active[resource_group] >= group_limit:
            return False
        return True

    def _wake_eligible(self) -> None:
        """Wake waiters whose resource group now has capacity."""
        # Try to wake the highest-priority waiter that can acquire
        new_heap: list[tuple[int, int, asyncio.Future, str]] = []
        woke_one = False

        while self._waiters:
            entry = heapq.heappop(self._waiters)
            priority, counter, future, group = entry
            if future.done():
                continue
            if not woke_one and self._can_acquire(group):
                future.set_result(None)
                woke_one = True
            else:
                new_heap.append(entry)

        self._waiters = new_heap
        heapq.heapify(self._waiters)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_shared_resource_pool.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/shared/resource_pool.py packages/cli/tests/test_scanner/test_shared_resource_pool.py
git commit -m "feat(shared): AdaptiveResourcePool — priority heap with per-group limits"
```

---

### Task 15: Full Test Suite Verification

**Files:** None (verification only)

- [ ] **Step 1: Run all scanner tests**

Run: `cd packages/cli && python -m pytest tests/test_scanner/ -v --tb=short`
Expected: All tests PASS

- [ ] **Step 2: Run all existing CLI tests to verify no regressions**

Run: `cd packages/cli && python -m pytest tests/ -v --tb=short`
Expected: All tests PASS (existing + new)

- [ ] **Step 3: Commit any fixups if needed, then tag completion**

```bash
git log --oneline -10
```

Verify all Plan 1 commits are present. The foundation is complete and ready for Plan 2 (Executors + DAG Engine).
