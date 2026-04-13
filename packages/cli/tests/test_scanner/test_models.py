"""Tests for scanner models — enums, core models, finding models, and progress events."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from opentools.models import FindingStatus, Severity
from opentools.scanner.models import (
    # Enums
    ScanStatus,
    ScanMode,
    TargetType,
    TaskType,
    TaskStatus,
    ExecutionTier,
    TaskIsolation,
    EvidenceQuality,
    LocationPrecision,
    ProgressEventType,
    # Core config models
    TargetRateLimit,
    NotificationChannel,
    ScanNotification,
    RetryPolicy,
    ScanConfig,
    ScanMetrics,
    ReactiveEdge,
    ScanTask,
    Scan,
    # Finding models
    RawFinding,
    DeduplicatedFinding,
    FindingCorrelation,
    RemediationGroup,
    SuppressionRule,
    FindingAnnotation,
    ScanAttestation,
    ToolEffectiveness,
    ScanBatch,
    ScanQuota,
    EnrichedContext,
    # Progress event models
    ProgressEvent,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


# ===========================================================================
# Task 1: Enum tests
# ===========================================================================


class TestScanStatus:
    def test_all_values(self):
        assert ScanStatus.PENDING == "pending"
        assert ScanStatus.RUNNING == "running"
        assert ScanStatus.PAUSED == "paused"
        assert ScanStatus.COMPLETED == "completed"
        assert ScanStatus.FAILED == "failed"
        assert ScanStatus.CANCELLED == "cancelled"

    def test_is_str(self):
        assert isinstance(ScanStatus.PENDING, str)

    def test_count(self):
        assert len(list(ScanStatus)) == 6


class TestScanMode:
    def test_all_values(self):
        assert ScanMode.AUTO == "auto"
        assert ScanMode.ASSISTED == "assisted"

    def test_count(self):
        assert len(list(ScanMode)) == 2


class TestTargetType:
    def test_all_values(self):
        assert TargetType.SOURCE_CODE == "source_code"
        assert TargetType.URL == "url"
        assert TargetType.BINARY == "binary"
        assert TargetType.DOCKER_IMAGE == "docker_image"
        assert TargetType.APK == "apk"
        assert TargetType.NETWORK == "network"

    def test_count(self):
        assert len(list(TargetType)) == 6


class TestTaskType:
    def test_all_values(self):
        assert TaskType.SHELL == "shell"
        assert TaskType.DOCKER_EXEC == "docker_exec"
        assert TaskType.MCP_CALL == "mcp_call"
        assert TaskType.PREFLIGHT == "preflight"
        assert TaskType.PROVISION == "provision"

    def test_count(self):
        assert len(list(TaskType)) == 5


class TestTaskStatus:
    def test_all_values(self):
        assert TaskStatus.PENDING == "pending"
        assert TaskStatus.BLOCKED == "blocked"
        assert TaskStatus.RUNNING == "running"
        assert TaskStatus.COMPLETED == "completed"
        assert TaskStatus.FAILED == "failed"
        assert TaskStatus.SKIPPED == "skipped"

    def test_count(self):
        assert len(list(TaskStatus)) == 7


class TestExecutionTier:
    def test_all_values(self):
        assert ExecutionTier.FAST == "fast"
        assert ExecutionTier.NORMAL == "normal"
        assert ExecutionTier.HEAVY == "heavy"

    def test_count(self):
        assert len(list(ExecutionTier)) == 3


class TestTaskIsolation:
    def test_all_values(self):
        assert TaskIsolation.NONE == "none"
        assert TaskIsolation.CONTAINER == "container"
        assert TaskIsolation.NETWORK_ISOLATED == "network_isolated"

    def test_count(self):
        assert len(list(TaskIsolation)) == 3


class TestEvidenceQuality:
    def test_all_values(self):
        assert EvidenceQuality.PROVEN == "proven"
        assert EvidenceQuality.TRACED == "traced"
        assert EvidenceQuality.STRUCTURED == "structured"
        assert EvidenceQuality.PATTERN == "pattern"
        assert EvidenceQuality.HEURISTIC == "heuristic"

    def test_count(self):
        assert len(list(EvidenceQuality)) == 5


class TestLocationPrecision:
    def test_all_values(self):
        assert LocationPrecision.EXACT_LINE == "exact_line"
        assert LocationPrecision.LINE_RANGE == "line_range"
        assert LocationPrecision.FUNCTION == "function"
        assert LocationPrecision.FILE == "file"
        assert LocationPrecision.ENDPOINT == "endpoint"
        assert LocationPrecision.HOST == "host"

    def test_count(self):
        assert len(list(LocationPrecision)) == 6


# ===========================================================================
# Task 2: Core model tests
# ===========================================================================


class TestTargetRateLimit:
    def test_defaults(self):
        r = TargetRateLimit()
        assert r.max_requests_per_second == 50
        assert r.max_concurrent_connections == 10
        assert r.backoff_on_429 is True
        assert r.backoff_on_timeout is True

    def test_override(self):
        r = TargetRateLimit(max_requests_per_second=10, backoff_on_429=False)
        assert r.max_requests_per_second == 10
        assert r.backoff_on_429 is False


class TestNotificationChannel:
    def test_minimal(self):
        ch = NotificationChannel(type="webhook")
        assert ch.type == "webhook"
        assert ch.url is None
        assert "scan_completed" in ch.events
        assert "scan_failed" in ch.events
        assert "critical_finding_discovered" in ch.events

    def test_with_url(self):
        ch = NotificationChannel(type="slack", url="https://hooks.slack.com/x")
        assert ch.url == "https://hooks.slack.com/x"

    def test_custom_events(self):
        ch = NotificationChannel(type="email", events=["scan_started"])
        assert ch.events == ["scan_started"]


class TestScanNotification:
    def test_empty_default(self):
        n = ScanNotification()
        assert n.channels == []

    def test_with_channels(self):
        ch = NotificationChannel(type="webhook")
        n = ScanNotification(channels=[ch])
        assert len(n.channels) == 1


class TestRetryPolicy:
    def test_defaults(self):
        r = RetryPolicy()
        assert r.max_retries == 2
        assert r.backoff_seconds == 5.0
        assert "timeout" in r.retry_on
        assert "connection_error" in r.retry_on

    def test_custom(self):
        r = RetryPolicy(max_retries=5, backoff_seconds=10.0, retry_on=["timeout"])
        assert r.max_retries == 5
        assert r.backoff_seconds == 10.0
        assert r.retry_on == ["timeout"]


class TestScanConfig:
    def test_defaults(self):
        c = ScanConfig()
        assert c.severity_threshold == Severity.INFO
        assert c.max_concurrent_tasks == 8
        assert c.max_duration_seconds is None
        assert c.timeout_override is None
        assert c.tool_args == {}
        assert c.notifications is None
        assert c.steering_frequency == "phase_boundary"
        assert c.target_rate_limit is None

    def test_custom_severity(self):
        c = ScanConfig(severity_threshold=Severity.HIGH)
        assert c.severity_threshold == Severity.HIGH

    def test_with_rate_limit(self):
        c = ScanConfig(target_rate_limit=TargetRateLimit(max_requests_per_second=5))
        assert c.target_rate_limit is not None
        assert c.target_rate_limit.max_requests_per_second == 5


class TestScanMetrics:
    def test_all_defaults_zero(self):
        m = ScanMetrics()
        # Check a selection of fields
        assert m.tasks_total == 0
        assert m.tasks_pending == 0
        assert m.tasks_blocked == 0
        assert m.tasks_running == 0
        assert m.tasks_completed == 0
        assert m.tasks_failed == 0
        assert m.tasks_skipped == 0
        assert m.tasks_cached == 0
        assert m.tasks_retried == 0
        assert m.edges_fired == 0
        assert m.edges_suppressed == 0
        assert m.raw_findings_total == 0
        assert m.raw_findings_deduplicated == 0
        assert m.false_positives_suppressed == 0
        assert m.critical_count == 0
        assert m.high_count == 0
        assert m.medium_count == 0
        assert m.low_count == 0
        assert m.info_count == 0
        assert m.steering_calls == 0
        assert m.mcp_calls == 0
        assert m.shell_commands == 0
        assert m.docker_execs == 0
        assert m.total_duration_ms == 0
        assert m.tool_errors == 0

    def test_field_count(self):
        """ScanMetrics should have exactly 25 int/float fields."""
        assert len(ScanMetrics.model_fields) == 25


class TestReactiveEdge:
    def test_minimal(self):
        e = ReactiveEdge(
            id="edge-1",
            trigger_task_id="task-1",
            evaluator="my_evaluator",
        )
        assert e.id == "edge-1"
        assert e.trigger_task_id == "task-1"
        assert e.evaluator == "my_evaluator"
        assert e.condition is None
        assert e.spawns is None
        assert e.max_spawns == 20
        assert e.max_spawns_per_trigger == 5
        assert e.cooldown_seconds == 0
        assert e.budget_group is None
        assert e.min_upstream_confidence == 0.5

    def test_custom_spawns(self):
        e = ReactiveEdge(
            id="edge-2",
            trigger_task_id="task-2",
            evaluator="eval2",
            spawns=["task-a", "task-b"],
            max_spawns=5,
        )
        assert e.spawns == ["task-a", "task-b"]
        assert e.max_spawns == 5


class TestScanTask:
    def test_minimal(self):
        t = ScanTask(
            id="task-1",
            scan_id="scan-1",
            name="semgrep-scan",
            tool="semgrep",
            task_type=TaskType.SHELL,
        )
        assert t.id == "task-1"
        assert t.scan_id == "scan-1"
        assert t.name == "semgrep-scan"
        assert t.tool == "semgrep"
        assert t.task_type == TaskType.SHELL
        assert t.status == TaskStatus.PENDING
        assert t.priority == 50
        assert t.tier == ExecutionTier.NORMAL
        assert t.isolation == TaskIsolation.NONE
        assert t.cached is False
        assert t.depends_on == []
        assert t.reactive_edges == []
        assert t.exit_code is None
        assert t.stdout is None
        assert t.stderr is None
        assert t.output_hash is None
        assert t.duration_ms is None
        assert t.spawned_by is None
        assert t.spawned_reason is None
        assert t.started_at is None
        assert t.completed_at is None

    def test_with_retry_policy(self):
        t = ScanTask(
            id="task-2",
            scan_id="scan-1",
            name="nuclei",
            tool="nuclei",
            task_type=TaskType.SHELL,
            retry_policy=RetryPolicy(max_retries=3),
        )
        assert t.retry_policy is not None
        assert t.retry_policy.max_retries == 3

    def test_mcp_task(self):
        t = ScanTask(
            id="task-3",
            scan_id="scan-1",
            name="mcp-call",
            tool="mcp",
            task_type=TaskType.MCP_CALL,
            mcp_server="my-server",
            mcp_tool="run_scan",
            mcp_args={"target": "localhost"},
        )
        assert t.mcp_server == "my-server"
        assert t.mcp_tool == "run_scan"
        assert t.mcp_args == {"target": "localhost"}

    def test_docker_exec_task(self):
        t = ScanTask(
            id="task-4",
            scan_id="scan-1",
            name="docker-task",
            tool="trivy",
            task_type=TaskType.DOCKER_EXEC,
            isolation=TaskIsolation.CONTAINER,
        )
        assert t.isolation == TaskIsolation.CONTAINER


class TestScan:
    def test_minimal(self):
        s = Scan(
            id="scan-1",
            engagement_id="eng-1",
            target="/path/to/repo",
            target_type=TargetType.SOURCE_CODE,
            created_at=_now(),
        )
        assert s.id == "scan-1"
        assert s.engagement_id == "eng-1"
        assert s.target == "/path/to/repo"
        assert s.target_type == TargetType.SOURCE_CODE
        assert s.mode == ScanMode.AUTO
        assert s.status == ScanStatus.PENDING
        assert s.config is None
        assert s.resolved_path is None
        assert s.target_metadata == {}
        assert s.profile is None
        assert s.profile_snapshot == {}
        assert s.baseline_scan_id is None
        assert s.tools_planned == []
        assert s.tools_completed == []
        assert s.tools_failed == []
        assert s.finding_count == 0
        assert s.estimated_duration_seconds is None
        assert s.metrics is None
        assert s.started_at is None
        assert s.completed_at is None

    def test_with_config(self):
        s = Scan(
            id="scan-2",
            engagement_id="eng-1",
            target="https://example.com",
            target_type=TargetType.URL,
            config=ScanConfig(max_concurrent_tasks=4),
            created_at=_now(),
        )
        assert s.config is not None
        assert s.config.max_concurrent_tasks == 4

    def test_assisted_mode(self):
        s = Scan(
            id="scan-3",
            engagement_id="eng-1",
            target="app.apk",
            target_type=TargetType.APK,
            mode=ScanMode.ASSISTED,
            created_at=_now(),
        )
        assert s.mode == ScanMode.ASSISTED


# ===========================================================================
# Task 3: Finding model tests
# ===========================================================================


class TestRawFinding:
    def test_minimal(self):
        f = RawFinding(
            id="rf-1",
            scan_task_id="task-1",
            scan_id="scan-1",
            tool="semgrep",
            raw_severity="HIGH",
            title="SQL Injection",
            evidence_quality=EvidenceQuality.STRUCTURED,
            evidence_hash="abc123",
            location_fingerprint="fp-001",
            location_precision=LocationPrecision.EXACT_LINE,
            parser_version="1.0.0",
            parser_confidence=0.95,
            discovered_at=_now(),
        )
        assert f.id == "rf-1"
        assert f.tool == "semgrep"
        assert f.raw_severity == "HIGH"
        assert f.title == "SQL Injection"
        assert f.evidence_quality == EvidenceQuality.STRUCTURED
        assert f.location_precision == LocationPrecision.EXACT_LINE
        assert f.parser_confidence == 0.95
        assert f.canonical_title is None
        assert f.description is None
        assert f.file_path is None
        assert f.line_start is None
        assert f.line_end is None
        assert f.url is None
        assert f.evidence is None
        assert f.cwe is None
        assert f.raw_output_excerpt is None
        assert f.causal_chain is None

    def test_with_all_optional_fields(self):
        f = RawFinding(
            id="rf-2",
            scan_task_id="task-1",
            scan_id="scan-1",
            tool="bandit",
            raw_severity="MEDIUM",
            title="Hardcoded Password",
            canonical_title="Hardcoded Credential",
            description="A hardcoded password was found.",
            file_path="/app/config.py",
            line_start=42,
            line_end=42,
            url="https://cwe.mitre.org/data/definitions/259.html",
            evidence="password = 'secret'",
            evidence_quality=EvidenceQuality.PROVEN,
            evidence_hash="def456",
            cwe="CWE-259",
            location_fingerprint="fp-002",
            location_precision=LocationPrecision.EXACT_LINE,
            parser_version="2.1.0",
            parser_confidence=0.99,
            raw_output_excerpt="[HIGH] Hardcoded Password found",
            discovered_at=_now(),
            causal_chain=["step-a", "step-b"],
        )
        assert f.file_path == "/app/config.py"
        assert f.line_start == 42
        assert f.cwe == "CWE-259"
        assert f.causal_chain == ["step-a", "step-b"]


class TestDeduplicatedFinding:
    def test_minimal(self):
        f = DeduplicatedFinding(
            id="df-1",
            engagement_id="eng-1",
            fingerprint="fp-abc",
            confidence_score=0.85,
            severity_consensus="high",
            canonical_title="SQL Injection",
            location_fingerprint="loc-fp-001",
            location_precision=LocationPrecision.EXACT_LINE,
            evidence_quality_best=EvidenceQuality.STRUCTURED,
            first_seen_scan_id="scan-1",
            created_at=_now(),
            updated_at=_now(),
        )
        assert f.id == "df-1"
        assert f.engagement_id == "eng-1"
        assert f.fingerprint == "fp-abc"
        assert f.finding_id is None
        assert f.raw_finding_ids == []
        assert f.tools == []
        assert f.corroboration_count == 1
        assert f.previously_marked_fp is False
        assert f.suppressed is False
        assert f.suppression_rule_id is None
        assert f.status == FindingStatus.DISCOVERED
        assert f.last_confirmed_scan_id is None
        assert f.last_confirmed_at is None

    def test_with_suppression(self):
        f = DeduplicatedFinding(
            id="df-2",
            engagement_id="eng-1",
            fingerprint="fp-xyz",
            confidence_score=0.5,
            severity_consensus="low",
            canonical_title="Test Finding",
            location_fingerprint="loc-fp-002",
            location_precision=LocationPrecision.FILE,
            evidence_quality_best=EvidenceQuality.HEURISTIC,
            suppressed=True,
            suppression_rule_id="rule-001",
            first_seen_scan_id="scan-1",
            created_at=_now(),
            updated_at=_now(),
        )
        assert f.suppressed is True
        assert f.suppression_rule_id == "rule-001"


class TestFindingCorrelation:
    def test_creation(self):
        c = FindingCorrelation(
            id="corr-1",
            engagement_id="eng-1",
            scan_id="scan-1",
            finding_ids=["f-1", "f-2"],
            correlation_type="attack_chain",
            narrative="These findings form a chain.",
            severity="critical",
            created_at=_now(),
        )
        assert c.id == "corr-1"
        assert c.finding_ids == ["f-1", "f-2"]
        assert c.kill_chain_phases is None

    def test_with_kill_chain(self):
        c = FindingCorrelation(
            id="corr-2",
            engagement_id="eng-1",
            scan_id="scan-1",
            finding_ids=["f-3"],
            correlation_type="lateral_movement",
            narrative="Some narrative.",
            severity="high",
            kill_chain_phases=["reconnaissance", "exploitation"],
            created_at=_now(),
        )
        assert c.kill_chain_phases == ["reconnaissance", "exploitation"]


class TestRemediationGroup:
    def test_creation(self):
        g = RemediationGroup(
            id="rg-1",
            engagement_id="eng-1",
            scan_id="scan-1",
            action="Upgrade dependency X to version Y",
            action_type="dependency_upgrade",
            finding_ids=["f-1", "f-2", "f-3"],
            findings_count=3,
            max_severity="high",
            created_at=_now(),
        )
        assert g.id == "rg-1"
        assert g.findings_count == 3
        assert g.effort_estimate is None


class TestSuppressionRule:
    def test_creation(self):
        r = SuppressionRule(
            id="sr-1",
            scope="global",
            rule_type="path_prefix",
            pattern="tests/",
            reason="Test files excluded from security scanning",
            created_by="admin",
            created_at=_now(),
        )
        assert r.id == "sr-1"
        assert r.engagement_id is None
        assert r.expires_at is None

    def test_with_engagement_scope(self):
        r = SuppressionRule(
            id="sr-2",
            scope="engagement",
            engagement_id="eng-1",
            rule_type="fingerprint",
            pattern="fp-abc123",
            reason="Confirmed false positive",
            created_by="analyst",
            created_at=_now(),
        )
        assert r.engagement_id == "eng-1"


class TestFindingAnnotation:
    def test_creation(self):
        a = FindingAnnotation(
            id="ann-1",
            finding_fingerprint="fp-abc",
            annotation_type="comment",
            value="This is a confirmed vulnerability.",
            created_by="analyst",
            created_at=_now(),
        )
        assert a.id == "ann-1"
        assert a.engagement_id is None
        assert a.annotation_type == "comment"


class TestScanAttestation:
    def test_creation(self):
        a = ScanAttestation(
            scan_id="scan-1",
            findings_hash="sha256:abc123",
            profile_hash="sha256:def456",
            tool_versions={"semgrep": "1.0.0", "bandit": "1.7.5"},
            signature="sig-xyz",
            created_at=_now(),
        )
        assert a.scan_id == "scan-1"
        assert a.tool_versions["semgrep"] == "1.0.0"


class TestToolEffectiveness:
    def test_defaults(self):
        t = ToolEffectiveness(
            tool="semgrep",
            target_type="source_code",
            updated_at=_now(),
        )
        assert t.total_findings == 0
        assert t.confirmed_findings == 0
        assert t.false_positive_count == 0
        assert t.false_positive_rate == 0.0
        assert t.avg_duration_seconds == 0.0
        assert t.sample_count == 0


class TestScanBatch:
    def test_defaults(self):
        b = ScanBatch(id="batch-1", created_at=_now())
        assert b.scan_ids == []
        assert b.max_parallel_scans == 2
        assert b.status == "pending"
        assert b.completed_at is None

    def test_with_scans(self):
        b = ScanBatch(
            id="batch-2",
            scan_ids=["scan-1", "scan-2"],
            max_parallel_scans=4,
            created_at=_now(),
        )
        assert len(b.scan_ids) == 2
        assert b.max_parallel_scans == 4


class TestScanQuota:
    def test_defaults(self):
        q = ScanQuota()
        assert q.max_concurrent_scans == 3
        assert q.max_scans_per_day == 20
        assert q.max_scan_duration_seconds == 3600
        assert q.max_assisted_mode_calls == 50
        assert q.max_batch_size == 10


class TestEnrichedContext:
    def test_minimal(self):
        c = EnrichedContext(code_snippet="x = 1")
        assert c.code_snippet == "x = 1"
        assert c.function_name is None
        assert c.file_imports == []

    def test_full(self):
        c = EnrichedContext(
            code_snippet="def login(user, pwd): ...",
            function_name="login",
            file_imports=["os", "hashlib"],
        )
        assert c.function_name == "login"
        assert "os" in c.file_imports


# ===========================================================================
# Task 4: Progress event model tests
# ===========================================================================


class TestProgressEventType:
    def test_all_values(self):
        assert ProgressEventType.SCAN_STARTED == "scan_started"
        assert ProgressEventType.SCAN_COMPLETED == "scan_completed"
        assert ProgressEventType.SCAN_FAILED == "scan_failed"
        assert ProgressEventType.SCAN_PAUSED == "scan_paused"
        assert ProgressEventType.SCAN_RESUMED == "scan_resumed"
        assert ProgressEventType.TASK_QUEUED == "task_queued"
        assert ProgressEventType.TASK_STARTED == "task_started"
        assert ProgressEventType.TASK_PROGRESS == "task_progress"
        assert ProgressEventType.TASK_COMPLETED == "task_completed"
        assert ProgressEventType.TASK_FAILED == "task_failed"
        assert ProgressEventType.TASK_SKIPPED == "task_skipped"
        assert ProgressEventType.TASK_CACHED == "task_cached"
        assert ProgressEventType.TASK_RETRYING == "task_retrying"
        assert ProgressEventType.FINDING_DISCOVERED == "finding_discovered"
        assert ProgressEventType.FINDING_CORRELATED == "finding_correlated"
        assert ProgressEventType.EDGE_FIRED == "edge_fired"
        assert ProgressEventType.STEERING_DECISION == "steering_decision"
        assert ProgressEventType.THREAT_SUMMARY_UPDATED == "threat_summary_updated"
        assert ProgressEventType.RESOURCE_WARNING == "resource_warning"

    def test_count(self):
        assert len(list(ProgressEventType)) == 19

    def test_is_str(self):
        assert isinstance(ProgressEventType.SCAN_STARTED, str)


class TestProgressEvent:
    def test_minimal(self):
        e = ProgressEvent(
            id="evt-1",
            type=ProgressEventType.SCAN_STARTED,
            timestamp=_now(),
            scan_id="scan-1",
            sequence=0,
            tasks_total=10,
            tasks_completed=0,
            tasks_running=0,
            findings_total=0,
            elapsed_seconds=0.0,
        )
        assert e.id == "evt-1"
        assert e.type == ProgressEventType.SCAN_STARTED
        assert e.scan_id == "scan-1"
        assert e.sequence == 0
        assert e.task_id is None
        assert e.data == {}
        assert e.tasks_total == 10
        assert e.tasks_completed == 0
        assert e.tasks_running == 0
        assert e.findings_total == 0
        assert e.elapsed_seconds == 0.0
        assert e.estimated_remaining_seconds is None

    def test_with_optional_fields(self):
        e = ProgressEvent(
            id="evt-2",
            type=ProgressEventType.TASK_COMPLETED,
            timestamp=_now(),
            scan_id="scan-1",
            sequence=5,
            task_id="task-3",
            data={"exit_code": 0, "duration_ms": 1200},
            tasks_total=10,
            tasks_completed=5,
            tasks_running=2,
            findings_total=3,
            elapsed_seconds=30.5,
            estimated_remaining_seconds=60.0,
        )
        assert e.task_id == "task-3"
        assert e.data["exit_code"] == 0
        assert e.tasks_completed == 5
        assert e.elapsed_seconds == 30.5
        assert e.estimated_remaining_seconds == 60.0

    def test_finding_discovered_event(self):
        e = ProgressEvent(
            id="evt-3",
            type=ProgressEventType.FINDING_DISCOVERED,
            timestamp=_now(),
            scan_id="scan-1",
            sequence=7,
            data={"severity": "high", "title": "SQL Injection"},
            tasks_total=10,
            tasks_completed=5,
            tasks_running=1,
            findings_total=4,
            elapsed_seconds=45.0,
        )
        assert e.type == ProgressEventType.FINDING_DISCOVERED
        assert e.data["severity"] == "high"

    def test_resource_warning_event(self):
        e = ProgressEvent(
            id="evt-4",
            type=ProgressEventType.RESOURCE_WARNING,
            timestamp=_now(),
            scan_id="scan-1",
            sequence=12,
            data={"resource": "memory", "used_pct": 92},
            tasks_total=10,
            tasks_completed=8,
            tasks_running=1,
            findings_total=6,
            elapsed_seconds=120.0,
        )
        assert e.type == ProgressEventType.RESOURCE_WARNING
        assert e.data["used_pct"] == 92
