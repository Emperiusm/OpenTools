from datetime import datetime, timezone
import pytest
from opentools.models import (
    Severity, EngagementType, EngagementStatus, FindingStatus, Confidence,
    IOCType, ArtifactType, StepType, FailureAction, ToolStatus,
    Engagement, Finding, TimelineEvent, IOC, Artifact, ToolConfig,
    Recipe, RecipeStep, RecipeVariable, AuditEntry,
    EngagementSummary, DeduplicationReport, StepResult, RecipeResult,
    ToolCheckResult, PreflightSummary, PreflightReport,
    ContainerStatus, ContainerResult, ToolkitConfig,
)


def test_severity_enum():
    assert Severity.CRITICAL == "critical"
    assert Severity.HIGH == "high"
    assert Severity.INFO == "info"


def test_engagement_creation():
    e = Engagement(
        id="test-id",
        name="test-engagement",
        target="192.168.1.0/24",
        type=EngagementType.PENTEST,
        status=EngagementStatus.ACTIVE,
        skills_used=["pentest"],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    assert e.name == "test-engagement"
    assert e.type == EngagementType.PENTEST


def test_finding_defaults():
    f = Finding(
        id="f-1",
        engagement_id="e-1",
        tool="semgrep",
        title="SQL Injection",
        severity=Severity.HIGH,
        created_at=datetime.now(timezone.utc),
    )
    assert f.false_positive is False
    assert f.corroborated_by == []
    assert f.severity_by_tool == {}
    assert f.status == FindingStatus.DISCOVERED
    assert f.deleted_at is None


def test_finding_rejects_invalid_severity():
    with pytest.raises(ValueError):
        Finding(
            id="f-1",
            engagement_id="e-1",
            tool="semgrep",
            title="test",
            severity="ultra-critical",
            created_at=datetime.now(timezone.utc),
        )


def test_ioc_types():
    ioc = IOC(
        id="i-1",
        engagement_id="e-1",
        ioc_type=IOCType.IP,
        value="10.0.0.1",
        context="C2 callback",
    )
    assert ioc.ioc_type == IOCType.IP


def test_recipe_step_defaults():
    step = RecipeStep(
        name="scan",
        tool="nuclei",
        command="nuclei -u {{target}}",
        timeout=300,
    )
    assert step.step_type == StepType.SHELL
    assert step.on_failure == FailureAction.CONTINUE
    assert step.depends_on is None


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
