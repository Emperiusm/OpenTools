from datetime import datetime, timezone
import pytest
from opentools.models import (
    Engagement, EngagementType, EngagementStatus, Severity, FindingStatus,
    Finding, TimelineEvent, IOC, IOCType, Artifact, ArtifactType, Confidence,
)


def test_create_and_get_engagement(store, sample_engagement):
    store.create(sample_engagement)
    result = store.get(sample_engagement.id)
    assert result.name == "test-pentest"
    assert result.type == EngagementType.PENTEST


def test_list_all_engagements(store, sample_engagement):
    store.create(sample_engagement)
    results = store.list_all()
    assert len(results) == 1
    assert results[0].id == sample_engagement.id


def test_update_status(store, sample_engagement):
    store.create(sample_engagement)
    store.update_status(sample_engagement.id, EngagementStatus.COMPLETE)
    result = store.get(sample_engagement.id)
    assert result.status == EngagementStatus.COMPLETE


def test_add_finding_creates_timeline_event(store, sample_engagement):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    finding = Finding(
        id="f-1", engagement_id=sample_engagement.id,
        tool="semgrep", title="SQL Injection",
        severity=Severity.HIGH, created_at=now,
    )
    finding_id = store.add_finding(finding)
    assert finding_id == "f-1"
    timeline = store.get_timeline(sample_engagement.id)
    assert len(timeline) == 1
    assert timeline[0].finding_id == "f-1"
    assert "SQL Injection" in timeline[0].event


def test_add_ioc_upserts(store, sample_engagement):
    store.create(sample_engagement)
    ioc1 = IOC(
        id="ioc-1", engagement_id=sample_engagement.id,
        ioc_type=IOCType.IP, value="10.0.0.1", context="C2",
        first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    store.add_ioc(ioc1)
    ioc2 = IOC(
        id="ioc-2", engagement_id=sample_engagement.id,
        ioc_type=IOCType.IP, value="10.0.0.1", context="C2",
        last_seen=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    store.add_ioc(ioc2)
    iocs = store.get_iocs(sample_engagement.id)
    assert len(iocs) == 1
    assert iocs[0].last_seen is not None


def test_soft_delete_finding(store, sample_engagement):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    finding = Finding(
        id="f-1", engagement_id=sample_engagement.id,
        tool="test", title="Test Finding",
        severity=Severity.LOW, created_at=now,
    )
    store.add_finding(finding)
    store.flag_false_positive("f-1")
    findings = store.get_findings(sample_engagement.id)
    assert len(findings) == 1
    assert findings[0].false_positive is True


def test_get_summary(store, sample_engagement):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    for i, sev in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.HIGH]):
        store.add_finding(Finding(
            id=f"f-{i}", engagement_id=sample_engagement.id,
            tool="test", title=f"Finding {i}",
            severity=sev, created_at=now,
        ))
    summary = store.get_summary(sample_engagement.id)
    assert summary.finding_counts["critical"] == 1
    assert summary.finding_counts["high"] == 2


def test_search_findings_fts(store, sample_engagement):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    store.add_finding(Finding(
        id="f-1", engagement_id=sample_engagement.id,
        tool="test", title="Buffer overflow in parse_header",
        description="Stack-based buffer overflow when parsing malformed HTTP headers",
        severity=Severity.CRITICAL, created_at=now,
    ))
    store.add_finding(Finding(
        id="f-2", engagement_id=sample_engagement.id,
        tool="test", title="Missing CSRF token",
        severity=Severity.MEDIUM, created_at=now,
    ))
    results = store.search_findings("buffer overflow")
    assert len(results) == 1
    assert results[0].id == "f-1"


from opentools.engagement.export import export_engagement, import_engagement
import json


def test_export_creates_json_file(store, sample_engagement, tmp_path):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    store.add_finding(Finding(
        id="f-1", engagement_id=sample_engagement.id,
        tool="test", title="Test Finding", severity=Severity.HIGH, created_at=now,
    ))
    output = tmp_path / "export.json"
    export_engagement(store, sample_engagement.id, output)
    assert output.exists()
    data = json.loads(output.read_text())
    assert data["engagement"]["name"] == "test-pentest"
    assert len(data["findings"]) == 1
    assert "schema_version" in data


def test_import_creates_new_engagement(store, sample_engagement, tmp_path):
    # Export first
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    store.add_finding(Finding(
        id="f-1", engagement_id=sample_engagement.id,
        tool="test", title="Test Finding", severity=Severity.HIGH, created_at=now,
    ))
    output = tmp_path / "export.json"
    export_engagement(store, sample_engagement.id, output)

    # Import into same store (new IDs)
    new_id = import_engagement(store, output)
    assert new_id != sample_engagement.id
    engagements = store.list_all()
    assert len(engagements) == 2

    # Verify imported engagement has findings
    imported_findings = store.get_findings(new_id)
    assert len(imported_findings) == 1
    assert imported_findings[0].title == "Test Finding"


def test_add_finding_dedup_merges_duplicate(store, sample_engagement):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    f1 = Finding(id="f-1", engagement_id=sample_engagement.id,
                 tool="semgrep", title="SQL Injection", severity=Severity.HIGH,
                 cwe="CWE-89", file_path="src/api.py", line_start=42, created_at=now)
    id1 = store.add_finding(f1)
    assert id1 == "f-1"

    f2 = Finding(id="f-2", engagement_id=sample_engagement.id,
                 tool="codebadger", title="Taint flow to SQL sink", severity=Severity.CRITICAL,
                 cwe="CWE-89", file_path="src/api.py", line_start=43, created_at=now)
    id2 = store.add_finding(f2)
    assert id2 == "f-1"

    findings = store.get_findings(sample_engagement.id)
    assert len(findings) == 1
    assert "codebadger" in findings[0].corroborated_by
    assert findings[0].severity == Severity.CRITICAL


def test_add_finding_dedup_distinct_far_lines(store, sample_engagement):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    store.add_finding(Finding(id="f-1", engagement_id=sample_engagement.id,
                              tool="semgrep", title="SQL Injection", severity=Severity.HIGH,
                              cwe="CWE-89", file_path="src/api.py", line_start=42, created_at=now))
    store.add_finding(Finding(id="f-2", engagement_id=sample_engagement.id,
                              tool="codebadger", title="Another SQLi", severity=Severity.HIGH,
                              cwe="CWE-89", file_path="src/api.py", line_start=200, created_at=now))
    findings = store.get_findings(sample_engagement.id)
    assert len(findings) == 2


def test_add_finding_dedup_normalized_paths(store, sample_engagement):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    store.add_finding(Finding(id="f-1", engagement_id=sample_engagement.id,
                              tool="semgrep", title="XSS", severity=Severity.HIGH,
                              cwe="CWE-79", file_path="src/views/index.js", line_start=10, created_at=now))
    id2 = store.add_finding(Finding(id="f-2", engagement_id=sample_engagement.id,
                                    tool="nuclei", title="Reflected XSS", severity=Severity.MEDIUM,
                                    cwe="CWE-79", file_path="./src\\views\\index.js", line_start=11, created_at=now))
    assert id2 == "f-1"
    findings = store.get_findings(sample_engagement.id)
    assert len(findings) == 1


def test_add_findings_batch(store, sample_engagement):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    findings = [
        Finding(id="f-1", engagement_id=sample_engagement.id,
                tool="semgrep", title="SQL Injection", severity=Severity.HIGH,
                cwe="CWE-89", file_path="src/api.py", line_start=42, created_at=now),
        Finding(id="f-2", engagement_id=sample_engagement.id,
                tool="nuclei", title="SQLi detected", severity=Severity.CRITICAL,
                cwe="CWE-89", file_path="src/api.py", line_start=43, created_at=now),
        Finding(id="f-3", engagement_id=sample_engagement.id,
                tool="semgrep", title="XSS in template", severity=Severity.MEDIUM,
                cwe="CWE-79", file_path="src/views.py", line_start=10, created_at=now),
    ]
    ids = store.add_findings_batch(findings)
    assert len(ids) == 3
    assert ids[1] == ids[0]
    assert ids[2] != ids[0]
    all_findings = store.get_findings(sample_engagement.id)
    assert len(all_findings) == 2
