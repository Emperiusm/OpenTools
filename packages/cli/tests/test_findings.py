import json
from datetime import datetime, timezone

import pytest

from opentools.findings import infer_cwe, check_duplicate, export_sarif, export_csv, export_json, CWE_KEYWORDS
from opentools.models import Finding, Severity, Confidence


def test_infer_cwe_sql_injection():
    assert infer_cwe("SQL injection in login form") == "CWE-89"


def test_infer_cwe_xss():
    assert infer_cwe("reflected XSS via search parameter") == "CWE-79"


def test_infer_cwe_no_match():
    assert infer_cwe("some random finding about nothing") is None


def test_infer_cwe_multiple_matches_picks_most_hits():
    # "sql injection sqli" has 2 hits for CWE-89
    assert infer_cwe("sql injection sqli in query") == "CWE-89"


def test_check_duplicate_same_cwe_same_file_close_lines():
    now = datetime.now(timezone.utc)
    existing = Finding(
        id="f-1", engagement_id="e-1", tool="semgrep",
        title="SQL Injection", severity=Severity.HIGH,
        cwe="CWE-89", file_path="src/api.py", line_start=42,
        created_at=now,
    )
    new = Finding(
        id="f-2", engagement_id="e-1", tool="codebadger",
        title="Taint flow to SQL sink", severity=Severity.CRITICAL,
        cwe="CWE-89", file_path="src/api.py", line_start=43,
        created_at=now,
    )
    result = check_duplicate(new, [existing])
    assert result is not None
    assert result.match.id == "f-1"
    assert result.confidence == Confidence.HIGH


def test_check_duplicate_same_cwe_far_lines():
    now = datetime.now(timezone.utc)
    existing = Finding(
        id="f-1", engagement_id="e-1", tool="semgrep",
        title="SQL Injection", severity=Severity.HIGH,
        cwe="CWE-89", file_path="src/api.py", line_start=42,
        created_at=now,
    )
    new = Finding(
        id="f-2", engagement_id="e-1", tool="codebadger",
        title="Another SQLi", severity=Severity.HIGH,
        cwe="CWE-89", file_path="src/api.py", line_start=200,
        created_at=now,
    )
    result = check_duplicate(new, [existing])
    assert result is None  # too far apart


def test_check_duplicate_inferred_cwe():
    now = datetime.now(timezone.utc)
    existing = Finding(
        id="f-1", engagement_id="e-1", tool="semgrep",
        title="SQL injection found", severity=Severity.HIGH,
        cwe=None, file_path="src/api.py", line_start=42,
        created_at=now,
    )
    new = Finding(
        id="f-2", engagement_id="e-1", tool="nuclei",
        title="sqli error-based", severity=Severity.HIGH,
        cwe=None, file_path="src/api.py", line_start=44,
        created_at=now,
    )
    result = check_duplicate(new, [existing])
    assert result is not None
    assert result.confidence == Confidence.LOW


def test_check_duplicate_no_cwe_no_inference():
    now = datetime.now(timezone.utc)
    existing = Finding(
        id="f-1", engagement_id="e-1", tool="semgrep",
        title="Something weird", severity=Severity.LOW,
        cwe=None, file_path="src/api.py", line_start=42,
        created_at=now,
    )
    new = Finding(
        id="f-2", engagement_id="e-1", tool="nuclei",
        title="Another weird thing", severity=Severity.LOW,
        cwe=None, file_path="src/api.py", line_start=43,
        created_at=now,
    )
    result = check_duplicate(new, [existing])
    assert result is None  # can't merge without CWE


def test_export_sarif_groups_by_tool():
    now = datetime.now(timezone.utc)
    findings = [
        Finding(id="f-1", engagement_id="e-1", tool="semgrep", title="SQLi",
                severity=Severity.HIGH, cwe="CWE-89", file_path="app.py", line_start=10, created_at=now),
        Finding(id="f-2", engagement_id="e-1", tool="nuclei", title="XSS",
                severity=Severity.MEDIUM, cwe="CWE-79", file_path="index.html", line_start=5, created_at=now),
    ]
    sarif = export_sarif(findings)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 2
    tool_names = {run["tool"]["driver"]["name"] for run in sarif["runs"]}
    assert tool_names == {"semgrep", "nuclei"}


def test_export_sarif_severity_mapping():
    now = datetime.now(timezone.utc)
    findings = [
        Finding(id="f-1", engagement_id="e-1", tool="test", title="Crit", severity=Severity.CRITICAL, created_at=now),
        Finding(id="f-2", engagement_id="e-1", tool="test", title="Med", severity=Severity.MEDIUM, created_at=now),
        Finding(id="f-3", engagement_id="e-1", tool="test", title="Low", severity=Severity.LOW, created_at=now),
    ]
    sarif = export_sarif(findings)
    levels = [r["level"] for r in sarif["runs"][0]["results"]]
    assert levels == ["error", "warning", "note"]


def test_export_sarif_fingerprints():
    now = datetime.now(timezone.utc)
    f = Finding(id="f-1", engagement_id="e-1", tool="test", title="SQLi",
                severity=Severity.HIGH, cwe="CWE-89", file_path="app.py", line_start=42, created_at=now)
    sarif = export_sarif([f])
    result = sarif["runs"][0]["results"][0]
    assert "primaryLocationLineHash" in result["partialFingerprints"]


def test_export_csv():
    now = datetime.now(timezone.utc)
    findings = [
        Finding(id="f-1", engagement_id="e-1", tool="semgrep", title="SQLi",
                severity=Severity.HIGH, cwe="CWE-89", file_path="app.py", line_start=10, created_at=now),
    ]
    csv_str = export_csv(findings)
    assert "f-1" in csv_str
    assert "CWE-89" in csv_str
    assert csv_str.startswith("id,severity")


def test_export_json():
    now = datetime.now(timezone.utc)
    findings = [
        Finding(id="f-1", engagement_id="e-1", tool="test", title="Test",
                severity=Severity.LOW, created_at=now),
    ]
    json_str = export_json(findings)
    parsed = json.loads(json_str)
    assert len(parsed) == 1
    assert parsed[0]["id"] == "f-1"
