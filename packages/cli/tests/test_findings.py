from datetime import datetime, timezone
import pytest
from opentools.findings import infer_cwe, check_duplicate, CWE_KEYWORDS
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
