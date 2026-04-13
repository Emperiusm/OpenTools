"""Tests for NormalizationEngine — paths, CWEs, severities, titles."""

import hashlib
import uuid
from datetime import datetime, timezone

import pytest

from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)
from opentools.scanner.parsing.normalization import NormalizationEngine


def _make_finding(**overrides) -> RawFinding:
    """Helper to build a RawFinding with sane defaults."""
    defaults = dict(
        id=str(uuid.uuid4()),
        scan_task_id="task-1",
        scan_id="scan-1",
        tool="semgrep",
        raw_severity="ERROR",
        title="sql injection detected",
        description="Found SQL injection",
        file_path="src/api/users.py",
        line_start=42,
        line_end=42,
        evidence="test",
        evidence_quality=EvidenceQuality.STRUCTURED,
        evidence_hash=hashlib.sha256(b"test").hexdigest(),
        cwe="CWE-89",
        location_fingerprint="src/api/users.py:42",
        location_precision=LocationPrecision.EXACT_LINE,
        parser_version="1.0.0",
        parser_confidence=0.9,
        discovered_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return RawFinding(**defaults)


class TestPathNormalization:
    def test_backslash_to_forward_slash(self):
        engine = NormalizationEngine()
        f = _make_finding(file_path="src\\api\\users.py")
        [result] = engine.normalize([f])
        assert result.file_path == "src/api/users.py"

    def test_strip_leading_dot_slash(self):
        engine = NormalizationEngine()
        f = _make_finding(file_path="./src/api/users.py")
        [result] = engine.normalize([f])
        assert result.file_path == "src/api/users.py"

    def test_strip_absolute_prefix(self):
        engine = NormalizationEngine()
        f = _make_finding(file_path="C:\\Users\\dev\\project\\src\\api\\users.py")
        [result] = engine.normalize([f])
        # Should strip to relative path; at minimum, forward slashes
        assert "\\" not in result.file_path

    def test_none_path_unchanged(self):
        engine = NormalizationEngine()
        f = _make_finding(file_path=None)
        [result] = engine.normalize([f])
        assert result.file_path is None


class TestSeverityNormalization:
    def test_semgrep_error_to_high(self):
        engine = NormalizationEngine()
        f = _make_finding(tool="semgrep", raw_severity="ERROR")
        [result] = engine.normalize([f])
        assert result.raw_severity == "high"

    def test_semgrep_warning_to_medium(self):
        engine = NormalizationEngine()
        f = _make_finding(tool="semgrep", raw_severity="WARNING")
        [result] = engine.normalize([f])
        assert result.raw_severity == "medium"

    def test_trivy_critical_unchanged(self):
        engine = NormalizationEngine()
        f = _make_finding(tool="trivy", raw_severity="CRITICAL")
        [result] = engine.normalize([f])
        assert result.raw_severity == "critical"

    def test_gitleaks_secret_to_high(self):
        engine = NormalizationEngine()
        f = _make_finding(tool="gitleaks", raw_severity="secret")
        [result] = engine.normalize([f])
        assert result.raw_severity == "high"

    def test_unknown_tool_passes_through(self):
        engine = NormalizationEngine()
        f = _make_finding(tool="unknown_tool", raw_severity="SCARY")
        [result] = engine.normalize([f])
        assert result.raw_severity == "SCARY"


class TestCWENormalization:
    def test_alias_resolution(self):
        engine = NormalizationEngine()
        f = _make_finding(cwe="sqli")
        [result] = engine.normalize([f])
        assert result.cwe == "CWE-89"

    def test_canonical_unchanged(self):
        engine = NormalizationEngine()
        f = _make_finding(cwe="CWE-79")
        [result] = engine.normalize([f])
        assert result.cwe == "CWE-79"

    def test_none_cwe_stays_none(self):
        engine = NormalizationEngine()
        f = _make_finding(cwe=None)
        [result] = engine.normalize([f])
        assert result.cwe is None


class TestTitleNormalization:
    def test_sql_injection_canonical(self):
        engine = NormalizationEngine()
        f = _make_finding(title="potential sql injection via user input")
        [result] = engine.normalize([f])
        assert result.canonical_title == "SQL Injection"

    def test_xss_canonical(self):
        engine = NormalizationEngine()
        f = _make_finding(title="reflected XSS in search parameter")
        [result] = engine.normalize([f])
        # Should match one of the XSS patterns
        assert "Cross-Site Scripting" in result.canonical_title or "XSS" in result.canonical_title

    def test_no_match_uses_original(self):
        engine = NormalizationEngine()
        f = _make_finding(title="totally unique finding name xyz")
        [result] = engine.normalize([f])
        assert result.canonical_title == "totally unique finding name xyz"

    def test_hardcoded_credentials_canonical(self):
        engine = NormalizationEngine()
        f = _make_finding(title="hard-coded password found in config.py")
        [result] = engine.normalize([f])
        assert result.canonical_title == "Hardcoded Credentials"


class TestLocationFingerprintUpdate:
    def test_fingerprint_uses_normalized_path(self):
        engine = NormalizationEngine()
        f = _make_finding(
            file_path="./src\\api\\users.py",
            location_fingerprint="./src\\api\\users.py:42",
        )
        [result] = engine.normalize([f])
        assert result.location_fingerprint == "src/api/users.py:42"
