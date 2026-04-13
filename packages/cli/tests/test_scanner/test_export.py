"""Tests for ScanResultExporter — JSON, SARIF, CSV, Markdown."""

import csv
import io
import json
import uuid
from datetime import datetime, timezone

import pytest

from opentools.models import FindingStatus
from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    FindingCorrelation,
    LocationPrecision,
    RemediationGroup,
    Scan,
    ScanMode,
    ScanStatus,
    TargetType,
)
from opentools.scanner.export import ScanResultExporter


def _make_scan() -> Scan:
    return Scan(
        id="scan-1",
        engagement_id="eng-1",
        target="https://example.com",
        target_type=TargetType.URL,
        mode=ScanMode.AUTO,
        status=ScanStatus.COMPLETED,
        tools_planned=["semgrep", "trivy"],
        tools_completed=["semgrep", "trivy"],
        created_at=datetime(2026, 4, 12, tzinfo=timezone.utc),
        started_at=datetime(2026, 4, 12, 0, 1, tzinfo=timezone.utc),
        completed_at=datetime(2026, 4, 12, 0, 10, tzinfo=timezone.utc),
    )


def _make_findings() -> list[DeduplicatedFinding]:
    now = datetime.now(timezone.utc)
    return [
        DeduplicatedFinding(
            id="finding-1",
            engagement_id="eng-1",
            fingerprint="fp1",
            raw_finding_ids=["raw-1", "raw-2"],
            tools=["semgrep", "trivy"],
            corroboration_count=2,
            confidence_score=0.92,
            severity_consensus="high",
            canonical_title="SQL Injection",
            cwe="CWE-89",
            location_fingerprint="src/api/users.py:42",
            location_precision=LocationPrecision.EXACT_LINE,
            evidence_quality_best=EvidenceQuality.STRUCTURED,
            status=FindingStatus.CONFIRMED,
            first_seen_scan_id="scan-1",
            created_at=now,
            updated_at=now,
        ),
        DeduplicatedFinding(
            id="finding-2",
            engagement_id="eng-1",
            fingerprint="fp2",
            raw_finding_ids=["raw-3"],
            tools=["trivy"],
            corroboration_count=1,
            confidence_score=0.9,
            severity_consensus="critical",
            canonical_title="CVE-2023-22796: ReDoS in Active Support",
            cwe="CWE-1333",
            location_fingerprint="Gemfile.lock:activesupport:7.0.4",
            location_precision=LocationPrecision.FILE,
            evidence_quality_best=EvidenceQuality.STRUCTURED,
            status=FindingStatus.DISCOVERED,
            first_seen_scan_id="scan-1",
            created_at=now,
            updated_at=now,
        ),
    ]


class TestJsonExport:
    def test_valid_json(self):
        exporter = ScanResultExporter()
        result = exporter.to_json(_make_scan(), _make_findings())
        parsed = json.loads(result)
        assert parsed["scan"]["id"] == "scan-1"
        assert len(parsed["findings"]) == 2

    def test_json_finding_fields(self):
        exporter = ScanResultExporter()
        result = exporter.to_json(_make_scan(), _make_findings())
        parsed = json.loads(result)
        f = parsed["findings"][0]
        assert f["canonical_title"] == "SQL Injection"
        assert f["severity_consensus"] == "high"
        assert f["cwe"] == "CWE-89"
        assert f["confidence_score"] == 0.92

    def test_json_empty_findings(self):
        exporter = ScanResultExporter()
        result = exporter.to_json(_make_scan(), [])
        parsed = json.loads(result)
        assert parsed["findings"] == []


class TestSarifExport:
    def test_valid_sarif(self):
        exporter = ScanResultExporter()
        result = exporter.to_sarif(_make_scan(), _make_findings())
        parsed = json.loads(result)
        assert parsed["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"]) == 1

    def test_sarif_results(self):
        exporter = ScanResultExporter()
        result = exporter.to_sarif(_make_scan(), _make_findings())
        parsed = json.loads(result)
        results = parsed["runs"][0]["results"]
        assert len(results) == 2

    def test_sarif_result_fields(self):
        exporter = ScanResultExporter()
        result = exporter.to_sarif(_make_scan(), _make_findings())
        parsed = json.loads(result)
        r = parsed["runs"][0]["results"][0]
        assert r["ruleId"] == "CWE-89"
        assert r["level"] == "error"  # high -> error
        assert r["message"]["text"] == "SQL Injection"

    def test_sarif_tool_info(self):
        exporter = ScanResultExporter()
        result = exporter.to_sarif(_make_scan(), _make_findings())
        parsed = json.loads(result)
        tool = parsed["runs"][0]["tool"]["driver"]
        assert tool["name"] == "opentools-scanner"


class TestCsvExport:
    def test_valid_csv(self):
        exporter = ScanResultExporter()
        result = exporter.to_csv(_make_findings())
        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)
        assert len(rows) == 2

    def test_csv_headers(self):
        exporter = ScanResultExporter()
        result = exporter.to_csv(_make_findings())
        reader = csv.DictReader(io.StringIO(result))
        headers = reader.fieldnames
        assert "id" in headers
        assert "severity" in headers
        assert "title" in headers
        assert "cwe" in headers
        assert "location" in headers
        assert "confidence" in headers
        assert "tools" in headers

    def test_csv_values(self):
        exporter = ScanResultExporter()
        result = exporter.to_csv(_make_findings())
        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)
        assert rows[0]["title"] == "SQL Injection"
        assert rows[0]["severity"] == "high"

    def test_csv_empty(self):
        exporter = ScanResultExporter()
        result = exporter.to_csv([])
        # Should have header line only
        lines = result.strip().split("\n")
        assert len(lines) == 1  # header only


class TestMarkdownExport:
    def test_markdown_contains_header(self):
        exporter = ScanResultExporter()
        result = exporter.to_markdown(_make_scan(), _make_findings())
        assert "# Scan Report" in result
        assert "scan-1" in result

    def test_markdown_contains_findings(self):
        exporter = ScanResultExporter()
        result = exporter.to_markdown(_make_scan(), _make_findings())
        assert "SQL Injection" in result
        assert "CWE-89" in result
        assert "high" in result.lower() or "HIGH" in result

    def test_markdown_summary(self):
        exporter = ScanResultExporter()
        result = exporter.to_markdown(_make_scan(), _make_findings())
        assert "critical" in result.lower() or "Critical" in result
        assert "2" in result  # total findings count

    def test_markdown_empty_findings(self):
        exporter = ScanResultExporter()
        result = exporter.to_markdown(_make_scan(), [])
        assert "No findings" in result or "0" in result
