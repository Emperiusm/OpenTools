"""Tests for ScanDiffEngine — baseline comparison."""

import uuid
from datetime import datetime, timezone

import pytest

from opentools.models import FindingStatus
from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
)
from opentools.scanner.diff import ScanDiffEngine, ScanDiffResult, DiffSummary


def _make_dedup(
    fingerprint: str = "fp1",
    severity_consensus: str = "high",
    tools: list[str] | None = None,
    scan_id: str = "scan-1",
) -> DeduplicatedFinding:
    now = datetime.now(timezone.utc)
    return DeduplicatedFinding(
        id=str(uuid.uuid4()),
        engagement_id="eng-1",
        fingerprint=fingerprint,
        raw_finding_ids=[str(uuid.uuid4())],
        tools=tools or ["semgrep"],
        corroboration_count=1,
        confidence_score=0.9,
        severity_consensus=severity_consensus,
        canonical_title="SQL Injection",
        cwe="CWE-89",
        location_fingerprint="a.py:10",
        location_precision=LocationPrecision.EXACT_LINE,
        evidence_quality_best=EvidenceQuality.STRUCTURED,
        status=FindingStatus.DISCOVERED,
        first_seen_scan_id=scan_id,
        created_at=now,
        updated_at=now,
    )


class TestScanDiff:
    def test_all_new_findings(self):
        engine = ScanDiffEngine()
        current = [_make_dedup(fingerprint="fp-new", scan_id="scan-2")]
        baseline: list[DeduplicatedFinding] = []
        diff = engine.diff(
            current=current,
            baseline=baseline,
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert isinstance(diff, ScanDiffResult)
        assert len(diff.new_findings) == 1
        assert len(diff.resolved_findings) == 0
        assert len(diff.persistent_findings) == 0

    def test_all_resolved_findings(self):
        engine = ScanDiffEngine()
        current: list[DeduplicatedFinding] = []
        baseline = [_make_dedup(fingerprint="fp-old", scan_id="scan-1")]
        diff = engine.diff(
            current=current,
            baseline=baseline,
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert len(diff.new_findings) == 0
        assert len(diff.resolved_findings) == 1
        assert len(diff.persistent_findings) == 0

    def test_persistent_findings(self):
        engine = ScanDiffEngine()
        baseline = [_make_dedup(fingerprint="fp-both", scan_id="scan-1")]
        current = [_make_dedup(fingerprint="fp-both", scan_id="scan-2")]
        diff = engine.diff(
            current=current,
            baseline=baseline,
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert len(diff.new_findings) == 0
        assert len(diff.resolved_findings) == 0
        assert len(diff.persistent_findings) == 1

    def test_mixed_scenario(self):
        engine = ScanDiffEngine()
        baseline = [
            _make_dedup(fingerprint="fp-persist", scan_id="scan-1"),
            _make_dedup(fingerprint="fp-resolved", scan_id="scan-1"),
        ]
        current = [
            _make_dedup(fingerprint="fp-persist", scan_id="scan-2"),
            _make_dedup(fingerprint="fp-new", scan_id="scan-2"),
        ]
        diff = engine.diff(
            current=current,
            baseline=baseline,
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert len(diff.new_findings) == 1
        assert len(diff.resolved_findings) == 1
        assert len(diff.persistent_findings) == 1

    def test_severity_change_detected(self):
        engine = ScanDiffEngine()
        baseline = [_make_dedup(fingerprint="fp1", severity_consensus="medium")]
        current = [_make_dedup(fingerprint="fp1", severity_consensus="critical")]
        diff = engine.diff(
            current=current,
            baseline=baseline,
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert len(diff.severity_changes) == 1
        assert diff.severity_changes[0]["from"] == "medium"
        assert diff.severity_changes[0]["to"] == "critical"

    def test_tool_diff(self):
        engine = ScanDiffEngine()
        baseline = [_make_dedup(fingerprint="fp1", tools=["semgrep"])]
        current = [_make_dedup(fingerprint="fp1", tools=["semgrep", "trivy"])]
        diff = engine.diff(
            current=current,
            baseline=baseline,
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert "trivy" in diff.new_tools_used

    def test_summary(self):
        engine = ScanDiffEngine()
        baseline = [
            _make_dedup(fingerprint="fp-persist"),
            _make_dedup(fingerprint="fp-resolved"),
        ]
        current = [
            _make_dedup(fingerprint="fp-persist"),
            _make_dedup(fingerprint="fp-new"),
        ]
        diff = engine.diff(
            current=current,
            baseline=baseline,
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert isinstance(diff.summary, DiffSummary)
        assert diff.summary.new_count == 1
        assert diff.summary.resolved_count == 1
        assert diff.summary.persistent_count == 1
        assert diff.summary.net_risk_change == "stable"

    def test_empty_both(self):
        engine = ScanDiffEngine()
        diff = engine.diff(
            current=[],
            baseline=[],
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert diff.summary.new_count == 0
        assert diff.summary.resolved_count == 0
        assert diff.summary.net_risk_change == "stable"
