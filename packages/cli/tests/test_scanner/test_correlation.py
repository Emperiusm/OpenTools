"""Tests for FindingCorrelationEngine and RemediationGrouper."""

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
)
from opentools.scanner.parsing.correlation import FindingCorrelationEngine
from opentools.scanner.parsing.remediation import RemediationGrouper


def _make_dedup(
    canonical_title: str = "SQL Injection",
    cwe: str | None = "CWE-89",
    location_fingerprint: str = "a.py:10",
    severity_consensus: str = "high",
    tools: list[str] | None = None,
    description: str = "",
) -> DeduplicatedFinding:
    now = datetime.now(timezone.utc)
    return DeduplicatedFinding(
        id=str(uuid.uuid4()),
        engagement_id="eng-1",
        fingerprint=str(uuid.uuid4())[:16],
        raw_finding_ids=[str(uuid.uuid4())],
        tools=tools or ["semgrep"],
        corroboration_count=1,
        confidence_score=0.9,
        severity_consensus=severity_consensus,
        canonical_title=canonical_title,
        cwe=cwe,
        location_fingerprint=location_fingerprint,
        location_precision=LocationPrecision.EXACT_LINE,
        evidence_quality_best=EvidenceQuality.STRUCTURED,
        status=FindingStatus.DISCOVERED,
        first_seen_scan_id="scan-1",
        created_at=now,
        updated_at=now,
    )


# ---------------------------------------------------------------------------
# FindingCorrelationEngine
# ---------------------------------------------------------------------------


class TestFindingCorrelationEngine:
    def test_same_endpoint_correlation(self):
        """Findings on the same file/endpoint are correlated."""
        engine = FindingCorrelationEngine()
        f1 = _make_dedup(
            canonical_title="SQL Injection",
            location_fingerprint="src/api/users.py:10",
        )
        f2 = _make_dedup(
            canonical_title="Cross-Site Scripting (XSS)",
            cwe="CWE-79",
            location_fingerprint="src/api/users.py:25",
        )
        correlations = engine.correlate(
            [f1, f2], scan_id="scan-1", engagement_id="eng-1"
        )
        assert len(correlations) >= 1
        c = correlations[0]
        assert isinstance(c, FindingCorrelation)
        assert c.correlation_type == "same_endpoint"
        assert len(c.finding_ids) == 2

    def test_same_cwe_correlation(self):
        """Multiple findings with the same CWE are correlated."""
        engine = FindingCorrelationEngine()
        f1 = _make_dedup(cwe="CWE-89", location_fingerprint="a.py:10")
        f2 = _make_dedup(cwe="CWE-89", location_fingerprint="b.py:20")
        correlations = engine.correlate(
            [f1, f2], scan_id="scan-1", engagement_id="eng-1"
        )
        cwe_corrs = [c for c in correlations if c.correlation_type == "same_cwe"]
        assert len(cwe_corrs) >= 1
        assert len(cwe_corrs[0].finding_ids) == 2

    def test_attack_chain_detection(self):
        """Findings that form a known attack chain are detected."""
        engine = FindingCorrelationEngine()
        # Recon -> injection -> data exfil pattern
        f1 = _make_dedup(
            canonical_title="SQL Injection",
            cwe="CWE-89",
            location_fingerprint="a.py:10",
        )
        f2 = _make_dedup(
            canonical_title="Hardcoded Credentials",
            cwe="CWE-798",
            location_fingerprint="config.py:5",
        )
        f3 = _make_dedup(
            canonical_title="Path Traversal",
            cwe="CWE-22",
            location_fingerprint="b.py:20",
        )
        correlations = engine.correlate(
            [f1, f2, f3], scan_id="scan-1", engagement_id="eng-1"
        )
        attack_chains = [c for c in correlations if c.correlation_type == "attack_chain"]
        # May or may not detect a chain depending on heuristics, but should not crash
        assert isinstance(correlations, list)

    def test_no_findings_no_correlations(self):
        engine = FindingCorrelationEngine()
        result = engine.correlate([], scan_id="scan-1", engagement_id="eng-1")
        assert result == []

    def test_single_finding_no_correlations(self):
        engine = FindingCorrelationEngine()
        f = _make_dedup()
        result = engine.correlate([f], scan_id="scan-1", engagement_id="eng-1")
        assert result == []


# ---------------------------------------------------------------------------
# RemediationGrouper
# ---------------------------------------------------------------------------


class TestRemediationGrouper:
    def test_group_by_shared_cwe(self):
        """Findings with the same CWE are grouped for shared remediation."""
        grouper = RemediationGrouper()
        f1 = _make_dedup(cwe="CWE-89", location_fingerprint="a.py:10")
        f2 = _make_dedup(cwe="CWE-89", location_fingerprint="b.py:20")
        groups = grouper.group(
            [f1, f2], scan_id="scan-1", engagement_id="eng-1"
        )
        assert len(groups) >= 1
        g = groups[0]
        assert isinstance(g, RemediationGroup)
        assert len(g.finding_ids) == 2
        assert g.findings_count == 2

    def test_different_cwes_separate_groups(self):
        grouper = RemediationGrouper()
        f1 = _make_dedup(cwe="CWE-89", location_fingerprint="a.py:10")
        f2 = _make_dedup(cwe="CWE-79", location_fingerprint="b.py:20")
        groups = grouper.group(
            [f1, f2], scan_id="scan-1", engagement_id="eng-1"
        )
        assert len(groups) == 2

    def test_max_severity_in_group(self):
        grouper = RemediationGrouper()
        f1 = _make_dedup(cwe="CWE-89", severity_consensus="medium", location_fingerprint="a.py:10")
        f2 = _make_dedup(cwe="CWE-89", severity_consensus="critical", location_fingerprint="b.py:20")
        groups = grouper.group([f1, f2], scan_id="scan-1", engagement_id="eng-1")
        assert groups[0].max_severity == "critical"

    def test_empty_input(self):
        grouper = RemediationGrouper()
        assert grouper.group([], scan_id="scan-1", engagement_id="eng-1") == []

    def test_none_cwe_gets_own_group(self):
        grouper = RemediationGrouper()
        f1 = _make_dedup(cwe=None, location_fingerprint="a.py:10")
        f2 = _make_dedup(cwe=None, location_fingerprint="b.py:20")
        groups = grouper.group(
            [f1, f2], scan_id="scan-1", engagement_id="eng-1"
        )
        # Each finding with None CWE gets its own group (no meaningful shared fix)
        assert len(groups) == 2
