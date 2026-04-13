"""Tests for EngagementDedupEngine — cross-scan dedup within an engagement."""

import uuid
from datetime import datetime, timezone

import pytest

from opentools.models import FindingStatus
from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
)
from opentools.scanner.parsing.engagement_dedup import EngagementDedupEngine


def _make_dedup(
    fingerprint: str = "fp1",
    canonical_title: str = "SQL Injection",
    cwe: str | None = "CWE-89",
    location_fingerprint: str = "a.py:10",
    tools: list[str] | None = None,
    scan_id: str = "scan-1",
    engagement_id: str = "eng-1",
    confidence_score: float = 0.9,
    severity_consensus: str = "high",
    status: FindingStatus = FindingStatus.DISCOVERED,
) -> DeduplicatedFinding:
    now = datetime.now(timezone.utc)
    return DeduplicatedFinding(
        id=str(uuid.uuid4()),
        engagement_id=engagement_id,
        fingerprint=fingerprint,
        raw_finding_ids=[str(uuid.uuid4())],
        tools=tools or ["semgrep"],
        corroboration_count=1,
        confidence_score=confidence_score,
        severity_consensus=severity_consensus,
        canonical_title=canonical_title,
        cwe=cwe,
        location_fingerprint=location_fingerprint,
        location_precision=LocationPrecision.EXACT_LINE,
        evidence_quality_best=EvidenceQuality.STRUCTURED,
        status=status,
        first_seen_scan_id=scan_id,
        last_confirmed_scan_id=scan_id,
        last_confirmed_at=now,
        created_at=now,
        updated_at=now,
    )


class TestEngagementDedup:
    def test_new_finding_added(self):
        """A finding not in prior results is returned as new."""
        engine = EngagementDedupEngine()
        current = [_make_dedup(fingerprint="fp-new")]
        prior: list[DeduplicatedFinding] = []
        merged = engine.reconcile(current, prior, scan_id="scan-2")
        assert len(merged) == 1
        assert merged[0].fingerprint == "fp-new"

    def test_matching_fingerprint_merges(self):
        """Same fingerprint across scans merges into one finding."""
        engine = EngagementDedupEngine()
        prior = [_make_dedup(fingerprint="fp1", tools=["semgrep"], scan_id="scan-1")]
        current = [_make_dedup(fingerprint="fp1", tools=["trivy"], scan_id="scan-2")]
        merged = engine.reconcile(current, prior, scan_id="scan-2")
        assert len(merged) == 1
        # Should have tools from both scans
        assert "semgrep" in merged[0].tools
        assert "trivy" in merged[0].tools
        assert merged[0].last_confirmed_scan_id == "scan-2"

    def test_confirmed_by_rescan(self):
        """A DISCOVERED finding reconfirmed in a new scan transitions to CONFIRMED."""
        engine = EngagementDedupEngine()
        prior = [_make_dedup(
            fingerprint="fp1",
            status=FindingStatus.DISCOVERED,
            confidence_score=0.85,
        )]
        current = [_make_dedup(fingerprint="fp1")]
        merged = engine.reconcile(current, prior, scan_id="scan-2")
        assert len(merged) == 1
        assert merged[0].status == FindingStatus.CONFIRMED

    def test_prior_only_findings_kept(self):
        """Findings in prior but not in current are still included (not removed)."""
        engine = EngagementDedupEngine()
        prior = [_make_dedup(fingerprint="fp-old")]
        current: list[DeduplicatedFinding] = []
        merged = engine.reconcile(current, prior, scan_id="scan-2")
        assert len(merged) == 1
        assert merged[0].fingerprint == "fp-old"

    def test_multiple_findings_mixed(self):
        """Mix of new, reconfirmed, and prior-only findings."""
        engine = EngagementDedupEngine()
        prior = [
            _make_dedup(fingerprint="fp-shared"),
            _make_dedup(fingerprint="fp-old-only"),
        ]
        current = [
            _make_dedup(fingerprint="fp-shared"),
            _make_dedup(fingerprint="fp-new"),
        ]
        merged = engine.reconcile(current, prior, scan_id="scan-2")
        fps = {f.fingerprint for f in merged}
        assert "fp-shared" in fps
        assert "fp-old-only" in fps
        assert "fp-new" in fps
        assert len(merged) == 3
