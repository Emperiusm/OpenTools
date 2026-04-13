"""Tests for FindingLifecycle — auto state transitions."""

import uuid
from datetime import datetime, timezone

import pytest

from opentools.models import FindingStatus
from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
)
from opentools.scanner.parsing.lifecycle import FindingLifecycle


def _make_dedup(
    status: FindingStatus = FindingStatus.DISCOVERED,
    corroboration_count: int = 1,
    confidence_score: float = 0.7,
    suppressed: bool = False,
) -> DeduplicatedFinding:
    now = datetime.now(timezone.utc)
    return DeduplicatedFinding(
        id=str(uuid.uuid4()),
        engagement_id="eng-1",
        fingerprint=str(uuid.uuid4())[:16],
        raw_finding_ids=[str(uuid.uuid4())],
        tools=["semgrep"],
        corroboration_count=corroboration_count,
        confidence_score=confidence_score,
        severity_consensus="high",
        canonical_title="SQL Injection",
        cwe="CWE-89",
        location_fingerprint="a.py:10",
        location_precision=LocationPrecision.EXACT_LINE,
        evidence_quality_best=EvidenceQuality.STRUCTURED,
        suppressed=suppressed,
        status=status,
        first_seen_scan_id="scan-1",
        created_at=now,
        updated_at=now,
    )


class TestFindingLifecycle:
    def test_discovered_to_confirmed_by_corroboration(self):
        """discovered -> confirmed when corroboration_count >= 2."""
        lc = FindingLifecycle()
        f = _make_dedup(
            status=FindingStatus.DISCOVERED,
            corroboration_count=2,
        )
        [result] = lc.apply([f])
        assert result.status == FindingStatus.CONFIRMED

    def test_discovered_to_confirmed_by_confidence(self):
        """discovered -> confirmed when confidence >= 0.85."""
        lc = FindingLifecycle()
        f = _make_dedup(
            status=FindingStatus.DISCOVERED,
            corroboration_count=1,
            confidence_score=0.85,
        )
        [result] = lc.apply([f])
        assert result.status == FindingStatus.CONFIRMED

    def test_discovered_stays_discovered_low_confidence(self):
        """discovered stays discovered when neither threshold met."""
        lc = FindingLifecycle()
        f = _make_dedup(
            status=FindingStatus.DISCOVERED,
            corroboration_count=1,
            confidence_score=0.5,
        )
        [result] = lc.apply([f])
        assert result.status == FindingStatus.DISCOVERED

    def test_confirmed_stays_confirmed(self):
        """confirmed is not downgraded."""
        lc = FindingLifecycle()
        f = _make_dedup(status=FindingStatus.CONFIRMED)
        [result] = lc.apply([f])
        assert result.status == FindingStatus.CONFIRMED

    def test_suppressed_findings_skipped(self):
        """Suppressed findings are not transitioned."""
        lc = FindingLifecycle()
        f = _make_dedup(
            status=FindingStatus.DISCOVERED,
            corroboration_count=5,
            confidence_score=0.99,
            suppressed=True,
        )
        [result] = lc.apply([f])
        assert result.status == FindingStatus.DISCOVERED

    def test_custom_thresholds(self):
        """Custom corroboration and confidence thresholds."""
        lc = FindingLifecycle(
            confirm_corroboration=3,
            confirm_confidence=0.95,
        )
        f = _make_dedup(
            status=FindingStatus.DISCOVERED,
            corroboration_count=2,
            confidence_score=0.9,
        )
        [result] = lc.apply([f])
        assert result.status == FindingStatus.DISCOVERED

        f2 = _make_dedup(
            status=FindingStatus.DISCOVERED,
            corroboration_count=3,
        )
        [result2] = lc.apply([f2])
        assert result2.status == FindingStatus.CONFIRMED

    def test_empty_input(self):
        lc = FindingLifecycle()
        assert lc.apply([]) == []
