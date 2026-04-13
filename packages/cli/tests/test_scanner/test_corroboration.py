"""Tests for CorroborationScorer — confidence scoring based on tool diversity."""

import uuid
from datetime import datetime, timezone

import pytest

from opentools.models import FindingStatus
from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
)
from opentools.scanner.parsing.confidence import CorroborationScorer, ConfidenceDecay


def _make_dedup(
    tools: list[str] | None = None,
    corroboration_count: int = 1,
    confidence_score: float = 0.7,
    previously_marked_fp: bool = False,
) -> DeduplicatedFinding:
    now = datetime.now(timezone.utc)
    return DeduplicatedFinding(
        id=str(uuid.uuid4()),
        engagement_id="eng-1",
        fingerprint="fp1",
        raw_finding_ids=[str(uuid.uuid4())],
        tools=tools or ["semgrep"],
        corroboration_count=corroboration_count,
        confidence_score=confidence_score,
        severity_consensus="high",
        canonical_title="SQL Injection",
        cwe="CWE-89",
        location_fingerprint="a.py:10",
        location_precision=LocationPrecision.EXACT_LINE,
        evidence_quality_best=EvidenceQuality.STRUCTURED,
        previously_marked_fp=previously_marked_fp,
        status=FindingStatus.DISCOVERED,
        first_seen_scan_id="scan-1",
        created_at=now,
        updated_at=now,
    )


class TestCorroborationScorer:
    def test_single_tool_no_boost(self):
        scorer = CorroborationScorer()
        f = _make_dedup(tools=["semgrep"], confidence_score=0.9)
        [result] = scorer.score([f])
        # 1 tool = 1.0x boost, no FP penalty
        # base_confidence * 1.0 * 1.0 * 1.0 = 0.9
        assert result.confidence_score == pytest.approx(0.9, abs=0.01)

    def test_two_tools_same_category_boost(self):
        scorer = CorroborationScorer()
        # Two SAST tools
        f = _make_dedup(
            tools=["semgrep", "codebadger"],
            corroboration_count=2,
            confidence_score=0.8,
        )
        [result] = scorer.score([f])
        # 2 tools same category = 1.2x
        assert result.confidence_score > 0.8

    def test_two_tools_different_category_higher_boost(self):
        scorer = CorroborationScorer()
        # SAST + SCA
        f = _make_dedup(
            tools=["semgrep", "trivy"],
            corroboration_count=2,
            confidence_score=0.8,
        )
        [result] = scorer.score([f])
        # 2 tools different category = 1.4x
        assert result.confidence_score > 0.8

    def test_three_tools_maximum_boost(self):
        scorer = CorroborationScorer()
        f = _make_dedup(
            tools=["semgrep", "trivy", "nuclei"],
            corroboration_count=3,
            confidence_score=0.7,
        )
        [result] = scorer.score([f])
        # 3+ tools = 1.5x
        assert result.confidence_score > 0.7

    def test_fp_penalty(self):
        scorer = CorroborationScorer()
        f = _make_dedup(
            tools=["semgrep"],
            confidence_score=0.9,
            previously_marked_fp=True,
        )
        [result] = scorer.score([f])
        # FP penalty = 0.3
        assert result.confidence_score < 0.5

    def test_confidence_capped_at_one(self):
        scorer = CorroborationScorer()
        f = _make_dedup(
            tools=["semgrep", "trivy", "nuclei"],
            corroboration_count=3,
            confidence_score=0.95,
        )
        [result] = scorer.score([f])
        assert result.confidence_score <= 1.0

    def test_empty_input(self):
        scorer = CorroborationScorer()
        assert scorer.score([]) == []


class TestConfidenceDecay:
    def test_no_decay_within_30_days(self):
        decay = ConfidenceDecay()
        now = datetime.now(timezone.utc)
        f = _make_dedup(confidence_score=0.9)
        f = f.model_copy(update={"last_confirmed_at": now})
        [result] = decay.apply([f], reference_time=now)
        assert result.confidence_score == pytest.approx(0.9, abs=0.01)

    def test_decay_after_60_days(self):
        decay = ConfidenceDecay()
        now = datetime.now(timezone.utc)
        from datetime import timedelta
        old = now - timedelta(days=60)
        f = _make_dedup(confidence_score=0.9)
        f = f.model_copy(update={"last_confirmed_at": old})
        [result] = decay.apply([f], reference_time=now)
        # 60 days = 1 period past the 30-day grace, so -5%
        assert result.confidence_score < 0.9
        assert result.confidence_score >= 0.85 * 0.9 - 0.01

    def test_decay_floor_at_20_percent(self):
        decay = ConfidenceDecay()
        now = datetime.now(timezone.utc)
        from datetime import timedelta
        very_old = now - timedelta(days=365 * 3)
        f = _make_dedup(confidence_score=0.9)
        f = f.model_copy(update={"last_confirmed_at": very_old})
        [result] = decay.apply([f], reference_time=now)
        assert result.confidence_score >= 0.2

    def test_none_last_confirmed_no_decay(self):
        decay = ConfidenceDecay()
        now = datetime.now(timezone.utc)
        f = _make_dedup(confidence_score=0.9)
        f = f.model_copy(update={"last_confirmed_at": None})
        [result] = decay.apply([f], reference_time=now)
        assert result.confidence_score == pytest.approx(0.9, abs=0.01)
