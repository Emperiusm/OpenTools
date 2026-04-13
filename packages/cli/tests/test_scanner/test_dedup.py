"""Tests for DedupEngine — strict fingerprint + fuzzy multi-pass dedup."""

import hashlib
import uuid
from datetime import datetime, timezone

import pytest

from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)
from opentools.scanner.parsing.dedup import DedupEngine


def _make_finding(
    tool: str = "semgrep",
    title: str = "SQL Injection",
    file_path: str = "src/api/users.py",
    line_start: int = 42,
    line_end: int | None = None,
    cwe: str | None = "CWE-89",
    raw_severity: str = "high",
    evidence_quality: EvidenceQuality = EvidenceQuality.STRUCTURED,
    location_precision: LocationPrecision = LocationPrecision.EXACT_LINE,
    parser_confidence: float = 0.9,
    evidence_hash: str | None = None,
    location_fingerprint: str | None = None,
) -> RawFinding:
    eid = evidence_hash or hashlib.sha256(
        f"{tool}:{title}:{file_path}:{line_start}".encode()
    ).hexdigest()
    lfp = location_fingerprint or f"{file_path}:{line_start}"
    return RawFinding(
        id=str(uuid.uuid4()),
        scan_task_id="task-1",
        scan_id="scan-1",
        tool=tool,
        raw_severity=raw_severity,
        title=title,
        canonical_title=title,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end or line_start,
        evidence="test evidence",
        evidence_quality=evidence_quality,
        evidence_hash=eid,
        cwe=cwe,
        location_fingerprint=lfp,
        location_precision=location_precision,
        parser_version="1.0.0",
        parser_confidence=parser_confidence,
        discovered_at=datetime.now(timezone.utc),
    )


class TestStrictDedup:
    def test_identical_fingerprint_merges(self):
        """Two findings with same CWE + location_fingerprint merge in Pass 1."""
        engine = DedupEngine()
        f1 = _make_finding(tool="semgrep", cwe="CWE-89", file_path="a.py", line_start=10)
        f2 = _make_finding(tool="trivy", cwe="CWE-89", file_path="a.py", line_start=10)
        results = engine.deduplicate([f1, f2])
        assert len(results) == 1
        assert results[0].corroboration_count == 2
        assert set(results[0].tools) == {"semgrep", "trivy"}
        assert len(results[0].raw_finding_ids) == 2

    def test_same_evidence_hash_merges(self):
        """Two findings with same evidence_hash merge even with different location."""
        engine = DedupEngine()
        eh = hashlib.sha256(b"shared").hexdigest()
        f1 = _make_finding(tool="semgrep", evidence_hash=eh, file_path="a.py", line_start=10)
        f2 = _make_finding(tool="trivy", evidence_hash=eh, file_path="b.py", line_start=20)
        results = engine.deduplicate([f1, f2])
        assert len(results) == 1

    def test_different_findings_stay_separate(self):
        """Findings with different CWEs and locations remain separate."""
        engine = DedupEngine()
        f1 = _make_finding(cwe="CWE-89", file_path="a.py", line_start=10)
        f2 = _make_finding(cwe="CWE-79", file_path="b.py", line_start=20)
        results = engine.deduplicate([f1, f2])
        assert len(results) == 2

    def test_single_finding(self):
        engine = DedupEngine()
        f = _make_finding()
        results = engine.deduplicate([f])
        assert len(results) == 1
        assert results[0].corroboration_count == 1

    def test_empty_input(self):
        engine = DedupEngine()
        results = engine.deduplicate([])
        assert results == []


class TestFuzzyDedup:
    def test_overlapping_line_ranges_merge(self):
        """Findings within N lines of each other with same CWE merge in Pass 2."""
        engine = DedupEngine(fuzzy_line_threshold=5)
        f1 = _make_finding(
            tool="semgrep", cwe="CWE-89", file_path="a.py",
            line_start=42, location_fingerprint="a.py:42",
        )
        f2 = _make_finding(
            tool="nuclei", cwe="CWE-89", file_path="a.py",
            line_start=44, location_fingerprint="a.py:44",
        )
        results = engine.deduplicate([f1, f2])
        assert len(results) == 1
        assert results[0].corroboration_count == 2

    def test_line_range_contains_exact_line(self):
        """EXACT_LINE at line 42 merges with LINE_RANGE 40-45 when CWE matches."""
        engine = DedupEngine(fuzzy_line_threshold=5)
        f1 = _make_finding(
            tool="semgrep", cwe="CWE-89", file_path="a.py",
            line_start=42, location_precision=LocationPrecision.EXACT_LINE,
            location_fingerprint="a.py:42",
        )
        f2 = _make_finding(
            tool="codebadger", cwe="CWE-89", file_path="a.py",
            line_start=40, line_end=45,
            location_precision=LocationPrecision.LINE_RANGE,
            location_fingerprint="a.py:40",
        )
        results = engine.deduplicate([f1, f2])
        assert len(results) == 1

    def test_related_cwes_merge(self):
        """Findings with related CWEs (parent/child) at same location merge."""
        engine = DedupEngine(fuzzy_line_threshold=5)
        f1 = _make_finding(
            tool="semgrep", cwe="CWE-89", file_path="a.py", line_start=10,
            location_fingerprint="a.py:10",
        )
        # CWE-564 is child of CWE-89 in the hierarchy
        f2 = _make_finding(
            tool="codebadger", cwe="CWE-564", file_path="a.py", line_start=10,
            location_fingerprint="a.py:10",
        )
        results = engine.deduplicate([f1, f2])
        assert len(results) == 1

    def test_file_level_no_merge_with_exact_unless_cwe_exact(self):
        """FILE-level findings don't merge with EXACT_LINE unless CWE matches exactly."""
        engine = DedupEngine(fuzzy_line_threshold=5)
        f1 = _make_finding(
            cwe="CWE-89", file_path="a.py", line_start=10,
            location_precision=LocationPrecision.EXACT_LINE,
            location_fingerprint="a.py:10",
        )
        f2 = _make_finding(
            cwe="CWE-79", file_path="a.py", line_start=0,
            location_precision=LocationPrecision.FILE,
            location_fingerprint="a.py:0",
        )
        results = engine.deduplicate([f1, f2])
        assert len(results) == 2

    def test_too_far_apart_no_merge(self):
        """Findings more than N lines apart don't merge even with same CWE."""
        engine = DedupEngine(fuzzy_line_threshold=5)
        f1 = _make_finding(
            cwe="CWE-89", file_path="a.py", line_start=10,
            location_fingerprint="a.py:10",
        )
        f2 = _make_finding(
            cwe="CWE-89", file_path="a.py", line_start=100,
            location_fingerprint="a.py:100",
        )
        results = engine.deduplicate([f1, f2])
        assert len(results) == 2


class TestSeverityConsensus:
    def test_weighted_vote_higher_confidence_wins(self):
        """Severity consensus takes the value from the higher-confidence tool."""
        engine = DedupEngine()
        f1 = _make_finding(
            tool="semgrep", raw_severity="high", parser_confidence=0.9,
            cwe="CWE-89", file_path="a.py", line_start=10,
        )
        f2 = _make_finding(
            tool="nmap", raw_severity="medium", parser_confidence=0.5,
            cwe="CWE-89", file_path="a.py", line_start=10,
        )
        results = engine.deduplicate([f1, f2])
        assert len(results) == 1
        assert results[0].severity_consensus == "high"

    def test_tie_breaks_to_more_severe(self):
        """When parser confidences are equal, tie breaks to more severe."""
        engine = DedupEngine()
        f1 = _make_finding(
            tool="semgrep", raw_severity="medium", parser_confidence=0.9,
            cwe="CWE-89", file_path="a.py", line_start=10,
        )
        f2 = _make_finding(
            tool="trivy", raw_severity="high", parser_confidence=0.9,
            cwe="CWE-89", file_path="a.py", line_start=10,
        )
        results = engine.deduplicate([f1, f2])
        assert len(results) == 1
        assert results[0].severity_consensus == "high"


class TestDedupOutput:
    def test_dedup_result_type(self):
        engine = DedupEngine()
        f = _make_finding()
        results = engine.deduplicate([f])
        assert len(results) == 1
        assert isinstance(results[0], DeduplicatedFinding)

    def test_best_evidence_quality_selected(self):
        engine = DedupEngine()
        f1 = _make_finding(
            tool="semgrep", evidence_quality=EvidenceQuality.STRUCTURED,
            cwe="CWE-89", file_path="a.py", line_start=10,
        )
        f2 = _make_finding(
            tool="nmap", evidence_quality=EvidenceQuality.HEURISTIC,
            cwe="CWE-89", file_path="a.py", line_start=10,
        )
        results = engine.deduplicate([f1, f2])
        assert results[0].evidence_quality_best == EvidenceQuality.STRUCTURED
