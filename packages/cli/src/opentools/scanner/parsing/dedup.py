"""DedupEngine — multi-pass deduplication for scan findings.

Pass 1 (strict): exact fingerprint match on (CWE + location_fingerprint),
(canonical_title + location_fingerprint), (CWE + evidence_hash), or evidence_hash.

Pass 2 (fuzzy): precision-aware fuzzy match on remaining unmatched findings —
overlapping line ranges, related CWEs, same file within N lines.
"""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from opentools.models import FindingStatus
from opentools.scanner.cwe import CWEHierarchy
from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_EQ_ORDER = {
    EvidenceQuality.PROVEN: 4,
    EvidenceQuality.TRACED: 3,
    EvidenceQuality.STRUCTURED: 2,
    EvidenceQuality.PATTERN: 1,
    EvidenceQuality.HEURISTIC: 0,
}


class DedupEngine:
    """Multi-pass dedup engine.

    Parameters
    ----------
    fuzzy_line_threshold : int
        Maximum line distance for fuzzy matching (default 5).
    """

    def __init__(self, fuzzy_line_threshold: int = 5) -> None:
        self._fuzzy_line_threshold = fuzzy_line_threshold
        self._cwe = CWEHierarchy()

    def deduplicate(self, findings: list[RawFinding]) -> list[DeduplicatedFinding]:
        """Run both passes and return merged DeduplicatedFinding objects."""
        if not findings:
            return []

        # Each group is a list of RawFinding indices
        groups: list[list[int]] = []
        matched: set[int] = set()

        # --- Pass 1: Strict fingerprint match ---
        # Build indexes
        cwe_loc_idx: dict[str, list[int]] = defaultdict(list)
        title_loc_idx: dict[str, list[int]] = defaultdict(list)
        cwe_eh_idx: dict[str, list[int]] = defaultdict(list)
        eh_idx: dict[str, list[int]] = defaultdict(list)

        for i, f in enumerate(findings):
            if f.cwe and f.location_fingerprint:
                cwe_loc_idx[f"{f.cwe}:{f.location_fingerprint}"].append(i)
            if f.canonical_title and f.location_fingerprint:
                title_loc_idx[f"{f.canonical_title}:{f.location_fingerprint}"].append(i)
            if f.cwe and f.evidence_hash:
                cwe_eh_idx[f"{f.cwe}:{f.evidence_hash}"].append(i)
            eh_idx[f.evidence_hash].append(i)

        # Merge by each strict key, in priority order
        for index in [cwe_loc_idx, title_loc_idx, cwe_eh_idx, eh_idx]:
            for _key, indices in index.items():
                # Filter to only unmatched
                unmatched_in_group = [i for i in indices if i not in matched]
                if len(unmatched_in_group) >= 2:
                    groups.append(unmatched_in_group)
                    matched.update(unmatched_in_group)

        # --- Pass 2: Fuzzy match on remaining unmatched ---
        unmatched = [i for i in range(len(findings)) if i not in matched]
        fuzzy_matched: set[int] = set()

        for idx_a, i in enumerate(unmatched):
            if i in fuzzy_matched:
                continue
            group = [i]
            fi = findings[i]
            for j in unmatched[idx_a + 1:]:
                if j in fuzzy_matched:
                    continue
                fj = findings[j]
                if self._fuzzy_match(fi, fj):
                    group.append(j)
                    fuzzy_matched.add(j)
            if len(group) >= 2:
                groups.append(group)
                matched.update(group)
                fuzzy_matched.add(i)

        # --- Build DeduplicatedFinding from each group ---
        result: list[DeduplicatedFinding] = []

        # Grouped findings
        for group in groups:
            raw_group = [findings[i] for i in group]
            result.append(self._merge_group(raw_group))

        # Remaining singletons
        for i in range(len(findings)):
            if i not in matched:
                result.append(self._merge_group([findings[i]]))

        return result

    def _fuzzy_match(self, a: RawFinding, b: RawFinding) -> bool:
        """Return True if two findings should merge in the fuzzy pass."""
        # Must be in the same file
        if a.file_path != b.file_path or a.file_path is None:
            return False

        # Precision-aware: FILE-level doesn't merge with EXACT_LINE unless CWE is exact match
        if LocationPrecision.FILE in (a.location_precision, b.location_precision):
            if a.cwe != b.cwe or a.cwe is None:
                return False
            return True

        # Check CWE relationship
        cwe_match = False
        if a.cwe and b.cwe:
            cwe_match = self._cwe.is_related(a.cwe, b.cwe)
        elif a.canonical_title and b.canonical_title:
            cwe_match = a.canonical_title == b.canonical_title
        else:
            return False

        if not cwe_match:
            return False

        # Check line proximity
        return self._lines_overlap_or_close(a, b)

    def _lines_overlap_or_close(self, a: RawFinding, b: RawFinding) -> bool:
        """Check if two findings' line ranges overlap or are within threshold."""
        a_start = a.line_start or 0
        a_end = a.line_end or a_start
        b_start = b.line_start or 0
        b_end = b.line_end or b_start

        # Check overlap
        if a_start <= b_end and b_start <= a_end:
            return True

        # Check proximity
        distance = min(abs(a_start - b_end), abs(b_start - a_end))
        return distance <= self._fuzzy_line_threshold

    def _merge_group(self, raw_findings: list[RawFinding]) -> DeduplicatedFinding:
        """Merge a group of related RawFindings into a single DeduplicatedFinding."""
        now = datetime.now(timezone.utc)
        tools = list({f.tool for f in raw_findings})
        raw_ids = [f.id for f in raw_findings]

        # Severity consensus: weighted vote by parser_confidence
        severity = self._severity_consensus(raw_findings)

        # Best evidence quality
        best_eq = max(raw_findings, key=lambda f: _EQ_ORDER.get(f.evidence_quality, 0))

        # Best location precision
        best_lp = max(
            raw_findings,
            key=lambda f: {
                LocationPrecision.EXACT_LINE: 5,
                LocationPrecision.LINE_RANGE: 4,
                LocationPrecision.FUNCTION: 3,
                LocationPrecision.FILE: 2,
                LocationPrecision.ENDPOINT: 1,
                LocationPrecision.HOST: 0,
            }.get(f.location_precision, 0),
        )

        # Use canonical title if available, otherwise title from highest-confidence parser
        best_conf = max(raw_findings, key=lambda f: f.parser_confidence)
        canonical_title = best_conf.canonical_title or best_conf.title

        # Use CWE from most specific finding (prefer non-None, then most specific child)
        cwe = next(
            (
                f.cwe
                for f in sorted(raw_findings, key=lambda f: f.parser_confidence, reverse=True)
                if f.cwe
            ),
            None,
        )

        # Fingerprint: derive from canonical title + best location fingerprint
        fp_source = f"{canonical_title}:{best_lp.location_fingerprint}:{cwe or 'none'}"
        fingerprint = hashlib.sha256(fp_source.encode()).hexdigest()[:32]

        # Confidence: average of parser confidences (pre-corroboration)
        avg_conf = sum(f.parser_confidence for f in raw_findings) / len(raw_findings)

        return DeduplicatedFinding(
            id=str(uuid.uuid4()),
            engagement_id="",  # Set by caller / EngagementDedupEngine
            fingerprint=fingerprint,
            raw_finding_ids=raw_ids,
            tools=tools,
            corroboration_count=len(raw_findings),
            confidence_score=round(avg_conf, 4),
            severity_consensus=severity,
            canonical_title=canonical_title,
            cwe=cwe,
            location_fingerprint=best_lp.location_fingerprint,
            location_precision=best_lp.location_precision,
            evidence_quality_best=best_eq.evidence_quality,
            status=FindingStatus.DISCOVERED,
            first_seen_scan_id=raw_findings[0].scan_id,
            created_at=now,
            updated_at=now,
        )

    def _severity_consensus(self, findings: list[RawFinding]) -> str:
        """Weighted severity vote. Ties break to more severe."""
        votes: dict[str, float] = defaultdict(float)
        for f in findings:
            sev = f.raw_severity.lower()
            votes[sev] += f.parser_confidence

        if not votes:
            return "info"

        max_weight = max(votes.values())
        # All severities with the max weight
        candidates = [s for s, w in votes.items() if w == max_weight]
        # Tie-break: more severe wins
        return max(candidates, key=lambda s: _SEVERITY_ORDER.get(s, 0))
