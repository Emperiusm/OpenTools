"""FindingLifecycle — automatic state transitions for deduplicated findings.

Transition rules (auto):
- discovered -> confirmed: corroboration_count >= 2 OR confidence >= 0.85
- remediated -> verified: handled by ScanDiff (not in this module)

Manual transitions (reported, remediated) are handled by the API layer.
"""

from __future__ import annotations

from opentools.models import FindingStatus
from opentools.scanner.models import DeduplicatedFinding


class FindingLifecycle:
    """Applies automatic state transitions to findings.

    Parameters
    ----------
    confirm_corroboration : int
        Minimum corroboration count to auto-confirm (default 2).
    confirm_confidence : float
        Minimum confidence score to auto-confirm (default 0.85).
    """

    def __init__(
        self,
        confirm_corroboration: int = 2,
        confirm_confidence: float = 0.85,
    ) -> None:
        self._confirm_corroboration = confirm_corroboration
        self._confirm_confidence = confirm_confidence

    def apply(self, findings: list[DeduplicatedFinding]) -> list[DeduplicatedFinding]:
        """Return a new list with state transitions applied."""
        return [self._transition(f) for f in findings]

    def _transition(self, f: DeduplicatedFinding) -> DeduplicatedFinding:
        """Apply auto-transition rules to a single finding."""
        # Skip suppressed findings
        if f.suppressed:
            return f

        if f.status == FindingStatus.DISCOVERED:
            if (
                f.corroboration_count >= self._confirm_corroboration
                or f.confidence_score >= self._confirm_confidence
            ):
                f.status = FindingStatus.CONFIRMED

        return f
