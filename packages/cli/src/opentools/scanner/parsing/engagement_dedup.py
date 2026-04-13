"""EngagementDedupEngine — cross-scan reconciliation within an engagement.

Merges current scan findings with prior engagement findings by fingerprint.
Handles:
- Reconfirmation: updates last_confirmed_scan_id, transitions DISCOVERED -> CONFIRMED
- Tool aggregation: merges tool lists across scans
- Preservation: prior findings not in current scan are retained
"""

from __future__ import annotations

from datetime import datetime, timezone

from opentools.models import FindingStatus
from opentools.scanner.models import DeduplicatedFinding


class EngagementDedupEngine:
    """Reconciles current scan findings with prior engagement-level findings."""

    def reconcile(
        self,
        current: list[DeduplicatedFinding],
        prior: list[DeduplicatedFinding],
        scan_id: str,
    ) -> list[DeduplicatedFinding]:
        """Merge current scan findings with prior engagement findings.

        Returns a list of DeduplicatedFinding objects representing the full
        engagement state after this scan.
        """
        now = datetime.now(timezone.utc)
        prior_by_fp = {f.fingerprint: f for f in prior}
        current_by_fp = {f.fingerprint: f for f in current}

        result: list[DeduplicatedFinding] = []
        seen_fps: set[str] = set()

        # Process current findings
        for fp, cf in current_by_fp.items():
            seen_fps.add(fp)
            pf = prior_by_fp.get(fp)
            if pf is not None:
                # Merge: reconfirm existing finding
                merged_tools = list(set(pf.tools) | set(cf.tools))
                merged_raw_ids = list(set(pf.raw_finding_ids) | set(cf.raw_finding_ids))

                # Transition DISCOVERED -> CONFIRMED on reconfirmation
                new_status = pf.status
                if pf.status == FindingStatus.DISCOVERED:
                    new_status = FindingStatus.CONFIRMED

                result.append(pf.model_copy(update={
                    "tools": merged_tools,
                    "raw_finding_ids": merged_raw_ids,
                    "corroboration_count": max(pf.corroboration_count, cf.corroboration_count) + 1,
                    "last_confirmed_scan_id": scan_id,
                    "last_confirmed_at": now,
                    "status": new_status,
                    "updated_at": now,
                }))
            else:
                # New finding for this engagement
                result.append(cf.model_copy(update={
                    "last_confirmed_scan_id": scan_id,
                    "last_confirmed_at": now,
                }))

        # Retain prior findings not seen in current scan
        for fp, pf in prior_by_fp.items():
            if fp not in seen_fps:
                result.append(pf)

        return result
