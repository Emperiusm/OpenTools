"""Bridge scan pipeline output into the engagement findings table.

The scanner persists its own ``raw_finding`` and ``dedup_finding`` rows into
``~/.opentools/scans.db``. Downstream features (attack-chain extraction,
kill-chain queries, reports, dashboards) read from the engagement's
``findings`` table in ``<repo>/engagements/opentools.db``. Without a bridge,
every scan produces output that nothing else can consume.

This module runs after a scan completes — if ``engagement_id`` is set and
an engagement exists in the engagement store, raw findings are converted
into :class:`opentools.models.Finding` records and inserted in batch.

Idempotency is approximate: we compare ``(scan_id, tool, title, file_path)``
against existing findings for the engagement and skip exact matches.
Re-running the same scan is uncommon; the intent is to prevent accidental
duplication when imports are retried.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Iterable, Optional

from opentools.engagement.store import EngagementStore
from opentools.models import Finding, Severity
from opentools.scanner.models import RawFinding


_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _raw_to_finding(rf: RawFinding, engagement_id: str, now: datetime) -> Finding:
    severity = _SEVERITY_MAP.get(rf.raw_severity.lower(), Severity.INFO)
    return Finding(
        id=str(uuid.uuid4()),
        engagement_id=engagement_id,
        tool=rf.tool,
        cwe=rf.cwe,
        severity=severity,
        title=rf.title,
        description=rf.description,
        file_path=rf.url or rf.file_path,
        line_start=rf.line_start,
        line_end=rf.line_end,
        evidence=rf.evidence,
        created_at=rf.discovered_at or now,
        scan_id=rf.scan_id,
    )


def _dedup_key(f: Finding) -> tuple:
    return (f.scan_id or "", f.tool, f.title, f.file_path or "")


def import_scan_findings(
    raw_findings: Iterable[RawFinding],
    engagement_id: Optional[str],
    engagement_store: EngagementStore,
) -> int:
    """Import raw findings into the engagement's findings table.

    Returns the number of new findings inserted. Skips rows if the
    engagement does not exist in the store or if an identical finding
    already exists.
    """
    if not engagement_id:
        return 0

    try:
        existing = engagement_store.get_findings(engagement_id)
    except Exception:
        return 0

    existing_keys = {_dedup_key(f) for f in existing}
    now = datetime.now(timezone.utc)

    inserted = 0
    for rf in raw_findings:
        candidate = _raw_to_finding(rf, engagement_id, now)
        if _dedup_key(candidate) in existing_keys:
            continue
        try:
            engagement_store.add_finding(candidate)
            existing_keys.add(_dedup_key(candidate))
            inserted += 1
        except Exception:
            continue
    return inserted
