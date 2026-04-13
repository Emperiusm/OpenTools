"""Scan business logic — PostgreSQL-backed, user-scoped queries."""
from __future__ import annotations

import json
from typing import Optional

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    ScanEventRecord,
    ScanRecord,
    ScanTaskRecord,
    User,
)


class ScanService:
    """Service layer for scan read endpoints.

    Follows the same pattern as ``EngagementService``: constructor takes
    an ``AsyncSession`` and the authenticated ``User``, and every query
    is scoped to ``user_id == self.user.id``.
    """

    def __init__(self, session: AsyncSession, user: User):
        self.session = session
        self.user = user

    # ------------------------------------------------------------------
    # List / detail
    # ------------------------------------------------------------------

    async def list_scans(
        self,
        engagement_id: Optional[str] = None,
        limit: int = 50,
    ) -> list[ScanRecord]:
        stmt = (
            select(ScanRecord)
            .where(ScanRecord.user_id == self.user.id)
            .order_by(ScanRecord.created_at.desc())
            .limit(limit)
        )
        if engagement_id is not None:
            stmt = stmt.where(ScanRecord.engagement_id == engagement_id)

        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_scan(self, scan_id: str) -> Optional[ScanRecord]:
        stmt = select(ScanRecord).where(
            ScanRecord.id == scan_id,
            ScanRecord.user_id == self.user.id,
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    # ------------------------------------------------------------------
    # Tasks
    # ------------------------------------------------------------------

    async def get_scan_tasks(self, scan_id: str) -> list[ScanTaskRecord]:
        """Return tasks for *scan_id* after verifying the scan belongs to the user."""
        scan = await self.get_scan(scan_id)
        if scan is None:
            return []

        stmt = (
            select(ScanTaskRecord)
            .where(ScanTaskRecord.scan_id == scan_id)
            .order_by(ScanTaskRecord.priority.desc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Findings (raw SQL against dedup_finding — no ORM model yet)
    # ------------------------------------------------------------------

    async def get_scan_findings(
        self,
        scan_id: str,
        severity: Optional[str] = None,
    ) -> list[dict]:
        """Return dedup findings whose first_seen_scan_id matches *scan_id*.

        Uses raw SQL because ``dedup_finding`` has a complex schema and
        no ORM model yet.  The scan ownership check is done first via
        ``get_scan`` so user scoping is enforced.
        """
        scan = await self.get_scan(scan_id)
        if scan is None:
            return []

        query = text(
            "SELECT id, canonical_title, severity_consensus, tools, "
            "confidence_score, location_fingerprint, suppressed "
            "FROM dedup_finding "
            "WHERE first_seen_scan_id = :scan_id"
            + (" AND severity_consensus = :severity" if severity else "")
        )
        params: dict = {"scan_id": scan_id}
        if severity:
            params["severity"] = severity

        result = await self.session.execute(query, params)
        rows = result.mappings().all()
        return [
            {
                "id": r["id"],
                "canonical_title": r["canonical_title"],
                "severity_consensus": r["severity_consensus"],
                "tools": json.loads(r["tools"]) if isinstance(r["tools"], str) else r["tools"],
                "confidence_score": r["confidence_score"],
                "location_fingerprint": r["location_fingerprint"],
                "suppressed": bool(r["suppressed"]),
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Events (for SSE streaming)
    # ------------------------------------------------------------------

    async def get_scan_events_after(
        self, scan_id: str, sequence: int
    ) -> list[ScanEventRecord]:
        """Return events for *scan_id* with sequence > *sequence*.

        Scan ownership is verified first.
        """
        scan = await self.get_scan(scan_id)
        if scan is None:
            return []

        stmt = (
            select(ScanEventRecord)
            .where(
                ScanEventRecord.scan_id == scan_id,
                ScanEventRecord.sequence > sequence,
            )
            .order_by(ScanEventRecord.sequence.asc())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Persist a newly planned scan
    # ------------------------------------------------------------------

    async def persist_scan(self, scan_record: ScanRecord) -> ScanRecord:
        """Insert a ScanRecord (typically after ScanAPI.plan())."""
        scan_record.user_id = self.user.id
        self.session.add(scan_record)
        await self.session.commit()
        await self.session.refresh(scan_record)
        return scan_record

    async def persist_tasks(self, tasks: list[ScanTaskRecord]) -> None:
        """Bulk-insert task records for a planned scan."""
        for t in tasks:
            self.session.add(t)
        await self.session.commit()

    async def get_task_by_ticket(self, scan_id: str, ticket_id: str) -> ScanTaskRecord | None:
        """Find a task by its approval ticket ID within a scan."""
        from sqlalchemy import select
        stmt = (
            select(ScanTaskRecord)
            .where(ScanTaskRecord.scan_id == scan_id)
            .where(ScanTaskRecord.approval_ticket_id == ticket_id)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_task_approval_status(self, task_id: str, status: str) -> None:
        """Update a task's status for gate approval/rejection."""
        from sqlalchemy import update
        stmt = (
            update(ScanTaskRecord)
            .where(ScanTaskRecord.id == task_id)
            .values(status=status)
        )
        await self.session.execute(stmt)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def parse_json_list(raw: str) -> list[str]:
        """Safely parse a TEXT column that stores a JSON array of strings."""
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []
