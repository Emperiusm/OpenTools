"""Finding business logic."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Finding, TimelineEvent, User


class FindingService:
    def __init__(self, session: AsyncSession, user: User):
        self.session = session
        self.user = user

    async def list(
        self,
        engagement_id: str,
        cursor: Optional[str] = None,
        limit: int = 50,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        phase: Optional[str] = None,
    ) -> tuple[list[Finding], Optional[str]]:
        stmt = (
            select(Finding)
            .where(
                Finding.engagement_id == engagement_id,
                Finding.user_id == self.user.id,
                Finding.deleted_at.is_(None),
            )
            .order_by(Finding.created_at.desc())
            .limit(limit + 1)
        )
        if cursor:
            stmt = stmt.where(Finding.created_at < cursor)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if status:
            stmt = stmt.where(Finding.status == status)
        if phase:
            stmt = stmt.where(Finding.phase == phase)

        result = await self.session.execute(stmt)
        rows = list(result.scalars().all())

        next_cursor: Optional[str] = None
        if len(rows) > limit:
            rows = rows[:limit]
            next_cursor = rows[-1].created_at.isoformat()

        return rows, next_cursor

    async def create(
        self,
        engagement_id: str,
        tool: str,
        title: str,
        severity: str,
        cwe: Optional[str] = None,
        file_path: Optional[str] = None,
        line_start: Optional[int] = None,
        description: Optional[str] = None,
        evidence: Optional[str] = None,
    ) -> Finding:
        now = datetime.now(timezone.utc)
        finding_id = str(uuid.uuid4())
        finding = Finding(
            id=finding_id,
            user_id=self.user.id,
            engagement_id=engagement_id,
            tool=tool,
            title=title,
            severity=severity,
            cwe=cwe,
            file_path=file_path,
            line_start=line_start,
            description=description,
            evidence=evidence,
            status="discovered",
            false_positive=False,
            created_at=now,
        )
        self.session.add(finding)

        # Auto-create timeline event
        timeline_event = TimelineEvent(
            id=str(uuid.uuid4()),
            user_id=self.user.id,
            engagement_id=engagement_id,
            timestamp=now,
            source=tool,
            event=f"Finding discovered: {title}",
            details=f"Severity: {severity}",
            confidence="high",
            finding_id=finding_id,
        )
        self.session.add(timeline_event)

        await self.session.commit()
        await self.session.refresh(finding)
        return finding

    async def get(self, id: str) -> Optional[Finding]:
        stmt = select(Finding).where(
            Finding.id == id,
            Finding.user_id == self.user.id,
            Finding.deleted_at.is_(None),
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_status(self, id: str, status: str) -> Optional[Finding]:
        finding = await self.get(id)
        if not finding:
            return None
        finding.status = status
        self.session.add(finding)
        await self.session.commit()
        await self.session.refresh(finding)
        return finding

    async def flag_false_positive(self, id: str) -> Optional[Finding]:
        finding = await self.get(id)
        if not finding:
            return None
        finding.false_positive = not finding.false_positive
        self.session.add(finding)
        await self.session.commit()
        await self.session.refresh(finding)
        return finding

    async def search(self, query: str, limit: int = 50) -> list[Finding]:
        result = await self.session.execute(
            text(
                "SELECT * FROM finding "
                "WHERE user_id = :uid "
                "AND deleted_at IS NULL "
                "AND search_vector @@ plainto_tsquery('english', :q) "
                "ORDER BY ts_rank(search_vector, plainto_tsquery('english', :q)) DESC "
                "LIMIT :lim"
            ),
            {"uid": str(self.user.id), "q": query, "lim": limit},
        )
        rows = result.mappings().all()
        return [Finding(**row) for row in rows]

    async def bulk_flag_fp(self, finding_ids: list[str]) -> int:
        stmt = (
            update(Finding)
            .where(
                Finding.id.in_(finding_ids),
                Finding.user_id == self.user.id,
                Finding.deleted_at.is_(None),
            )
            .values(false_positive=True)
        )
        result = await self.session.execute(stmt)
        await self.session.commit()
        return result.rowcount  # type: ignore[return-value]

    async def bulk_update_status(self, finding_ids: list[str], status: str) -> int:
        stmt = (
            update(Finding)
            .where(
                Finding.id.in_(finding_ids),
                Finding.user_id == self.user.id,
                Finding.deleted_at.is_(None),
            )
            .values(status=status)
        )
        result = await self.session.execute(stmt)
        await self.session.commit()
        return result.rowcount  # type: ignore[return-value]
