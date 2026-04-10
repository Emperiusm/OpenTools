"""Engagement business logic."""

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Artifact,
    AuditEntry,
    Engagement,
    Finding,
    IOC,
    TimelineEvent,
    User,
)


class EngagementService:
    def __init__(self, session: AsyncSession, user: User):
        self.session = session
        self.user = user

    async def list(
        self, cursor: Optional[str] = None, limit: int = 50
    ) -> tuple[list[Engagement], Optional[str]]:
        stmt = (
            select(Engagement)
            .where(Engagement.user_id == self.user.id)
            .order_by(Engagement.created_at.desc())
            .limit(limit + 1)
        )
        if cursor:
            # cursor is the created_at ISO timestamp of the last item seen
            stmt = stmt.where(Engagement.created_at < cursor)

        result = await self.session.execute(stmt)
        rows = list(result.scalars().all())

        next_cursor: Optional[str] = None
        if len(rows) > limit:
            rows = rows[:limit]
            next_cursor = rows[-1].created_at.isoformat()

        return rows, next_cursor

    async def create(
        self, name: str, target: str, type: str, scope: Optional[str] = None
    ) -> Engagement:
        now = datetime.now(timezone.utc)
        engagement = Engagement(
            id=str(uuid.uuid4()),
            user_id=self.user.id,
            name=name,
            target=target,
            type=type,
            scope=scope,
            status="active",
            created_at=now,
            updated_at=now,
        )
        self.session.add(engagement)
        await self.session.commit()
        await self.session.refresh(engagement)
        return engagement

    async def get(self, id: str) -> Optional[Engagement]:
        stmt = select(Engagement).where(
            Engagement.id == id, Engagement.user_id == self.user.id
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def update(self, id: str, **kwargs: Any) -> Optional[Engagement]:
        engagement = await self.get(id)
        if not engagement:
            return None
        for key, value in kwargs.items():
            if hasattr(engagement, key) and value is not None:
                setattr(engagement, key, value)
        engagement.updated_at = datetime.now(timezone.utc)
        self.session.add(engagement)
        await self.session.commit()
        await self.session.refresh(engagement)
        return engagement

    async def delete(self, id: str) -> bool:
        engagement = await self.get(id)
        if not engagement:
            return False

        # Cascade delete in dependency order
        for model in (AuditEntry, Artifact, IOC, TimelineEvent, Finding):
            stmt = delete(model).where(
                model.engagement_id == id, model.user_id == self.user.id
            )
            await self.session.execute(stmt)

        # AuditEntry may not have engagement_id; delete engagement-specific ones
        await self.session.execute(
            delete(AuditEntry).where(
                AuditEntry.engagement_id == id, AuditEntry.user_id == self.user.id
            )
        )

        await self.session.delete(engagement)
        await self.session.commit()
        return True

    async def get_summary(self, id: str) -> Optional[dict]:
        engagement = await self.get(id)
        if not engagement:
            return None

        # Finding counts by severity
        sev_stmt = (
            select(Finding.severity, func.count())
            .where(
                Finding.engagement_id == id,
                Finding.user_id == self.user.id,
                Finding.deleted_at.is_(None),
            )
            .group_by(Finding.severity)
        )
        sev_result = await self.session.execute(sev_stmt)
        severity_counts = {row[0]: row[1] for row in sev_result.all()}

        # Finding counts by status
        status_stmt = (
            select(Finding.status, func.count())
            .where(
                Finding.engagement_id == id,
                Finding.user_id == self.user.id,
                Finding.deleted_at.is_(None),
            )
            .group_by(Finding.status)
        )
        status_result = await self.session.execute(status_stmt)
        status_counts = {row[0]: row[1] for row in status_result.all()}

        # IOC count
        ioc_stmt = select(func.count()).where(
            IOC.engagement_id == id, IOC.user_id == self.user.id
        )
        ioc_result = await self.session.execute(ioc_stmt)
        ioc_count = ioc_result.scalar() or 0

        # Timeline count
        tl_stmt = select(func.count()).where(
            TimelineEvent.engagement_id == id,
            TimelineEvent.user_id == self.user.id,
        )
        tl_result = await self.session.execute(tl_stmt)
        timeline_count = tl_result.scalar() or 0

        return {
            "engagement": engagement,
            "severity_counts": severity_counts,
            "status_counts": status_counts,
            "ioc_count": ioc_count,
            "timeline_count": timeline_count,
        }
