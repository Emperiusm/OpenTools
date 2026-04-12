"""Async correlation and trending service for web backend."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlmodel import select, func, and_
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import IOC, Engagement, IOCEnrichment, User
from opentools.models import (
    CorrelationResult, TrendingIOC, EnrichmentResult, IOCEnrichmentRecord,
)


class CorrelationService:
    """Async correlation + trending service, user-scoped."""

    def __init__(self, session: AsyncSession, user: User):
        self.session = session
        self.user = user

    async def correlate(self, ioc_value: str) -> CorrelationResult:
        """Find all engagements containing this IOC value."""
        stmt = select(IOC).where(
            IOC.value == ioc_value,
            IOC.user_id == self.user.id,
        ).order_by(IOC.first_seen)
        result = await self.session.execute(stmt)
        rows = result.scalars().all()

        if not rows:
            return CorrelationResult(ioc_type="unknown", ioc_value=ioc_value)

        engagements = []
        eng_ids_seen = set()
        first_seen_global = None
        last_seen_global = None
        ioc_type = rows[0].ioc_type

        for row in rows:
            if row.engagement_id in eng_ids_seen:
                continue
            eng_ids_seen.add(row.engagement_id)
            eng_stmt = select(Engagement).where(Engagement.id == row.engagement_id)
            eng_result = await self.session.execute(eng_stmt)
            eng = eng_result.scalar_one_or_none()
            if not eng:
                continue
            engagements.append({
                "id": eng.id,
                "name": eng.name,
                "first_seen": row.first_seen.isoformat() if row.first_seen else None,
                "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            })
            if row.first_seen:
                if not first_seen_global or row.first_seen < first_seen_global:
                    first_seen_global = row.first_seen
            effective_last = row.last_seen or row.first_seen
            if effective_last:
                if not last_seen_global or effective_last > last_seen_global:
                    last_seen_global = effective_last

        active_days = 0
        if first_seen_global and last_seen_global:
            active_days = (last_seen_global - first_seen_global).days

        return CorrelationResult(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            engagements=engagements,
            engagement_count=len(engagements),
            total_occurrences=len(rows),
            first_seen_global=first_seen_global,
            last_seen_global=last_seen_global,
            active_days=active_days,
        )

    async def correlate_engagement(self, engagement_id: str) -> list[CorrelationResult]:
        """For each IOC in an engagement, find cross-engagement overlaps."""
        stmt = select(IOC).where(
            IOC.engagement_id == engagement_id,
            IOC.user_id == self.user.id,
        )
        result = await self.session.execute(stmt)
        iocs = result.scalars().all()

        results = []
        for ioc in iocs:
            correlation = await self.correlate(ioc.value)
            if correlation.engagement_count > 1:
                results.append(correlation)
        return results

    async def hot_iocs(self, limit: int = 10, days: int = 30) -> list[TrendingIOC]:
        """Top N most-seen IOCs in the last N days."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        stmt = select(
            IOC.ioc_type,
            IOC.value,
            func.count(func.distinct(IOC.engagement_id)).label("eng_count"),
            func.count(IOC.id).label("total"),
        ).where(
            IOC.user_id == self.user.id,
        ).group_by(IOC.ioc_type, IOC.value).order_by(
            func.count(func.distinct(IOC.engagement_id)).desc(),
            func.count(IOC.id).desc(),
        ).limit(limit)

        result = await self.session.execute(stmt)
        rows = result.all()

        results = []
        for row in rows:
            freq = await self.frequency(row.ioc_type, row.value)
            from opentools.correlation.trending import TrendingEngine
            trend = TrendingEngine.classify_trend(freq)
            results.append(TrendingIOC(
                ioc_type=row.ioc_type,
                ioc_value=row.value,
                engagement_count=row.eng_count,
                total_occurrences=row.total,
                frequency_by_month=freq,
                trend=trend,
            ))
        return results

    async def frequency(self, ioc_type: str, ioc_value: str, months: int = 6) -> dict[str, int]:
        """Monthly frequency for an IOC."""
        stmt = select(IOC.first_seen).where(
            IOC.ioc_type == ioc_type,
            IOC.value == ioc_value,
            IOC.user_id == self.user.id,
        ).order_by(IOC.first_seen)
        result = await self.session.execute(stmt)
        rows = result.scalars().all()

        freq: dict[str, int] = {}
        for first_seen in rows:
            if first_seen:
                month = first_seen.isoformat()[:7]
                freq[month] = freq.get(month, 0) + 1
        return freq

    async def lifecycle(self, ioc_type: str, ioc_value: str) -> dict:
        """Lifecycle info for an IOC."""
        stmt = select(IOC).where(
            IOC.ioc_type == ioc_type,
            IOC.value == ioc_value,
            IOC.user_id == self.user.id,
        )
        result = await self.session.execute(stmt)
        rows = result.scalars().all()

        if not rows:
            return {"first_seen": None, "last_seen": None, "active_days": 0, "engagements": []}

        first = None
        last = None
        engagements = []
        for ioc in rows:
            if ioc.first_seen and (first is None or ioc.first_seen < first):
                first = ioc.first_seen
            effective_last = ioc.last_seen or ioc.first_seen
            if effective_last and (last is None or effective_last > last):
                last = effective_last
            engagements.append({
                "engagement_id": ioc.engagement_id,
                "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
            })

        return {
            "first_seen": first.isoformat() if first else None,
            "last_seen": last.isoformat() if last else None,
            "active_days": (last - first).days if first and last else 0,
            "engagements": engagements,
        }
