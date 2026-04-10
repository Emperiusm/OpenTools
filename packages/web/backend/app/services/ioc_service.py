"""IOC business logic."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import IOC, User


class IOCService:
    def __init__(self, session: AsyncSession, user: User):
        self.session = session
        self.user = user

    async def list(self, engagement_id: str) -> list[IOC]:
        stmt = (
            select(IOC)
            .where(IOC.engagement_id == engagement_id, IOC.user_id == self.user.id)
            .order_by(IOC.last_seen.desc().nullslast())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create(
        self,
        engagement_id: str,
        ioc_type: str,
        value: str,
        context: Optional[str] = None,
    ) -> IOC:
        now = datetime.now(timezone.utc)

        # Upsert: check if this IOC value already exists in the engagement
        stmt = select(IOC).where(
            IOC.engagement_id == engagement_id,
            IOC.user_id == self.user.id,
            IOC.ioc_type == ioc_type,
            IOC.value == value,
        )
        result = await self.session.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            existing.last_seen = now
            if context:
                existing.context = context
            self.session.add(existing)
            await self.session.commit()
            await self.session.refresh(existing)
            return existing

        ioc = IOC(
            id=str(uuid.uuid4()),
            user_id=self.user.id,
            engagement_id=engagement_id,
            ioc_type=ioc_type,
            value=value,
            context=context,
            first_seen=now,
            last_seen=now,
        )
        self.session.add(ioc)
        await self.session.commit()
        await self.session.refresh(ioc)
        return ioc

    async def search(self, query: str) -> list[IOC]:
        stmt = (
            select(IOC)
            .where(
                IOC.user_id == self.user.id,
                IOC.value.contains(query),
            )
            .order_by(IOC.last_seen.desc().nullslast())
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
