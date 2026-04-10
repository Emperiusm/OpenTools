"""Async SQLModel engine and session factory."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=(settings.log_level == "debug"),
    pool_size=15,
    max_overflow=25,
    pool_timeout=30,
    pool_recycle=1800,
)

async_session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session
