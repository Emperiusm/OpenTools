"""Async SQLModel engine and session factory."""

from collections.abc import AsyncGenerator
from datetime import datetime, timezone

from sqlalchemy import event
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


def stamp_naive_datetimes_utc(
    conn, cursor, statement, parameters, context, executemany
):
    """Promote tz-naive datetime bind params to UTC-aware.

    SQLModel fields typed ``datetime`` without an explicit ``sa_column``
    override infer ``DateTime()`` (no timezone), so SQLAlchemy's bind
    converter strips tz from tz-aware values before handing them to
    asyncpg. When the underlying Postgres column is ``TIMESTAMPTZ``
    (which every Alembic migration in this project declares via
    ``sa.DateTime(timezone=True)``), asyncpg raises
    ``DataError: can't subtract offset-naive and offset-aware datetimes``.
    Rather than annotating ~22 datetime fields across the SQLModel tables
    with ``sa_column_kwargs``, this listener upgrades any naive datetime
    to UTC-aware right before the DBAPI sees it. Idempotent on already
    tz-aware values and a no-op on SQLite (which stores both variants
    as ISO strings).

    Registered with ``retval=True`` so SQLAlchemy picks up the modified
    parameters even when they arrive as immutable tuples (the asyncpg
    dialect uses positional tuple parameters by default).
    """

    def _fix(value):
        if isinstance(value, datetime) and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    def _fix_row(row):
        if isinstance(row, dict):
            return {k: _fix(v) for k, v in row.items()}
        if isinstance(row, tuple):
            return tuple(_fix(v) for v in row)
        if isinstance(row, list):
            return [_fix(v) for v in row]
        return row

    if parameters is None:
        return statement, parameters

    if executemany and isinstance(parameters, list):
        new_params = [_fix_row(r) for r in parameters]
        return statement, new_params

    return statement, _fix_row(parameters)


# AsyncEngine exposes the underlying sync_engine for Core event hooks.
# retval=True lets us return modified (statement, parameters) tuples
# for immutable param containers (asyncpg uses positional tuples).
event.listen(
    engine.sync_engine,
    "before_cursor_execute",
    stamp_naive_datetimes_utc,
    retval=True,
)


async_session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session
