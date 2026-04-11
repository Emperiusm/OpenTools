from datetime import datetime, timezone

import pytest
import pytest_asyncio

from opentools.engagement.store import EngagementStore
from opentools.models import (
    Engagement,
    EngagementStatus,
    EngagementType,
)


@pytest_asyncio.fixture
async def engagement_store_and_chain(tmp_path):
    """Yield ``(EngagementStore, AsyncChainStore, now)`` sharing one DB file.

    The sync ``EngagementStore`` holds a sqlite3 connection and applies
    migrations v1-v4 on construction. The async ``AsyncChainStore``
    opens its own aiosqlite connection to the same file in WAL mode and
    verifies schema via ``migrate_async`` on ``initialize()`` — the
    second migration run is a no-op because ``user_version`` is already
    at 4.

    Tests that need both a real Finding row (inserted via the sync
    store) and async protocol calls use this fixture.
    """
    from opentools.chain.stores.sqlite_async import AsyncChainStore

    db_path = tmp_path / "async_combined.db"
    engagement_store = EngagementStore(db_path=db_path)
    now = datetime.now(timezone.utc)
    engagement_store.create(
        Engagement(
            id="eng_test",
            name="test",
            target="example.com",
            type=EngagementType.PENTEST,
            status=EngagementStatus.ACTIVE,
            created_at=now,
            updated_at=now,
        )
    )

    chain_store = AsyncChainStore(db_path=db_path)
    await chain_store.initialize()
    try:
        yield engagement_store, chain_store, now
    finally:
        await chain_store.close()
        engagement_store._conn.close()


@pytest.fixture(autouse=True)
def _reset_entity_type_registry():
    """Protect test isolation: tests that register custom entity types
    don't persist those registrations into later tests. Built-in types
    are re-registered via module re-import if they were cleared.
    """
    from opentools.chain.types import ENTITY_TYPE_REGISTRY
    snapshot = dict(ENTITY_TYPE_REGISTRY)
    yield
    ENTITY_TYPE_REGISTRY.clear()
    ENTITY_TYPE_REGISTRY.update(snapshot)
