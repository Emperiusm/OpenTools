import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytest_asyncio

from opentools.chain.store_extensions import ChainStore
from opentools.engagement.schema import migrate
from opentools.engagement.store import EngagementStore
from opentools.models import (
    Engagement,
    EngagementStatus,
    EngagementType,
    Finding,
    FindingStatus,
    Severity,
)


@pytest.fixture
def chain_store(tmp_path):
    """Yield a ChainStore backed by a fresh SQLite database with all migrations applied."""
    db_path = tmp_path / "test_chain.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    migrate(conn)
    store = ChainStore(conn)
    yield store
    conn.close()


@pytest.fixture
def engagement_store_and_chain(tmp_path):
    """Yield both EngagementStore and ChainStore sharing the same SQLite connection.

    Useful for tests that need to insert real findings and then reference them
    from chain tables via foreign keys.
    """
    db_path = tmp_path / "test_combined.db"
    engagement_store = EngagementStore(db_path=db_path)
    chain_store = ChainStore(engagement_store._conn)
    # Create a baseline engagement and finding for tests that need them
    now = datetime.now(timezone.utc)
    engagement = Engagement(
        id="eng_test",
        name="test",
        target="example.com",
        type=EngagementType.PENTEST,
        status=EngagementStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )
    engagement_store.create(engagement)
    yield engagement_store, chain_store, now


@pytest_asyncio.fixture
async def async_chain_stores(tmp_path):
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
