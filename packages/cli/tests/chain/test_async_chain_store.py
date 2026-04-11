"""Unit tests for AsyncChainStore (aiosqlite backend)."""
import pytest

from opentools.chain.stores._common import StoreNotInitialized
from opentools.chain.stores.sqlite_async import AsyncChainStore


@pytest.mark.asyncio
async def test_construction_requires_db_path_or_conn():
    with pytest.raises(ValueError, match="Provide either"):
        AsyncChainStore()


@pytest.mark.asyncio
async def test_construction_rejects_both_db_path_and_conn(tmp_path):
    import aiosqlite
    conn = await aiosqlite.connect(":memory:")
    try:
        with pytest.raises(ValueError, match="not both"):
            AsyncChainStore(db_path=tmp_path / "x.db", conn=conn)
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_initialize_opens_connection_and_runs_migrations(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    await store.initialize()
    try:
        # Smoke check: a simple SQL query through the internal conn works
        async with store._conn.execute("SELECT 1") as cursor:
            row = await cursor.fetchone()
        assert row[0] == 1
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_initialize_is_idempotent(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    await store.initialize()
    await store.initialize()  # second call must not raise
    await store.close()


@pytest.mark.asyncio
async def test_method_raises_before_initialize(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    with pytest.raises(StoreNotInitialized, match="get_entity"):
        await store.get_entity("eid", user_id=None)


@pytest.mark.asyncio
async def test_method_raises_after_close(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    await store.initialize()
    await store.close()
    with pytest.raises(StoreNotInitialized, match="get_entity"):
        await store.get_entity("eid", user_id=None)


@pytest.mark.asyncio
async def test_transaction_context_commits_on_success(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    await store.initialize()
    try:
        async with store.transaction():
            await store._conn.execute(
                "CREATE TABLE IF NOT EXISTS _test_txn (x INTEGER)"
            )
            await store._conn.execute("INSERT INTO _test_txn VALUES (42)")
        # Outside the transaction, row should be committed
        async with store._conn.execute("SELECT x FROM _test_txn") as cur:
            row = await cur.fetchone()
        assert row[0] == 42
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_transaction_rolls_back_on_exception(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    await store.initialize()
    try:
        await store._conn.execute(
            "CREATE TABLE IF NOT EXISTS _test_roll (x INTEGER)"
        )
        await store._conn.commit()

        with pytest.raises(RuntimeError, match="boom"):
            async with store.transaction():
                await store._conn.execute("INSERT INTO _test_roll VALUES (1)")
                raise RuntimeError("boom")

        async with store._conn.execute(
            "SELECT COUNT(*) FROM _test_roll"
        ) as cur:
            row = await cur.fetchone()
        assert row[0] == 0
    finally:
        await store.close()
