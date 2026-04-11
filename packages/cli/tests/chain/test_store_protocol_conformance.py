"""Shared ChainStoreProtocol conformance tests.

Every protocol method is exercised via a parameterized fixture so that
AsyncChainStore (aiosqlite) and later PostgresChainStore (SQLAlchemy)
are verified to behave identically.

In Phase 1, only the SQLite parameter is active. Phase 5 (Task 42)
adds the Postgres parameter.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import pytest_asyncio

from opentools.chain.models import (
    Entity,
    EntityMention,
    FindingRelation,
    RelationReason,
    entity_id_for,
)
from opentools.chain.stores._common import (
    ScopingViolation,
    StoreNotInitialized,
)
from opentools.chain.types import (
    LinkerMode,
    LinkerScope,
    MentionField,
    RelationStatus,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


@pytest_asyncio.fixture(params=["sqlite_async"])
async def conformant_store(request, tmp_path):
    """Yield (store, user_id) for the parameterized backend."""
    if request.param == "sqlite_async":
        from opentools.chain.stores.sqlite_async import AsyncChainStore
        store = AsyncChainStore(db_path=tmp_path / f"{request.param}.db")
        await store.initialize()
        try:
            yield store, None
        finally:
            await store.close()
    else:
        pytest.skip(f"backend {request.param} not available in this phase")


# --- Lifecycle ---


@pytest.mark.asyncio
async def test_method_raises_before_initialize(tmp_path):
    from opentools.chain.stores.sqlite_async import AsyncChainStore
    store = AsyncChainStore(db_path=tmp_path / "no_init.db")
    with pytest.raises(StoreNotInitialized):
        await store.get_entity("eid", user_id=None)


@pytest.mark.asyncio
async def test_transaction_commit_on_success(conformant_store):
    store, user_id = conformant_store
    entity_id = entity_id_for("host", "10.0.0.5")
    async with store.transaction():
        await store.upsert_entity(
            Entity(
                id=entity_id, type="host", canonical_value="10.0.0.5",
                first_seen_at=_now(), last_seen_at=_now(),
                mention_count=0,
            ),
            user_id=user_id,
        )
    result = await store.get_entity(entity_id, user_id=user_id)
    assert result is not None
    assert result.canonical_value == "10.0.0.5"


@pytest.mark.asyncio
async def test_transaction_rollback_on_exception(conformant_store):
    store, user_id = conformant_store
    entity_id = entity_id_for("host", "1.2.3.4")
    with pytest.raises(RuntimeError, match="boom"):
        async with store.transaction():
            await store.upsert_entity(
                Entity(
                    id=entity_id, type="host", canonical_value="1.2.3.4",
                    first_seen_at=_now(), last_seen_at=_now(),
                    mention_count=0,
                ),
                user_id=user_id,
            )
            raise RuntimeError("boom")
    result = await store.get_entity(entity_id, user_id=user_id)
    assert result is None  # rolled back


@pytest.mark.asyncio
async def test_transaction_read_your_writes(conformant_store):
    """A write inside a transaction must be visible to a read in the
    same transaction (spec A10)."""
    store, user_id = conformant_store
    entity_id = entity_id_for("host", "5.6.7.8")
    async with store.transaction():
        await store.upsert_entity(
            Entity(
                id=entity_id, type="host", canonical_value="5.6.7.8",
                first_seen_at=_now(), last_seen_at=_now(),
                mention_count=0,
            ),
            user_id=user_id,
        )
        result = await store.get_entity(entity_id, user_id=user_id)
        assert result is not None
    result = await store.get_entity(entity_id, user_id=user_id)
    assert result is not None


# --- Entity CRUD ---


@pytest.mark.asyncio
async def test_upsert_entity_and_get(conformant_store):
    store, user_id = conformant_store
    e = Entity(
        id=entity_id_for("host", "10.0.0.5"),
        type="host", canonical_value="10.0.0.5",
        first_seen_at=_now(), last_seen_at=_now(),
        mention_count=1,
    )
    await store.upsert_entity(e, user_id=user_id)
    result = await store.get_entity(e.id, user_id=user_id)
    assert result is not None
    assert result.type == "host"


@pytest.mark.asyncio
async def test_list_entities_with_type_filter(conformant_store):
    store, user_id = conformant_store
    for t, v in [("host", "1.1.1.1"), ("host", "2.2.2.2"), ("cve", "CVE-2024-1")]:
        await store.upsert_entity(
            Entity(
                id=entity_id_for(t, v), type=t, canonical_value=v,
                first_seen_at=_now(), last_seen_at=_now(),
                mention_count=1,
            ),
            user_id=user_id,
        )
    hosts = await store.list_entities(user_id=user_id, entity_type="host")
    assert len(hosts) == 2
    cves = await store.list_entities(user_id=user_id, entity_type="cve")
    assert len(cves) == 1


@pytest.mark.asyncio
async def test_upsert_entities_bulk_round_trip(conformant_store):
    store, user_id = conformant_store
    entities = [
        Entity(
            id=entity_id_for("user", f"u{i}"),
            type="user",
            canonical_value=f"u{i}",
            first_seen_at=_now(),
            last_seen_at=_now(),
            mention_count=0,
        )
        for i in range(3)
    ]
    await store.upsert_entities_bulk(entities, user_id=user_id)
    fetched = await store.get_entities_by_ids(
        [e.id for e in entities], user_id=user_id
    )
    # get_entities_by_ids returns dict[str, Entity]
    assert len(fetched) == 3
    for e in entities:
        assert e.id in fetched


@pytest.mark.asyncio
async def test_delete_entity(conformant_store):
    store, user_id = conformant_store
    entity_id = entity_id_for("host", "del-me")
    await store.upsert_entity(
        Entity(
            id=entity_id, type="host", canonical_value="del-me",
            first_seen_at=_now(), last_seen_at=_now(),
            mention_count=0,
        ),
        user_id=user_id,
    )
    await store.delete_entity(entity_id, user_id=user_id)
    assert await store.get_entity(entity_id, user_id=user_id) is None


# --- LinkerRun lifecycle ---


@pytest.mark.asyncio
async def test_start_and_finish_linker_run(conformant_store):
    store, user_id = conformant_store
    run = await store.start_linker_run(
        scope=LinkerScope.ENGAGEMENT,
        scope_id="eng_1",
        mode=LinkerMode.RULES_ONLY,
        user_id=user_id,
    )
    assert run.generation >= 1
    await store.finish_linker_run(
        run.id,
        findings_processed=5,
        entities_extracted=12,
        relations_created=3,
        relations_updated=1,
        relations_skipped_sticky=0,
        rule_stats={"shared_strong": 2},
        duration_ms=150,
        error=None,
        user_id=user_id,
    )
    runs = await store.fetch_linker_runs(user_id=user_id, limit=5)
    assert any(r.id == run.id for r in runs)


@pytest.mark.asyncio
async def test_current_linker_generation_monotone(conformant_store):
    store, user_id = conformant_store
    start_gen = await store.current_linker_generation(user_id=user_id)
    await store.start_linker_run(
        scope=LinkerScope.ENGAGEMENT,
        scope_id="eng_a",
        mode=LinkerMode.RULES_ONLY,
        user_id=user_id,
    )
    new_gen = await store.current_linker_generation(user_id=user_id)
    assert new_gen >= start_gen + 1


# --- Extraction state ---


@pytest.mark.asyncio
async def test_upsert_and_get_extraction_hash(conformant_store):
    store, user_id = conformant_store
    # Seed a finding row so the FK holds
    await store._conn.execute(
        "INSERT OR IGNORE INTO engagements (id, name, target, type, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("eng_conf", "c", "t", "assess", _now().isoformat(), _now().isoformat()),
    )
    await store._conn.execute(
        "INSERT OR IGNORE INTO findings (id, engagement_id, tool, severity, title, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        ("fnd_conf", "eng_conf", "test", "high", "t", _now().isoformat()),
    )
    await store._conn.commit()

    await store.upsert_extraction_state(
        finding_id="fnd_conf",
        extraction_input_hash="abc123",
        extractor_set=["ioc", "cve"],
        user_id=user_id,
    )
    got = await store.get_extraction_hash("fnd_conf", user_id=user_id)
    assert got == "abc123"


# --- LLM caches ---


@pytest.mark.asyncio
async def test_put_and_get_extraction_cache(conformant_store):
    store, user_id = conformant_store
    await store.put_extraction_cache(
        cache_key="ckey_a",
        provider="ollama",
        model="llama3.1",
        schema_version=1,
        result_json=b"{}",
        user_id=user_id,
    )
    got = await store.get_extraction_cache("ckey_a", user_id=user_id)
    assert got == b"{}"


@pytest.mark.asyncio
async def test_put_and_get_llm_link_cache(conformant_store):
    store, user_id = conformant_store
    await store.put_llm_link_cache(
        cache_key="lkey_a",
        provider="ollama",
        model="llama3.1",
        schema_version=1,
        classification_json=b"[]",
        user_id=user_id,
    )
    got = await store.get_llm_link_cache("lkey_a", user_id=user_id)
    assert got == b"[]"


# --- Findings / count ---


@pytest.mark.asyncio
async def test_count_findings_in_scope_zero_when_empty(conformant_store):
    store, user_id = conformant_store
    count = await store.count_findings_in_scope(user_id=user_id)
    assert count == 0


@pytest.mark.asyncio
async def test_compute_avg_idf_empty_returns_one(conformant_store):
    store, user_id = conformant_store
    val = await store.compute_avg_idf(scope_total=0, user_id=user_id)
    assert val == 1.0
