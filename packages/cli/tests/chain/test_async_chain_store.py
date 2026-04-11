"""Unit tests for AsyncChainStore (aiosqlite backend)."""
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from opentools.chain.models import (
    Entity,
    EntityMention,
    FindingRelation,
    RelationReason,
)
from opentools.chain.stores._common import StoreNotInitialized
from opentools.chain.stores.sqlite_async import AsyncChainStore
from opentools.chain.types import MentionField, RelationStatus


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


# --- Entity CRUD ---


@pytest_asyncio.fixture
async def entity_store(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    await store.initialize()
    try:
        yield store
    finally:
        await store.close()


def _make_entity(
    *,
    id: str = "ent-1",
    type: str = "host",
    canonical_value: str = "host-a",
    mention_count: int = 1,
    first_seen_at: datetime | None = None,
    last_seen_at: datetime | None = None,
) -> Entity:
    now = datetime.now(timezone.utc)
    return Entity(
        id=id,
        type=type,
        canonical_value=canonical_value,
        first_seen_at=first_seen_at or now,
        last_seen_at=last_seen_at or now,
        mention_count=mention_count,
        user_id=None,
    )


@pytest.mark.asyncio
async def test_upsert_entity_inserts_new(entity_store):
    ent = _make_entity(id="e1", type="host", canonical_value="h1", mention_count=3)
    await entity_store.upsert_entity(ent, user_id=None)

    fetched = await entity_store.get_entity("e1", user_id=None)
    assert fetched is not None
    assert fetched.id == "e1"
    assert fetched.type == "host"
    assert fetched.canonical_value == "h1"
    assert fetched.mention_count == 3


@pytest.mark.asyncio
async def test_upsert_entity_updates_on_conflict(entity_store):
    first_seen = datetime.now(timezone.utc) - timedelta(days=2)
    later_seen = datetime.now(timezone.utc)
    initial = _make_entity(
        id="e2",
        canonical_value="h2",
        mention_count=1,
        first_seen_at=first_seen,
        last_seen_at=first_seen,
    )
    await entity_store.upsert_entity(initial, user_id=None)

    updated = _make_entity(
        id="e2",
        canonical_value="h2",
        mention_count=7,
        first_seen_at=later_seen,  # should be ignored on conflict
        last_seen_at=later_seen,
    )
    await entity_store.upsert_entity(updated, user_id=None)

    fetched = await entity_store.get_entity("e2", user_id=None)
    assert fetched is not None
    assert fetched.mention_count == 7
    # first_seen_at preserved from the original insert
    assert fetched.first_seen_at == first_seen
    assert fetched.last_seen_at == later_seen


@pytest.mark.asyncio
async def test_get_entity_returns_none_when_missing(entity_store):
    assert await entity_store.get_entity("nope", user_id=None) is None


@pytest.mark.asyncio
async def test_upsert_entities_bulk_empty_iterable(entity_store):
    # Should not raise and should not insert anything
    await entity_store.upsert_entities_bulk([], user_id=None)
    rows = await entity_store.list_entities(user_id=None)
    assert rows == []


@pytest.mark.asyncio
async def test_upsert_entities_bulk_inserts_many(entity_store):
    entities = [
        _make_entity(id=f"b{i}", canonical_value=f"v{i}", mention_count=i)
        for i in range(1, 4)
    ]
    await entity_store.upsert_entities_bulk(entities, user_id=None)

    got = await entity_store.get_entities_by_ids(
        ["b1", "b2", "b3"], user_id=None
    )
    assert set(got.keys()) == {"b1", "b2", "b3"}
    assert got["b2"].mention_count == 2


@pytest.mark.asyncio
async def test_get_entities_by_ids_empty_input_returns_empty_dict(entity_store):
    result = await entity_store.get_entities_by_ids([], user_id=None)
    assert result == {}


@pytest.mark.asyncio
async def test_get_entities_by_ids_skips_missing(entity_store):
    await entity_store.upsert_entity(
        _make_entity(id="real", canonical_value="real-v"), user_id=None
    )
    got = await entity_store.get_entities_by_ids(
        ["real", "ghost"], user_id=None
    )
    assert set(got.keys()) == {"real"}


@pytest.mark.asyncio
async def test_list_entities_default_returns_all(entity_store):
    for i in range(3):
        await entity_store.upsert_entity(
            _make_entity(id=f"l{i}", canonical_value=f"v{i}"), user_id=None
        )
    rows = await entity_store.list_entities(user_id=None)
    assert len(rows) == 3


@pytest.mark.asyncio
async def test_list_entities_filters_by_type(entity_store):
    await entity_store.upsert_entity(
        _make_entity(id="h1", type="host", canonical_value="host-a"),
        user_id=None,
    )
    await entity_store.upsert_entity(
        _make_entity(id="c1", type="cve", canonical_value="CVE-1"),
        user_id=None,
    )
    rows = await entity_store.list_entities(user_id=None, entity_type="host")
    assert len(rows) == 1
    assert rows[0].id == "h1"


@pytest.mark.asyncio
async def test_list_entities_applies_min_mentions(entity_store):
    await entity_store.upsert_entity(
        _make_entity(id="low", canonical_value="low-v", mention_count=1),
        user_id=None,
    )
    await entity_store.upsert_entity(
        _make_entity(id="high", canonical_value="high-v", mention_count=5),
        user_id=None,
    )
    rows = await entity_store.list_entities(user_id=None, min_mentions=3)
    assert [r.id for r in rows] == ["high"]


@pytest.mark.asyncio
async def test_list_entities_respects_limit_and_offset(entity_store):
    for i in range(5):
        await entity_store.upsert_entity(
            _make_entity(
                id=f"p{i}", canonical_value=f"v{i}", mention_count=10 - i
            ),
            user_id=None,
        )
    page1 = await entity_store.list_entities(user_id=None, limit=2, offset=0)
    page2 = await entity_store.list_entities(user_id=None, limit=2, offset=2)
    assert len(page1) == 2
    assert len(page2) == 2
    assert {e.id for e in page1}.isdisjoint({e.id for e in page2})


@pytest.mark.asyncio
async def test_list_entities_orders_by_mention_count_desc(entity_store):
    await entity_store.upsert_entity(
        _make_entity(id="a", canonical_value="a-v", mention_count=1),
        user_id=None,
    )
    await entity_store.upsert_entity(
        _make_entity(id="b", canonical_value="b-v", mention_count=9),
        user_id=None,
    )
    await entity_store.upsert_entity(
        _make_entity(id="c", canonical_value="c-v", mention_count=4),
        user_id=None,
    )
    rows = await entity_store.list_entities(user_id=None)
    assert [r.id for r in rows] == ["b", "c", "a"]


@pytest.mark.asyncio
async def test_delete_entity_removes_row(entity_store):
    await entity_store.upsert_entity(
        _make_entity(id="dead", canonical_value="dead-v"), user_id=None
    )
    assert await entity_store.get_entity("dead", user_id=None) is not None

    await entity_store.delete_entity("dead", user_id=None)
    assert await entity_store.get_entity("dead", user_id=None) is None


@pytest.mark.asyncio
async def test_delete_entity_idempotent_on_missing(entity_store):
    # Should not raise
    await entity_store.delete_entity("never-existed", user_id=None)


# --- Mention CRUD ---


async def _seed_finding(store, engagement_id="eng1", finding_id="f1"):
    now = datetime.now(timezone.utc).isoformat()
    await store._conn.execute(
        "INSERT OR IGNORE INTO engagements (id, name, target, type, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (engagement_id, "e", "t", "assess", now, now),
    )
    await store._conn.execute(
        "INSERT OR IGNORE INTO findings (id, engagement_id, tool, severity, title, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (finding_id, engagement_id, "test", "high", "t", now),
    )
    await store._conn.commit()


_mention_offset_counter = {"n": 0}


def _make_mention(
    *,
    id: str,
    entity_id: str,
    finding_id: str = "f1",
    field: MentionField = MentionField.TITLE,
    raw_value: str = "raw",
    extractor: str = "test",
    confidence: float = 0.9,
    offset_start: int | None = None,
) -> EntityMention:
    # Default to a monotonically increasing offset so the
    # (entity_id, finding_id, field, offset_start) UNIQUE constraint in
    # entity_mention doesn't collapse mentions that only differ by id.
    if offset_start is None:
        _mention_offset_counter["n"] += 1
        offset_start = _mention_offset_counter["n"]
    return EntityMention(
        id=id,
        entity_id=entity_id,
        finding_id=finding_id,
        field=field,
        raw_value=raw_value,
        offset_start=offset_start,
        offset_end=offset_start + len(raw_value),
        extractor=extractor,
        confidence=confidence,
        created_at=datetime.now(timezone.utc),
        user_id=None,
    )


@pytest_asyncio.fixture
async def mention_store(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    await store.initialize()
    try:
        yield store
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_add_mentions_bulk_empty_returns_zero(mention_store):
    n = await mention_store.add_mentions_bulk([], user_id=None)
    assert n == 0


@pytest.mark.asyncio
async def test_add_mentions_bulk_inserts_and_returns_count(mention_store):
    await _seed_finding(mention_store)
    await mention_store.upsert_entity(
        _make_entity(id="e1", canonical_value="host-a"), user_id=None
    )
    mentions = [
        _make_mention(id="m1", entity_id="e1"),
        _make_mention(id="m2", entity_id="e1", field=MentionField.DESCRIPTION),
    ]
    n = await mention_store.add_mentions_bulk(mentions, user_id=None)
    assert n == 2
    got = await mention_store.mentions_for_finding("f1", user_id=None)
    assert len(got) == 2


@pytest.mark.asyncio
async def test_mentions_for_finding_returns_all_mentions(mention_store):
    await _seed_finding(mention_store, finding_id="f1")
    await _seed_finding(mention_store, finding_id="f2")
    await mention_store.upsert_entity(
        _make_entity(id="e1", canonical_value="v1"), user_id=None
    )
    await mention_store.add_mentions_bulk(
        [
            _make_mention(id="m1", entity_id="e1", finding_id="f1"),
            _make_mention(id="m2", entity_id="e1", finding_id="f1"),
            _make_mention(id="m3", entity_id="e1", finding_id="f2"),
        ],
        user_id=None,
    )
    got = await mention_store.mentions_for_finding("f1", user_id=None)
    assert {m.id for m in got} == {"m1", "m2"}
    assert all(isinstance(m, EntityMention) for m in got)
    assert all(m.field in MentionField for m in got)


@pytest.mark.asyncio
async def test_delete_mentions_for_finding_removes_rows_and_returns_count(
    mention_store,
):
    await _seed_finding(mention_store)
    await mention_store.upsert_entity(
        _make_entity(id="e1", canonical_value="v1"), user_id=None
    )
    await mention_store.add_mentions_bulk(
        [
            _make_mention(id="m1", entity_id="e1"),
            _make_mention(id="m2", entity_id="e1"),
        ],
        user_id=None,
    )
    deleted = await mention_store.delete_mentions_for_finding(
        "f1", user_id=None
    )
    assert deleted == 2
    remaining = await mention_store.mentions_for_finding("f1", user_id=None)
    assert remaining == []


@pytest.mark.asyncio
async def test_recompute_mention_counts_updates_entity_count(mention_store):
    await _seed_finding(mention_store)
    await mention_store.upsert_entity(
        _make_entity(id="e1", canonical_value="v1", mention_count=0),
        user_id=None,
    )
    await mention_store.upsert_entity(
        _make_entity(id="e2", canonical_value="v2", mention_count=0),
        user_id=None,
    )
    await mention_store.add_mentions_bulk(
        [
            _make_mention(id="m1", entity_id="e1"),
            _make_mention(id="m2", entity_id="e1"),
            _make_mention(id="m3", entity_id="e2"),
        ],
        user_id=None,
    )

    await mention_store.recompute_mention_counts(["e1", "e2"], user_id=None)

    e1 = await mention_store.get_entity("e1", user_id=None)
    e2 = await mention_store.get_entity("e2", user_id=None)
    assert e1 is not None and e1.mention_count == 2
    assert e2 is not None and e2.mention_count == 1


@pytest.mark.asyncio
async def test_recompute_mention_counts_empty_is_no_op(mention_store):
    await mention_store.upsert_entity(
        _make_entity(id="e1", canonical_value="v1", mention_count=5),
        user_id=None,
    )
    await mention_store.recompute_mention_counts([], user_id=None)
    # Untouched
    e1 = await mention_store.get_entity("e1", user_id=None)
    assert e1 is not None and e1.mention_count == 5


@pytest.mark.asyncio
async def test_rewrite_mentions_entity_id_moves_mentions(mention_store):
    await _seed_finding(mention_store)
    await mention_store.upsert_entity(
        _make_entity(id="old", canonical_value="v-old"), user_id=None
    )
    await mention_store.upsert_entity(
        _make_entity(id="new", canonical_value="v-new"), user_id=None
    )
    await mention_store.add_mentions_bulk(
        [
            _make_mention(id="m1", entity_id="old"),
            _make_mention(id="m2", entity_id="old"),
        ],
        user_id=None,
    )
    moved = await mention_store.rewrite_mentions_entity_id(
        from_entity_id="old", to_entity_id="new", user_id=None
    )
    assert moved == 2
    got = await mention_store.mentions_for_finding("f1", user_id=None)
    assert {m.entity_id for m in got} == {"new"}


@pytest.mark.asyncio
async def test_rewrite_mentions_by_ids_moves_selected_mentions(mention_store):
    await _seed_finding(mention_store)
    await mention_store.upsert_entity(
        _make_entity(id="e1", canonical_value="v1"), user_id=None
    )
    await mention_store.upsert_entity(
        _make_entity(id="e2", canonical_value="v2"), user_id=None
    )
    await mention_store.add_mentions_bulk(
        [
            _make_mention(id="m1", entity_id="e1"),
            _make_mention(id="m2", entity_id="e1"),
            _make_mention(id="m3", entity_id="e1"),
        ],
        user_id=None,
    )
    moved = await mention_store.rewrite_mentions_by_ids(
        mention_ids=["m1", "m3"], to_entity_id="e2", user_id=None
    )
    assert moved == 2
    got = {m.id: m.entity_id for m in await mention_store.mentions_for_finding("f1", user_id=None)}
    assert got == {"m1": "e2", "m2": "e1", "m3": "e2"}


@pytest.mark.asyncio
async def test_rewrite_mentions_by_ids_empty_returns_zero(mention_store):
    n = await mention_store.rewrite_mentions_by_ids(
        mention_ids=[], to_entity_id="anything", user_id=None
    )
    assert n == 0


@pytest.mark.asyncio
async def test_fetch_mentions_with_engagement_returns_mention_engagement_pairs(
    mention_store,
):
    await _seed_finding(
        mention_store, engagement_id="engA", finding_id="fA"
    )
    await _seed_finding(
        mention_store, engagement_id="engB", finding_id="fB"
    )
    await mention_store.upsert_entity(
        _make_entity(id="e1", canonical_value="v1"), user_id=None
    )
    await mention_store.add_mentions_bulk(
        [
            _make_mention(id="m1", entity_id="e1", finding_id="fA"),
            _make_mention(id="m2", entity_id="e1", finding_id="fB"),
        ],
        user_id=None,
    )
    pairs = await mention_store.fetch_mentions_with_engagement(
        "e1", user_id=None
    )
    assert set(pairs) == {("m1", "engA"), ("m2", "engB")}


# --- Relation CRUD ---


@pytest_asyncio.fixture
async def relation_store(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    await store.initialize()
    try:
        yield store
    finally:
        await store.close()


def _make_relation(
    *,
    id: str,
    source_finding_id: str,
    target_finding_id: str,
    weight: float = 0.75,
    status: RelationStatus = RelationStatus.CANDIDATE,
    symmetric: bool = False,
    llm_rationale: str | None = None,
    llm_relation_type: str | None = None,
    llm_confidence: float | None = None,
) -> FindingRelation:
    now = datetime.now(timezone.utc)
    return FindingRelation(
        id=id,
        source_finding_id=source_finding_id,
        target_finding_id=target_finding_id,
        weight=weight,
        weight_model_version="additive_v1",
        status=status,
        symmetric=symmetric,
        reasons=[
            RelationReason(
                rule="shared_host",
                weight_contribution=weight,
                idf_factor=None,
                details={},
            )
        ],
        llm_rationale=llm_rationale,
        llm_relation_type=llm_relation_type,
        llm_confidence=llm_confidence,
        confirmed_at_reasons=None,
        created_at=now,
        updated_at=now,
        user_id=None,
    )


@pytest.mark.asyncio
async def test_upsert_relations_bulk_empty_returns_zero_zero(relation_store):
    result = await relation_store.upsert_relations_bulk([], user_id=None)
    assert result == (0, 0)


@pytest.mark.asyncio
async def test_upsert_relations_bulk_inserts_new_relations(relation_store):
    await _seed_finding(relation_store, finding_id="fa")
    await _seed_finding(relation_store, finding_id="fb")
    await _seed_finding(relation_store, finding_id="fc")

    relations = [
        _make_relation(id="r1", source_finding_id="fa", target_finding_id="fb"),
        _make_relation(id="r2", source_finding_id="fa", target_finding_id="fc"),
    ]
    created, updated = await relation_store.upsert_relations_bulk(
        relations, user_id=None
    )
    assert (created, updated) == (2, 0)

    got = await relation_store.relations_for_finding("fa", user_id=None)
    assert {r.id for r in got} == {"r1", "r2"}


@pytest.mark.asyncio
async def test_upsert_relations_bulk_updates_existing(relation_store):
    await _seed_finding(relation_store, finding_id="fa")
    await _seed_finding(relation_store, finding_id="fb")

    initial = _make_relation(
        id="r1", source_finding_id="fa", target_finding_id="fb", weight=0.5
    )
    await relation_store.upsert_relations_bulk([initial], user_id=None)

    bumped = _make_relation(
        id="r1", source_finding_id="fa", target_finding_id="fb", weight=0.9
    )
    created, updated = await relation_store.upsert_relations_bulk(
        [bumped], user_id=None
    )
    assert (created, updated) == (0, 1)

    got = await relation_store.relations_for_finding("fa", user_id=None)
    assert len(got) == 1
    assert got[0].weight == 0.9


@pytest.mark.asyncio
async def test_upsert_relations_bulk_preserves_user_confirmed_status(
    relation_store,
):
    await _seed_finding(relation_store, finding_id="fa")
    await _seed_finding(relation_store, finding_id="fb")

    confirmed = _make_relation(
        id="r1",
        source_finding_id="fa",
        target_finding_id="fb",
        status=RelationStatus.USER_CONFIRMED,
    )
    await relation_store.upsert_relations_bulk([confirmed], user_id=None)

    # Try to downgrade status to candidate via upsert
    resuggested = _make_relation(
        id="r1",
        source_finding_id="fa",
        target_finding_id="fb",
        status=RelationStatus.CANDIDATE,
        weight=0.3,
    )
    created, updated = await relation_store.upsert_relations_bulk(
        [resuggested], user_id=None
    )
    assert (created, updated) == (0, 1)

    got = await relation_store.relations_for_finding("fa", user_id=None)
    assert len(got) == 1
    # Status must still be user_confirmed (sticky), but weight updated
    assert got[0].status == RelationStatus.USER_CONFIRMED
    assert got[0].weight == 0.3


@pytest.mark.asyncio
async def test_relations_for_finding_matches_source_or_target(relation_store):
    await _seed_finding(relation_store, finding_id="fa")
    await _seed_finding(relation_store, finding_id="fb")
    await _seed_finding(relation_store, finding_id="fc")

    relations = [
        _make_relation(id="r1", source_finding_id="fa", target_finding_id="fb"),
        _make_relation(id="r2", source_finding_id="fc", target_finding_id="fb"),
    ]
    await relation_store.upsert_relations_bulk(relations, user_id=None)

    got = await relation_store.relations_for_finding("fb", user_id=None)
    # fb appears as target in both
    assert {r.id for r in got} == {"r1", "r2"}


@pytest.mark.asyncio
async def test_fetch_relations_in_scope_no_filter_returns_all(relation_store):
    await _seed_finding(relation_store, finding_id="fa")
    await _seed_finding(relation_store, finding_id="fb")
    await _seed_finding(relation_store, finding_id="fc")

    await relation_store.upsert_relations_bulk(
        [
            _make_relation(
                id="r1",
                source_finding_id="fa",
                target_finding_id="fb",
                status=RelationStatus.CANDIDATE,
            ),
            _make_relation(
                id="r2",
                source_finding_id="fa",
                target_finding_id="fc",
                status=RelationStatus.AUTO_CONFIRMED,
            ),
        ],
        user_id=None,
    )

    got = await relation_store.fetch_relations_in_scope(user_id=None)
    assert {r.id for r in got} == {"r1", "r2"}


@pytest.mark.asyncio
async def test_fetch_relations_in_scope_filters_by_status(relation_store):
    await _seed_finding(relation_store, finding_id="fa")
    await _seed_finding(relation_store, finding_id="fb")
    await _seed_finding(relation_store, finding_id="fc")

    await relation_store.upsert_relations_bulk(
        [
            _make_relation(
                id="r1",
                source_finding_id="fa",
                target_finding_id="fb",
                status=RelationStatus.CANDIDATE,
            ),
            _make_relation(
                id="r2",
                source_finding_id="fa",
                target_finding_id="fc",
                status=RelationStatus.AUTO_CONFIRMED,
            ),
        ],
        user_id=None,
    )

    got = await relation_store.fetch_relations_in_scope(
        user_id=None, statuses={RelationStatus.AUTO_CONFIRMED}
    )
    assert [r.id for r in got] == ["r2"]


@pytest.mark.asyncio
async def test_stream_relations_in_scope_yields_rows(relation_store):
    await _seed_finding(relation_store, finding_id="fa")
    await _seed_finding(relation_store, finding_id="fb")
    await _seed_finding(relation_store, finding_id="fc")

    await relation_store.upsert_relations_bulk(
        [
            _make_relation(id="r1", source_finding_id="fa", target_finding_id="fb"),
            _make_relation(id="r2", source_finding_id="fa", target_finding_id="fc"),
        ],
        user_id=None,
    )

    collected: list[FindingRelation] = []
    async for rel in relation_store.stream_relations_in_scope(user_id=None):
        collected.append(rel)

    assert {r.id for r in collected} == {"r1", "r2"}


@pytest.mark.asyncio
async def test_apply_link_classification_updates_row(relation_store):
    await _seed_finding(relation_store, finding_id="fa")
    await _seed_finding(relation_store, finding_id="fb")

    await relation_store.upsert_relations_bulk(
        [_make_relation(id="r1", source_finding_id="fa", target_finding_id="fb")],
        user_id=None,
    )

    await relation_store.apply_link_classification(
        relation_id="r1",
        status=RelationStatus.AUTO_CONFIRMED,
        rationale="shared infrastructure",
        relation_type="lateral_movement",
        confidence=0.82,
        user_id=None,
    )

    got = await relation_store.relations_for_finding("fa", user_id=None)
    assert len(got) == 1
    r = got[0]
    assert r.status == RelationStatus.AUTO_CONFIRMED
    assert r.llm_rationale == "shared infrastructure"
    assert r.llm_relation_type == "lateral_movement"
    assert r.llm_confidence == 0.82


@pytest.mark.asyncio
async def test_entity_crud_respects_transaction(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    await store.initialize()
    try:
        # Commit a baseline entity so we know the table is good
        await store.upsert_entity(
            _make_entity(id="base", canonical_value="base-v"), user_id=None
        )

        # Now open a transaction, upsert inside it, then raise — the new
        # row must be rolled back while the baseline remains.
        with pytest.raises(RuntimeError, match="boom"):
            async with store.transaction():
                await store.upsert_entity(
                    _make_entity(id="tx", canonical_value="tx-v"),
                    user_id=None,
                )
                # Mid-transaction visibility via the same connection
                assert (
                    await store.get_entity("tx", user_id=None)
                ) is not None
                raise RuntimeError("boom")

        # After rollback, the tx entity is gone but baseline survives
        assert await store.get_entity("tx", user_id=None) is None
        assert await store.get_entity("base", user_id=None) is not None
    finally:
        await store.close()
