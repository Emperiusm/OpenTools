"""Schema/cascade/CRUD smoke tests against the async chain store.

These tests used to target the sync ChainStore helper and its
``execute_all``/``execute_one`` convenience API. Task 30 deleted the
sync path; the async-store equivalents below exercise the same
behaviours (PRAGMA foreign_keys on, expected tables present, entity
upsert + lookup, mention add/fetch, relation upsert, FK cascade on
hard delete) via :class:`AsyncChainStore`.
"""
from datetime import datetime, timezone

import pytest

from opentools.chain.models import (
    Entity,
    EntityMention,
    FindingRelation,
    RelationReason,
    entity_id_for,
)
from opentools.chain.types import MentionField, RelationStatus
from opentools.models import Finding, FindingStatus, Severity

pytestmark = pytest.mark.asyncio


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def test_pragmas_and_schema(engagement_store_and_chain):
    """foreign_keys PRAGMA is enabled on the async connection."""
    _engagement_store, chain_store, _now_ = engagement_store_and_chain
    async with chain_store._conn.execute("PRAGMA foreign_keys") as cursor:
        row = await cursor.fetchone()
    assert row[0] == 1


async def test_all_chain_tables_created(engagement_store_and_chain):
    _engagement_store, chain_store, _now_ = engagement_store_and_chain
    async with chain_store._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ) as cursor:
        rows = await cursor.fetchall()
    names = {r[0] for r in rows}
    for expected in [
        "entity",
        "entity_mention",
        "finding_relation",
        "linker_run",
        "extraction_cache",
        "llm_link_cache",
        "finding_extraction_state",
        "finding_parser_output",
    ]:
        assert expected in names, f"missing table {expected}"


async def test_upsert_entity_and_lookup(engagement_store_and_chain):
    _engagement_store, chain_store, now = engagement_store_and_chain
    eid = entity_id_for("host", "10.0.0.5")
    e = Entity(
        id=eid, type="host", canonical_value="10.0.0.5",
        first_seen_at=now, last_seen_at=now, mention_count=0,
    )
    await chain_store.upsert_entity(e, user_id=None)
    found = await chain_store.get_entity(eid, user_id=None)
    assert found is not None
    assert found.type == "host"
    assert found.canonical_value == "10.0.0.5"


async def test_upsert_entity_updates_mention_count(engagement_store_and_chain):
    _engagement_store, chain_store, now = engagement_store_and_chain
    eid = entity_id_for("host", "10.0.0.5")
    e1 = Entity(
        id=eid, type="host", canonical_value="10.0.0.5",
        first_seen_at=now, last_seen_at=now, mention_count=1,
    )
    await chain_store.upsert_entity(e1, user_id=None)
    e2 = Entity(
        id=eid, type="host", canonical_value="10.0.0.5",
        first_seen_at=now, last_seen_at=now, mention_count=5,
    )
    await chain_store.upsert_entity(e2, user_id=None)
    fetched = await chain_store.get_entity(eid, user_id=None)
    assert fetched is not None
    assert fetched.mention_count == 5


async def test_add_mentions_and_fetch(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    # Insert a real finding so the FK resolves
    finding = Finding(
        id="fnd_1", engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title="Open port 22", description="SSH exposed on 10.0.0.5",
        created_at=now,
    )
    engagement_store.add_finding(finding)

    eid = entity_id_for("host", "10.0.0.5")
    await chain_store.upsert_entity(
        Entity(
            id=eid, type="host", canonical_value="10.0.0.5",
            first_seen_at=now, last_seen_at=now, mention_count=0,
        ),
        user_id=None,
    )
    mentions = [
        EntityMention(
            id=f"mnt_{i}", entity_id=eid, finding_id="fnd_1",
            field=MentionField.DESCRIPTION, raw_value="10.0.0.5",
            offset_start=10, offset_end=18, extractor="ioc_finder",
            confidence=0.9, created_at=now,
        )
        for i in range(3)
    ]
    await chain_store.add_mentions_bulk(mentions, user_id=None)
    fetched = await chain_store.mentions_for_finding("fnd_1", user_id=None)
    # Unique on (entity_id, finding_id, field, offset_start) — duplicates collapse
    assert len(fetched) == 1
    assert fetched[0].raw_value == "10.0.0.5"


async def test_upsert_relations_and_fetch(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    # Insert two real findings so the FKs resolve
    for i in (1, 2):
        engagement_store.add_finding(
            Finding(
                id=f"fnd_{i}", engagement_id="eng_test", tool="nmap",
                severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
                title=f"Finding {i}", description=f"desc {i}",
                created_at=now,
            )
        )
    rel = FindingRelation(
        id="rel_1",
        source_finding_id="fnd_1",
        target_finding_id="fnd_2",
        weight=1.5,
        status=RelationStatus.AUTO_CONFIRMED,
        symmetric=False,
        reasons=[
            RelationReason(
                rule="shared_strong_entity",
                weight_contribution=1.5,
                idf_factor=1.0,
                details={},
            )
        ],
        created_at=now, updated_at=now,
    )
    await chain_store.upsert_relations_bulk([rel], user_id=None)
    fetched = await chain_store.relations_for_finding("fnd_1", user_id=None)
    assert len(fetched) == 1
    assert fetched[0].weight == 1.5
    assert fetched[0].status == RelationStatus.AUTO_CONFIRMED
    assert len(fetched[0].reasons) == 1
    assert fetched[0].reasons[0].rule == "shared_strong_entity"


async def test_finding_hard_delete_cascades_mentions(engagement_store_and_chain):
    """Hard DELETE from findings (not soft-delete via deleted_at) must cascade to
    entity_mention and finding_relation via ON DELETE CASCADE."""
    engagement_store, chain_store, now = engagement_store_and_chain
    engagement_store.add_finding(
        Finding(
            id="fnd_del", engagement_id="eng_test", tool="nmap",
            severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
            title="will be deleted", description="", created_at=now,
        )
    )
    eid = entity_id_for("host", "10.0.0.5")
    await chain_store.upsert_entity(
        Entity(
            id=eid, type="host", canonical_value="10.0.0.5",
            first_seen_at=now, last_seen_at=now,
        ),
        user_id=None,
    )
    await chain_store.add_mentions_bulk(
        [
            EntityMention(
                id="mnt_x", entity_id=eid, finding_id="fnd_del",
                field=MentionField.TITLE, raw_value="10.0.0.5",
                offset_start=0, offset_end=8, extractor="ioc_finder",
                confidence=0.9, created_at=now,
            )
        ],
        user_id=None,
    )
    # Hard delete directly via SQL (simulates what delete_engagement cascade
    # would do). First NULL out timeline_events.finding_id since that FK is
    # NO ACTION (not CASCADE).
    engagement_store._conn.execute(
        "UPDATE timeline_events SET finding_id = NULL WHERE finding_id = ?",
        ("fnd_del",),
    )
    engagement_store._conn.execute(
        "DELETE FROM findings WHERE id = ?", ("fnd_del",)
    )
    engagement_store._conn.commit()
    # The async store has its own connection (WAL) — it will observe the
    # commit after a read. foreign_keys=ON on both connections means the
    # CASCADE already fired on the engagement connection; we just verify
    # the async store no longer sees any mentions for fnd_del.
    fetched = await chain_store.mentions_for_finding("fnd_del", user_id=None)
    assert fetched == []
