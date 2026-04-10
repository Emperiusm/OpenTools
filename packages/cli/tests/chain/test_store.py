from datetime import datetime, timezone

from opentools.chain.models import (
    Entity,
    EntityMention,
    FindingRelation,
    RelationReason,
    entity_id_for,
)
from opentools.chain.types import MentionField, RelationStatus
from opentools.models import Finding, FindingStatus, Severity


def _now() -> datetime:
    return datetime.now(timezone.utc)


def test_pragmas_and_schema(chain_store):
    # foreign_keys must be on
    row = chain_store.execute_one("PRAGMA foreign_keys")
    assert row[0] == 1


def test_all_chain_tables_created(chain_store):
    rows = chain_store.execute_all(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
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


def test_upsert_entity_and_lookup(chain_store):
    eid = entity_id_for("host", "10.0.0.5")
    e = Entity(
        id=eid, type="host", canonical_value="10.0.0.5",
        first_seen_at=_now(), last_seen_at=_now(), mention_count=0,
    )
    chain_store.upsert_entity(e)
    found = chain_store.get_entity(eid)
    assert found is not None
    assert found.type == "host"
    assert found.canonical_value == "10.0.0.5"


def test_upsert_entity_updates_mention_count(chain_store):
    eid = entity_id_for("host", "10.0.0.5")
    e1 = Entity(
        id=eid, type="host", canonical_value="10.0.0.5",
        first_seen_at=_now(), last_seen_at=_now(), mention_count=1,
    )
    chain_store.upsert_entity(e1)
    e2 = Entity(
        id=eid, type="host", canonical_value="10.0.0.5",
        first_seen_at=_now(), last_seen_at=_now(), mention_count=5,
    )
    chain_store.upsert_entity(e2)
    assert chain_store.get_entity(eid).mention_count == 5


def test_add_mentions_and_fetch(engagement_store_and_chain):
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
    chain_store.upsert_entity(Entity(
        id=eid, type="host", canonical_value="10.0.0.5",
        first_seen_at=now, last_seen_at=now, mention_count=0,
    ))
    mentions = [
        EntityMention(
            id=f"mnt_{i}", entity_id=eid, finding_id="fnd_1",
            field=MentionField.DESCRIPTION, raw_value="10.0.0.5",
            offset_start=10, offset_end=18, extractor="ioc_finder",
            confidence=0.9, created_at=now,
        )
        for i in range(3)
    ]
    chain_store.add_mentions(mentions)
    fetched = chain_store.mentions_for_finding("fnd_1")
    # Unique on (entity_id, finding_id, field, offset_start) — duplicates collapse
    assert len(fetched) == 1
    assert fetched[0].raw_value == "10.0.0.5"


def test_upsert_relations_and_fetch(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    # Insert two real findings so the FKs resolve
    for i in (1, 2):
        engagement_store.add_finding(Finding(
            id=f"fnd_{i}", engagement_id="eng_test", tool="nmap",
            severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
            title=f"Finding {i}", description=f"desc {i}", created_at=now,
        ))
    rel = FindingRelation(
        id="rel_1",
        source_finding_id="fnd_1",
        target_finding_id="fnd_2",
        weight=1.5,
        status=RelationStatus.AUTO_CONFIRMED,
        symmetric=False,
        reasons=[RelationReason(
            rule="shared_strong_entity",
            weight_contribution=1.5,
            idf_factor=1.0,
            details={},
        )],
        created_at=now, updated_at=now,
    )
    chain_store.upsert_relations_bulk([rel])
    fetched = chain_store.relations_for_finding("fnd_1")
    assert len(fetched) == 1
    assert fetched[0].weight == 1.5
    assert fetched[0].status == RelationStatus.AUTO_CONFIRMED
    assert len(fetched[0].reasons) == 1
    assert fetched[0].reasons[0].rule == "shared_strong_entity"


def test_finding_hard_delete_cascades_mentions(engagement_store_and_chain):
    """Hard DELETE from findings (not soft-delete via deleted_at) must cascade to
    entity_mention and finding_relation via ON DELETE CASCADE."""
    engagement_store, chain_store, now = engagement_store_and_chain
    engagement_store.add_finding(Finding(
        id="fnd_del", engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title="will be deleted", description="", created_at=now,
    ))
    eid = entity_id_for("host", "10.0.0.5")
    chain_store.upsert_entity(Entity(
        id=eid, type="host", canonical_value="10.0.0.5",
        first_seen_at=now, last_seen_at=now,
    ))
    chain_store.add_mentions([
        EntityMention(
            id="mnt_x", entity_id=eid, finding_id="fnd_del",
            field=MentionField.TITLE, raw_value="10.0.0.5",
            offset_start=0, offset_end=8, extractor="ioc_finder",
            confidence=0.9, created_at=now,
        )
    ])
    # Hard delete directly via SQL (simulates what delete_engagement cascade would do).
    # First NULL out timeline_events.finding_id since that FK is NO ACTION (not CASCADE).
    engagement_store._conn.execute(
        "UPDATE timeline_events SET finding_id = NULL WHERE finding_id = ?", ("fnd_del",)
    )
    engagement_store._conn.execute("DELETE FROM findings WHERE id = ?", ("fnd_del",))
    engagement_store._conn.commit()
    assert chain_store.mentions_for_finding("fnd_del") == []
