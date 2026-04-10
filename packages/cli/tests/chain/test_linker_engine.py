from datetime import datetime, timedelta, timezone

import pytest

from opentools.chain.config import ChainConfig
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine, get_default_rules
from opentools.chain.types import RelationStatus
from opentools.models import Finding, FindingStatus, Severity


def _finding(id: str, tool: str = "nmap", description: str = "", **kwargs) -> Finding:
    defaults = dict(
        id=id, engagement_id="eng_test", tool=tool,
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title=f"Finding {id}", description=description,
        created_at=kwargs.get("created_at", datetime.now(timezone.utc)),
    )
    return Finding(**{**defaults, **kwargs})


def _seed_two_findings_sharing_host(engagement_store, chain_store):
    """Insert two findings sharing IP 10.0.0.5 and run extraction on both."""
    now = datetime.now(timezone.utc)
    a = _finding("fnd_a", description="SSH on 10.0.0.5", created_at=now)
    b = _finding("fnd_b", description="HTTP on 10.0.0.5", created_at=now + timedelta(minutes=2))
    engagement_store.add_finding(a)
    engagement_store.add_finding(b)

    pipeline = ExtractionPipeline(store=chain_store, config=ChainConfig())
    pipeline.extract_for_finding(a)
    pipeline.extract_for_finding(b)
    return a, b


def test_linker_creates_edge_for_shared_host(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    a, b = _seed_two_findings_sharing_host(engagement_store, chain_store)

    engine = LinkerEngine(store=chain_store, config=ChainConfig(), rules=get_default_rules(ChainConfig()))
    ctx = engine.make_context(user_id=None)
    run = engine.link_finding(a.id, user_id=None, context=ctx)

    assert run.findings_processed >= 1
    # An edge between fnd_a and fnd_b should exist now
    rels = chain_store.relations_for_finding(a.id)
    partner_ids = {r.target_finding_id if r.source_finding_id == a.id else r.source_finding_id for r in rels}
    assert b.id in partner_ids


def test_linker_edge_status_auto_confirmed_when_over_threshold(engagement_store_and_chain):
    """A shared strong entity should produce weight >= 1.0 -> auto_confirmed."""
    engagement_store, chain_store, now = engagement_store_and_chain
    a, b = _seed_two_findings_sharing_host(engagement_store, chain_store)

    engine = LinkerEngine(store=chain_store, config=ChainConfig(), rules=get_default_rules(ChainConfig()))
    ctx = engine.make_context(user_id=None)
    engine.link_finding(a.id, user_id=None, context=ctx)

    rels = chain_store.relations_for_finding(a.id)
    assert len(rels) >= 1
    assert any(r.status == RelationStatus.AUTO_CONFIRMED for r in rels)


def test_linker_no_edge_for_unrelated_findings(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    now_dt = datetime.now(timezone.utc)
    a = _finding("fnd_u1", description="unrelated one", created_at=now_dt)
    b = _finding("fnd_u2", description="unrelated two", created_at=now_dt)
    engagement_store.add_finding(a)
    engagement_store.add_finding(b)

    pipeline = ExtractionPipeline(store=chain_store, config=ChainConfig())
    pipeline.extract_for_finding(a)
    pipeline.extract_for_finding(b)

    engine = LinkerEngine(store=chain_store, config=ChainConfig(), rules=get_default_rules(ChainConfig()))
    ctx = engine.make_context(user_id=None)
    engine.link_finding(a.id, user_id=None, context=ctx)

    rels = chain_store.relations_for_finding(a.id)
    # Without any shared entities there should be no relations
    assert rels == []


def test_linker_sticky_user_confirmed_preserved_on_rerun(engagement_store_and_chain):
    """USER_CONFIRMED status must survive a linker re-run."""
    engagement_store, chain_store, now = engagement_store_and_chain
    a, b = _seed_two_findings_sharing_host(engagement_store, chain_store)

    engine = LinkerEngine(store=chain_store, config=ChainConfig(), rules=get_default_rules(ChainConfig()))
    ctx = engine.make_context(user_id=None)
    engine.link_finding(a.id, user_id=None, context=ctx)

    # Manually mark the edge as USER_CONFIRMED
    chain_store._conn.execute(
        "UPDATE finding_relation SET status = ? WHERE source_finding_id = ? OR target_finding_id = ?",
        (RelationStatus.USER_CONFIRMED.value, a.id, a.id),
    )
    chain_store._conn.commit()

    # Re-run the linker
    engine.link_finding(a.id, user_id=None, context=ctx)

    rels = chain_store.relations_for_finding(a.id)
    assert all(r.status == RelationStatus.USER_CONFIRMED for r in rels)


def test_linker_run_records_stats(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    a, b = _seed_two_findings_sharing_host(engagement_store, chain_store)

    engine = LinkerEngine(store=chain_store, config=ChainConfig(), rules=get_default_rules(ChainConfig()))
    ctx = engine.make_context(user_id=None)
    run = engine.link_finding(a.id, user_id=None, context=ctx)

    assert run.id
    assert run.findings_processed >= 1
    assert run.relations_created >= 0
    assert run.duration_ms is not None
    assert run.generation >= 1

    # The run should be in the linker_run table
    row = chain_store.execute_one("SELECT id FROM linker_run WHERE id = ?", (run.id,))
    assert row is not None


def test_get_default_rules_returns_seven():
    rules = get_default_rules(ChainConfig())
    assert len(rules) == 7
    names = {r.name for r in rules}
    assert names == {
        "shared_strong_entity", "shared_weak_entity", "temporal_proximity",
        "tool_chain", "shared_ioc_cross_engagement", "cve_adjacency",
        "kill_chain_adjacency",
    }
