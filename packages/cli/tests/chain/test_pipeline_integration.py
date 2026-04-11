"""End-to-end pipeline integration test using canonical fixtures.

Loads the hand-curated canonical_findings.json, runs the full extraction
+ linking pipeline against the async store, and asserts known
entity/relation outcomes within tolerance.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from opentools.chain.config import ChainConfig
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine, get_default_rules
from opentools.chain.query.endpoints import parse_endpoint_spec
from opentools.chain.query.engine import ChainQueryEngine
from opentools.chain.query.graph_cache import GraphCache
from opentools.chain.query.presets import mitre_coverage
from opentools.chain.stores.sqlite_async import AsyncChainStore
from opentools.engagement.store import EngagementStore
from opentools.models import (
    Engagement,
    EngagementStatus,
    EngagementType,
    Finding,
    FindingStatus,
    Severity,
)

pytestmark = pytest.mark.asyncio

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str):
    return json.loads((FIXTURES / name).read_text())


def _finding_from_dict(d: dict) -> Finding:
    return Finding(
        id=d["id"],
        engagement_id=d["engagement_id"],
        tool=d["tool"],
        severity=Severity(d["severity"]),
        status=FindingStatus(d["status"]),
        title=d["title"],
        description=d.get("description", ""),
        created_at=datetime.fromisoformat(d["created_at"]),
    )


async def _seed_canonical(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "canonical.db"
    es = EngagementStore(db_path=db_path)
    now = datetime.now()
    # Create both engagements used by the fixture set
    for eng_id in ["eng_canonical", "eng_canonical_2"]:
        es.create(Engagement(
            id=eng_id,
            name=eng_id,
            target="canonical",
            type=EngagementType.PENTEST,
            status=EngagementStatus.ACTIVE,
            created_at=now,
            updated_at=now,
        ))
    # Load and insert findings via the sync engagement store
    findings_data = _load_fixture("canonical_findings.json")
    findings = []
    for d in findings_data:
        f = _finding_from_dict(d)
        es.add_finding(f)
        findings.append(f)
    # Close the sync handle so aiosqlite can open the file cleanly.
    es._conn.close()

    async_store = AsyncChainStore(db_path=db_path)
    await async_store.initialize()
    return db_path, async_store, findings


async def _entity_rows(store: AsyncChainStore) -> list[tuple[str, str, int]]:
    async with store._conn.execute(
        "SELECT type, canonical_value, mention_count FROM entity"
    ) as cur:
        rows = await cur.fetchall()
    return [(r[0], r[1], r[2]) for r in rows]


async def _relation_rows(
    store: AsyncChainStore,
) -> list[tuple[str, str, float]]:
    async with store._conn.execute(
        "SELECT source_finding_id, target_finding_id, weight FROM finding_relation"
    ) as cur:
        rows = await cur.fetchall()
    return [(r[0], r[1], r[2]) for r in rows]


async def _count_entities(store: AsyncChainStore) -> int:
    async with store._conn.execute("SELECT COUNT(*) FROM entity") as cur:
        row = await cur.fetchone()
    return row[0]


async def _count_relations(store: AsyncChainStore) -> int:
    async with store._conn.execute(
        "SELECT COUNT(*) FROM finding_relation"
    ) as cur:
        row = await cur.fetchone()
    return row[0]


async def test_pipeline_full_integration(tmp_path):
    db_path, cs, findings = await _seed_canonical(tmp_path)
    try:
        cfg = ChainConfig()
        pipeline = ExtractionPipeline(store=cs, config=cfg)
        for f in findings:
            await pipeline.extract_for_finding(f)

        engine = LinkerEngine(store=cs, config=cfg, rules=get_default_rules(cfg))
        ctx = await engine.make_context(user_id=None)
        for f in findings:
            await engine.link_finding(f.id, user_id=None, context=ctx)

        # ── Entity assertions ────────────────────────────────────────────
        expected_ents = _load_fixture("expected_entities.json")
        entity_rows = await _entity_rows(cs)
        assert len(entity_rows) >= expected_ents["min_total_entities"], (
            f"expected >= {expected_ents['min_total_entities']} entities, "
            f"got {len(entity_rows)}: {[(t, v) for t, v, _c in entity_rows]}"
        )

        entity_pairs = {(t, v) for t, v, _c in entity_rows}
        for exp in expected_ents["expected_present"]:
            assert (exp["type"], exp["canonical_value"]) in entity_pairs, (
                f"missing expected entity: {exp['type']}:{exp['canonical_value']}. "
                f"present: {sorted(entity_pairs)}"
            )

        mention_counts = {(t, v): c for t, v, c in entity_rows}
        for key, min_count in expected_ents.get(
            "expected_min_mention_count", {}
        ).items():
            etype, evalue = key.split(":", 1)
            count = mention_counts.get((etype, evalue))
            assert count is not None, f"entity {key} not found in DB"
            assert count >= min_count, (
                f"entity {key} has mention_count={count}, expected >= {min_count}"
            )

        # ── Relation assertions ──────────────────────────────────────────
        expected_edges = _load_fixture("expected_edges.json")
        rel_rows = await _relation_rows(cs)
        assert len(rel_rows) >= expected_edges["min_total_relations"], (
            f"expected >= {expected_edges['min_total_relations']} relations, "
            f"got {len(rel_rows)}"
        )

        # Build bidirectional index to handle symmetric relations
        rel_index: dict[tuple[str, str], float] = {}
        for src, tgt, weight in rel_rows:
            rel_index[(src, tgt)] = weight
            # Always index reverse so symmetric checks pass regardless of
            # direction stored.
            rel_index[(tgt, src)] = weight

        for exp in expected_edges["expected_pairs"]:
            key = (exp["source"], exp["target"])
            assert key in rel_index, (
                f"missing expected edge: {exp['source']} - {exp['target']}. "
                f"present pairs: {sorted(set(rel_index))}"
            )
            assert rel_index[key] >= exp["min_weight"], (
                f"edge {exp['source']} - {exp['target']} weight "
                f"{rel_index[key]:.3f} < min {exp['min_weight']}"
            )

        # ── Query sanity: k-shortest path between known-connected findings
        cache = GraphCache(store=cs, maxsize=4)
        qe = ChainQueryEngine(store=cs, graph_cache=cache, config=cfg)
        first_pair = expected_edges["expected_pairs"][0]
        src_spec = parse_endpoint_spec(first_pair["source"])
        tgt_spec = parse_endpoint_spec(first_pair["target"])
        paths = await qe.k_shortest_paths(
            from_spec=src_spec, to_spec=tgt_spec,
            user_id=None, k=3, include_candidates=True,
        )
        assert len(paths) >= 1, (
            f"k_shortest_paths returned no results between "
            f"{first_pair['source']} and {first_pair['target']}"
        )

        # ── MITRE coverage preset sanity ─────────────────────────────────
        mc = await mitre_coverage("eng_canonical", store=cs)
        assert len(mc.tactics_present) >= 1, (
            f"mitre_coverage returned no tactics for eng_canonical. "
            f"tactic_counts={mc.tactic_counts}"
        )
    finally:
        await cs.close()


async def test_pipeline_resume_matches_single_run(tmp_path):
    """Resumability: partial run followed by continuation equals a fresh full run."""
    # ── Run 1: process half the findings, then resume with all ──────────
    _db1, cs1, findings1 = await _seed_canonical(tmp_path / "run1")
    _db2, cs2, findings2 = await _seed_canonical(tmp_path / "run2")
    try:
        cfg = ChainConfig()
        pipeline1 = ExtractionPipeline(store=cs1, config=cfg)
        engine1 = LinkerEngine(
            store=cs1, config=cfg, rules=get_default_rules(cfg),
        )

        half = len(findings1) // 2
        # Simulate first half
        for f in findings1[:half]:
            await pipeline1.extract_for_finding(f)
        ctx1 = await engine1.make_context(user_id=None)
        for f in findings1[:half]:
            await engine1.link_finding(f.id, user_id=None, context=ctx1)

        # Resume: process second half then re-link everything
        for f in findings1[half:]:
            await pipeline1.extract_for_finding(f)
        ctx1_v2 = await engine1.make_context(user_id=None)
        for f in findings1:
            await engine1.link_finding(f.id, user_id=None, context=ctx1_v2)

        # ── Run 2: fresh, process everything at once ─────────────────────
        pipeline2 = ExtractionPipeline(store=cs2, config=cfg)
        engine2 = LinkerEngine(
            store=cs2, config=cfg, rules=get_default_rules(cfg),
        )
        for f in findings2:
            await pipeline2.extract_for_finding(f)
        ctx2 = await engine2.make_context(user_id=None)
        for f in findings2:
            await engine2.link_finding(f.id, user_id=None, context=ctx2)

        # ── Entity count parity ──────────────────────────────────────────
        ent_count1 = await _count_entities(cs1)
        ent_count2 = await _count_entities(cs2)
        assert ent_count1 == ent_count2, (
            f"entity count mismatch: partial+resume={ent_count1}, "
            f"single-run={ent_count2}"
        )

        # ── Relation count parity ────────────────────────────────────────
        rel_count1 = await _count_relations(cs1)
        rel_count2 = await _count_relations(cs2)
        assert rel_count1 == rel_count2, (
            f"relation count mismatch: partial+resume={rel_count1}, "
            f"single-run={rel_count2}"
        )
    finally:
        await cs1.close()
        await cs2.close()
