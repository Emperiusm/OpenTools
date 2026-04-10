"""End-to-end pipeline integration test using canonical fixtures.

Loads the hand-curated canonical_findings.json, runs the full extraction +
linking pipeline, and asserts known entity/relation outcomes within tolerance.
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
from opentools.chain.store_extensions import ChainStore
from opentools.engagement.store import EngagementStore
from opentools.models import (
    Engagement,
    EngagementStatus,
    EngagementType,
    Finding,
    FindingStatus,
    Severity,
)

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


def _seed_canonical(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "canonical.db"
    es = EngagementStore(db_path=db_path)
    # Create both engagements used by the fixture set
    now = datetime.now()
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
    # Load and insert findings
    findings_data = _load_fixture("canonical_findings.json")
    findings = []
    for d in findings_data:
        f = _finding_from_dict(d)
        es.add_finding(f)
        findings.append(f)
    cs = ChainStore(es._conn)
    return es, cs, findings


def test_pipeline_full_integration(tmp_path):
    es, cs, findings = _seed_canonical(tmp_path)

    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=cs, config=cfg)
    for f in findings:
        pipeline.extract_for_finding(f)

    engine = LinkerEngine(store=cs, config=cfg, rules=get_default_rules(cfg))
    ctx = engine.make_context(user_id=None)
    for f in findings:
        engine.link_finding(f.id, user_id=None, context=ctx)

    # ── Entity assertions ────────────────────────────────────────────────
    expected_ents = _load_fixture("expected_entities.json")
    entity_rows = cs.execute_all(
        "SELECT type, canonical_value, mention_count FROM entity"
    )
    assert len(entity_rows) >= expected_ents["min_total_entities"], (
        f"expected >= {expected_ents['min_total_entities']} entities, "
        f"got {len(entity_rows)}: {[(r['type'], r['canonical_value']) for r in entity_rows]}"
    )

    entity_pairs = {(r["type"], r["canonical_value"]) for r in entity_rows}
    for exp in expected_ents["expected_present"]:
        assert (exp["type"], exp["canonical_value"]) in entity_pairs, (
            f"missing expected entity: {exp['type']}:{exp['canonical_value']}. "
            f"present: {sorted(entity_pairs)}"
        )

    for key, min_count in expected_ents.get("expected_min_mention_count", {}).items():
        etype, evalue = key.split(":", 1)
        row = cs.execute_one(
            "SELECT mention_count FROM entity WHERE type = ? AND canonical_value = ?",
            (etype, evalue),
        )
        assert row is not None, f"entity {key} not found in DB"
        assert row["mention_count"] >= min_count, (
            f"entity {key} has mention_count={row['mention_count']}, expected >= {min_count}"
        )

    # ── Relation assertions ──────────────────────────────────────────────
    expected_edges = _load_fixture("expected_edges.json")
    rel_rows = cs.execute_all(
        "SELECT source_finding_id, target_finding_id, weight FROM finding_relation"
    )
    assert len(rel_rows) >= expected_edges["min_total_relations"], (
        f"expected >= {expected_edges['min_total_relations']} relations, "
        f"got {len(rel_rows)}"
    )

    # Build bidirectional index to handle symmetric relations
    rel_index: dict[tuple[str, str], float] = {}
    for r in rel_rows:
        rel_index[(r["source_finding_id"], r["target_finding_id"])] = r["weight"]
        # Always index reverse so symmetric checks pass regardless of direction stored
        rel_index[(r["target_finding_id"], r["source_finding_id"])] = r["weight"]

    for exp in expected_edges["expected_pairs"]:
        key = (exp["source"], exp["target"])
        assert key in rel_index, (
            f"missing expected edge: {exp['source']} - {exp['target']}. "
            f"present pairs: {sorted(set((a, b) for (a, b) in rel_index))}"
        )
        assert rel_index[key] >= exp["min_weight"], (
            f"edge {exp['source']} - {exp['target']} weight "
            f"{rel_index[key]:.3f} < min {exp['min_weight']}"
        )

    # ── Query sanity: k-shortest path between known-connected findings ───
    cache = GraphCache(store=cs, maxsize=4)
    qe = ChainQueryEngine(store=cs, graph_cache=cache, config=cfg)
    first_pair = expected_edges["expected_pairs"][0]
    src_spec = parse_endpoint_spec(first_pair["source"])
    tgt_spec = parse_endpoint_spec(first_pair["target"])
    paths = qe.k_shortest_paths(
        from_spec=src_spec, to_spec=tgt_spec, user_id=None, k=3,
        include_candidates=True,
    )
    assert len(paths) >= 1, (
        f"k_shortest_paths returned no results between "
        f"{first_pair['source']} and {first_pair['target']}"
    )

    # ── MITRE coverage preset sanity ────────────────────────────────────
    result = mitre_coverage("eng_canonical", store=cs)
    assert len(result.tactics_present) >= 1, (
        f"mitre_coverage returned no tactics for eng_canonical. "
        f"tactic_counts={result.tactic_counts}"
    )


def test_pipeline_resume_matches_single_run(tmp_path):
    """Resumability: partial run followed by continuation equals a fresh full run."""
    # ── Run 1: process half the findings, then resume with all ──────────
    es1, cs1, findings1 = _seed_canonical(tmp_path / "run1")
    cfg = ChainConfig()
    pipeline1 = ExtractionPipeline(store=cs1, config=cfg)
    engine1 = LinkerEngine(store=cs1, config=cfg, rules=get_default_rules(cfg))

    half = len(findings1) // 2
    # Simulate first half
    for f in findings1[:half]:
        pipeline1.extract_for_finding(f)
    ctx1 = engine1.make_context(user_id=None)
    for f in findings1[:half]:
        engine1.link_finding(f.id, user_id=None, context=ctx1)

    # Resume: process second half then re-link everything
    for f in findings1[half:]:
        pipeline1.extract_for_finding(f)
    ctx1_v2 = engine1.make_context(user_id=None)
    for f in findings1:
        engine1.link_finding(f.id, user_id=None, context=ctx1_v2)

    # ── Run 2: fresh, process everything at once ─────────────────────────
    es2, cs2, findings2 = _seed_canonical(tmp_path / "run2")
    pipeline2 = ExtractionPipeline(store=cs2, config=cfg)
    engine2 = LinkerEngine(store=cs2, config=cfg, rules=get_default_rules(cfg))
    for f in findings2:
        pipeline2.extract_for_finding(f)
    ctx2 = engine2.make_context(user_id=None)
    for f in findings2:
        engine2.link_finding(f.id, user_id=None, context=ctx2)

    # ── Entity count parity ──────────────────────────────────────────────
    ent_count1 = cs1.execute_one("SELECT COUNT(*) FROM entity")[0]
    ent_count2 = cs2.execute_one("SELECT COUNT(*) FROM entity")[0]
    assert ent_count1 == ent_count2, (
        f"entity count mismatch: partial+resume={ent_count1}, single-run={ent_count2}"
    )

    # ── Relation count parity ────────────────────────────────────────────
    rel_count1 = cs1.execute_one("SELECT COUNT(*) FROM finding_relation")[0]
    rel_count2 = cs2.execute_one("SELECT COUNT(*) FROM finding_relation")[0]
    assert rel_count1 == rel_count2, (
        f"relation count mismatch: partial+resume={rel_count1}, single-run={rel_count2}"
    )
