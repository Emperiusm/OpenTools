import asyncio
import math
from datetime import datetime, timezone

import pytest

from opentools.chain.config import ChainConfig
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine, get_default_rules
from opentools.chain.query.cost import edge_cost
from opentools.chain.query.graph_cache import (
    GraphCache,
    MasterGraph,
    PathEdgeRef,
    PathNode,
    PathResult,
)
from opentools.models import Finding, FindingStatus, Severity


# ─── edge_cost ────────────────────────────────────────────────────────


def test_edge_cost_strong_edge_low_cost():
    """weight at max should give near-zero cost (plus epsilon)."""
    c = edge_cost(weight=5.0, max_edge_weight=5.0)
    assert abs(c - 0.01) < 0.001  # log(1) == 0 plus epsilon


def test_edge_cost_weak_edge_high_cost():
    """weight < max should give positive cost."""
    c = edge_cost(weight=1.0, max_edge_weight=5.0)
    # -log(0.2) + 0.01 = 1.609 + 0.01 ≈ 1.619
    assert 1.5 < c < 1.7


def test_edge_cost_handles_zero_weight():
    """Zero weight should not divide by zero."""
    c = edge_cost(weight=0.0, max_edge_weight=5.0)
    assert math.isfinite(c)
    assert c > 10  # very high cost for a zero-weight edge


# ─── PathResult, PathNode, PathEdgeRef ─────────────────────────────────


def test_path_node_construction():
    n = PathNode(
        finding_id="fnd_1", index=0,
        severity="high", tool="nmap", title="Open port 22",
    )
    assert n.finding_id == "fnd_1"
    assert n.index == 0


def test_path_edge_ref_construction():
    e = PathEdgeRef(
        source_finding_id="fnd_1", target_finding_id="fnd_2",
        weight=1.5, status="auto_confirmed",
        reasons_summary=["shared_strong_entity"],
        llm_rationale=None, llm_relation_type=None,
    )
    assert e.weight == 1.5


def test_path_result_construction():
    nodes = [PathNode(finding_id=f"fnd_{i}", index=i, severity="high", tool="nmap", title=f"T{i}") for i in range(3)]
    edges = [
        PathEdgeRef(
            source_finding_id=f"fnd_{i}", target_finding_id=f"fnd_{i+1}",
            weight=1.0, status="auto_confirmed", reasons_summary=[],
            llm_rationale=None, llm_relation_type=None,
        )
        for i in range(2)
    ]
    p = PathResult(
        nodes=nodes, edges=edges, total_cost=2.0, length=2,
        source_finding_id="fnd_0", target_finding_id="fnd_2",
    )
    assert p.length == 2
    assert len(p.nodes) == 3
    assert p.truncated is False
    assert p.narration is None


# ─── GraphCache ────────────────────────────────────────────────────────


async def _build_linked_engagement(engagement_store, chain_store, n_findings: int = 3):
    """Seed an engagement with n findings sharing host 10.0.0.5 and run the linker."""
    now = datetime.now(timezone.utc)
    findings = []
    for i in range(n_findings):
        f = Finding(
            id=f"gc_f{i}", engagement_id="eng_test", tool="nmap",
            severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
            title=f"Finding {i}", description=f"SSH on 10.0.0.5 entry {i}",
            created_at=now,
        )
        engagement_store.add_finding(f)
        findings.append(f)

    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=chain_store, config=cfg)
    for f in findings:
        await pipeline.extract_for_finding(f)

    engine = LinkerEngine(
        store=chain_store, config=cfg, rules=get_default_rules(cfg),
    )
    ctx = await engine.make_context(user_id=None)
    for f in findings:
        await engine.link_finding(f.id, user_id=None, context=ctx)
    return findings


@pytest.mark.asyncio
async def test_graph_cache_build_master_graph(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    findings = await _build_linked_engagement(
        engagement_store, chain_store, n_findings=3,
    )

    cache = GraphCache(store=chain_store, maxsize=4)
    master = await cache.get_master_graph(
        user_id=None, include_candidates=False, include_rejected=False,
    )

    assert isinstance(master, MasterGraph)
    assert master.graph.num_nodes() == 3
    assert master.graph.num_edges() >= 2  # fully connected triangle = 3 edges directed


@pytest.mark.asyncio
async def test_graph_cache_hit_returns_same_instance(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    await _build_linked_engagement(engagement_store, chain_store)

    cache = GraphCache(store=chain_store, maxsize=4)
    a = await cache.get_master_graph(
        user_id=None, include_candidates=False, include_rejected=False,
    )
    b = await cache.get_master_graph(
        user_id=None, include_candidates=False, include_rejected=False,
    )
    assert a is b


@pytest.mark.asyncio
async def test_graph_cache_invalidation(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    await _build_linked_engagement(engagement_store, chain_store)

    cache = GraphCache(store=chain_store, maxsize=4)
    a = await cache.get_master_graph(
        user_id=None, include_candidates=False, include_rejected=False,
    )
    cache.invalidate(user_id=None)
    b = await cache.get_master_graph(
        user_id=None, include_candidates=False, include_rejected=False,
    )
    assert a is not b


@pytest.mark.asyncio
async def test_graph_cache_subgraph_method(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    findings = await _build_linked_engagement(
        engagement_store, chain_store, n_findings=3,
    )

    cache = GraphCache(store=chain_store, maxsize=4)
    master = await cache.get_master_graph(
        user_id=None, include_candidates=False, include_rejected=False,
    )

    # Project to just 2 of the 3 findings
    target_ids = {findings[0].id, findings[1].id}
    target_indices = [master.node_map[fid] for fid in target_ids]
    sub = cache.subgraph(master, target_indices)
    assert sub.num_nodes() == 2


@pytest.mark.asyncio
async def test_graph_cache_concurrent_build_collapses_to_one(engagement_store_and_chain):
    """Spec G4: concurrent callers for the same cache key must collapse to
    a single ``_build_master_graph`` invocation via the per-key
    ``asyncio.Lock``.
    """
    engagement_store, chain_store, _ = engagement_store_and_chain
    await _build_linked_engagement(
        engagement_store, chain_store, n_findings=2,
    )

    cache = GraphCache(store=chain_store, maxsize=4)

    build_count = 0
    original_build = cache._build_master_graph

    async def counting_build(*args, **kwargs):
        nonlocal build_count
        build_count += 1
        # Yield to the event loop so racing callers can all enter
        # get_master_graph before the first builder finishes.
        await asyncio.sleep(0)
        return await original_build(*args, **kwargs)

    cache._build_master_graph = counting_build  # type: ignore[assignment]

    results = await asyncio.gather(*[
        cache.get_master_graph(user_id=None) for _ in range(10)
    ])

    # Exactly one build across 10 racing callers.
    assert build_count == 1
    # All callers observe the same cached MasterGraph instance.
    assert all(r is results[0] for r in results)
