from datetime import datetime, timezone

import pytest
import rustworkx as rx

from opentools.chain.config import ChainConfig
from opentools.chain.extractors.pipeline import AsyncExtractionPipeline
from opentools.chain.linker.engine import AsyncLinkerEngine, get_default_rules
from opentools.chain.query.bounded import simple_paths_bounded
from opentools.chain.query.graph_cache import (
    EdgeData,
    FindingNode,
    GraphCache,
    MasterGraph,
    PathEdgeRef,
    PathNode,
)
from opentools.chain.query.neighborhood import NeighborhoodResult, neighborhood
from opentools.chain.query.subgraph import filter_subgraph
from opentools.models import Finding, FindingStatus, Severity

pytestmark = pytest.mark.asyncio


async def _seed_three_linked(engagement_store, chain_store):
    now = datetime.now(timezone.utc)
    findings = []
    for i in range(3):
        f = Finding(
            id=f"nb_f{i}", engagement_id="eng_test", tool="nmap",
            severity=Severity.HIGH if i % 2 == 0 else Severity.LOW,
            status=FindingStatus.DISCOVERED,
            title=f"F{i}", description=f"ssh on 10.0.0.5 step {i}",
            created_at=now,
        )
        engagement_store.add_finding(f)
        findings.append(f)
    cfg = ChainConfig()
    pipeline = AsyncExtractionPipeline(store=chain_store, config=cfg)
    for f in findings:
        await pipeline.extract_for_finding(f)
    engine = AsyncLinkerEngine(
        store=chain_store, config=cfg, rules=get_default_rules(cfg),
    )
    ctx = await engine.make_context(user_id=None)
    for f in findings:
        await engine.link_finding(f.id, user_id=None, context=ctx)
    return findings


# ─── bounded ──────────────────────────────────────────────────────────


async def test_simple_paths_bounded_finds_paths(async_chain_stores):
    engagement_store, chain_store, _ = async_chain_stores
    findings = await _seed_three_linked(engagement_store, chain_store)
    cache = GraphCache(store=chain_store, maxsize=4)
    master = await cache.get_master_graph(user_id=None)

    sources = {master.node_map[findings[0].id]}
    targets = {master.node_map[findings[2].id]}
    results, truncated, reason = simple_paths_bounded(
        master, sources, targets, max_hops=4, max_results=10,
    )
    assert len(results) >= 1
    assert truncated is False
    assert reason is None


async def test_simple_paths_bounded_max_results_truncation(async_chain_stores):
    engagement_store, chain_store, _ = async_chain_stores
    findings = await _seed_three_linked(engagement_store, chain_store)
    cache = GraphCache(store=chain_store, maxsize=4)
    master = await cache.get_master_graph(user_id=None)

    sources = {master.node_map[findings[0].id]}
    targets = {master.node_map[findings[2].id]}
    results, truncated, reason = simple_paths_bounded(
        master, sources, targets, max_hops=4, max_results=0,
    )
    # max_results=0 should truncate immediately
    assert len(results) == 0


# ─── neighborhood ─────────────────────────────────────────────────────


async def test_neighborhood_radius_one(async_chain_stores):
    engagement_store, chain_store, _ = async_chain_stores
    findings = await _seed_three_linked(engagement_store, chain_store)
    cache = GraphCache(store=chain_store, maxsize=4)
    master = await cache.get_master_graph(user_id=None)

    seed_idx = master.node_map[findings[0].id]
    result = neighborhood(master, seed_idx, hops=1, direction="both")
    assert isinstance(result, NeighborhoodResult)
    assert result.seed_finding_id == findings[0].id
    # Should include seed + direct neighbors
    assert len(result.nodes) >= 1


async def test_neighborhood_radius_zero_only_seed(async_chain_stores):
    engagement_store, chain_store, _ = async_chain_stores
    findings = await _seed_three_linked(engagement_store, chain_store)
    cache = GraphCache(store=chain_store, maxsize=4)
    master = await cache.get_master_graph(user_id=None)

    seed_idx = master.node_map[findings[0].id]
    result = neighborhood(master, seed_idx, hops=0, direction="both")
    assert len(result.nodes) == 1
    assert result.edges == []


# ─── subgraph ─────────────────────────────────────────────────────────


async def test_filter_subgraph_by_severity(async_chain_stores):
    engagement_store, chain_store, _ = async_chain_stores
    findings = await _seed_three_linked(engagement_store, chain_store)
    cache = GraphCache(store=chain_store, maxsize=4)
    master = await cache.get_master_graph(user_id=None)

    # Keep only HIGH severity findings (nb_f0, nb_f2)
    def predicate(node: FindingNode) -> bool:
        return node.severity == "high"

    sub = filter_subgraph(master, predicate)
    assert sub.num_nodes() == 2


async def test_filter_subgraph_empty_predicate(async_chain_stores):
    engagement_store, chain_store, _ = async_chain_stores
    await _seed_three_linked(engagement_store, chain_store)
    cache = GraphCache(store=chain_store, maxsize=4)
    master = await cache.get_master_graph(user_id=None)

    def predicate(node: FindingNode) -> bool:
        return False

    sub = filter_subgraph(master, predicate)
    assert sub.num_nodes() == 0
