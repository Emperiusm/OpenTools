"""End-to-end integration: parse → plan → build virtual graph → execute."""
from __future__ import annotations
from datetime import datetime, timezone
from unittest.mock import AsyncMock
import pytest
import rustworkx as rx
from opentools.chain.cypher.limits import QueryLimits
from opentools.chain.cypher.parser import parse_cypher
from opentools.chain.cypher.planner import plan_query
from opentools.chain.cypher.executor import CypherExecutor
from opentools.chain.cypher.plugins import PluginFunctionRegistry
from opentools.chain.cypher.session import QuerySession
from opentools.chain.cypher.virtual_graph import VirtualGraphBuilder, VirtualGraphCache, EntityNode, MentionedInEdge
from opentools.chain.models import Entity, EntityMention
from opentools.chain.query.graph_cache import EdgeData, FindingNode, MasterGraph, GraphCache
from opentools.chain.types import MentionField


def _make_master_graph() -> MasterGraph:
    g = rx.PyDiGraph()
    now = datetime.now(timezone.utc)
    n0 = g.add_node(FindingNode(finding_id="fnd_1", severity="high", tool="nmap", title="Open SSH", created_at=now))
    n1 = g.add_node(FindingNode(finding_id="fnd_2", severity="critical", tool="nuclei", title="RCE vuln", created_at=now))
    n2 = g.add_node(FindingNode(finding_id="fnd_3", severity="medium", tool="burp", title="XSS", created_at=now))
    g.add_edge(n0, n1, EdgeData(relation_id="rel_1", weight=2.0, cost=0.5, status="auto_confirmed", symmetric=False, reasons=[], llm_rationale=None, llm_relation_type=None))
    g.add_edge(n1, n2, EdgeData(relation_id="rel_2", weight=1.5, cost=0.7, status="auto_confirmed", symmetric=False, reasons=[], llm_rationale=None, llm_relation_type=None))
    return MasterGraph(graph=g, node_map={"fnd_1": n0, "fnd_2": n1, "fnd_3": n2}, reverse_map={n0: "fnd_1", n1: "fnd_2", n2: "fnd_3"}, generation=1, max_weight=2.0)


def _make_entities() -> list[Entity]:
    now = datetime.now(timezone.utc)
    return [
        Entity(id="ent_host1", type="host", canonical_value="10.0.0.1", first_seen_at=now, last_seen_at=now, mention_count=2),
        Entity(id="ent_cve1", type="cve", canonical_value="CVE-2024-1234", first_seen_at=now, last_seen_at=now, mention_count=1),
    ]


def _make_mentions() -> list[EntityMention]:
    now = datetime.now(timezone.utc)
    return [
        EntityMention(id="m1", entity_id="ent_host1", finding_id="fnd_1", field=MentionField.DESCRIPTION, raw_value="10.0.0.1", extractor="ioc_finder", confidence=1.0, created_at=now),
        EntityMention(id="m2", entity_id="ent_host1", finding_id="fnd_2", field=MentionField.DESCRIPTION, raw_value="10.0.0.1", extractor="ioc_finder", confidence=1.0, created_at=now),
        EntityMention(id="m3", entity_id="ent_cve1", finding_id="fnd_2", field=MentionField.TITLE, raw_value="CVE-2024-1234", extractor="security_regex", confidence=0.95, created_at=now),
    ]


@pytest.mark.asyncio
async def test_full_pipeline_via_virtual_graph_cache():
    """Build virtual graph through cache, execute query, get results."""
    master = _make_master_graph()
    entities = _make_entities()
    mentions = _make_mentions()

    store = AsyncMock()
    store.current_linker_generation = AsyncMock(return_value=1)
    store.list_entities = AsyncMock(return_value=entities)
    store.fetch_all_mentions_in_scope = AsyncMock(return_value=mentions)

    graph_cache = AsyncMock()
    graph_cache.get_master_graph = AsyncMock(return_value=master)

    vg_cache = VirtualGraphCache(store=store, graph_cache=graph_cache, maxsize=4)

    # Build virtual graph through cache
    vg = await vg_cache.get(user_id=None, include_candidates=False, engagement_ids=None)
    assert vg.graph.num_nodes() == 5  # 3 findings + 2 entities

    # Execute query
    limits = QueryLimits()
    ast = parse_cypher("MATCH (a:Finding) RETURN a")
    plan = plan_query(ast, limits)
    executor = CypherExecutor(
        virtual_graph=vg, plan=plan, session=QuerySession(),
        plugin_registry=PluginFunctionRegistry(), limits=limits,
    )
    result = await executor.execute()

    assert len(result.rows) == 3
    assert "a" in result.columns


@pytest.mark.asyncio
async def test_full_pipeline_entity_traversal():
    """Query that traverses through entity nodes."""
    master = _make_master_graph()
    entities = _make_entities()
    mentions = _make_mentions()

    store = AsyncMock()
    store.current_linker_generation = AsyncMock(return_value=1)
    store.list_entities = AsyncMock(return_value=entities)
    store.fetch_all_mentions_in_scope = AsyncMock(return_value=mentions)

    graph_cache = AsyncMock()
    graph_cache.get_master_graph = AsyncMock(return_value=master)

    vg_cache = VirtualGraphCache(store=store, graph_cache=graph_cache, maxsize=4)
    vg = await vg_cache.get(user_id=None, include_candidates=False, engagement_ids=None)

    limits = QueryLimits()
    ast = parse_cypher("MATCH (h:Host)-[r:MENTIONED_IN]->(f:Finding) RETURN h, f")
    plan = plan_query(ast, limits)
    executor = CypherExecutor(
        virtual_graph=vg, plan=plan, session=QuerySession(),
        plugin_registry=PluginFunctionRegistry(), limits=limits,
    )
    result = await executor.execute()

    assert len(result.rows) == 2  # host mentions fnd_1 and fnd_2
