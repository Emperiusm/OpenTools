from __future__ import annotations
import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock
import pytest
import rustworkx as rx
from opentools.chain.cypher.virtual_graph import EntityNode, VirtualGraph, VirtualGraphBuilder, VirtualGraphCache
from opentools.chain.models import Entity, EntityMention
from opentools.chain.query.graph_cache import EdgeData, FindingNode, MasterGraph
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

def test_build_virtual_graph_node_counts():
    master = _make_master_graph()
    builder = VirtualGraphBuilder()
    vg = builder.build(master, _make_entities(), _make_mentions())
    assert vg.graph.num_nodes() == 5
    assert len(vg.finding_map) == 3
    assert len(vg.entity_map) == 2

def test_build_virtual_graph_edge_counts():
    master = _make_master_graph()
    builder = VirtualGraphBuilder()
    vg = builder.build(master, _make_entities(), _make_mentions())
    assert vg.graph.num_edges() == 5  # 2 LINKED + 3 MENTIONED_IN

def test_build_virtual_graph_node_labels():
    master = _make_master_graph()
    builder = VirtualGraphBuilder()
    vg = builder.build(master, _make_entities(), _make_mentions())
    finding_labels = [vg.node_labels[idx] for idx in vg.finding_map.values()]
    assert all(l == "Finding" for l in finding_labels)
    host_idx = vg.entity_map["ent_host1"]
    assert vg.node_labels[host_idx] == "Host"
    cve_idx = vg.entity_map["ent_cve1"]
    assert vg.node_labels[cve_idx] == "CVE"

def test_mentioned_in_direction():
    master = _make_master_graph()
    builder = VirtualGraphBuilder()
    vg = builder.build(master, _make_entities(), _make_mentions())
    host_idx = vg.entity_map["ent_host1"]
    successors = list(vg.graph.successor_indices(host_idx))
    assert len(successors) == 2
    successor_ids = {vg.reverse_map[s] for s in successors}
    assert successor_ids == {"fnd_1", "fnd_2"}

def test_linked_edges_preserved():
    master = _make_master_graph()
    builder = VirtualGraphBuilder()
    vg = builder.build(master, _make_entities(), _make_mentions())
    fnd1_idx = vg.finding_map["fnd_1"]
    fnd2_idx = vg.finding_map["fnd_2"]
    edge_data = vg.graph.get_edge_data(fnd1_idx, fnd2_idx)
    assert edge_data is not None

def test_entity_node_properties():
    master = _make_master_graph()
    builder = VirtualGraphBuilder()
    vg = builder.build(master, _make_entities(), _make_mentions())
    host_idx = vg.entity_map["ent_host1"]
    node_data = vg.graph.get_node_data(host_idx)
    assert isinstance(node_data, EntityNode)
    assert node_data.entity_id == "ent_host1"
    assert node_data.canonical_value == "10.0.0.1"
    assert node_data.entity_type == "host"

@pytest.mark.asyncio
async def test_virtual_graph_cache_reuse():
    master = _make_master_graph()
    entities = _make_entities()
    mentions = _make_mentions()
    store = AsyncMock()
    store.current_linker_generation = AsyncMock(return_value=1)
    store.list_entities = AsyncMock(return_value=entities)
    store.fetch_all_mentions_in_scope = AsyncMock(return_value=mentions)
    graph_cache = AsyncMock()
    graph_cache.get_master_graph = AsyncMock(return_value=master)
    cache = VirtualGraphCache(store=store, graph_cache=graph_cache, maxsize=4)
    vg1 = await cache.get(user_id=None, include_candidates=False, engagement_ids=None)
    vg2 = await cache.get(user_id=None, include_candidates=False, engagement_ids=None)
    assert vg1 is vg2
