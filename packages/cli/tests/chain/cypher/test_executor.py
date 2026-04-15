from __future__ import annotations
from datetime import datetime, timezone
import pytest
import rustworkx as rx
from opentools.chain.cypher.executor import CypherExecutor
from opentools.chain.cypher.limits import QueryLimits
from opentools.chain.cypher.parser import parse_cypher
from opentools.chain.cypher.planner import plan_query
from opentools.chain.cypher.plugins import PluginFunctionRegistry
from opentools.chain.cypher.result import QueryResult
from opentools.chain.cypher.session import QuerySession
from opentools.chain.cypher.virtual_graph import EntityNode, MentionedInEdge, VirtualGraph
from opentools.chain.query.graph_cache import EdgeData, FindingNode

def _build_test_vg() -> VirtualGraph:
    """3 findings, 1 host entity, 2 LINKED edges, 2 MENTIONED_IN edges."""
    g = rx.PyDiGraph()
    now = datetime.now(timezone.utc)
    n0 = g.add_node(FindingNode(finding_id="fnd_1", severity="high", tool="nmap", title="Open SSH", created_at=now))
    n1 = g.add_node(FindingNode(finding_id="fnd_2", severity="critical", tool="nuclei", title="RCE vuln", created_at=now))
    n2 = g.add_node(FindingNode(finding_id="fnd_3", severity="medium", tool="burp", title="XSS", created_at=now))
    n3 = g.add_node(EntityNode(entity_id="ent_host1", entity_type="host", canonical_value="10.0.0.1", mention_count=2))
    g.add_edge(n0, n1, EdgeData(relation_id="rel_1", weight=2.0, cost=0.5, status="auto_confirmed", symmetric=False, reasons=[], llm_rationale=None, llm_relation_type=None))
    g.add_edge(n1, n2, EdgeData(relation_id="rel_2", weight=1.5, cost=0.7, status="auto_confirmed", symmetric=False, reasons=[], llm_rationale=None, llm_relation_type=None))
    g.add_edge(n3, n0, MentionedInEdge(mention_id="m1", field="description", confidence=1.0, extractor="ioc_finder"))
    g.add_edge(n3, n1, MentionedInEdge(mention_id="m2", field="description", confidence=1.0, extractor="ioc_finder"))
    return VirtualGraph(
        graph=g, finding_map={"fnd_1": n0, "fnd_2": n1, "fnd_3": n2},
        entity_map={"ent_host1": n3}, reverse_map={n0: "fnd_1", n1: "fnd_2", n2: "fnd_3", n3: "ent_host1"},
        node_labels={n0: "Finding", n1: "Finding", n2: "Finding", n3: "Host"}, generation=1,
    )

def _execute_sync(query_str: str, vg: VirtualGraph | None = None, limits: QueryLimits | None = None) -> QueryResult:
    import asyncio
    if vg is None:
        vg = _build_test_vg()
    if limits is None:
        limits = QueryLimits()
    ast = parse_cypher(query_str)
    plan = plan_query(ast, limits)
    executor = CypherExecutor(
        virtual_graph=vg, plan=plan, session=QuerySession(),
        plugin_registry=PluginFunctionRegistry(), limits=limits,
    )
    return asyncio.run(executor.execute())

def test_scan_all_findings():
    result = _execute_sync("MATCH (a:Finding) RETURN a")
    assert len(result.rows) == 3
    assert "a" in result.columns

def test_scan_entity_label():
    result = _execute_sync("MATCH (h:Host) RETURN h")
    assert len(result.rows) == 1

def test_expand_linked():
    result = _execute_sync("MATCH (a:Finding)-[r:LINKED]->(b:Finding) RETURN a, b")
    assert len(result.rows) == 2  # fnd_1->fnd_2, fnd_2->fnd_3

def test_expand_mentioned_in():
    result = _execute_sync("MATCH (h:Host)-[r:MENTIONED_IN]->(f:Finding) RETURN h, f")
    assert len(result.rows) == 2  # host->fnd_1, host->fnd_2

def test_where_filter():
    result = _execute_sync('MATCH (a:Finding) WHERE a.severity = "critical" RETURN a')
    assert len(result.rows) == 1
    assert result.rows[0]["a"]["severity"] == "critical"

def test_where_numeric_comparison():
    result = _execute_sync("MATCH (a:Finding)-[r:LINKED]->(b:Finding) WHERE r.weight > 1.8 RETURN a, b")
    assert len(result.rows) == 1  # only rel_1 has weight=2.0

def test_return_property():
    result = _execute_sync("MATCH (a:Finding) RETURN a.title, a.severity")
    assert len(result.rows) == 3

def test_subgraph_projection():
    result = _execute_sync("MATCH (a:Finding)-[r:LINKED]->(b:Finding) RETURN a, b")
    assert result.subgraph is not None
    assert len(result.subgraph.node_indices) >= 2

def test_resource_limit_max_rows():
    result = _execute_sync("MATCH (a:Finding) RETURN a", limits=QueryLimits(max_rows=1))
    assert len(result.rows) == 1
    assert result.truncated is True

def test_empty_result():
    result = _execute_sync('MATCH (a:Finding) WHERE a.severity = "nonexistent" RETURN a')
    assert len(result.rows) == 0
    assert result.truncated is False
