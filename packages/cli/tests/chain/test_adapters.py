import json
from datetime import datetime, timezone

import rustworkx as rx

from opentools.chain.models import RelationReason
from opentools.chain.query.adapters import (
    SCHEMA_VERSION,
    to_canonical_json,
    to_cosmograph,
    to_cytoscape,
    to_dot,
    to_force_graph,
)
from opentools.chain.query.graph_cache import EdgeData, FindingNode, MasterGraph


def _build_master() -> MasterGraph:
    g = rx.PyDiGraph()
    n1 = g.add_node(FindingNode(finding_id="f1", severity="high", tool="nmap", title="Open port", created_at=None))
    n2 = g.add_node(FindingNode(finding_id="f2", severity="critical", tool="nuclei", title="RCE", created_at=None))
    reasons = [RelationReason(rule="shared_strong_entity", weight_contribution=1.5, idf_factor=1.2, details={})]
    g.add_edge(n1, n2, EdgeData(
        relation_id="rel_1", weight=1.5, cost=0.5,
        status="auto_confirmed", symmetric=False, reasons=reasons,
        llm_rationale="shared host", llm_relation_type="pivots_to",
    ))
    return MasterGraph(
        graph=g,
        node_map={"f1": n1, "f2": n2},
        reverse_map={n1: "f1", n2: "f2"},
        generation=1,
        max_weight=5.0,
    )


def test_canonical_json_schema_version():
    master = _build_master()
    data = to_canonical_json(master)
    assert data["schema_version"] == SCHEMA_VERSION
    assert len(data["nodes"]) == 2
    assert len(data["edges"]) == 1
    assert data["metadata"]["generation"] == 1


def test_canonical_json_has_expected_fields():
    data = to_canonical_json(_build_master())
    edge = data["edges"][0]
    assert edge["source"] == "f1"
    assert edge["target"] == "f2"
    assert edge["weight"] == 1.5
    assert edge["status"] == "auto_confirmed"
    assert "shared_strong_entity" in edge["reasons"]
    assert edge["relation_type"] == "pivots_to"


def test_force_graph_shape():
    canonical = to_canonical_json(_build_master())
    fg = to_force_graph(canonical)
    assert "nodes" in fg and "links" in fg
    assert fg["nodes"][0]["id"] == "f1"
    assert fg["links"][0]["source"] == "f1"
    assert fg["links"][0]["target"] == "f2"


def test_cytoscape_shape():
    canonical = to_canonical_json(_build_master())
    cy = to_cytoscape(canonical)
    assert "elements" in cy
    assert "nodes" in cy["elements"]
    assert "edges" in cy["elements"]
    assert cy["elements"]["nodes"][0]["data"]["id"] == "f1"
    assert cy["elements"]["edges"][0]["data"]["source"] == "f1"


def test_cosmograph_shape():
    canonical = to_canonical_json(_build_master())
    cg = to_cosmograph(canonical)
    assert "nodes" in cg and "links" in cg
    assert cg["nodes"][0]["id"] == "f1"


def test_dot_valid_syntax():
    canonical = to_canonical_json(_build_master())
    dot = to_dot(canonical)
    assert dot.startswith("digraph chain {")
    assert dot.endswith("}")
    assert '"f1"' in dot
    assert '"f2"' in dot
    assert '->' in dot


def test_all_formats_json_serializable():
    canonical = to_canonical_json(_build_master())
    # canonical, force-graph, cytoscape, cosmograph all must be JSON serializable
    json.dumps(canonical)
    json.dumps(to_force_graph(canonical))
    json.dumps(to_cytoscape(canonical))
    json.dumps(to_cosmograph(canonical))


def test_canonical_empty_graph():
    empty_g = rx.PyDiGraph()
    master = MasterGraph(graph=empty_g, node_map={}, reverse_map={}, generation=0, max_weight=1.0)
    data = to_canonical_json(master)
    assert data["nodes"] == []
    assert data["edges"] == []
