"""Graph output format adapters.

All adapters start from a canonical schema_version=1.0 JSON shape
produced by to_canonical_json. Downstream viz libraries consume the
lib-specific variants without round-tripping through disparate
intermediate formats.
"""
from __future__ import annotations

from typing import Any

import rustworkx as rx

from opentools.chain.query.graph_cache import EdgeData, FindingNode, MasterGraph


SCHEMA_VERSION = "1.0"


def to_canonical_json(master: MasterGraph, subgraph: rx.PyDiGraph | None = None) -> dict:
    """Canonical graph-json shape.

    If ``subgraph`` is provided, emit nodes/edges from that; otherwise
    use the full master graph.
    """
    graph = subgraph if subgraph is not None else master.graph

    nodes: list[dict] = []
    for idx in graph.node_indices():
        data = graph.get_node_data(idx)
        if not isinstance(data, FindingNode):
            continue
        nodes.append({
            "id": data.finding_id,
            "type": "finding",
            "severity": data.severity,
            "tool": data.tool,
            "title": data.title,
        })

    edges: list[dict] = []
    # Walk node pairs to extract edges (rustworkx edge_list returns (src, tgt))
    try:
        edge_pairs = graph.edge_list()
    except Exception:
        edge_pairs = []

    for src_idx, tgt_idx in edge_pairs:
        src_data = graph.get_node_data(src_idx)
        tgt_data = graph.get_node_data(tgt_idx)
        if not isinstance(src_data, FindingNode) or not isinstance(tgt_data, FindingNode):
            continue
        try:
            ed = graph.get_edge_data(src_idx, tgt_idx)
        except Exception:
            continue
        if not isinstance(ed, EdgeData):
            continue
        edges.append({
            "source": src_data.finding_id,
            "target": tgt_data.finding_id,
            "weight": ed.weight,
            "status": ed.status,
            "symmetric": ed.symmetric,
            "reasons": [r.rule for r in ed.reasons],
            "relation_type": ed.llm_relation_type,
            "rationale": ed.llm_rationale,
        })

    return {
        "schema_version": SCHEMA_VERSION,
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "generation": master.generation,
            "max_weight": master.max_weight,
        },
    }


def to_force_graph(canonical: dict) -> dict:
    """Convert to vasturiano/force-graph shape: {nodes, links}."""
    return {
        "nodes": [
            {
                "id": n["id"],
                "name": n.get("title") or n["id"],
                "severity": n.get("severity"),
                "tool": n.get("tool"),
            }
            for n in canonical["nodes"]
        ],
        "links": [
            {
                "source": e["source"],
                "target": e["target"],
                "value": e["weight"],
                "status": e["status"],
            }
            for e in canonical["edges"]
        ],
    }


def to_cytoscape(canonical: dict) -> dict:
    """Convert to cytoscape.js shape: {elements: {nodes, edges}} with nested data."""
    return {
        "elements": {
            "nodes": [
                {
                    "data": {
                        "id": n["id"],
                        "label": n.get("title") or n["id"],
                        "severity": n.get("severity"),
                        "tool": n.get("tool"),
                    }
                }
                for n in canonical["nodes"]
            ],
            "edges": [
                {
                    "data": {
                        "id": f"{e['source']}-{e['target']}",
                        "source": e["source"],
                        "target": e["target"],
                        "weight": e["weight"],
                        "status": e["status"],
                    }
                }
                for e in canonical["edges"]
            ],
        }
    }


def to_cosmograph(canonical: dict) -> dict:
    """Convert to cosmograph shape: {nodes, links} (similar to force-graph)."""
    return {
        "nodes": [
            {
                "id": n["id"],
                "label": n.get("title") or n["id"],
                "category": n.get("severity"),
            }
            for n in canonical["nodes"]
        ],
        "links": [
            {
                "source": e["source"],
                "target": e["target"],
                "weight": e["weight"],
            }
            for e in canonical["edges"]
        ],
    }


def to_dot(canonical: dict) -> str:
    """Convert to Graphviz DOT syntax."""
    lines: list[str] = ["digraph chain {"]
    lines.append('  rankdir=LR;')
    lines.append('  node [shape=box, style=filled, fontname="sans-serif"];')
    lines.append('  edge [fontname="sans-serif", fontsize=10];')

    for n in canonical["nodes"]:
        label = (n.get("title") or n["id"]).replace('"', r"\"")
        color = _severity_color(n.get("severity"))
        lines.append(f'  "{n["id"]}" [label="{label}", fillcolor="{color}"];')

    for e in canonical["edges"]:
        label = f"{e['weight']:.2f}"
        lines.append(f'  "{e["source"]}" -> "{e["target"]}" [label="{label}"];')

    lines.append("}")
    return "\n".join(lines)


def _severity_color(severity: str | None) -> str:
    if severity is None:
        return "white"
    mapping = {
        "critical": "#e0b0ff",
        "high": "#ffb3b3",
        "medium": "#ffe0b3",
        "low": "#ffffb3",
        "info": "#d3d3d3",
    }
    return mapping.get(severity.lower(), "white")
