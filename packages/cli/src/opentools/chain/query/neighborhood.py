"""Neighborhood BFS from a seed finding."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Literal

from opentools.chain.query.graph_cache import (
    EdgeData,
    FindingNode,
    MasterGraph,
    PathEdgeRef,
    PathNode,
)


@dataclass
class NeighborhoodResult:
    seed_finding_id: str
    radius: int
    direction: str
    nodes: list[PathNode] = field(default_factory=list)
    edges: list[PathEdgeRef] = field(default_factory=list)


def neighborhood(
    master: MasterGraph,
    seed: int,
    *,
    hops: int = 2,
    direction: Literal["out", "in", "both"] = "both",
) -> NeighborhoodResult:
    """BFS from seed up to ``hops`` edges in the given direction."""
    seed_node = master.graph.get_node_data(seed)
    if not isinstance(seed_node, FindingNode):
        return NeighborhoodResult(seed_finding_id="", radius=hops, direction=direction)

    visited: dict[int, int] = {seed: 0}
    queue: deque[tuple[int, int]] = deque([(seed, 0)])
    edges_collected: list[tuple[int, int]] = []

    while queue:
        node, dist = queue.popleft()
        if dist >= hops:
            continue
        if direction in ("out", "both"):
            for nxt in master.graph.successor_indices(node):
                edges_collected.append((node, nxt))
                if nxt not in visited or visited[nxt] > dist + 1:
                    visited[nxt] = dist + 1
                    queue.append((nxt, dist + 1))
        if direction in ("in", "both"):
            for prv in master.graph.predecessor_indices(node):
                edges_collected.append((prv, node))
                if prv not in visited or visited[prv] > dist + 1:
                    visited[prv] = dist + 1
                    queue.append((prv, dist + 1))

    nodes: list[PathNode] = []
    for idx in visited:
        data = master.graph.get_node_data(idx)
        if isinstance(data, FindingNode):
            nodes.append(
                PathNode(
                    finding_id=data.finding_id, index=idx,
                    severity=data.severity, tool=data.tool, title=data.title,
                )
            )

    edges: list[PathEdgeRef] = []
    seen_edges: set[tuple[int, int]] = set()
    for src_idx, tgt_idx in edges_collected:
        if (src_idx, tgt_idx) in seen_edges:
            continue
        if src_idx not in visited or tgt_idx not in visited:
            continue
        try:
            ed = master.graph.get_edge_data(src_idx, tgt_idx)
        except Exception:
            continue
        if not isinstance(ed, EdgeData):
            continue
        src_data = master.graph.get_node_data(src_idx)
        tgt_data = master.graph.get_node_data(tgt_idx)
        if not isinstance(src_data, FindingNode) or not isinstance(tgt_data, FindingNode):
            continue
        edges.append(
            PathEdgeRef(
                source_finding_id=src_data.finding_id,
                target_finding_id=tgt_data.finding_id,
                weight=ed.weight, status=ed.status,
                reasons_summary=[r.rule for r in ed.reasons],
                llm_rationale=ed.llm_rationale, llm_relation_type=ed.llm_relation_type,
            )
        )
        seen_edges.add((src_idx, tgt_idx))

    return NeighborhoodResult(
        seed_finding_id=seed_node.finding_id,
        radius=hops,
        direction=direction,
        nodes=nodes,
        edges=edges,
    )
