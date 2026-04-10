"""Bounded simple path enumeration."""
from __future__ import annotations

import time

import rustworkx as rx

from opentools.chain.query.graph_cache import (
    EdgeData,
    FindingNode,
    MasterGraph,
    PathEdgeRef,
    PathNode,
    PathResult,
)


def simple_paths_bounded(
    master: MasterGraph,
    sources: set[int],
    targets: set[int],
    *,
    max_hops: int = 4,
    max_results: int = 50,
    timeout_sec: float = 10.0,
) -> tuple[list[PathResult], bool, str | None]:
    """Return up to max_results simple paths between any source and target.

    Returns (results, truncated, reason). truncated=True if max_results or
    timeout reached. rustworkx.all_simple_paths already guarantees simple
    (acyclic) paths.
    """
    if max_results <= 0:
        return [], True, "max_results"

    deadline = time.monotonic() + timeout_sec
    results: list[PathResult] = []
    truncated = False
    reason: str | None = None

    for source in sources:
        if truncated:
            break
        for target in targets:
            if source == target:
                continue
            if time.monotonic() > deadline:
                truncated = True
                reason = "timeout"
                break
            try:
                iter_paths = rx.all_simple_paths(master.graph, source, target, cutoff=max_hops)
            except Exception:
                continue
            for path_indices in iter_paths:
                if time.monotonic() > deadline:
                    truncated = True
                    reason = "timeout"
                    break
                pr = _build_path_result(master, list(path_indices))
                if pr is not None:
                    results.append(pr)
                    if len(results) >= max_results:
                        truncated = True
                        reason = "max_results"
                        break
            if truncated:
                break

    results.sort(key=lambda p: (p.total_cost, p.length))
    return results, truncated, reason


def _build_path_result(master: MasterGraph, indices: list[int]) -> PathResult | None:
    nodes: list[PathNode] = []
    for idx in indices:
        try:
            node_data = master.graph.get_node_data(idx)
        except Exception:
            return None
        if not isinstance(node_data, FindingNode):
            return None
        nodes.append(
            PathNode(
                finding_id=node_data.finding_id,
                index=idx,
                severity=node_data.severity,
                tool=node_data.tool,
                title=node_data.title,
            )
        )

    edges: list[PathEdgeRef] = []
    total_cost = 0.0
    for i in range(len(indices) - 1):
        try:
            ed = master.graph.get_edge_data(indices[i], indices[i + 1])
        except Exception:
            return None
        if not isinstance(ed, EdgeData):
            return None
        edges.append(
            PathEdgeRef(
                source_finding_id=nodes[i].finding_id,
                target_finding_id=nodes[i + 1].finding_id,
                weight=ed.weight,
                status=ed.status,
                reasons_summary=[r.rule for r in ed.reasons],
                llm_rationale=ed.llm_rationale,
                llm_relation_type=ed.llm_relation_type,
            )
        )
        total_cost += ed.cost

    return PathResult(
        nodes=nodes,
        edges=edges,
        total_cost=total_cost,
        length=len(edges),
        source_finding_id=nodes[0].finding_id,
        target_finding_id=nodes[-1].finding_id,
    )
