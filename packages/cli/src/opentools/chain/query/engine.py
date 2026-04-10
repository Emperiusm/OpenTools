"""ChainQueryEngine: k-shortest paths with virtual super-source/sink reduction."""
from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

import rustworkx as rx

from opentools.chain.config import ChainConfig
from opentools.chain.query.endpoints import EndpointSpec, resolve_endpoint
from opentools.chain.query.graph_cache import (
    EdgeData,
    FindingNode,
    GraphCache,
    MasterGraph,
    PathEdgeRef,
    PathNode,
    PathResult,
)
from opentools.chain.query.yen import RawPath, yens_k_shortest
from opentools.chain.store_extensions import ChainStore


# Sentinel payloads for virtual nodes
_VIRTUAL_SOURCE = "__super_source__"
_VIRTUAL_SINK = "__super_sink__"
_VIRTUAL_COST = 0.0


class _VirtualEdge:
    """Zero-cost sentinel edge for virtual super-source/sink connections."""
    cost = _VIRTUAL_COST


def _edge_cost(edge_data) -> float:
    if isinstance(edge_data, _VirtualEdge):
        return 0.0
    if hasattr(edge_data, "cost"):
        return float(edge_data.cost)
    return float(edge_data)


class ChainQueryEngine:
    def __init__(
        self,
        *,
        store: ChainStore,
        graph_cache: GraphCache,
        config: ChainConfig,
    ) -> None:
        self.store = store
        self.graph_cache = graph_cache
        self.config = config

    def k_shortest_paths(
        self,
        *,
        from_spec: EndpointSpec,
        to_spec: EndpointSpec,
        user_id: UUID | None,
        k: int = 5,
        max_hops: int = 6,
        include_candidates: bool = False,
    ) -> list[PathResult]:
        master = self.graph_cache.get_master_graph(
            user_id=user_id,
            include_candidates=include_candidates,
            include_rejected=False,
        )
        source_set = resolve_endpoint(from_spec, master, self.store)
        target_set = resolve_endpoint(to_spec, master, self.store)

        if not source_set or not target_set:
            return []

        # Build a scratch copy with virtual super-source and super-sink
        scratch = master.graph.copy()
        super_source = scratch.add_node(_VIRTUAL_SOURCE)
        super_sink = scratch.add_node(_VIRTUAL_SINK)

        for src in source_set:
            scratch.add_edge(super_source, src, _VirtualEdge())
        for tgt in target_set:
            scratch.add_edge(tgt, super_sink, _VirtualEdge())

        # Yen's over the scratch graph (+2 hops to account for virtual endpoints)
        raw_paths = yens_k_shortest(
            scratch,
            source=super_source,
            target=super_sink,
            k=k,
            max_hops=max_hops + 2,
            cost_key=_edge_cost,
        )

        results: list[PathResult] = []
        for raw in raw_paths:
            # Strip virtual endpoints: raw.node_indices[0] == super_source, [-1] == super_sink
            real_indices = raw.node_indices[1:-1]
            if not real_indices:
                continue  # skip degenerate
            if len(real_indices) - 1 > max_hops:
                continue  # hop cap after stripping

            path_result = self._build_path_result(master, real_indices, raw.total_cost)
            if path_result is not None:
                results.append(path_result)

        # Sort by cost (should already be sorted but stabilize)
        results.sort(key=lambda p: (p.total_cost, p.length))
        return results[:k]

    # ─── helpers ──────────────────────────────────────────────────────

    def _build_path_result(
        self,
        master: MasterGraph,
        indices: list[int],
        total_cost: float,
    ) -> PathResult | None:
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
        for i in range(len(indices) - 1):
            try:
                edge_data = master.graph.get_edge_data(indices[i], indices[i + 1])
            except Exception:
                return None
            if not isinstance(edge_data, EdgeData):
                return None
            edges.append(
                PathEdgeRef(
                    source_finding_id=nodes[i].finding_id,
                    target_finding_id=nodes[i + 1].finding_id,
                    weight=edge_data.weight,
                    status=edge_data.status,
                    reasons_summary=[r.rule for r in edge_data.reasons],
                    llm_rationale=edge_data.llm_rationale,
                    llm_relation_type=edge_data.llm_relation_type,
                )
            )

        # Recompute total cost from real edges (excludes virtual edges)
        real_cost = sum(
            _edge_cost(master.graph.get_edge_data(indices[i], indices[i + 1]))
            for i in range(len(indices) - 1)
        )

        return PathResult(
            nodes=nodes,
            edges=edges,
            total_cost=real_cost,
            length=len(edges),
            source_finding_id=nodes[0].finding_id,
            target_finding_id=nodes[-1].finding_id,
        )
