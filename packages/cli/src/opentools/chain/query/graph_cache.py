"""Master graph cache + PathResult types for chain query engine."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from uuid import UUID

import orjson
import rustworkx as rx

from opentools.chain.models import RelationReason
from opentools.chain.query.cost import edge_cost
from opentools.chain.store_extensions import ChainStore
from opentools.chain.types import RelationStatus


# ─── node/edge payloads attached to rustworkx nodes ───────────────────


@dataclass
class FindingNode:
    finding_id: str
    severity: str | None
    tool: str | None
    title: str | None
    created_at: datetime | None


@dataclass
class EdgeData:
    relation_id: str
    weight: float
    cost: float
    status: str
    symmetric: bool
    reasons: list[RelationReason]
    llm_rationale: str | None
    llm_relation_type: str | None


# ─── PathResult hierarchy (consumed by path query executors) ──────────


@dataclass
class PathNode:
    """One node in a query result path."""
    finding_id: str
    index: int                      # rustworkx node index in the master graph
    severity: str | None
    tool: str | None
    title: str | None


@dataclass
class PathEdgeRef:
    """One edge in a query result path."""
    source_finding_id: str
    target_finding_id: str
    weight: float
    status: str                     # RelationStatus.value
    reasons_summary: list[str]      # rule names that fired
    llm_rationale: str | None
    llm_relation_type: str | None


@dataclass
class PathResult:
    """Canonical return type for all path query executors."""
    nodes: list[PathNode]
    edges: list[PathEdgeRef]
    total_cost: float
    length: int                     # number of edges
    source_finding_id: str
    target_finding_id: str
    truncated: bool = False
    truncation_reason: str | None = None
    narration: str | None = None


# ─── Master graph + cache ─────────────────────────────────────────────


@dataclass
class MasterGraph:
    graph: rx.PyDiGraph
    node_map: dict[str, int]        # finding_id -> rustworkx node index
    reverse_map: dict[int, str]     # rustworkx node index -> finding_id
    generation: int
    max_weight: float


class GraphCache:
    """LRU cache of master graphs keyed by (user_id, generation, include_candidates, include_rejected).

    Cache capacity is bounded by ``maxsize``. The graph is invalidated
    when the linker generation advances. Subgraph projection is not
    cached — it's cheap (O(V' + E')) and always derived on demand.
    """

    def __init__(self, *, store: ChainStore, maxsize: int = 8) -> None:
        self.store = store
        self.maxsize = maxsize
        self._cache: dict[tuple, MasterGraph] = {}
        self._access_order: list[tuple] = []

    def get_master_graph(
        self,
        *,
        user_id: UUID | None,
        include_candidates: bool = False,
        include_rejected: bool = False,
    ) -> MasterGraph:
        generation = self._current_generation(user_id)
        key = (str(user_id) if user_id else None, generation, include_candidates, include_rejected)

        if key in self._cache:
            # LRU bump
            self._access_order.remove(key)
            self._access_order.append(key)
            return self._cache[key]

        master = self._build_master_graph(user_id, generation, include_candidates, include_rejected)
        self._cache[key] = master
        self._access_order.append(key)

        # Evict oldest if over capacity
        while len(self._access_order) > self.maxsize:
            oldest = self._access_order.pop(0)
            self._cache.pop(oldest, None)

        return master

    def invalidate(self, *, user_id: UUID | None) -> None:
        """Drop all cached graphs for a specific user (all flag combinations)."""
        user_key = str(user_id) if user_id else None
        to_remove = [k for k in self._access_order if k[0] == user_key]
        for k in to_remove:
            self._access_order.remove(k)
            self._cache.pop(k, None)

    def clear(self) -> None:
        self._cache.clear()
        self._access_order.clear()

    def subgraph(self, master: MasterGraph, node_indices: list[int]) -> rx.PyDiGraph:
        """Project a master graph to a subset of nodes via rustworkx.subgraph()."""
        return master.graph.subgraph(node_indices)

    # ─── internals ─────────────────────────────────────────────────────

    def _current_generation(self, user_id: UUID | None) -> int:
        row = self.store.execute_one(
            "SELECT COALESCE(MAX(generation), 0) FROM linker_run"
        )
        return row[0] if row else 0

    def _status_filter(self, include_candidates: bool, include_rejected: bool) -> list[str]:
        allowed = [
            RelationStatus.AUTO_CONFIRMED.value,
            RelationStatus.USER_CONFIRMED.value,
        ]
        if include_candidates:
            allowed.append(RelationStatus.CANDIDATE.value)
        if include_rejected:
            allowed.append(RelationStatus.REJECTED.value)
            allowed.append(RelationStatus.USER_REJECTED.value)
        return allowed

    def _build_master_graph(
        self,
        user_id: UUID | None,
        generation: int,
        include_candidates: bool,
        include_rejected: bool,
    ) -> MasterGraph:
        graph = rx.PyDiGraph()
        node_map: dict[str, int] = {}
        reverse_map: dict[int, str] = {}

        # Load relations first so we know which findings are in the graph
        statuses = self._status_filter(include_candidates, include_rejected)
        placeholders = ",".join("?" * len(statuses))
        rel_rows = self.store.execute_all(
            f"SELECT * FROM finding_relation WHERE status IN ({placeholders})",
            tuple(statuses),
        )

        if not rel_rows:
            # Still include findings so single-node queries work
            rel_finding_ids: set[str] = set()
        else:
            rel_finding_ids = set()
            for r in rel_rows:
                rel_finding_ids.add(r["source_finding_id"])
                rel_finding_ids.add(r["target_finding_id"])

        # Load findings that appear in relations (or all if no relations)
        if rel_finding_ids:
            placeholders = ",".join("?" * len(rel_finding_ids))
            finding_rows = self.store.execute_all(
                f"SELECT id, severity, tool, title, created_at FROM findings "
                f"WHERE id IN ({placeholders}) AND deleted_at IS NULL",
                tuple(rel_finding_ids),
            )
        else:
            finding_rows = self.store.execute_all(
                "SELECT id, severity, tool, title, created_at FROM findings WHERE deleted_at IS NULL"
            )

        for row in finding_rows:
            node = FindingNode(
                finding_id=row["id"],
                severity=row["severity"],
                tool=row["tool"],
                title=row["title"],
                created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else None,
            )
            idx = graph.add_node(node)
            node_map[row["id"]] = idx
            reverse_map[idx] = row["id"]

        # Compute max weight for normalized cost
        max_weight = max((r["weight"] for r in rel_rows), default=1.0)
        if max_weight <= 0:
            max_weight = 1.0

        # Add edges
        for r in rel_rows:
            src = node_map.get(r["source_finding_id"])
            tgt = node_map.get(r["target_finding_id"])
            if src is None or tgt is None:
                continue
            reasons = [RelationReason.model_validate(rr) for rr in orjson.loads(r["reasons_json"])]
            data = EdgeData(
                relation_id=r["id"],
                weight=r["weight"],
                cost=edge_cost(r["weight"], max_weight),
                status=r["status"],
                symmetric=bool(r["symmetric"]),
                reasons=reasons,
                llm_rationale=r["llm_rationale"],
                llm_relation_type=r["llm_relation_type"],
            )
            graph.add_edge(src, tgt, data)
            if data.symmetric:
                # Add the reverse edge so undirected paths work
                graph.add_edge(tgt, src, data)

        return MasterGraph(
            graph=graph,
            node_map=node_map,
            reverse_map=reverse_map,
            generation=generation,
            max_weight=max_weight,
        )
