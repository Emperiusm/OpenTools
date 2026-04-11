"""Master graph cache + PathResult types for chain query engine."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Literal
from uuid import UUID

import rustworkx as rx

from opentools.chain.models import RelationReason
from opentools.chain.query.cost import edge_cost
from opentools.chain.types import RelationStatus

if TYPE_CHECKING:
    from opentools.chain.store_protocol import ChainStoreProtocol


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
    """Async LRU cache of master graphs with per-key build lock (spec G4).

    Keyed by ``(user_id, generation, include_candidates, include_rejected)``.
    Capacity bounded by ``maxsize``. The graph is invalidated when the linker
    generation advances. Subgraph projection is not cached — it's cheap
    (O(V' + E')) and always derived on demand.

    Concurrent callers for the same key collapse to a single build via a
    per-key ``asyncio.Lock``: the first waiter builds and populates the
    cache; subsequent waiters re-check the cache under the lock and return
    the cached instance without rebuilding.
    """

    def __init__(self, *, store: "ChainStoreProtocol", maxsize: int = 8) -> None:
        self.store = store
        self.maxsize = maxsize
        self._cache: dict[tuple, MasterGraph] = {}
        self._access_order: list[tuple] = []
        self._build_locks: dict[tuple, asyncio.Lock] = {}

    async def get_master_graph(
        self,
        *,
        user_id: UUID | None,
        include_candidates: bool = False,
        include_rejected: bool = False,
    ) -> MasterGraph:
        generation = await self.store.current_linker_generation(user_id=user_id)
        key = (
            str(user_id) if user_id else None,
            generation,
            include_candidates,
            include_rejected,
        )

        if key in self._cache:
            # LRU bump
            self._access_order.remove(key)
            self._access_order.append(key)
            return self._cache[key]

        # Per-key build lock prevents duplicate concurrent builds (spec G4).
        # Use setdefault so racing callers observe the same lock instance.
        lock = self._build_locks.setdefault(key, asyncio.Lock())
        async with lock:
            # Another waiter may have populated the cache while we waited.
            if key in self._cache:
                self._access_order.remove(key)
                self._access_order.append(key)
                return self._cache[key]

            master = await self._build_master_graph(
                user_id, generation, include_candidates, include_rejected,
            )
            self._cache[key] = master
            self._access_order.append(key)

            # Evict oldest if over capacity
            while len(self._access_order) > self.maxsize:
                oldest = self._access_order.pop(0)
                self._cache.pop(oldest, None)
                self._build_locks.pop(oldest, None)

            return master

    def invalidate(self, *, user_id: UUID | None) -> None:
        """Drop all cached graphs for a specific user (all flag combinations).

        Sync because it only mutates in-memory dicts; no store access.
        """
        user_key = str(user_id) if user_id else None
        to_remove = [k for k in self._access_order if k[0] == user_key]
        for k in to_remove:
            self._access_order.remove(k)
            self._cache.pop(k, None)
            self._build_locks.pop(k, None)

    def clear(self) -> None:
        self._cache.clear()
        self._access_order.clear()
        self._build_locks.clear()

    def subgraph(self, master: MasterGraph, node_indices: list[int]) -> rx.PyDiGraph:
        """Project a master graph to a subset of nodes via rustworkx.subgraph()."""
        return master.graph.subgraph(node_indices)

    # ─── internals ─────────────────────────────────────────────────────

    def _status_filter(
        self, include_candidates: bool, include_rejected: bool
    ) -> set[RelationStatus]:
        allowed: set[RelationStatus] = {
            RelationStatus.AUTO_CONFIRMED,
            RelationStatus.USER_CONFIRMED,
        }
        if include_candidates:
            allowed.add(RelationStatus.CANDIDATE)
        if include_rejected:
            allowed.add(RelationStatus.REJECTED)
            allowed.add(RelationStatus.USER_REJECTED)
        return allowed

    async def _build_master_graph(
        self,
        user_id: UUID | None,
        generation: int,
        include_candidates: bool,
        include_rejected: bool,
    ) -> MasterGraph:
        graph = rx.PyDiGraph()
        node_map: dict[str, int] = {}
        reverse_map: dict[int, str] = {}

        # Collect relations and track which finding ids appear. Stream via
        # the protocol so backends can push this down (Postgres server-side
        # cursor, aiosqlite async row iteration, etc.).
        allowed_statuses = self._status_filter(include_candidates, include_rejected)
        relations: list = []
        rel_finding_ids: set[str] = set()
        async for rel in self.store.stream_relations_in_scope(
            user_id=user_id, statuses=allowed_statuses,
        ):
            relations.append(rel)
            rel_finding_ids.add(rel.source_finding_id)
            rel_finding_ids.add(rel.target_finding_id)

        # Load findings for the graph nodes. If there are no relations we
        # still load all findings so single-node / endpoint-only queries work.
        if rel_finding_ids:
            findings = await self.store.fetch_findings_by_ids(
                list(rel_finding_ids), user_id=user_id,
            )
        else:
            all_ids = await self.store.fetch_all_finding_ids(user_id=user_id)
            findings = await self.store.fetch_findings_by_ids(
                all_ids, user_id=user_id,
            )

        for f in findings:
            node = FindingNode(
                finding_id=f.id,
                severity=str(f.severity) if f.severity is not None else None,
                tool=f.tool,
                title=f.title,
                created_at=f.created_at,
            )
            idx = graph.add_node(node)
            node_map[f.id] = idx
            reverse_map[idx] = f.id

        # Compute max weight for normalized cost
        max_weight = max((r.weight for r in relations), default=1.0)
        if max_weight <= 0:
            max_weight = 1.0

        # Add edges
        for r in relations:
            src = node_map.get(r.source_finding_id)
            tgt = node_map.get(r.target_finding_id)
            if src is None or tgt is None:
                continue
            status_value = (
                r.status.value if hasattr(r.status, "value") else str(r.status)
            )
            data = EdgeData(
                relation_id=r.id,
                weight=r.weight,
                cost=edge_cost(r.weight, max_weight),
                status=status_value,
                symmetric=bool(r.symmetric),
                reasons=list(r.reasons),
                llm_rationale=r.llm_rationale,
                llm_relation_type=r.llm_relation_type,
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
