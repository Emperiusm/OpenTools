"""Virtual heterogeneous graph builder and cache for the Cypher DSL executor.

The VirtualGraph overlays entity nodes on top of the MasterGraph (finding
nodes + LINKED edges) so that the executor can traverse across both node
types in a single graph walk.

Node labels:
    Finding           — every FindingNode from the MasterGraph
    Host / IP / CVE / Domain / Port / MitreAttack / Entity
                      — EntityNode instances, label derived from entity.type

Edge types:
    LINKED            — copied from MasterGraph (EdgeData payload)
    MENTIONED_IN      — Entity → Finding (MentionedInEdge payload)

The VirtualGraphCache is an async LRU with per-key build lock, mirroring
the design of GraphCache in opentools.chain.query.graph_cache.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID

import rustworkx as rx

from opentools.chain.models import Entity, EntityMention
from opentools.chain.query.graph_cache import MasterGraph

if TYPE_CHECKING:
    from opentools.chain.query.graph_cache import GraphCache
    from opentools.chain.store_protocol import ChainStoreProtocol


# ─── node / edge payload types ────────────────────────────────────────────────


@dataclass
class EntityNode:
    """Payload attached to entity nodes in the VirtualGraph."""

    entity_id: str
    entity_type: str
    canonical_value: str
    mention_count: int


@dataclass
class MentionedInEdge:
    """Payload for Entity → Finding edges."""

    mention_id: str
    field: str          # MentionField value
    confidence: float
    extractor: str


# ─── label mapping ────────────────────────────────────────────────────────────

_TYPE_TO_LABEL: dict[str, str] = {
    "host": "Host",
    "ip": "IP",
    "cve": "CVE",
    "domain": "Domain",
    "port": "Port",
    "mitre_technique": "MitreAttack",
}

_FINDING_LABEL = "Finding"


def _entity_label(entity_type: str) -> str:
    return _TYPE_TO_LABEL.get(entity_type.lower(), "Entity")


# ─── VirtualGraph ─────────────────────────────────────────────────────────────


@dataclass
class VirtualGraph:
    """Heterogeneous graph combining findings and entities.

    Attributes:
        graph        — rustworkx directed graph
        finding_map  — finding_id → node index in *this* graph
        entity_map   — entity_id  → node index in *this* graph
        reverse_map  — node index → id (finding_id or entity_id)
        node_labels  — node index → label string ("Finding", "Host", …)
        generation   — linker generation from the source MasterGraph
    """

    graph: rx.PyDiGraph
    finding_map: dict[str, int]
    entity_map: dict[str, int]
    reverse_map: dict[int, str]
    node_labels: dict[int, str]
    generation: int


# ─── VirtualGraphBuilder ──────────────────────────────────────────────────────


class VirtualGraphBuilder:
    """Builds a VirtualGraph from a MasterGraph plus entity/mention lists."""

    def build(
        self,
        master: MasterGraph,
        entities: list[Entity],
        mentions: list[EntityMention],
    ) -> VirtualGraph:
        vg = rx.PyDiGraph()
        finding_map: dict[str, int] = {}
        entity_map: dict[str, int] = {}
        reverse_map: dict[int, str] = {}
        node_labels: dict[int, str] = {}

        # ── 1. Copy finding nodes from master ─────────────────────────────
        # master.node_map: finding_id -> master node index
        # We create new node indices in the virtual graph.
        master_to_virtual: dict[int, int] = {}
        for finding_id, master_idx in master.node_map.items():
            node_data = master.graph.get_node_data(master_idx)
            v_idx = vg.add_node(node_data)
            master_to_virtual[master_idx] = v_idx
            finding_map[finding_id] = v_idx
            reverse_map[v_idx] = finding_id
            node_labels[v_idx] = _FINDING_LABEL

        # ── 2. Copy LINKED edges from master ──────────────────────────────
        # edge_list() returns a list of (src_idx, tgt_idx) in master space.
        # edges() returns the corresponding payloads in the same order.
        master_endpoints = list(master.graph.edge_list())
        master_payloads = list(master.graph.edges())
        for (src_m, tgt_m), payload in zip(master_endpoints, master_payloads):
            src_v = master_to_virtual.get(src_m)
            tgt_v = master_to_virtual.get(tgt_m)
            if src_v is not None and tgt_v is not None:
                vg.add_edge(src_v, tgt_v, payload)

        # ── 3. Add entity nodes ───────────────────────────────────────────
        for entity in entities:
            node_data = EntityNode(
                entity_id=entity.id,
                entity_type=entity.type,
                canonical_value=entity.canonical_value,
                mention_count=entity.mention_count,
            )
            v_idx = vg.add_node(node_data)
            entity_map[entity.id] = v_idx
            reverse_map[v_idx] = entity.id
            node_labels[v_idx] = _entity_label(entity.type)

        # ── 4. Add MENTIONED_IN edges: Entity → Finding ───────────────────
        for mention in mentions:
            ent_v = entity_map.get(mention.entity_id)
            fnd_v = finding_map.get(mention.finding_id)
            if ent_v is None or fnd_v is None:
                continue
            edge_data = MentionedInEdge(
                mention_id=mention.id,
                field=str(mention.field),
                confidence=mention.confidence,
                extractor=mention.extractor,
            )
            vg.add_edge(ent_v, fnd_v, edge_data)

        return VirtualGraph(
            graph=vg,
            finding_map=finding_map,
            entity_map=entity_map,
            reverse_map=reverse_map,
            node_labels=node_labels,
            generation=master.generation,
        )


# ─── VirtualGraphCache ────────────────────────────────────────────────────────


class VirtualGraphCache:
    """Async LRU cache of VirtualGraphs with per-key build lock.

    Keyed by ``(user_id_str, generation, include_candidates, engagement_ids)``.
    Capacity bounded by ``maxsize``.  Concurrent callers for the same key
    collapse to a single build — the first waiter builds; subsequent waiters
    re-check and return the cached instance.

    Args:
        store:        ChainStoreProtocol instance
        graph_cache:  GraphCache instance (provides get_master_graph)
        maxsize:      maximum number of cached VirtualGraphs (default 4)
    """

    def __init__(
        self,
        *,
        store: "ChainStoreProtocol",
        graph_cache: "GraphCache",
        maxsize: int = 4,
    ) -> None:
        self.store = store
        self.graph_cache = graph_cache
        self.maxsize = maxsize
        self._cache: dict[tuple, VirtualGraph] = {}
        self._access_order: list[tuple] = []
        self._build_locks: dict[tuple, asyncio.Lock] = {}
        self._builder = VirtualGraphBuilder()

    async def get(
        self,
        *,
        user_id: UUID | None,
        include_candidates: bool = False,
        engagement_ids: tuple[str, ...] | list[str] | None = None,
    ) -> VirtualGraph:
        """Return a VirtualGraph for the given scope, building if necessary."""
        generation = await self.store.current_linker_generation(user_id=user_id)
        # Normalise engagement_ids to a hashable form
        eng_key = tuple(sorted(engagement_ids)) if engagement_ids else None
        key = (
            str(user_id) if user_id else None,
            generation,
            include_candidates,
            eng_key,
        )

        if key in self._cache:
            self._access_order.remove(key)
            self._access_order.append(key)
            return self._cache[key]

        lock = self._build_locks.setdefault(key, asyncio.Lock())
        async with lock:
            # Another waiter may have populated the cache while we waited.
            if key in self._cache:
                self._access_order.remove(key)
                self._access_order.append(key)
                return self._cache[key]

            vg = await self._build(
                user_id=user_id,
                include_candidates=include_candidates,
                engagement_ids=engagement_ids,
            )
            self._cache[key] = vg
            self._access_order.append(key)

            while len(self._access_order) > self.maxsize:
                oldest = self._access_order.pop(0)
                self._cache.pop(oldest, None)
                self._build_locks.pop(oldest, None)

            return vg

    def invalidate(self, *, user_id: UUID | None) -> None:
        """Drop all cached graphs for a specific user."""
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

    # ── internals ─────────────────────────────────────────────────────────────

    async def _build(
        self,
        *,
        user_id: UUID | None,
        include_candidates: bool,
        engagement_ids: tuple[str, ...] | list[str] | None,
    ) -> VirtualGraph:
        master = await self.graph_cache.get_master_graph(
            user_id=user_id,
            include_candidates=include_candidates,
        )
        entities = await self.store.list_entities(user_id=user_id, limit=10_000)
        mentions = await self.store.fetch_all_mentions_in_scope(
            user_id=user_id,
            engagement_ids=list(engagement_ids) if engagement_ids else None,
        )
        return self._builder.build(master, entities, mentions)
