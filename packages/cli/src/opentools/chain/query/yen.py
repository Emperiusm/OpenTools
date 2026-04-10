"""Yen's K-shortest paths algorithm on rustworkx.

Standard textbook algorithm: find the shortest path, then iteratively
compute spur paths from each node in the current best path, using edge
and node removal to prevent repetition of previously-found routes.
"""
from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Callable

import rustworkx as rx


@dataclass(order=True)
class _Candidate:
    cost: float
    tiebreak: int = field(compare=True)
    path: list[int] = field(compare=False, default_factory=list)


@dataclass
class RawPath:
    node_indices: list[int]
    total_cost: float
    hops: int


def _path_total_cost(
    graph: rx.PyDiGraph,
    path: list[int],
    cost_key: Callable[[object], float],
) -> float:
    if len(path) < 2:
        return 0.0
    total = 0.0
    for i in range(len(path) - 1):
        edge_data = graph.get_edge_data(path[i], path[i + 1])
        total += cost_key(edge_data)
    return total


def _dijkstra_path(
    graph: rx.PyDiGraph,
    source: int,
    target: int,
    cost_key: Callable[[object], float],
) -> list[int] | None:
    try:
        result = rx.dijkstra_shortest_paths(
            graph,
            source,
            target=target,
            weight_fn=lambda e: cost_key(e),
        )
    except Exception:
        return None
    if target not in result:
        return None
    return list(result[target])


def yens_k_shortest(
    graph: rx.PyDiGraph,
    source: int,
    target: int,
    k: int,
    max_hops: int,
    cost_key: Callable[[object], float],
) -> list[RawPath]:
    """Return up to k distinct simple shortest paths from source to target.

    Uses Yen's algorithm on top of rustworkx.dijkstra_shortest_paths.
    Paths are sorted by total_cost ascending, then by hop count.
    Does not mutate the input graph.
    """
    if source == target:
        return []
    if k <= 0:
        return []

    # 1. Find the initial shortest path
    initial = _dijkstra_path(graph, source, target, cost_key)
    if initial is None:
        return []
    if len(initial) - 1 > max_hops:
        return []

    A: list[list[int]] = [initial]
    B: list[_Candidate] = []
    tiebreak_counter = 0

    while len(A) < k:
        prev = A[-1]
        # For each node in the previous path except the last
        for i in range(len(prev) - 1):
            spur_node = prev[i]
            root_path = prev[: i + 1]

            working = graph.copy()

            # Remove edges that would reproduce already-found paths sharing the root
            for path in A:
                if len(path) > i and path[: i + 1] == root_path:
                    u = path[i]
                    v = path[i + 1]
                    try:
                        working.remove_edge(u, v)
                    except Exception:
                        pass

            # Remove nodes in the root path except the spur node (so the
            # spur path cannot revisit them, enforcing simple paths)
            root_nodes_to_remove = [n for n in root_path if n != spur_node]
            # rustworkx remove_node does NOT renumber, so order doesn't matter
            for n in root_nodes_to_remove:
                try:
                    working.remove_node(n)
                except Exception:
                    pass

            # Dijkstra from spur_node to target
            spur_path = _dijkstra_path(working, spur_node, target, cost_key)
            if spur_path is None:
                continue

            # rootPath ends at spur_node, spurPath starts with spur_node
            total_path = root_path[:-1] + spur_path
            hops = len(total_path) - 1
            if hops > max_hops:
                continue

            # Check for simplicity (defensive — Dijkstra gives simple paths already)
            if len(total_path) != len(set(total_path)):
                continue

            # Check for duplicate in A and B
            if any(total_path == a for a in A):
                continue
            if any(total_path == c.path for c in B):
                continue

            total_cost = _path_total_cost(graph, total_path, cost_key)
            tiebreak_counter += 1
            heapq.heappush(
                B,
                _Candidate(cost=total_cost, tiebreak=tiebreak_counter, path=total_path),
            )

        if not B:
            break

        # Take the lowest-cost candidate; skip duplicates that may have slipped in
        next_best = heapq.heappop(B)
        while next_best.path in A and B:
            next_best = heapq.heappop(B)
        if next_best.path in A:
            break
        A.append(next_best.path)

    # Convert to RawPath objects
    out: list[RawPath] = []
    for path in A:
        cost = _path_total_cost(graph, path, cost_key)
        out.append(RawPath(node_indices=path, total_cost=cost, hops=len(path) - 1))

    # Sort by cost, then by hops
    out.sort(key=lambda p: (p.total_cost, p.hops))
    return out[:k]
