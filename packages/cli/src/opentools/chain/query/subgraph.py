"""Predicate-filtered subgraph projection."""
from __future__ import annotations

from typing import Callable

import rustworkx as rx

from opentools.chain.query.graph_cache import FindingNode, MasterGraph


def filter_subgraph(master: MasterGraph, predicate: Callable) -> rx.PyDiGraph:
    """Return an induced subgraph of nodes matching the predicate."""
    keep: list[int] = []
    for idx in master.graph.node_indices():
        data = master.graph.get_node_data(idx)
        if not isinstance(data, FindingNode):
            continue
        try:
            if predicate(data):
                keep.append(idx)
        except Exception:
            continue
    return master.graph.subgraph(keep)
