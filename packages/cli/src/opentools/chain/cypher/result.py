"""Query result types."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class QueryStats:
    duration_ms: float = 0.0
    bindings_explored: int = 0
    rows_returned: int = 0


@dataclass
class SubgraphProjection:
    node_indices: set[int] = field(default_factory=set)
    edge_tuples: set[tuple[int, int]] = field(default_factory=set)


@dataclass
class QueryResult:
    columns: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    subgraph: SubgraphProjection | None = None
    stats: QueryStats = field(default_factory=QueryStats)
    truncated: bool = False
    truncation_reason: str | None = None
