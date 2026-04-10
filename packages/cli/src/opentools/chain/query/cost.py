"""Edge cost function for path queries.

Uses log-probability formulation:
    cost = -log(weight / max_edge_weight) + epsilon

Summing costs along a path = log of product of normalized weights,
which is the mathematically correct way to combine independent
probabilistic evidence. Stronger paths have lower cumulative cost.
The epsilon term provides a length tiebreak.
"""
from __future__ import annotations

from math import log


EPSILON = 0.01
MIN_NORMALIZED = 1e-6


def edge_cost(weight: float, max_edge_weight: float) -> float:
    """Return the log-probability cost for an edge.

    weight <= 0 gets a very high cost (because -log(epsilon) is large).
    """
    normalized = max(weight / max(max_edge_weight, 0.01), MIN_NORMALIZED)
    return -log(normalized) + EPSILON
