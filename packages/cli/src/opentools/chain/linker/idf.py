"""Inverse Document Frequency (IDF) weighting helpers.

Rare entities (low mention_count) are amplified; common entities are
dampened. Clamped to [0.2, 2.0] so no single entity dominates or disappears
entirely.
"""
from __future__ import annotations

import math

from opentools.chain.models import Entity


def compute_avg_idf(entities: list[Entity], scope_total: int) -> float:
    """Return the mean IDF across a set of entities.

    Used once per linker run to set the denominator for ``idf_factor``.
    Returns 1.0 for an empty list (factor becomes log-neutral).
    """
    if not entities:
        return 1.0
    return sum(
        math.log((scope_total + 1) / (e.mention_count + 1))
        for e in entities
    ) / len(entities)


def idf_factor(entity: Entity, scope_total: int, avg_idf: float) -> float:
    """Return the IDF multiplier for a shared-entity contribution.

    Rare entities (low mention_count) → factor > 1.0 (amplified).
    Common entities → factor < 1.0 (dampened).
    Clamped to [0.2, 2.0].
    """
    idf = math.log((scope_total + 1) / (entity.mention_count + 1))
    # Square the IDF so common entities (low raw IDF) are dampened more
    # aggressively while rare entities remain strongly amplified.
    raw = (idf ** 2) / max(avg_idf, 0.001)
    return max(0.2, min(2.0, raw))
