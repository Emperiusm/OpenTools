"""LinkerContext: shared state passed to rules during a linker run."""
from __future__ import annotations

import math
from dataclasses import dataclass
from uuid import UUID

from opentools.chain.config import ChainConfig


@dataclass
class LinkerContext:
    """State shared across all rules during a single linker run.

    ``is_web`` indicates whether the run is in a multi-user web context,
    which gates the cross-scope privacy enforcement. ``common_entity_threshold``
    is precomputed from scope_total * common_entity_pct so rules can cheaply
    filter entities that appear in too many findings to be informative.
    """
    user_id: UUID | None
    is_web: bool
    scope_total_findings: int
    avg_idf: float
    stopwords_extra: list[str]
    common_entity_pct: float
    common_entity_threshold: int
    config: ChainConfig
    generation: int


def derive_common_entity_threshold(scope_total: int, pct: float) -> int:
    """Return the mention count above which an entity is 'too common' to be signal."""
    return max(1, math.ceil(scope_total * pct))
