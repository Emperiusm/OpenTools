"""Public plugin API surface for the chain subsystem.

Plugins register extractors, rules, and presets via this module's
re-exported functions so the import path is stable across 3C.1
and future sub-phases.
"""
from __future__ import annotations

from opentools.chain.query.presets import register_query_preset, list_presets
from opentools.chain.types import (
    EntityTypeCategory,
    register_entity_type,
    is_strong_entity_type,
    is_weak_entity_type,
)

__all__ = [
    "register_query_preset",
    "list_presets",
    "register_entity_type",
    "is_strong_entity_type",
    "is_weak_entity_type",
    "EntityTypeCategory",
]
