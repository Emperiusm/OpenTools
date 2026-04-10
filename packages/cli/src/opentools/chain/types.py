"""Entity type registry, shared enums, and classification helpers."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Callable


class EntityTypeCategory(StrEnum):
    STRONG = "strong"
    WEAK = "weak"


class MentionField(StrEnum):
    TITLE = "title"
    DESCRIPTION = "description"
    EVIDENCE = "evidence"
    FILE_PATH = "file_path"
    IOC = "ioc"


class RelationStatus(StrEnum):
    AUTO_CONFIRMED = "auto_confirmed"
    CANDIDATE = "candidate"
    REJECTED = "rejected"
    USER_CONFIRMED = "user_confirmed"
    USER_REJECTED = "user_rejected"


class LinkerMode(StrEnum):
    RULES_ONLY = "rules_only"
    RULES_PLUS_LLM = "rules_plus_llm"
    MANUAL_MERGE = "manual_merge"
    MANUAL_SPLIT = "manual_split"


class LinkerScope(StrEnum):
    ENGAGEMENT = "engagement"
    CROSS_ENGAGEMENT = "cross_engagement"
    FINDING_BATCH = "finding_batch"
    FINDING_SINGLE = "finding_single"
    MANUAL_MERGE = "manual_merge"
    MANUAL_SPLIT = "manual_split"


@dataclass(frozen=True)
class EntityTypeSpec:
    name: str
    category: EntityTypeCategory
    normalizer: Callable[[str], str]


ENTITY_TYPE_REGISTRY: dict[str, EntityTypeSpec] = {}


def register_entity_type(
    name: str,
    *,
    category: EntityTypeCategory,
    normalizer: Callable[[str], str],
) -> None:
    """Register an entity type. Idempotent for identical re-registrations.

    Raises ValueError if the same name is registered with different category
    or normalizer (protects plugins from silently clobbering each other).
    """
    existing = ENTITY_TYPE_REGISTRY.get(name)
    if existing is not None:
        if existing.category == category and existing.normalizer is normalizer:
            return  # idempotent
        raise ValueError(f"entity type {name!r} already registered with different spec")
    ENTITY_TYPE_REGISTRY[name] = EntityTypeSpec(name=name, category=category, normalizer=normalizer)


def is_strong_entity_type(name: str) -> bool:
    spec = ENTITY_TYPE_REGISTRY.get(name)
    return spec is not None and spec.category == EntityTypeCategory.STRONG


def is_weak_entity_type(name: str) -> bool:
    spec = ENTITY_TYPE_REGISTRY.get(name)
    return spec is not None and spec.category == EntityTypeCategory.WEAK


# Built-in registrations happen in opentools.chain.normalizers (Task 6).
# This module provides only the registry machinery and type enums.
