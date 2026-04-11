"""Centralized content-addressed cache key functions.

All cache keys in the chain package go through this module so that
cache invalidation logic (bumping schema versions, changing input
composition) happens in one place.

All keys are user-scoped (spec G37 — prevents cross-user side-channel
leaks via content-addressed cache).
"""
from __future__ import annotations

import hashlib
from uuid import UUID


def _user_part(user_id: UUID | None) -> str:
    return str(user_id) if user_id else "_cli"


def extraction_cache_key(
    *,
    text: str,
    provider: str,
    model: str,
    schema_version: int,
    user_id: UUID | None,
) -> str:
    """Cache key for LLM entity extraction results."""
    payload = (
        f"extraction|{text}|{provider}|{model}|{schema_version}|"
        f"{_user_part(user_id)}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def link_classification_cache_key(
    *,
    source_id: str,
    target_id: str,
    provider: str,
    model: str,
    schema_version: int,
    user_id: UUID | None,
) -> str:
    """Cache key for LLM link classification results."""
    payload = (
        f"link|{source_id}|{target_id}|{provider}|{model}|"
        f"{schema_version}|{_user_part(user_id)}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def narration_cache_key(
    *,
    path_finding_ids: list[str],
    edge_reasons_summary: list[str],
    provider: str,
    model: str,
    schema_version: int,
    user_id: UUID | None,
) -> str:
    """Cache key for LLM path narration results."""
    finding_ids = ",".join(path_finding_ids)
    reasons = "+".join(sorted(edge_reasons_summary))
    payload = (
        f"narration|{finding_ids}|{reasons}|{provider}|{model}|"
        f"{schema_version}|{_user_part(user_id)}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
