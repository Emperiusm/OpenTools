"""Pydantic models for chain data layer.

The web backend mirrors these as SQLModel tables in packages/web/backend/app/models.py.
The CLI SQLite backend creates corresponding tables via SQLAlchemy Core in store_extensions.py.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from opentools.chain.types import (
    LinkerMode,
    LinkerScope,
    MentionField,
    RelationStatus,
)

FindingId = str  # CLI uses string finding ids; web stores UUID as string at the chain layer


def entity_id_for(entity_type: str, canonical_value: str) -> str:
    """Content-addressed entity id: sha256(type + '|' + canonical_value)[:16]."""
    payload = f"{entity_type}|{canonical_value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


class Entity(BaseModel):
    id: str
    type: str
    canonical_value: str
    first_seen_at: datetime
    last_seen_at: datetime
    mention_count: int = 0
    user_id: UUID | None = None


class EntityMention(BaseModel):
    id: str
    entity_id: str
    finding_id: FindingId
    field: MentionField
    raw_value: str
    offset_start: int | None = None
    offset_end: int | None = None
    extractor: str
    confidence: float = Field(ge=0.0, le=1.0)
    created_at: datetime
    user_id: UUID | None = None


class RelationReason(BaseModel):
    rule: str
    weight_contribution: float
    idf_factor: float | None = None
    details: dict = Field(default_factory=dict)


class FindingRelation(BaseModel):
    id: str
    source_finding_id: FindingId
    target_finding_id: FindingId
    weight: float
    weight_model_version: str = "additive_v1"
    status: RelationStatus
    symmetric: bool = False
    reasons: list[RelationReason] = Field(default_factory=list)
    llm_rationale: str | None = None
    llm_relation_type: str | None = None
    llm_confidence: float | None = None
    confirmed_at_reasons: list[RelationReason] | None = None
    created_at: datetime
    updated_at: datetime
    user_id: UUID | None = None


class LinkerRun(BaseModel):
    id: str
    started_at: datetime
    finished_at: datetime | None = None
    scope: LinkerScope
    scope_id: str | None = None
    mode: LinkerMode
    llm_provider: str | None = None
    findings_processed: int = 0
    entities_extracted: int = 0
    relations_created: int = 0
    relations_updated: int = 0
    relations_skipped_sticky: int = 0
    extraction_cache_hits: int = 0
    extraction_cache_misses: int = 0
    llm_calls_made: int = 0
    llm_cache_hits: int = 0
    llm_cache_misses: int = 0
    rule_stats: dict = Field(default_factory=dict)
    duration_ms: int | None = None
    error: str | None = None
    generation: int = 0
    user_id: UUID | None = None


class ExtractionCache(BaseModel):
    cache_key: str
    provider: str
    model: str
    schema_version: int
    result_json: bytes
    created_at: datetime


class LLMLinkCache(BaseModel):
    cache_key: str
    provider: str
    model: str
    schema_version: int
    classification_json: bytes
    created_at: datetime


class FindingExtractionState(BaseModel):
    finding_id: FindingId
    extraction_input_hash: str
    last_extracted_at: datetime
    last_extractor_set: list[str] = Field(default_factory=list)
    user_id: UUID | None = None


class FindingParserOutput(BaseModel):
    finding_id: FindingId
    parser_name: str
    data: dict
    created_at: datetime
    user_id: UUID | None = None


# ─── LLM output schemas (validated via instructor / PydanticRetryWrapper) ────


class LLMExtractedEntity(BaseModel):
    type: str
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str | None = None


class LLMExtractionResponse(BaseModel):
    entities: list[LLMExtractedEntity] = Field(default_factory=list)


class LLMLinkClassification(BaseModel):
    related: bool
    relation_type: Literal[
        "enables",
        "pivots_to",
        "escalates",
        "exploits",
        "provides_context",
        "same_target_only",
        "unrelated",
    ]
    rationale: str
    confidence: float = Field(ge=0.0, le=1.0)
