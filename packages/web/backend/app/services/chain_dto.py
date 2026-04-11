"""Conversion helpers from CLI domain objects to web response dicts.

The chain_service read methods delegate to ``PostgresChainStore``
(which returns CLI ``Entity`` / ``FindingRelation`` / ``LinkerRun``
domain objects). The FastAPI chain routes want dicts with field
names matching the old SQLModel row shapes so response-model
construction stays field-for-field. This module bridges the two
without touching the public API.

Closes the deferred follow-up from the Phase 3C.1.5 async store
refactor session 4 handoff: the web chain_service read path used to
run raw ORM selects because the routes expected web SQLModel row
shapes. With these DTO converters the service now delegates every
method (read and write) to the protocol, and the routes keep reading
the same field names.
"""
from __future__ import annotations

from typing import Any

from opentools.chain.models import (
    Entity,
    EntityMention,
    FindingRelation,
    LinkerRun,
)


def entity_to_dict(entity: Entity) -> dict[str, Any]:
    """Convert a CLI ``Entity`` to a web response dict.

    Field names mirror the ``ChainEntity`` SQLModel table so the
    route can build ``EntityResponse`` field-for-field from the dict.
    """
    return {
        "id": entity.id,
        "type": str(entity.type),
        "canonical_value": entity.canonical_value,
        "mention_count": entity.mention_count,
        "first_seen_at": entity.first_seen_at,
        "last_seen_at": entity.last_seen_at,
        "user_id": entity.user_id,
    }


def entities_to_list(entities: list[Entity]) -> list[dict[str, Any]]:
    return [entity_to_dict(e) for e in entities]


def relation_to_dict(relation: FindingRelation) -> dict[str, Any]:
    """Convert a CLI ``FindingRelation`` to a web response dict.

    ``status`` is unwrapped from the ``RelationStatus`` enum to its
    string value so the route's ``RelationResponse(status=...)``
    construction (which expects ``str``) keeps working.
    """
    status_value = (
        relation.status.value
        if hasattr(relation.status, "value")
        else str(relation.status)
    )
    return {
        "id": relation.id,
        "source_finding_id": relation.source_finding_id,
        "target_finding_id": relation.target_finding_id,
        "weight": relation.weight,
        "weight_model_version": relation.weight_model_version,
        "status": status_value,
        "symmetric": bool(relation.symmetric),
        "reasons": [
            {
                "rule": r.rule,
                "weight_contribution": r.weight_contribution,
                "idf_factor": r.idf_factor,
                "details": r.details,
            }
            for r in relation.reasons
        ],
        "llm_rationale": relation.llm_rationale,
        "llm_relation_type": relation.llm_relation_type,
        "llm_confidence": relation.llm_confidence,
        "created_at": relation.created_at,
        "updated_at": relation.updated_at,
        "user_id": relation.user_id,
    }


def relations_to_list(relations: list[FindingRelation]) -> list[dict[str, Any]]:
    return [relation_to_dict(r) for r in relations]


def linker_run_to_dict(run: LinkerRun) -> dict[str, Any]:
    """Convert a CLI ``LinkerRun`` to a web response dict.

    The web ``ChainLinkerRun`` table stores the status in a column
    called ``status_text`` whereas the CLI domain object uses
    ``status``. The dict exposes BOTH keys so both the rebuild route
    (which reads ``status_text``) and any future dict-based consumer
    can find what they expect.
    """
    return {
        "id": run.id,
        "scope": str(run.scope),
        "scope_id": run.scope_id,
        "mode": str(run.mode),
        "generation": run.generation,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "findings_processed": run.findings_processed,
        "entities_extracted": run.entities_extracted,
        "relations_created": run.relations_created,
        "relations_updated": run.relations_updated,
        "relations_skipped_sticky": run.relations_skipped_sticky,
        "rule_stats": run.rule_stats,
        "duration_ms": run.duration_ms,
        "error": run.error,
        "status": run.status,
        "status_text": run.status,
        "user_id": run.user_id,
    }


def mention_to_dict(mention: EntityMention) -> dict[str, Any]:
    """Convert a CLI ``EntityMention`` to a web response dict.

    Not currently consumed by any route, but kept alongside its
    sibling converters for future use (e.g. a ``/entities/{id}/mentions``
    endpoint).
    """
    return {
        "id": mention.id,
        "entity_id": mention.entity_id,
        "finding_id": mention.finding_id,
        "field": str(mention.field),
        "raw_value": mention.raw_value,
        "offset_start": mention.offset_start,
        "offset_end": mention.offset_end,
        "extractor": mention.extractor,
        "confidence": mention.confidence,
        "created_at": mention.created_at,
        "user_id": mention.user_id,
    }
