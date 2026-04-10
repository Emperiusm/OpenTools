from datetime import datetime, timezone
from uuid import uuid4

import pytest

from opentools.chain.models import (
    Entity,
    EntityMention,
    FindingRelation,
    RelationReason,
    LinkerRun,
    ExtractionCache,
    LLMLinkCache,
    FindingExtractionState,
    FindingParserOutput,
    LLMExtractedEntity,
    LLMExtractionResponse,
    LLMLinkClassification,
    entity_id_for,
)
from opentools.chain.types import (
    RelationStatus,
    MentionField,
    LinkerScope,
    LinkerMode,
)


def test_entity_id_is_content_addressed():
    a = entity_id_for("host", "10.0.0.5")
    b = entity_id_for("host", "10.0.0.5")
    c = entity_id_for("host", "10.0.0.6")
    assert a == b
    assert a != c
    assert len(a) == 16
    assert all(ch in "0123456789abcdef" for ch in a)


def test_entity_type_and_value_contribute_to_id():
    # Different type, same value should produce different ids
    assert entity_id_for("host", "admin") != entity_id_for("user", "admin")


def test_entity_construction():
    now = datetime.now(timezone.utc)
    e = Entity(
        id=entity_id_for("host", "10.0.0.5"),
        type="host",
        canonical_value="10.0.0.5",
        first_seen_at=now,
        last_seen_at=now,
        mention_count=0,
        user_id=None,
    )
    assert e.type == "host"
    assert e.canonical_value == "10.0.0.5"


def test_relation_reason_contribution_required():
    r = RelationReason(
        rule="shared_strong_entity",
        weight_contribution=1.2,
        idf_factor=1.5,
        details={"entity_id": "abc"},
    )
    assert r.rule == "shared_strong_entity"
    assert r.weight_contribution == 1.2
    assert r.idf_factor == 1.5
    assert r.details["entity_id"] == "abc"


def test_finding_relation_default_version():
    now = datetime.now(timezone.utc)
    rel = FindingRelation(
        id="rel_abc",
        source_finding_id="fnd_1",
        target_finding_id="fnd_2",
        weight=1.5,
        status=RelationStatus.AUTO_CONFIRMED,
        symmetric=False,
        reasons=[
            RelationReason(
                rule="shared_strong_entity",
                weight_contribution=1.5,
                idf_factor=1.2,
                details={},
            )
        ],
        created_at=now,
        updated_at=now,
    )
    assert rel.weight_model_version == "additive_v1"
    assert rel.llm_rationale is None
    assert rel.confirmed_at_reasons is None


def test_llm_link_classification_schema():
    cls = LLMLinkClassification(
        related=True,
        relation_type="pivots_to",
        rationale="Shared host 10.0.0.5",
        confidence=0.85,
    )
    assert cls.related is True
    assert cls.relation_type == "pivots_to"
    assert 0 <= cls.confidence <= 1


def test_llm_link_classification_rejects_out_of_range_confidence():
    with pytest.raises(ValueError):
        LLMLinkClassification(
            related=True, relation_type="enables", rationale="", confidence=1.5
        )


def test_llm_extraction_response_ok():
    resp = LLMExtractionResponse(
        entities=[
            LLMExtractedEntity(type="host", value="10.0.0.5", confidence=0.9),
            LLMExtractedEntity(type="cve", value="CVE-2024-1234", confidence=0.95),
        ]
    )
    assert len(resp.entities) == 2


def test_linker_run_accepts_all_scopes():
    for scope in LinkerScope:
        run = LinkerRun(
            id=f"run_{scope.value}",
            started_at=datetime.now(timezone.utc),
            scope=scope,
            mode=LinkerMode.RULES_ONLY,
            findings_processed=0,
            entities_extracted=0,
            relations_created=0,
            relations_updated=0,
            relations_skipped_sticky=0,
            extraction_cache_hits=0,
            extraction_cache_misses=0,
            llm_calls_made=0,
            llm_cache_hits=0,
            llm_cache_misses=0,
            rule_stats={},
            generation=1,
        )
        assert run.scope == scope
