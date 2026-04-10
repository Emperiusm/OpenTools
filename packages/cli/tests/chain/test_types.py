import pytest

from opentools.chain.types import (
    ENTITY_TYPE_REGISTRY,
    EntityTypeCategory,
    MentionField,
    RelationStatus,
    LinkerMode,
    LinkerScope,
    register_entity_type,
    is_strong_entity_type,
    is_weak_entity_type,
)


def test_strong_vs_weak_classification():
    # Register test types to exercise the classification functions.
    # Built-in registrations happen in normalizers.py (Task 6).
    register_entity_type("test_host", category=EntityTypeCategory.STRONG, normalizer=str.strip)
    register_entity_type("test_port", category=EntityTypeCategory.WEAK, normalizer=str.strip)
    assert is_strong_entity_type("test_host")
    assert is_weak_entity_type("test_port")
    assert not is_weak_entity_type("test_host")
    assert not is_strong_entity_type("test_port")


def test_register_entity_type_idempotent():
    register_entity_type("docker_container", category=EntityTypeCategory.STRONG, normalizer=str.lower)
    assert "docker_container" in ENTITY_TYPE_REGISTRY
    register_entity_type("docker_container", category=EntityTypeCategory.STRONG, normalizer=str.lower)
    assert "docker_container" in ENTITY_TYPE_REGISTRY


def test_register_entity_type_conflict_raises():
    register_entity_type("unique_thing", category=EntityTypeCategory.STRONG, normalizer=str.lower)
    with pytest.raises(ValueError, match="already registered"):
        register_entity_type("unique_thing", category=EntityTypeCategory.WEAK, normalizer=str.upper)


def test_relation_status_values():
    assert RelationStatus.AUTO_CONFIRMED.value == "auto_confirmed"
    assert RelationStatus.CANDIDATE.value == "candidate"
    assert RelationStatus.REJECTED.value == "rejected"
    assert RelationStatus.USER_CONFIRMED.value == "user_confirmed"
    assert RelationStatus.USER_REJECTED.value == "user_rejected"


def test_mention_field_values():
    assert MentionField.TITLE.value == "title"
    assert MentionField.DESCRIPTION.value == "description"
    assert MentionField.EVIDENCE.value == "evidence"
    assert MentionField.FILE_PATH.value == "file_path"
    assert MentionField.IOC.value == "ioc"


def test_linker_mode_and_scope_values():
    assert LinkerMode.RULES_ONLY.value == "rules_only"
    assert LinkerMode.RULES_PLUS_LLM.value == "rules_plus_llm"
    assert LinkerMode.MANUAL_MERGE.value == "manual_merge"
    assert LinkerMode.MANUAL_SPLIT.value == "manual_split"
    assert LinkerScope.ENGAGEMENT.value == "engagement"
    assert LinkerScope.CROSS_ENGAGEMENT.value == "cross_engagement"
    assert LinkerScope.FINDING_BATCH.value == "finding_batch"
    assert LinkerScope.FINDING_SINGLE.value == "finding_single"
    assert LinkerScope.MANUAL_MERGE.value == "manual_merge"
    assert LinkerScope.MANUAL_SPLIT.value == "manual_split"
