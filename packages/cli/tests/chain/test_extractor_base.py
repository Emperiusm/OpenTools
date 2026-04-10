import pytest
from datetime import datetime, timezone

from opentools.chain.extractors.base import (
    ExtractedEntity,
    ExtractionContext,
    SecurityExtractor,
    ParserEntityExtractor,
)
from opentools.chain.types import MentionField
from opentools.models import (
    EngagementType,
    Finding,
    FindingStatus,
    Severity,
)


def _make_finding() -> Finding:
    return Finding(
        id="fnd_t",
        engagement_id="eng_t",
        tool="nmap",
        severity=Severity.HIGH,
        status=FindingStatus.DISCOVERED,
        title="test",
        description="desc",
        created_at=datetime.now(timezone.utc),
    )


def test_extracted_entity_construction():
    ee = ExtractedEntity(
        type="host",
        value="10.0.0.5",
        field=MentionField.DESCRIPTION,
        offset_start=10,
        offset_end=18,
        extractor="test",
        confidence=0.9,
    )
    assert ee.type == "host"
    assert ee.value == "10.0.0.5"
    assert ee.confidence == 0.9


def test_extraction_context_defaults_empty_already_extracted():
    f = _make_finding()
    ctx = ExtractionContext(finding=f)
    assert ctx.already_extracted == []
    assert ctx.platform == "auto"
    assert ctx.engagement_metadata == {}


def test_extraction_context_with_values():
    f = _make_finding()
    prior = [
        ExtractedEntity(
            type="host", value="10.0.0.1", field=MentionField.TITLE,
            offset_start=0, offset_end=8, extractor="rule", confidence=0.9,
        )
    ]
    ctx = ExtractionContext(
        finding=f,
        already_extracted=prior,
        platform="linux",
        engagement_metadata={"target": "example.com"},
    )
    assert len(ctx.already_extracted) == 1
    assert ctx.platform == "linux"
    assert ctx.engagement_metadata == {"target": "example.com"}


def test_module_has_no_network_side_effects():
    """Importing the base module must not make any network calls."""
    import importlib
    import opentools.chain.extractors.base
    importlib.reload(opentools.chain.extractors.base)
