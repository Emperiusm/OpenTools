from datetime import datetime, timezone

import pytest

from opentools.chain.extractors.pipeline import (
    AsyncExtractionPipeline,
    ExtractionResult,
)
from opentools.chain.config import ChainConfig
from opentools.models import Finding, FindingStatus, Severity

pytestmark = pytest.mark.asyncio


def _finding(**kwargs) -> Finding:
    defaults = dict(
        id="fnd_1", engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title="Open port 22",
        description="SSH exposed on 10.0.0.5, CVE-2024-1234 applies",
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _insert_finding(engagement_store, finding: Finding):
    """Insert directly into findings table, bypassing dedup, for test isolation."""
    engagement_store.add_finding(finding)


async def test_pipeline_extracts_ip_and_cve(async_chain_stores):
    engagement_store, chain_store, now = async_chain_stores
    finding = _finding()
    _insert_finding(engagement_store, finding)

    pipeline = AsyncExtractionPipeline(store=chain_store, config=ChainConfig())
    result = await pipeline.extract_for_finding(finding)

    assert isinstance(result, ExtractionResult)
    assert result.cache_hit is False
    assert result.stage2_count >= 2  # at least ip + cve

    mentions = await chain_store.mentions_for_finding(finding.id, user_id=None)
    mention_values = {m.raw_value for m in mentions}
    assert "10.0.0.5" in mention_values
    assert any("CVE-2024-1234" in v or "cve-2024-1234" in v for v in mention_values)


async def test_pipeline_cache_hit_on_second_run(async_chain_stores):
    engagement_store, chain_store, now = async_chain_stores
    finding = _finding()
    _insert_finding(engagement_store, finding)

    pipeline = AsyncExtractionPipeline(store=chain_store, config=ChainConfig())
    first = await pipeline.extract_for_finding(finding)
    second = await pipeline.extract_for_finding(finding)

    assert first.cache_hit is False
    assert second.cache_hit is True
    # Second run doesn't delete/reinsert mentions
    mentions_after = await chain_store.mentions_for_finding(finding.id, user_id=None)
    assert len(mentions_after) == first.mentions_created


async def test_pipeline_force_bypasses_cache(async_chain_stores):
    engagement_store, chain_store, now = async_chain_stores
    finding = _finding()
    _insert_finding(engagement_store, finding)

    pipeline = AsyncExtractionPipeline(store=chain_store, config=ChainConfig())
    await pipeline.extract_for_finding(finding)
    result = await pipeline.extract_for_finding(finding, force=True)
    assert result.cache_hit is False


async def test_pipeline_update_replaces_mentions(async_chain_stores):
    engagement_store, chain_store, now = async_chain_stores
    finding = _finding()
    _insert_finding(engagement_store, finding)

    pipeline = AsyncExtractionPipeline(store=chain_store, config=ChainConfig())
    await pipeline.extract_for_finding(finding)
    first_mentions = await chain_store.mentions_for_finding(finding.id, user_id=None)
    assert any("10.0.0.5" in m.raw_value for m in first_mentions)

    # Simulate edit by constructing a new Finding with different content
    # but same id (as if the row was updated in-place)
    updated = finding.model_copy(update={
        "description": "Completely different content with 192.168.1.10 and CVE-2023-5678",
    })
    result = await pipeline.extract_for_finding(updated)
    assert result.cache_hit is False

    second_mentions = await chain_store.mentions_for_finding(finding.id, user_id=None)
    second_values = {m.raw_value for m in second_mentions}
    assert "10.0.0.5" not in second_values
    assert "192.168.1.10" in second_values


async def test_pipeline_llm_stage_not_run_without_provider(async_chain_stores):
    """llm_provider=None must never invoke an LLM stage."""
    engagement_store, chain_store, now = async_chain_stores
    finding = _finding()
    _insert_finding(engagement_store, finding)

    pipeline = AsyncExtractionPipeline(store=chain_store, config=ChainConfig())
    result = await pipeline.extract_for_finding(finding, llm_provider=None)
    assert result.stage3_count == 0


async def test_pipeline_llm_stage_runs_when_provided(async_chain_stores):
    engagement_store, chain_store, now = async_chain_stores
    finding = _finding()
    _insert_finding(engagement_store, finding)

    from opentools.chain.extractors.llm.ollama import OllamaProvider

    async def mock_call(prompt):
        return '{"entities": [{"type": "user", "value": "ctf_admin", "confidence": 0.85}]}'

    provider = OllamaProvider(call_fn=mock_call)

    pipeline = AsyncExtractionPipeline(store=chain_store, config=ChainConfig())
    result = await pipeline.extract_for_finding(finding, llm_provider=provider)
    assert result.stage3_count >= 1
    mentions = await chain_store.mentions_for_finding(finding.id, user_id=None)
    assert any("ctf_admin" in m.raw_value for m in mentions)


async def test_pipeline_normalizes_entity_values(async_chain_stores):
    engagement_store, chain_store, now = async_chain_stores
    finding = _finding(description="connect via SSH to 10.0.0.5 and cve-2024-1234")
    _insert_finding(engagement_store, finding)

    pipeline = AsyncExtractionPipeline(store=chain_store, config=ChainConfig())
    await pipeline.extract_for_finding(finding)

    # CVE should be normalized to uppercase in the Entity table
    mentions = await chain_store.mentions_for_finding(finding.id, user_id=None)
    cve_mentions = [m for m in mentions if "cve" in m.raw_value.lower()]
    assert cve_mentions
    cve_mention = cve_mentions[0]
    entity = await chain_store.get_entity(cve_mention.entity_id, user_id=None)
    assert entity is not None
    assert entity.canonical_value == "CVE-2024-1234"  # normalized


async def test_mention_count_matches_ground_truth_after_force_rerun(async_chain_stores):
    """Regression: force re-extraction must not double-count mentions.

    Before the fix, mention_count would drift upward on every re-extraction
    because it was incremented from the already-incremented stored value
    rather than recomputed from ground truth.
    """
    engagement_store, chain_store, now = async_chain_stores
    finding = _finding(description="10.0.0.5 appears here")
    _insert_finding(engagement_store, finding)

    pipeline = AsyncExtractionPipeline(store=chain_store, config=ChainConfig())
    await pipeline.extract_for_finding(finding)
    await pipeline.extract_for_finding(finding, force=True)
    await pipeline.extract_for_finding(finding, force=True)

    # For every entity touched by this finding, mention_count must match
    # the number of entity_mention rows that point at it.
    mentions = await chain_store.mentions_for_finding(finding.id, user_id=None)
    touched_ids = {m.entity_id for m in mentions}
    for eid in touched_ids:
        entity = await chain_store.get_entity(eid, user_id=None)
        assert entity is not None
        actual = sum(1 for m in mentions if m.entity_id == eid)
        # mention_count reflects ALL mentions across all findings, but in
        # this single-finding test the two should agree.
        assert entity.mention_count == actual, (
            f"entity {eid}: mention_count={entity.mention_count} but "
            f"{actual} mention rows exist"
        )


async def test_mention_count_accurate_across_findings(async_chain_stores):
    """Entity shared between two findings has mention_count = 2.

    After re-extracting one of the findings, mention_count must still be 2.
    """
    engagement_store, chain_store, now = async_chain_stores
    finding_a = _finding().model_copy(update={"id": "fnd_a", "description": "see 10.0.0.5 now"})
    finding_b = _finding().model_copy(update={"id": "fnd_b", "description": "also 10.0.0.5 here"})
    _insert_finding(engagement_store, finding_a)
    _insert_finding(engagement_store, finding_b)

    pipeline = AsyncExtractionPipeline(store=chain_store, config=ChainConfig())
    await pipeline.extract_for_finding(finding_a)
    await pipeline.extract_for_finding(finding_b)

    # Locate the ip entity via list_entities
    ip_entities = [
        e for e in await chain_store.list_entities(user_id=None, entity_type="ip")
        if e.canonical_value == "10.0.0.5"
    ]
    assert len(ip_entities) == 1
    assert ip_entities[0].mention_count == 2

    # Re-extract finding_a with force
    await pipeline.extract_for_finding(finding_a, force=True)
    ip_entities = [
        e for e in await chain_store.list_entities(user_id=None, entity_type="ip")
        if e.canonical_value == "10.0.0.5"
    ]
    assert ip_entities[0].mention_count == 2, (
        f"after re-extraction, mention_count should still be 2, "
        f"got {ip_entities[0].mention_count}"
    )


async def test_async_pipeline_awaits_llm_provider(async_chain_stores):
    """LLM stage 3 is awaited natively rather than running asyncio.run in sync code."""
    engagement_store, chain_store, _ = async_chain_stores
    finding = _finding(description="SSH on 10.0.0.5")
    _insert_finding(engagement_store, finding)

    from opentools.chain.extractors.llm.ollama import OllamaProvider

    calls: list[str] = []

    async def mock_call(prompt):
        calls.append(prompt)
        return '{"entities": [{"type": "user", "value": "ctf_admin", "confidence": 0.85}]}'

    provider = OllamaProvider(call_fn=mock_call)
    pipeline = AsyncExtractionPipeline(store=chain_store, config=ChainConfig())
    result = await pipeline.extract_for_finding(finding, llm_provider=provider)

    assert isinstance(result, ExtractionResult)
    assert result.stage3_count >= 1
    assert len(calls) >= 1  # LLM stage invoked at least once
    mentions = await chain_store.mentions_for_finding(finding.id, user_id=None)
    assert any("ctf_admin" in m.raw_value for m in mentions)
