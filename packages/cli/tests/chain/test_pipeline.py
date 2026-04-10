from datetime import datetime, timezone

from opentools.chain.extractors.pipeline import (
    ExtractionPipeline,
    ExtractionResult,
)
from opentools.chain.config import ChainConfig
from opentools.chain.store_extensions import ChainStore
from opentools.models import Finding, FindingStatus, Severity


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
    """Insert directly into findings table, bypassing dedup, for test isolation.

    Adjust if the test reveals that add_finding works fine for these inputs.
    """
    engagement_store.add_finding(finding)


def test_pipeline_extracts_ip_and_cve(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    finding = _finding()
    _insert_finding(engagement_store, finding)

    pipeline = ExtractionPipeline(store=chain_store, config=ChainConfig())
    result = pipeline.extract_for_finding(finding)

    assert isinstance(result, ExtractionResult)
    assert result.cache_hit is False
    assert result.stage2_count >= 2  # at least ip + cve

    mentions = chain_store.mentions_for_finding(finding.id)
    mention_values = {m.raw_value for m in mentions}
    assert "10.0.0.5" in mention_values
    assert any("CVE-2024-1234" in v or "cve-2024-1234" in v for v in mention_values)


def test_pipeline_cache_hit_on_second_run(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    finding = _finding()
    _insert_finding(engagement_store, finding)

    pipeline = ExtractionPipeline(store=chain_store, config=ChainConfig())
    first = pipeline.extract_for_finding(finding)
    second = pipeline.extract_for_finding(finding)

    assert first.cache_hit is False
    assert second.cache_hit is True
    # Second run doesn't delete/reinsert mentions
    mentions_after = chain_store.mentions_for_finding(finding.id)
    assert len(mentions_after) == first.mentions_created


def test_pipeline_force_bypasses_cache(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    finding = _finding()
    _insert_finding(engagement_store, finding)

    pipeline = ExtractionPipeline(store=chain_store, config=ChainConfig())
    pipeline.extract_for_finding(finding)
    result = pipeline.extract_for_finding(finding, force=True)
    assert result.cache_hit is False


def test_pipeline_update_replaces_mentions(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    finding = _finding()
    _insert_finding(engagement_store, finding)

    pipeline = ExtractionPipeline(store=chain_store, config=ChainConfig())
    pipeline.extract_for_finding(finding)
    first_mentions = chain_store.mentions_for_finding(finding.id)
    assert any("10.0.0.5" in m.raw_value for m in first_mentions)

    # Simulate edit by constructing a new Finding with different content
    # but same id (as if the row was updated in-place)
    updated = finding.model_copy(update={
        "description": "Completely different content with 192.168.1.10 and CVE-2023-5678",
    })
    result = pipeline.extract_for_finding(updated)
    assert result.cache_hit is False

    second_mentions = chain_store.mentions_for_finding(finding.id)
    second_values = {m.raw_value for m in second_mentions}
    assert "10.0.0.5" not in second_values
    assert "192.168.1.10" in second_values


def test_pipeline_llm_stage_not_run_without_provider(engagement_store_and_chain):
    """llm_provider=None must never invoke an LLM stage."""
    engagement_store, chain_store, now = engagement_store_and_chain
    finding = _finding()
    _insert_finding(engagement_store, finding)

    pipeline = ExtractionPipeline(store=chain_store, config=ChainConfig())
    result = pipeline.extract_for_finding(finding, llm_provider=None)
    assert result.stage3_count == 0


def test_pipeline_llm_stage_runs_when_provided(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    finding = _finding()
    _insert_finding(engagement_store, finding)

    # Mock provider that returns a single entity via call_fn
    from opentools.chain.extractors.llm.ollama import OllamaProvider

    async def mock_call(prompt):
        return '{"entities": [{"type": "user", "value": "ctf_admin", "confidence": 0.85}]}'

    provider = OllamaProvider(call_fn=mock_call)

    pipeline = ExtractionPipeline(store=chain_store, config=ChainConfig())
    result = pipeline.extract_for_finding(finding, llm_provider=provider)
    assert result.stage3_count >= 1
    mentions = chain_store.mentions_for_finding(finding.id)
    assert any("ctf_admin" in m.raw_value for m in mentions)


def test_pipeline_normalizes_entity_values(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    finding = _finding(description="connect via SSH to 10.0.0.5 and cve-2024-1234")
    _insert_finding(engagement_store, finding)

    pipeline = ExtractionPipeline(store=chain_store, config=ChainConfig())
    pipeline.extract_for_finding(finding)

    # CVE should be normalized to uppercase in the Entity table
    mentions = chain_store.mentions_for_finding(finding.id)
    cve_mentions = [m for m in mentions if "cve" in m.raw_value.lower()]
    assert cve_mentions
    cve_mention = cve_mentions[0]
    entity = chain_store.get_entity(cve_mention.entity_id)
    assert entity is not None
    assert entity.canonical_value == "CVE-2024-1234"  # normalized


def test_mention_count_matches_ground_truth_after_force_rerun(engagement_store_and_chain):
    """Regression: force re-extraction must not double-count mentions.

    Before the fix, mention_count would drift upward on every re-extraction
    because it was incremented from the already-incremented stored value
    rather than recomputed from ground truth.
    """
    engagement_store, chain_store, now = engagement_store_and_chain
    finding = _finding(description="10.0.0.5 appears here")
    _insert_finding(engagement_store, finding)

    pipeline = ExtractionPipeline(store=chain_store, config=ChainConfig())
    pipeline.extract_for_finding(finding)
    pipeline.extract_for_finding(finding, force=True)
    pipeline.extract_for_finding(finding, force=True)

    # Check that every entity's mention_count matches the actual number of rows
    rows = chain_store.execute_all("SELECT id, mention_count FROM entity")
    for row in rows:
        entity_id = row["id"]
        stored_count = row["mention_count"]
        actual = chain_store.execute_one(
            "SELECT COUNT(*) FROM entity_mention WHERE entity_id = ?",
            (entity_id,),
        )
        assert stored_count == actual[0], (
            f"entity {entity_id}: mention_count={stored_count} but {actual[0]} mention rows exist"
        )


def test_mention_count_accurate_across_findings(engagement_store_and_chain):
    """Entity shared between two findings has mention_count = 2.

    After re-extracting one of the findings, mention_count must still be 2.
    """
    engagement_store, chain_store, now = engagement_store_and_chain
    finding_a = _finding().model_copy(update={"id": "fnd_a", "description": "see 10.0.0.5 now"})
    finding_b = _finding().model_copy(update={"id": "fnd_b", "description": "also 10.0.0.5 here"})
    _insert_finding(engagement_store, finding_a)
    _insert_finding(engagement_store, finding_b)

    pipeline = ExtractionPipeline(store=chain_store, config=ChainConfig())
    pipeline.extract_for_finding(finding_a)
    pipeline.extract_for_finding(finding_b)

    # Find the ip entity
    ip_row = chain_store.execute_one(
        "SELECT id, mention_count FROM entity WHERE type = 'ip' AND canonical_value = '10.0.0.5'",
    )
    assert ip_row is not None
    assert ip_row["mention_count"] == 2

    # Re-extract finding_a with force
    pipeline.extract_for_finding(finding_a, force=True)
    ip_row = chain_store.execute_one(
        "SELECT id, mention_count FROM entity WHERE type = 'ip' AND canonical_value = '10.0.0.5'",
    )
    assert ip_row["mention_count"] == 2, (
        f"after re-extraction, mention_count should still be 2, got {ip_row['mention_count']}"
    )
