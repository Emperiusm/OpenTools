from datetime import datetime, timezone

import pytest

from opentools.chain.config import ChainConfig
from opentools.chain.entity_ops import (
    IncompatibleMerge,
    merge_entities,
    split_entity,
)
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.models import entity_id_for
from opentools.models import (
    Engagement,
    EngagementStatus,
    EngagementType,
    Finding,
    FindingStatus,
    Severity,
)

pytestmark = pytest.mark.asyncio


def _finding(id_: str, engagement_id: str = "eng_test", description: str = "") -> Finding:
    return Finding(
        id=id_, engagement_id=engagement_id, tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title=f"F {id_}", description=description,
        created_at=datetime.now(timezone.utc),
    )


async def test_merge_two_host_entities(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    f = _finding("m_a", description="SSH on 10.0.0.5 and 10.0.0.6")
    engagement_store.add_finding(f)
    await ExtractionPipeline(
        store=chain_store, config=ChainConfig()
    ).extract_for_finding(f)

    id_5 = entity_id_for("ip", "10.0.0.5")
    id_6 = entity_id_for("ip", "10.0.0.6")
    result = await merge_entities(
        store=chain_store, a_id=id_5, b_id=id_6, into="b"
    )
    assert result.merged_from_id == id_5
    assert result.merged_into_id == id_6
    assert result.mentions_rewritten >= 1
    # affected_findings should list the (distinct) findings that had a
    # mention of the merged-from entity. Both IPs share finding "m_a",
    # so merging id_5 into id_6 reports exactly that finding.
    assert result.affected_findings == ["m_a"]
    # Source entity no longer exists
    assert await chain_store.get_entity(id_5, user_id=None) is None
    # Target still exists
    assert await chain_store.get_entity(id_6, user_id=None) is not None


async def test_merge_affected_findings_spans_multiple_findings(
    engagement_store_and_chain,
):
    """merge_entities.affected_findings returns distinct ids across
    multiple findings, not just the single seeding finding."""
    engagement_store, chain_store, _ = engagement_store_and_chain
    f1 = _finding("m_af_1", description="SSH on 10.0.0.5 and 10.0.0.6")
    f2 = _finding("m_af_2", description="also 10.0.0.5 and 10.0.0.6")
    engagement_store.add_finding(f1)
    engagement_store.add_finding(f2)

    pipeline = ExtractionPipeline(store=chain_store, config=ChainConfig())
    await pipeline.extract_for_finding(f1)
    await pipeline.extract_for_finding(f2)

    id_5 = entity_id_for("ip", "10.0.0.5")
    id_6 = entity_id_for("ip", "10.0.0.6")
    result = await merge_entities(
        store=chain_store, a_id=id_5, b_id=id_6, into="b"
    )
    # Both findings mention 10.0.0.5 (the merged-from side). Distinct,
    # sorted for determinism.
    assert result.affected_findings == ["m_af_1", "m_af_2"]


async def test_merge_into_a_reverses_direction(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    f = _finding("m_b", description="SSH on 10.0.0.5 and 10.0.0.6")
    engagement_store.add_finding(f)
    await ExtractionPipeline(
        store=chain_store, config=ChainConfig()
    ).extract_for_finding(f)

    id_5 = entity_id_for("ip", "10.0.0.5")
    id_6 = entity_id_for("ip", "10.0.0.6")
    result = await merge_entities(
        store=chain_store, a_id=id_5, b_id=id_6, into="a"
    )
    assert result.merged_from_id == id_6
    assert result.merged_into_id == id_5
    assert await chain_store.get_entity(id_6, user_id=None) is None
    assert await chain_store.get_entity(id_5, user_id=None) is not None


async def test_merge_different_types_raises(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    f = _finding("m_t", description="10.0.0.5 and example.com")
    engagement_store.add_finding(f)
    await ExtractionPipeline(
        store=chain_store, config=ChainConfig()
    ).extract_for_finding(f)

    id_ip = entity_id_for("ip", "10.0.0.5")
    id_dom = entity_id_for("domain", "example.com")
    with pytest.raises(IncompatibleMerge):
        await merge_entities(store=chain_store, a_id=id_ip, b_id=id_dom)


async def test_merge_missing_entity_raises(engagement_store_and_chain):
    _engagement_store, chain_store, _ = engagement_store_and_chain
    with pytest.raises(IncompatibleMerge):
        await merge_entities(
            store=chain_store, a_id="missing_a", b_id="missing_b"
        )


async def test_split_entity_by_engagement(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain

    # Create a SECOND engagement so the shared entity spans both
    eng2 = Engagement(
        id="eng_test2", name="test2", target="example.org",
        type=EngagementType.PENTEST, status=EngagementStatus.ACTIVE,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    engagement_store.create(eng2)

    f1 = _finding("s_a", engagement_id="eng_test", description="host 10.0.0.5 here")
    f2 = _finding("s_b", engagement_id="eng_test2", description="host 10.0.0.5 there")
    engagement_store.add_finding(f1)
    engagement_store.add_finding(f2)

    pipeline = ExtractionPipeline(store=chain_store, config=ChainConfig())
    await pipeline.extract_for_finding(f1)
    await pipeline.extract_for_finding(f2)

    id_ip = entity_id_for("ip", "10.0.0.5")
    result = await split_entity(
        store=chain_store, entity_id=id_ip, by="engagement"
    )
    assert len(result.new_entity_ids) == 2
    assert result.mentions_repartitioned >= 2
    # Source entity is deleted
    assert await chain_store.get_entity(id_ip, user_id=None) is None
    # New entities exist
    for new_id in result.new_entity_ids:
        assert await chain_store.get_entity(new_id, user_id=None) is not None


async def test_split_single_engagement_no_op(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    f = _finding("s_c", description="only 10.0.0.5")
    engagement_store.add_finding(f)
    await ExtractionPipeline(
        store=chain_store, config=ChainConfig()
    ).extract_for_finding(f)

    id_ip = entity_id_for("ip", "10.0.0.5")
    result = await split_entity(
        store=chain_store, entity_id=id_ip, by="engagement"
    )
    assert result.new_entity_ids == []
    # Source still exists
    assert await chain_store.get_entity(id_ip, user_id=None) is not None
