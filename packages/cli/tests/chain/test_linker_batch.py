from datetime import datetime, timezone

import pytest

from opentools.chain.config import ChainConfig
from opentools.chain.extractors.pipeline import AsyncExtractionPipeline
from opentools.chain.linker.batch import AsyncChainBatchContext
from opentools.chain.linker.engine import AsyncLinkerEngine, get_default_rules
from opentools.chain.subscriptions import reset_subscriptions
from opentools.models import Finding, FindingStatus, Severity

pytestmark = pytest.mark.asyncio


def _finding(id: str, description: str = "on 10.0.0.5") -> Finding:
    return Finding(
        id=id, engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title=f"Finding {id}", description=description,
        created_at=datetime.now(timezone.utc),
    )


async def test_batch_context_processes_deferred_findings(async_chain_stores):
    engagement_store, chain_store, now = async_chain_stores
    reset_subscriptions()

    cfg = ChainConfig()
    pipeline = AsyncExtractionPipeline(store=chain_store, config=cfg)
    engine = AsyncLinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    async with AsyncChainBatchContext(pipeline=pipeline, engine=engine) as batch:
        a = _finding("b_a", description="SSH on 10.0.0.5")
        b = _finding("b_b", description="HTTP on 10.0.0.5")
        engagement_store.add_finding(a)
        engagement_store.add_finding(b)
        batch.defer_linking(a.id)
        batch.defer_linking(b.id)

    # After exiting the context, extraction and linking must have run
    mentions_a = await chain_store.mentions_for_finding("b_a", user_id=None)
    mentions_b = await chain_store.mentions_for_finding("b_b", user_id=None)
    assert len(mentions_a) >= 1
    assert len(mentions_b) >= 1

    rels = await chain_store.relations_for_finding("b_a", user_id=None)
    partner_ids = {r.target_finding_id if r.source_finding_id == "b_a" else r.source_finding_id for r in rels}
    assert "b_b" in partner_ids


async def test_batch_context_suppresses_inline_during_with_block(async_chain_stores):
    """Inside the with block, no extraction should happen until exit."""
    engagement_store, chain_store, now = async_chain_stores
    reset_subscriptions()

    cfg = ChainConfig()
    pipeline = AsyncExtractionPipeline(store=chain_store, config=cfg)
    engine = AsyncLinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    async with AsyncChainBatchContext(pipeline=pipeline, engine=engine) as batch:
        a = _finding("b_sup_a", description="SSH on 10.0.0.5")
        engagement_store.add_finding(a)
        batch.defer_linking(a.id)
        # Inside the block: no mentions yet
        assert await chain_store.mentions_for_finding("b_sup_a", user_id=None) == []

    # After exit: mentions exist
    assert len(await chain_store.mentions_for_finding("b_sup_a", user_id=None)) >= 1


async def test_batch_context_flushes_on_exception(async_chain_stores):
    """Exception in the with block still runs the flush on what was deferred."""
    engagement_store, chain_store, now = async_chain_stores
    reset_subscriptions()

    cfg = ChainConfig()
    pipeline = AsyncExtractionPipeline(store=chain_store, config=cfg)
    engine = AsyncLinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    with pytest.raises(RuntimeError, match="simulated"):
        async with AsyncChainBatchContext(pipeline=pipeline, engine=engine) as batch:
            a = _finding("b_exc_a", description="SSH on 10.0.0.5")
            engagement_store.add_finding(a)
            batch.defer_linking(a.id)
            raise RuntimeError("simulated failure")

    # Flush still ran; mentions exist
    assert len(await chain_store.mentions_for_finding("b_exc_a", user_id=None)) >= 1


async def test_batch_context_nested_raises(async_chain_stores):
    engagement_store, chain_store, now = async_chain_stores
    cfg = ChainConfig()
    pipeline = AsyncExtractionPipeline(store=chain_store, config=cfg)
    engine = AsyncLinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    async with AsyncChainBatchContext(pipeline=pipeline, engine=engine):
        with pytest.raises(RuntimeError, match="does not support nesting"):
            async with AsyncChainBatchContext(pipeline=pipeline, engine=engine):
                pass


async def test_batch_context_empty_deferred_ok(async_chain_stores):
    engagement_store, chain_store, now = async_chain_stores
    cfg = ChainConfig()
    pipeline = AsyncExtractionPipeline(store=chain_store, config=cfg)
    engine = AsyncLinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    async with AsyncChainBatchContext(pipeline=pipeline, engine=engine):
        pass  # no findings added, no defer_linking calls
    # Should not raise
