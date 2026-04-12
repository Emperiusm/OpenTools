from datetime import datetime, timezone

import pytest

from opentools.chain.config import ChainConfig
from opentools.chain.events import reset_event_bus
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine, get_default_rules
from opentools.chain.subscriptions import (
    _reset_drain_state,
    reset_subscriptions,
    set_batch_context,
    start_drain_worker,
)
from opentools.models import Finding, FindingStatus, Severity


def _finding(id: str, description: str = "on 10.0.0.5") -> Finding:
    return Finding(
        id=id, engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title=f"Finding {id}", description=description,
        created_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_drain_worker_processes_finding_created(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    reset_subscriptions()
    reset_event_bus()
    _reset_drain_state()

    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=chain_store, config=cfg)
    engine = LinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    worker = await start_drain_worker(chain_store, pipeline, engine)

    engagement_store.add_finding(_finding("drain_a", description="SSH on 10.0.0.5"))

    # Pump pending call_soon_threadsafe dispatches and wait for the
    # drain worker to fully process the queued finding.
    await worker.wait_idle()

    mentions = await chain_store.mentions_for_finding("drain_a", user_id=None)
    assert len(mentions) >= 1

    await worker.stop()
    reset_subscriptions()
    reset_event_bus()
    _reset_drain_state()


@pytest.mark.asyncio
async def test_drain_worker_respects_batch_context(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    reset_subscriptions()
    reset_event_bus()
    _reset_drain_state()

    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=chain_store, config=cfg)
    engine = LinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    worker = await start_drain_worker(chain_store, pipeline, engine)

    set_batch_context(True)
    try:
        engagement_store.add_finding(_finding("drain_b", description="HTTP on 10.0.0.5"))
        # Pump pending call_soon_threadsafe dispatches and wait for the
        # drain worker to consume the item (which it will short-circuit
        # because batch context is active).
        await worker.wait_idle()

        mentions = await chain_store.mentions_for_finding("drain_b", user_id=None)
        # Inside batch context the drain worker consumed the finding id
        # but did NOT extract — mentions list is empty
        assert mentions == []
    finally:
        set_batch_context(False)

    await worker.stop()
    reset_subscriptions()
    reset_event_bus()
    _reset_drain_state()
