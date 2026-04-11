from datetime import datetime, timezone

import pytest

from opentools.chain.config import ChainConfig
from opentools.chain.events import get_event_bus, reset_event_bus
from opentools.chain.extractors.pipeline import AsyncExtractionPipeline, ExtractionPipeline
from opentools.chain.linker.engine import AsyncLinkerEngine, LinkerEngine, get_default_rules
from opentools.chain.store_extensions import ChainStore
from opentools.chain.subscriptions import (
    DrainWorker,
    _reset_drain_state,
    reset_subscriptions,
    set_batch_context,
    start_drain_worker,
    subscribe_chain_handlers,
)
from opentools.models import Finding, FindingStatus, Severity


def _finding(id: str, description: str = "on 10.0.0.5") -> Finding:
    return Finding(
        id=id, engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title=f"Finding {id}", description=description,
        created_at=datetime.now(timezone.utc),
    )


def test_subscriptions_idempotent():
    reset_subscriptions()
    reset_event_bus()

    def store_factory():
        raise AssertionError("should not be called without events")

    subscribe_chain_handlers(
        store_factory=store_factory,
        pipeline_factory=lambda s: None,
        engine_factory=lambda s: None,
    )
    # Second call is a no-op
    subscribe_chain_handlers(
        store_factory=store_factory,
        pipeline_factory=lambda s: None,
        engine_factory=lambda s: None,
    )
    reset_subscriptions()


def test_subscriptions_no_factories_is_noop():
    reset_subscriptions()
    reset_event_bus()
    bus = get_event_bus()
    # No handlers subscribed
    subscribe_chain_handlers()
    # Bus has no handlers for the chain events
    assert bus._subscribers.get("finding.created") in (None, [])
    reset_subscriptions()


def test_inline_handler_extracts_and_links_on_finding_created(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    reset_subscriptions()
    reset_event_bus()

    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=chain_store, config=cfg)
    engine = LinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    subscribe_chain_handlers(
        store_factory=lambda: chain_store,
        pipeline_factory=lambda s: pipeline,
        engine_factory=lambda s: engine,
    )

    # First finding
    a = _finding("f_evt_a", description="SSH on 10.0.0.5")
    engagement_store.add_finding(a)

    # After add_finding commits and emits finding.created, the subscriber
    # should have run extraction. Verify by checking entity_mention.
    mentions = chain_store.mentions_for_finding("f_evt_a")
    assert len(mentions) >= 1

    # Second finding sharing the host — the linker should create a relation
    b = _finding("f_evt_b", description="HTTP on 10.0.0.5")
    engagement_store.add_finding(b)

    rels = chain_store.relations_for_finding("f_evt_b")
    # At least one relation partnering with a should exist
    partner_ids = {r.source_finding_id if r.target_finding_id == "f_evt_b" else r.target_finding_id for r in rels}
    assert "f_evt_a" in partner_ids

    reset_subscriptions()
    reset_event_bus()


def test_batch_context_suppresses_inline_handler(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    reset_subscriptions()
    reset_event_bus()

    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=chain_store, config=cfg)
    engine = LinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    subscribe_chain_handlers(
        store_factory=lambda: chain_store,
        pipeline_factory=lambda s: pipeline,
        engine_factory=lambda s: engine,
    )

    # Enter batch mode
    set_batch_context(True)
    try:
        f = _finding("f_batch_a", description="something with 10.0.0.5")
        engagement_store.add_finding(f)
        # Inline handler suppressed: no mentions should exist yet
        mentions = chain_store.mentions_for_finding("f_batch_a")
        assert mentions == []
    finally:
        set_batch_context(False)

    reset_subscriptions()
    reset_event_bus()


def test_disabled_config_skips_subscription():
    reset_subscriptions()
    reset_event_bus()

    from opentools.chain.config import set_chain_config, ChainConfig
    set_chain_config(ChainConfig(enabled=False))

    try:
        subscribe_chain_handlers(
            store_factory=lambda: None,
            pipeline_factory=lambda s: None,
            engine_factory=lambda s: None,
        )
        bus = get_event_bus()
        # No handlers subscribed when chain.enabled=False
        assert bus._subscribers.get("finding.created") in (None, [])
    finally:
        from opentools.chain.config import reset_chain_config
        reset_chain_config()
        reset_subscriptions()


@pytest.mark.asyncio
async def test_drain_worker_processes_finding_created(async_chain_stores):
    engagement_store, chain_store, _ = async_chain_stores
    reset_subscriptions()
    reset_event_bus()
    _reset_drain_state()

    cfg = ChainConfig()
    pipeline = AsyncExtractionPipeline(store=chain_store, config=cfg)
    engine = AsyncLinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

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
async def test_drain_worker_respects_batch_context(async_chain_stores):
    engagement_store, chain_store, _ = async_chain_stores
    reset_subscriptions()
    reset_event_bus()
    _reset_drain_state()

    cfg = ChainConfig()
    pipeline = AsyncExtractionPipeline(store=chain_store, config=cfg)
    engine = AsyncLinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

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
