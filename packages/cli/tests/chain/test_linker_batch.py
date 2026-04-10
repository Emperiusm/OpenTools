from datetime import datetime, timezone

import pytest

from opentools.chain.config import ChainConfig
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.batch import ChainBatchContext
from opentools.chain.linker.engine import LinkerEngine, get_default_rules
from opentools.chain.subscriptions import reset_subscriptions
from opentools.models import Finding, FindingStatus, Severity


def _finding(id: str, description: str = "on 10.0.0.5") -> Finding:
    return Finding(
        id=id, engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title=f"Finding {id}", description=description,
        created_at=datetime.now(timezone.utc),
    )


def test_batch_context_processes_deferred_findings(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    reset_subscriptions()

    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=chain_store, config=cfg)
    engine = LinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    with ChainBatchContext(pipeline=pipeline, engine=engine) as batch:
        a = _finding("b_a", description="SSH on 10.0.0.5")
        b = _finding("b_b", description="HTTP on 10.0.0.5")
        engagement_store.add_finding(a)
        engagement_store.add_finding(b)
        batch.defer_linking(a.id)
        batch.defer_linking(b.id)

    # After exiting the context, extraction and linking must have run
    mentions_a = chain_store.mentions_for_finding("b_a")
    mentions_b = chain_store.mentions_for_finding("b_b")
    assert len(mentions_a) >= 1
    assert len(mentions_b) >= 1

    rels = chain_store.relations_for_finding("b_a")
    partner_ids = {r.target_finding_id if r.source_finding_id == "b_a" else r.source_finding_id for r in rels}
    assert "b_b" in partner_ids


def test_batch_context_suppresses_inline_during_with_block(engagement_store_and_chain):
    """Inside the with block, no extraction should happen until exit."""
    engagement_store, chain_store, now = engagement_store_and_chain
    reset_subscriptions()

    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=chain_store, config=cfg)
    engine = LinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    with ChainBatchContext(pipeline=pipeline, engine=engine) as batch:
        a = _finding("b_sup_a", description="SSH on 10.0.0.5")
        engagement_store.add_finding(a)
        batch.defer_linking(a.id)
        # Inside the block: no mentions yet
        assert chain_store.mentions_for_finding("b_sup_a") == []

    # After exit: mentions exist
    assert len(chain_store.mentions_for_finding("b_sup_a")) >= 1


def test_batch_context_flushes_on_exception(engagement_store_and_chain):
    """Exception in the with block still runs the flush on what was deferred."""
    engagement_store, chain_store, now = engagement_store_and_chain
    reset_subscriptions()

    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=chain_store, config=cfg)
    engine = LinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    with pytest.raises(RuntimeError, match="simulated"):
        with ChainBatchContext(pipeline=pipeline, engine=engine) as batch:
            a = _finding("b_exc_a", description="SSH on 10.0.0.5")
            engagement_store.add_finding(a)
            batch.defer_linking(a.id)
            raise RuntimeError("simulated failure")

    # Flush still ran; mentions exist
    assert len(chain_store.mentions_for_finding("b_exc_a")) >= 1


def test_batch_context_nested_raises(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=chain_store, config=cfg)
    engine = LinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    with ChainBatchContext(pipeline=pipeline, engine=engine):
        with pytest.raises(RuntimeError, match="does not support nesting"):
            with ChainBatchContext(pipeline=pipeline, engine=engine):
                pass


def test_batch_context_empty_deferred_ok(engagement_store_and_chain):
    engagement_store, chain_store, now = engagement_store_and_chain
    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=chain_store, config=cfg)
    engine = LinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    with ChainBatchContext(pipeline=pipeline, engine=engine):
        pass  # no findings added, no defer_linking calls
    # Should not raise
