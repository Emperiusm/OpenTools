"""Subscription layer: wires the event bus to extraction + linking handlers.

Task 4 created StoreEventBus and had the engagement store emit events.
Task 17 built the ExtractionPipeline and Task 23 built LinkerEngine.
This module connects them: subscribers invoke the pipeline and engine
when finding.* events fire.

Batch context is a module-level flag set by Task 24's ChainBatchContext.
When active, inline handlers short-circuit so batch mode can defer
extraction + linking until the batch is fully committed.

Production code (CLI __main__ or web startup) is responsible for
constructing the store/pipeline/engine instances and passing factory
callables to subscribe_chain_handlers. This keeps the subscription
layer decoupled from the choice of SQLite file path or connection.
"""
from __future__ import annotations

import logging
from typing import Callable

from opentools.chain.config import get_chain_config
from opentools.chain.events import get_event_bus
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine
from opentools.chain.store_extensions import ChainStore

logger = logging.getLogger(__name__)

StoreFactory = Callable[[], ChainStore]
PipelineFactory = Callable[[ChainStore], ExtractionPipeline]
EngineFactory = Callable[[ChainStore], LinkerEngine]

_subscribed: bool = False
_in_batch_context: bool = False


def set_batch_context(active: bool) -> None:
    """Set the batch mode flag. When True, inline handlers short-circuit.

    Used by Task 24's ChainBatchContext.__enter__ / __exit__.
    """
    global _in_batch_context
    _in_batch_context = active


def reset_subscriptions() -> None:
    """Test helper: clear _subscribed so subscribe_chain_handlers can run again."""
    global _subscribed, _in_batch_context
    _subscribed = False
    _in_batch_context = False


def subscribe_chain_handlers(
    *,
    store_factory: StoreFactory | None = None,
    pipeline_factory: PipelineFactory | None = None,
    engine_factory: EngineFactory | None = None,
) -> None:
    """Subscribe extraction + linking handlers to finding.* events.

    Idempotent — subsequent calls are no-ops.
    No-op when:
    - chain.enabled is False in config
    - factories are not provided (production wiring is caller responsibility)
    """
    global _subscribed
    if _subscribed:
        return

    cfg = get_chain_config()
    if not cfg.enabled:
        logger.info("chain.enabled=False; skipping subscription wiring")
        _subscribed = True  # mark as "subscribed" to prevent retry storms
        return

    if store_factory is None or pipeline_factory is None or engine_factory is None:
        logger.debug(
            "subscribe_chain_handlers called without factories; "
            "no handlers attached (production code must pass factories)"
        )
        return

    bus = get_event_bus()

    def _on_created(finding_id, engagement_id=None, **_kwargs):
        if _in_batch_context:
            return
        try:
            store = store_factory()
            pipeline = pipeline_factory(store)
            engine = engine_factory(store)
            # Load the finding from the store
            finding = _load_finding(store, finding_id)
            if finding is None:
                return
            pipeline.extract_for_finding(finding)
            ctx = engine.make_context(user_id=None)
            engine.link_finding(finding_id, user_id=None, context=ctx)
        except Exception:
            logger.exception("chain on_created handler failed for %s", finding_id)

    def _on_updated(finding_id, engagement_id=None, **_kwargs):
        if _in_batch_context:
            return
        try:
            store = store_factory()
            pipeline = pipeline_factory(store)
            engine = engine_factory(store)
            finding = _load_finding(store, finding_id)
            if finding is None:
                return
            # Pipeline handles change detection + cascade delete of stale mentions
            pipeline.extract_for_finding(finding)
            ctx = engine.make_context(user_id=None)
            engine.link_finding(finding_id, user_id=None, context=ctx)
        except Exception:
            logger.exception("chain on_updated handler failed for %s", finding_id)

    def _on_deleted(finding_id, engagement_id=None, **_kwargs):
        # CASCADE on foreign keys handles entity_mention/finding_relation
        # removal automatically when the findings row is hard-deleted.
        # soft-delete via deleted_at does not cascade — document as known.
        pass

    bus.subscribe("finding.created", _on_created)
    bus.subscribe("finding.updated", _on_updated)
    bus.subscribe("finding.deleted", _on_deleted)
    _subscribed = True


def _load_finding(store: ChainStore, finding_id: str):
    """Load a Finding row via the shared SQLite connection."""
    from datetime import datetime
    from opentools.models import Finding, FindingStatus, Severity

    row = store.execute_one(
        "SELECT * FROM findings WHERE id = ? AND deleted_at IS NULL",
        (finding_id,),
    )
    if row is None:
        return None
    try:
        return Finding(
            id=row["id"],
            engagement_id=row["engagement_id"],
            tool=row["tool"],
            severity=Severity(row["severity"]),
            status=FindingStatus(row["status"]) if row["status"] else FindingStatus.DISCOVERED,
            title=row["title"],
            description=row["description"] or "",
            file_path=row["file_path"],
            evidence=row["evidence"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )
    except Exception:
        return None
