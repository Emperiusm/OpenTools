"""Subscription layer: wires the event bus to extraction + linking handlers.

Task 4 created StoreEventBus and had the engagement store emit events.
This module connects that bus to the async drain worker: finding.*
events enqueue finding ids, and a background drain worker awaits the
async extraction pipeline + linker engine.

Batch context is a module-level flag set by
:class:`opentools.chain.linker.batch.ChainBatchContext`. When active,
the drain worker consumes items but skips processing so batch mode can
own end-to-end extraction + linking without interference.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from opentools.chain.events import get_event_bus

logger = logging.getLogger(__name__)

_in_batch_context: bool = False


def set_batch_context(active: bool) -> None:
    """Set the batch mode flag. When True, the drain worker short-circuits.

    Used by ``ChainBatchContext.__aenter__`` / ``__aexit__``.
    """
    global _in_batch_context
    _in_batch_context = active


def reset_subscriptions() -> None:
    """Test helper: clear batch flag and drain worker state."""
    global _in_batch_context
    _in_batch_context = False
    _reset_drain_state()


# --- Async drain worker (Phase 2 Task 22e) -----------------------------

_drain_queue: "asyncio.Queue | None" = None
_drain_worker_task: "asyncio.Task | None" = None


def _reset_drain_state() -> None:
    """Test helper: clear drain worker module state.

    Cancels the worker task if running and clears the queue. Safe to call
    between tests even if the worker was never started.
    """
    global _drain_queue, _drain_worker_task
    if _drain_worker_task is not None and not _drain_worker_task.done():
        _drain_worker_task.cancel()
    _drain_queue = None
    _drain_worker_task = None


@dataclass
class DrainWorker:
    """Handle for a running drain worker.

    Returned by `start_drain_worker`. Call `await worker.stop()` during
    orderly shutdown to finish any pending work and cancel the background
    task cleanly.
    """
    task: "asyncio.Task"
    queue: "asyncio.Queue"

    async def wait_idle(self) -> None:
        """Pump pending emits and block until the queue is fully drained.

        The sync event-bus handler dispatches via
        ``loop.call_soon_threadsafe(queue.put_nowait, ...)`` so items
        emitted from a sync call (e.g. ``engagement_store.add_finding``)
        only land on the queue on the *next* event-loop tick. A single
        ``asyncio.sleep(0)`` yield pumps those pending callbacks, after
        which ``queue.join()`` observes the correct unfinished-task
        count and blocks until every drain worker handler has called
        ``task_done()``. Use this instead of a hand-rolled sleep when
        you need "everything emitted so far has been processed"
        semantics.
        """
        await asyncio.sleep(0)
        await self.queue.join()

    async def stop(self) -> None:
        """Wait for queued items to drain, then cancel the worker task."""
        await self.wait_idle()
        self.task.cancel()
        try:
            await self.task
        except asyncio.CancelledError:
            pass


async def start_drain_worker(store, pipeline, engine) -> DrainWorker:
    """Start a background drain worker and subscribe to finding.* events.

    Call from the CLI command lifecycle AFTER constructing the async
    store, pipeline, and engine. Returns a DrainWorker handle for clean
    shutdown (`await worker.stop()`).

    The sync event bus handler queues finding ids via
    `loop.call_soon_threadsafe(queue.put_nowait, ...)` so it is safe to
    invoke from any thread context (pytest main thread, engagement store
    commit callback, etc.).

    While `_in_batch_context` is True (set by batch context managers),
    drained items are consumed and silently skipped so batch mode can
    own end-to-end processing without interference.
    """
    global _drain_queue, _drain_worker_task

    if _drain_queue is None:
        _drain_queue = asyncio.Queue(maxsize=10000)

    async def _drain() -> None:
        while True:
            finding_id = await _drain_queue.get()
            try:
                if _in_batch_context:
                    continue
                findings = await store.fetch_findings_by_ids(
                    [finding_id], user_id=None,
                )
                if not findings:
                    continue
                await pipeline.extract_for_finding(findings[0])
                await engine.link_finding(finding_id, user_id=None)
            except Exception:
                logger.exception(
                    "drain worker extract+link failed for %s", finding_id,
                )
            finally:
                _drain_queue.task_done()

    _drain_worker_task = asyncio.create_task(_drain())

    bus = get_event_bus()
    loop = asyncio.get_running_loop()

    def _on_created(finding_id, **_kwargs):
        if _drain_queue is None:
            return
        try:
            loop.call_soon_threadsafe(_drain_queue.put_nowait, finding_id)
        except (asyncio.QueueFull, RuntimeError) as exc:
            logger.warning("drain queue dispatch failed: %s", exc)

    def _on_updated(finding_id, **_kwargs):
        _on_created(finding_id)

    def _on_deleted(finding_id, **_kwargs):
        pass  # FK cascade handles cleanup

    bus.subscribe("finding.created", _on_created)
    bus.subscribe("finding.updated", _on_updated)
    bus.subscribe("finding.deleted", _on_deleted)

    return DrainWorker(task=_drain_worker_task, queue=_drain_queue)
