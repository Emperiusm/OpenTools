"""Chain batch context manager for deferred extraction + linking."""
from __future__ import annotations

import asyncio
import logging

from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine
from opentools.chain.subscriptions import set_batch_context
from opentools.chain.store_extensions import ChainStore
from opentools.chain.subscriptions import _load_finding

logger = logging.getLogger(__name__)

_nesting = 0
_async_nesting = 0
_EXTRACTION_CONCURRENCY = 4


class ChainBatchContext:
    """Context manager that suppresses inline chain handlers during a batch.

    Usage:
        with ChainBatchContext(pipeline=..., engine=...) as batch:
            for f in many_findings:
                engagement_store.add_finding(f)
                batch.defer_linking(f.id)
        # On __exit__: extraction + linking runs once for all deferred findings

    On exception, the context manager still runs the flush (so partial
    progress is captured). set_batch_context(False) always runs in finally.
    Nested batches raise RuntimeError.
    """

    def __init__(self, *, pipeline: ExtractionPipeline, engine: LinkerEngine) -> None:
        self.pipeline = pipeline
        self.engine = engine
        self._deferred: list[str] = []
        self._entered = False

    def __enter__(self) -> "ChainBatchContext":
        global _nesting
        if _nesting > 0:
            raise RuntimeError("ChainBatchContext does not support nesting")
        _nesting += 1
        set_batch_context(True)
        self._entered = True
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        global _nesting
        try:
            self._flush()
        except Exception:
            logger.exception("ChainBatchContext flush failed")
            raise
        finally:
            _nesting -= 1
            set_batch_context(False)

    def defer_linking(self, finding_id: str) -> None:
        if not self._entered:
            raise RuntimeError("defer_linking called outside of 'with' block")
        self._deferred.append(finding_id)

    def _flush(self) -> None:
        store = self.pipeline.store
        if not self._deferred:
            return

        # Phase 1: extract all deferred findings
        for fid in self._deferred:
            finding = _load_finding(store, fid)
            if finding is None:
                continue
            try:
                self.pipeline.extract_for_finding(finding)
            except Exception:
                logger.exception("batch extract failed for %s", fid)

        # Phase 2: link each deferred finding
        # Build context once so rule_stats accumulate across the batch
        ctx = self.engine.make_context(user_id=None)
        for fid in self._deferred:
            try:
                self.engine.link_finding(fid, user_id=None, context=ctx)
            except Exception:
                logger.exception("batch link failed for %s", fid)


class AsyncChainBatchContext:
    """Async batch context manager with staged parallel extraction (spec O19).

    Parallel to sync ChainBatchContext. Async callers (drain worker,
    AsyncChainBatchContext-aware CLI commands, tests) use this class.
    Sync ChainBatchContext is deleted in Task 30.

    Flush stages:
      Stage 1: fetch ALL deferred findings in a single fetch_findings_by_ids call
      Stage 2: run extraction in parallel via asyncio.gather + Semaphore(4)
      Stage 3: link each finding sequentially (SQL serializes anyway)

    Each finding's extraction + persist runs in its own per-finding transaction
    inside the pipeline. Partial progress is visible and a mid-batch crash
    does not lose all prior work.
    """

    def __init__(
        self,
        *,
        pipeline: "AsyncExtractionPipeline",
        engine: "AsyncLinkerEngine",
    ) -> None:
        self.pipeline = pipeline
        self.engine = engine
        self._deferred: list[str] = []
        self._entered = False

    async def __aenter__(self) -> "AsyncChainBatchContext":
        global _async_nesting
        if _async_nesting > 0:
            raise RuntimeError("AsyncChainBatchContext does not support nesting")
        _async_nesting += 1
        set_batch_context(True)
        self._entered = True
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        global _async_nesting
        try:
            await self._flush()
        except Exception:
            logger.exception("AsyncChainBatchContext flush failed")
            raise
        finally:
            _async_nesting -= 1
            set_batch_context(False)

    def defer_linking(self, finding_id: str) -> None:
        if not self._entered:
            raise RuntimeError("defer_linking called outside of 'async with' block")
        self._deferred.append(finding_id)

    async def _flush(self) -> None:
        if not self._deferred:
            return

        store = self.pipeline.store

        # Stage 1: batch-fetch all deferred findings in one query
        findings = await store.fetch_findings_by_ids(self._deferred, user_id=None)

        # Stage 2: parallel extraction with bounded concurrency
        semaphore = asyncio.Semaphore(_EXTRACTION_CONCURRENCY)

        async def _extract_one(finding):
            async with semaphore:
                try:
                    await self.pipeline.extract_for_finding(finding)
                except Exception:
                    logger.exception(
                        "batch extract failed for %s", finding.id,
                    )

        await asyncio.gather(*(_extract_one(f) for f in findings))

        # Stage 3: link deferred findings sequentially (single shared context)
        ctx = await self.engine.make_context(user_id=None)
        for fid in self._deferred:
            try:
                await self.engine.link_finding(fid, user_id=None, context=ctx)
            except Exception:
                logger.exception("batch link failed for %s", fid)
