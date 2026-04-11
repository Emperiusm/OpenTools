"""Chain batch context manager for deferred extraction + linking."""
from __future__ import annotations

import asyncio
import logging

from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine
from opentools.chain.subscriptions import set_batch_context

logger = logging.getLogger(__name__)

_nesting = 0
_EXTRACTION_CONCURRENCY = 4


class ChainBatchContext:
    """Async batch context manager with staged parallel extraction (spec O19).

    Suppresses inline chain handlers during a batch so extraction +
    linking can be deferred until the batch commits.

    Flush stages:
      Stage 1: fetch ALL deferred findings in a single fetch_findings_by_ids call
      Stage 2: run extraction in parallel via asyncio.gather + Semaphore(4)
      Stage 3: link each finding sequentially (SQL serializes anyway)

    Each finding's extraction + persist runs in its own per-finding
    transaction inside the pipeline. Partial progress is visible and a
    mid-batch crash does not lose all prior work. Nested batches raise
    RuntimeError.
    """

    def __init__(
        self,
        *,
        pipeline: ExtractionPipeline,
        engine: LinkerEngine,
    ) -> None:
        self.pipeline = pipeline
        self.engine = engine
        self._deferred: list[str] = []
        self._entered = False

    async def __aenter__(self) -> "ChainBatchContext":
        global _nesting
        if _nesting > 0:
            raise RuntimeError("ChainBatchContext does not support nesting")
        _nesting += 1
        set_batch_context(True)
        self._entered = True
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        global _nesting
        try:
            await self._flush()
        except Exception:
            logger.exception("ChainBatchContext flush failed")
            raise
        finally:
            _nesting -= 1
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
