"""Background worker for chain rebuild using the shared pipeline.

Phase 5B of the chain async-store refactor. Replaces the duplicated
extractor/linker logic that lived in ``chain_rebuild.py`` with the
canonical CLI pipeline:

* :class:`opentools.chain.extractors.pipeline.ExtractionPipeline` —
  runs the full 3-stage extraction (parser-aware, rules, optional LLM)
  with change detection and cache support.
* :class:`opentools.chain.linker.engine.LinkerEngine` — runs all 6
  default linker rules (shared-strong-entity, temporal, tool-chain,
  CVE, kill-chain, cross-engagement) instead of just
  shared-strong-entity.

The worker is invoked via :func:`run_rebuild_shared`, which opens a
fresh ``AsyncSession`` from the supplied factory (the request-scoped
session from the route handler is closed by the time this runs),
instantiates :class:`PostgresChainStore` against it, walks the scope's
findings, and records run status transitions through the protocol.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Callable

logger = logging.getLogger(__name__)


async def run_rebuild_shared(
    *,
    session_factory: Callable[[], Any],
    run_id: str,
    user_id: uuid.UUID,
    engagement_id: str | None,
) -> None:
    """Execute chain rebuild for ``user_id`` via the shared pipeline.

    Parameters
    ----------
    session_factory
        Callable returning an async context manager that yields an
        ``AsyncSession`` (``async_sessionmaker`` qualifies). MUST NOT
        be the request-scoped session — it will be closed by the time
        this coroutine runs.
    run_id
        The pre-existing ``ChainLinkerRun.id`` created by the route
        handler via ``create_linker_run_pending``. The worker
        transitions this row through pending → running → done/failed.
    user_id
        Scoping user for all DB access.
    engagement_id
        When set, only findings in this engagement are rebuilt. When
        ``None``, all of the user's findings are in scope.
    """
    from sqlalchemy import select

    from opentools.chain.config import get_chain_config
    from opentools.chain.extractors.pipeline import ExtractionPipeline
    from opentools.chain.linker.engine import LinkerEngine, get_default_rules
    from opentools.chain.stores.postgres_async import PostgresChainStore

    logger.info(
        "chain rebuild (shared) start: run_id=%s engagement=%s",
        run_id,
        engagement_id,
    )

    try:
        async with session_factory() as session:
            from app.models import ChainLinkerRun, Finding

            store = PostgresChainStore(session=session)
            await store.initialize()

            # Mark the run as running before work starts.
            await store.set_run_status(run_id, "running", user_id=user_id)

            # Load finding ids in scope via a direct ORM query — we
            # need the user_id + engagement_id + soft-delete filter,
            # which is web-specific and not on the protocol.
            stmt = select(Finding.id).where(
                Finding.user_id == user_id,
                Finding.deleted_at.is_(None),
            )
            if engagement_id is not None:
                stmt = stmt.where(Finding.engagement_id == engagement_id)
            result = await session.execute(stmt)
            finding_ids = [row[0] for row in result.all()]

            # Convert to CLI Finding domain objects via the protocol.
            findings = await store.fetch_findings_by_ids(
                finding_ids, user_id=user_id,
            )

            cfg = get_chain_config()
            pipeline = ExtractionPipeline(store=store, config=cfg)
            engine = LinkerEngine(
                store=store,
                config=cfg,
                rules=get_default_rules(cfg),
            )

            # ── Extraction pass ─────────────────────────────────────
            entities_extracted_total = 0
            for f in findings:
                try:
                    res = await pipeline.extract_for_finding(
                        f, user_id=user_id, force=True,
                    )
                    entities_extracted_total += res.entities_created
                except Exception:
                    logger.exception(
                        "extract failed for finding %s", f.id,
                    )

            # ── Linking pass ────────────────────────────────────────
            # One make_context, reused across all findings to keep
            # the IDF/scope computation consistent.
            relations_created_total = 0
            relations_updated_total = 0
            relations_skipped_sticky_total = 0
            ctx = await engine.make_context(user_id=user_id, is_web=True)
            for f in findings:
                try:
                    sub_run = await engine.link_finding(
                        f.id, user_id=user_id, context=ctx,
                    )
                    relations_created_total += sub_run.relations_created
                    relations_updated_total += sub_run.relations_updated
                    relations_skipped_sticky_total += (
                        sub_run.relations_skipped_sticky
                    )
                except Exception:
                    logger.exception(
                        "link failed for finding %s", f.id,
                    )

            # ── Finalize run row ────────────────────────────────────
            await store.finish_linker_run(
                run_id,
                findings_processed=len(findings),
                entities_extracted=entities_extracted_total,
                relations_created=relations_created_total,
                relations_updated=relations_updated_total,
                relations_skipped_sticky=relations_skipped_sticky_total,
                rule_stats={},
                user_id=user_id,
            )
            await store.set_run_status(run_id, "done", user_id=user_id)
            await session.commit()

        logger.info(
            "chain rebuild (shared) done: run_id=%s findings=%d "
            "entities=%d relations_created=%d",
            run_id,
            len(findings),
            entities_extracted_total,
            relations_created_total,
        )
    except Exception as exc:
        logger.exception(
            "chain rebuild (shared) failed: run_id=%s", run_id,
        )
        try:
            async with session_factory() as fail_session:
                # Route the failure finalize through the protocol
                # instead of a direct SQL UPDATE. mark_run_failed was
                # added specifically for worker-style error handlers:
                # finish_linker_run expects a clean success with full
                # counters, which we don't have here.
                fail_store = PostgresChainStore(session=fail_session)
                await fail_store.initialize()
                await fail_store.mark_run_failed(
                    run_id,
                    error=str(exc)[:2000],
                    user_id=user_id,
                )
                await fail_session.commit()
        except Exception:
            logger.exception(
                "failed to mark rebuild failed for run_id=%s", run_id,
            )
