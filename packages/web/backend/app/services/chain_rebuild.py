"""Async background rebuild worker for the web chain data layer.

Intentionally a SUBSET of the CLI chain pipeline:
- Extraction: ioc-finder + all 7 security regex extractors (no parser-aware, no LLM)
- Linker: shared-strong-entity rule only (no IDF, no stopwords beyond the static list,
  no temporal/tool-chain/cve/kill-chain/cross-engagement rules)
- No change detection (always re-extracts all findings in scope)
- No caching

A future task should either (a) expand this to match the CLI, or (b) refactor
ChainStore to be database-agnostic so the full CLI ExtractionPipeline and
LinkerEngine can target the web's Postgres tables.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    ChainEntity,
    ChainEntityMention,
    ChainFindingRelation,
    ChainLinkerRun,
    Finding,
)
from opentools.chain.extractors.base import ExtractedEntity, ExtractionContext
from opentools.chain.extractors.ioc_finder import IocFinderExtractor
from opentools.chain.extractors.security_regex import BUILTIN_SECURITY_EXTRACTORS
from opentools.chain.models import entity_id_for
from opentools.chain.normalizers import normalize  # noqa: F401 — side-effect: registers builtins
from opentools.chain.types import MentionField, RelationStatus
from opentools.models import Finding as CoreFinding, FindingStatus, Severity

logger = logging.getLogger(__name__)


# Stateless extractors reused from the CLI package.
_EXTRACTORS = [IocFinderExtractor(), *BUILTIN_SECURITY_EXTRACTORS]


def _to_core_finding(row: Finding) -> CoreFinding:
    """Convert a web SQLModel Finding row to the CLI's Finding domain object."""
    return CoreFinding(
        id=row.id,
        engagement_id=row.engagement_id,
        tool=row.tool,
        severity=Severity(row.severity),
        status=FindingStatus(row.status) if row.status else FindingStatus.DISCOVERED,
        title=row.title,
        description=row.description or "",
        file_path=row.file_path,
        evidence=row.evidence,
        created_at=row.created_at,
    )


async def run_rebuild(
    *,
    session_factory,   # Callable[[], AsyncContextManager[AsyncSession]]
    run_id: str,
    user_id: uuid.UUID,
    engagement_id: str | None,
) -> None:
    """Background task entry point.

    Opens its own AsyncSession from session_factory (the registry stores the
    coroutine; the shared request-scoped session from the handler is closed
    by the time this runs).
    """
    logger.info("chain rebuild start: run_id=%s engagement=%s", run_id, engagement_id)
    try:
        async with session_factory() as session:
            await _set_run_status(session, run_id, user_id, "running")
            await session.commit()

        findings_processed = 0
        entities_extracted = 0
        relations_created = 0

        # Do extraction pass, then linking pass, in separate sessions so
        # progress is visible in the DB incrementally.
        async with session_factory() as session:
            findings = await _load_findings(session, user_id, engagement_id)
            findings_processed = len(findings)
            if findings:
                entities_extracted = await _extract_all(session, user_id, findings)
                await session.commit()

        async with session_factory() as session:
            relations_created = await _link_all(session, user_id, engagement_id)
            await session.commit()

        async with session_factory() as session:
            await _mark_run_done(
                session, run_id, user_id,
                findings_processed=findings_processed,
                entities_extracted=entities_extracted,
                relations_created=relations_created,
            )
            await session.commit()
        logger.info(
            "chain rebuild done: run_id=%s findings=%d entities=%d relations=%d",
            run_id, findings_processed, entities_extracted, relations_created,
        )
    except Exception as exc:
        logger.exception("chain rebuild failed: run_id=%s", run_id)
        try:
            async with session_factory() as session:
                await _mark_run_failed(session, run_id, user_id, str(exc))
                await session.commit()
        except Exception:
            logger.exception("failed to record rebuild failure for run_id=%s", run_id)


# ─── SQL helpers ─────────────────────────────────────────────────────


async def _set_run_status(session: AsyncSession, run_id: str, user_id: uuid.UUID, status: str) -> None:
    stmt = select(ChainLinkerRun).where(
        ChainLinkerRun.id == run_id,
        ChainLinkerRun.user_id == user_id,
    )
    result = await session.execute(stmt)
    run = result.scalar_one_or_none()
    if run is None:
        raise ValueError(f"run {run_id} not found for user {user_id}")
    run.status_text = status


async def _mark_run_done(
    session: AsyncSession,
    run_id: str,
    user_id: uuid.UUID,
    *,
    findings_processed: int,
    entities_extracted: int,
    relations_created: int,
) -> None:
    stmt = select(ChainLinkerRun).where(
        ChainLinkerRun.id == run_id,
        ChainLinkerRun.user_id == user_id,
    )
    result = await session.execute(stmt)
    run = result.scalar_one_or_none()
    if run is None:
        return
    run.status_text = "done"
    run.finished_at = datetime.now(timezone.utc)
    run.findings_processed = findings_processed
    run.entities_extracted = entities_extracted
    run.relations_created = relations_created


async def _mark_run_failed(session: AsyncSession, run_id: str, user_id: uuid.UUID, error_msg: str) -> None:
    stmt = select(ChainLinkerRun).where(
        ChainLinkerRun.id == run_id,
        ChainLinkerRun.user_id == user_id,
    )
    result = await session.execute(stmt)
    run = result.scalar_one_or_none()
    if run is None:
        return
    run.status_text = "failed"
    run.finished_at = datetime.now(timezone.utc)
    run.error = error_msg[:2000]


async def _load_findings(
    session: AsyncSession,
    user_id: uuid.UUID,
    engagement_id: str | None,
) -> list[Finding]:
    stmt = select(Finding).where(
        Finding.user_id == user_id,
        Finding.deleted_at.is_(None),
    )
    if engagement_id:
        stmt = stmt.where(Finding.engagement_id == engagement_id)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def _extract_all(
    session: AsyncSession,
    user_id: uuid.UUID,
    findings: list[Finding],
) -> int:
    """Delete old mentions for these findings, run extractors, upsert entities + mentions."""
    finding_ids = [f.id for f in findings]

    # Delete stale mentions for all scoped findings
    if finding_ids:
        await session.execute(
            delete(ChainEntityMention).where(
                ChainEntityMention.user_id == user_id,
                ChainEntityMention.finding_id.in_(finding_ids),
            )
        )

    now = datetime.now(timezone.utc)
    entities_added = 0

    for row in findings:
        core_finding = _to_core_finding(row)
        ctx = ExtractionContext(finding=core_finding)

        extracted: list[ExtractedEntity] = []
        fields_and_text = [
            (MentionField.TITLE, core_finding.title or ""),
            (MentionField.DESCRIPTION, core_finding.description or ""),
            (MentionField.EVIDENCE, core_finding.evidence or ""),
        ]
        for extractor in _EXTRACTORS:
            if hasattr(extractor, "applies_to") and not extractor.applies_to(core_finding):
                continue
            for field, text in fields_and_text:
                if not text:
                    continue
                try:
                    extracted.extend(extractor.extract(text, field, ctx))
                except Exception:
                    logger.exception(
                        "extractor %s failed for finding %s",
                        getattr(extractor, "name", type(extractor).__name__),
                        row.id,
                    )

        # Normalize + dedupe within the run
        new_entities: dict[str, ChainEntity] = {}
        mentions: list[ChainEntityMention] = []
        for ex in extracted:
            try:
                canonical = normalize(ex.type, ex.value)
            except Exception:
                continue
            if not canonical:
                continue
            eid = entity_id_for(ex.type, canonical)

            if eid not in new_entities:
                existing = await session.get(ChainEntity, eid)
                if existing is None:
                    ent = ChainEntity(
                        id=eid,
                        user_id=user_id,
                        type=ex.type,
                        canonical_value=canonical,
                        first_seen_at=now,
                        last_seen_at=now,
                        mention_count=0,
                    )
                    session.add(ent)
                    await session.flush()
                    new_entities[eid] = ent
                    entities_added += 1
                else:
                    existing.last_seen_at = now
                    new_entities[eid] = existing

            mentions.append(
                ChainEntityMention(
                    id=f"mnt_{uuid.uuid4().hex[:16]}",
                    user_id=user_id,
                    entity_id=eid,
                    finding_id=row.id,
                    field=ex.field.value,
                    raw_value=ex.value,
                    offset_start=ex.offset_start,
                    offset_end=ex.offset_end,
                    extractor=ex.extractor,
                    confidence=ex.confidence,
                    created_at=now,
                )
            )

        session.add_all(mentions)
        await session.flush()

    # Recompute mention_count from ground truth for all entities owned by this user
    count_stmt = (
        select(ChainEntityMention.entity_id, func.count(ChainEntityMention.id))
        .where(ChainEntityMention.user_id == user_id)
        .group_by(ChainEntityMention.entity_id)
    )
    result = await session.execute(count_stmt)
    counts = {row[0]: row[1] for row in result.all()}
    for eid, cnt in counts.items():
        await session.execute(
            update(ChainEntity)
            .where(ChainEntity.id == eid, ChainEntity.user_id == user_id)
            .values(mention_count=cnt)
        )

    return entities_added


async def _link_all(
    session: AsyncSession,
    user_id: uuid.UUID,
    engagement_id: str | None,
) -> int:
    """Simple shared-strong-entity linker: create a relation between every
    pair of findings that share at least one STRONG entity.

    Edges are symmetric, weight = count of shared strong entities (capped at 5.0),
    status = AUTO_CONFIRMED if weight >= 1.0 else CANDIDATE.
    """
    from opentools.chain.types import is_strong_entity_type

    now = datetime.now(timezone.utc)

    # Pull all mentions + entity types for this user scope in one query
    stmt = select(
        ChainEntityMention.entity_id,
        ChainEntityMention.finding_id,
        ChainEntity.type,
    ).join(
        ChainEntity, ChainEntity.id == ChainEntityMention.entity_id
    ).where(ChainEntityMention.user_id == user_id)

    if engagement_id:
        # Scope to findings in the engagement
        sub = select(Finding.id).where(
            Finding.user_id == user_id,
            Finding.engagement_id == engagement_id,
        )
        stmt = stmt.where(ChainEntityMention.finding_id.in_(sub))

    result = await session.execute(stmt)
    rows = list(result.all())

    # Invert: entity_id -> set of finding_ids, but only for strong types
    entity_to_findings: dict[str, set[str]] = {}
    for row in rows:
        if not is_strong_entity_type(row.type):
            continue
        entity_to_findings.setdefault(row.entity_id, set()).add(row.finding_id)

    # Build pair -> set of shared-entity-ids
    pair_shared: dict[tuple[str, str], set[str]] = {}
    for eid, fids in entity_to_findings.items():
        fid_list = sorted(fids)
        for i in range(len(fid_list)):
            for j in range(i + 1, len(fid_list)):
                key = (fid_list[i], fid_list[j])  # canonical ordering
                pair_shared.setdefault(key, set()).add(eid)

    # Delete existing non-sticky relations for these findings
    sticky = {RelationStatus.USER_CONFIRMED.value, RelationStatus.USER_REJECTED.value}
    all_fids: set[str] = set()
    for (a, b) in pair_shared.keys():
        all_fids.add(a)
        all_fids.add(b)
    if all_fids:
        await session.execute(
            delete(ChainFindingRelation).where(
                ChainFindingRelation.user_id == user_id,
                ChainFindingRelation.source_finding_id.in_(all_fids),
                ChainFindingRelation.target_finding_id.in_(all_fids),
                ~ChainFindingRelation.status.in_(sticky),
            )
        )
        await session.flush()

    relations_created = 0
    for (src, tgt), shared in pair_shared.items():
        weight = min(float(len(shared)), 5.0)
        status = (
            RelationStatus.AUTO_CONFIRMED.value
            if weight >= 1.0
            else RelationStatus.CANDIDATE.value
        )
        rel_id = _relation_id(src, tgt, user_id)

        # Check if a sticky relation already exists — if so, skip
        existing = await session.get(ChainFindingRelation, rel_id)
        if existing is not None and existing.status in sticky:
            continue

        rel = ChainFindingRelation(
            id=rel_id,
            user_id=user_id,
            source_finding_id=src,
            target_finding_id=tgt,
            weight=weight,
            weight_model_version="additive_v1",
            status=status,
            symmetric=True,
            reasons_json='[{"rule":"shared_strong_entity","count":%d}]' % len(shared),
            created_at=now,
            updated_at=now,
        )
        if existing is not None:
            existing.weight = weight
            existing.status = status
            existing.updated_at = now
            existing.reasons_json = rel.reasons_json
        else:
            session.add(rel)
            relations_created += 1

    await session.flush()
    return relations_created


def _relation_id(src: str, tgt: str, user_id: uuid.UUID | None) -> str:
    payload = f"{src}|{tgt}|{user_id or ''}".encode("utf-8")
    return f"rel_{hashlib.sha256(payload).hexdigest()[:16]}"
