"""On-demand LLM linking pass — classifies candidate edges."""
from __future__ import annotations

import asyncio
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable
from uuid import UUID

import orjson

from opentools.chain.config import ChainConfig
from opentools.chain.extractors.llm.base import LLMExtractionProvider
from opentools.chain.extractors.llm.prompts import LINK_CLASSIFICATION_SCHEMA_VERSION
from opentools.chain.models import (
    Entity,
    FindingRelation,
    LLMLinkClassification,
)
from opentools.chain.store_extensions import ChainStore
from opentools.chain.types import LinkerMode, LinkerScope, RelationStatus

logger = logging.getLogger(__name__)


@dataclass
class LLMLinkPassResult:
    candidates_seen: int = 0
    promoted: int = 0
    rejected: int = 0
    unchanged: int = 0
    cache_hits: int = 0
    llm_calls: int = 0
    dry_run: bool = False


def llm_link_pass(
    *,
    provider: LLMExtractionProvider,
    store: ChainStore,
    config: ChainConfig | None = None,
    min_weight: float = 0.3,
    max_weight: float = 1.0,
    dry_run: bool = False,
    user_id: UUID | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> LLMLinkPassResult:
    """Classify candidate edges via LLM and update statuses/rationales.

    Synchronous wrapper that runs the async classifications sequentially.
    For 3C.1 we don't parallelize; a future task can add a semaphore-gated
    asyncio.gather here.
    """
    cfg = config or ChainConfig()
    result = LLMLinkPassResult(dry_run=dry_run)

    # 1. Fetch candidate edges in scope
    rows = store.execute_all(
        """
        SELECT * FROM finding_relation
        WHERE status = ? AND weight >= ? AND weight <= ?
        """,
        (RelationStatus.CANDIDATE.value, min_weight, max_weight),
    )
    result.candidates_seen = len(rows)

    if dry_run:
        return result

    confidence_threshold = cfg.llm.link_classification.confidence_threshold

    for i, row in enumerate(rows):
        if progress_callback:
            try:
                progress_callback(i, len(rows))
            except Exception:
                pass

        edge_id = row["id"]
        src_id = row["source_finding_id"]
        tgt_id = row["target_finding_id"]

        cache_key = _cache_key(src_id, tgt_id, provider, LINK_CLASSIFICATION_SCHEMA_VERSION)
        cached = store.execute_one(
            "SELECT classification_json FROM llm_link_cache WHERE cache_key = ?",
            (cache_key,),
        )
        if cached is not None:
            classification_data = orjson.loads(cached["classification_json"])
            try:
                classification = LLMLinkClassification.model_validate(classification_data)
                result.cache_hits += 1
            except Exception:
                classification = None
        else:
            classification = None

        if classification is None:
            # Load the two findings and shared entities for the prompt
            finding_a = _load_finding(store, src_id)
            finding_b = _load_finding(store, tgt_id)
            if finding_a is None or finding_b is None:
                result.unchanged += 1
                continue
            shared = _shared_entities(store, src_id, tgt_id)
            try:
                classification = asyncio.run(
                    provider.classify_relation(finding_a, finding_b, shared)
                )
                result.llm_calls += 1
                # Cache the result
                store._conn.execute(
                    """
                    INSERT OR REPLACE INTO llm_link_cache
                        (cache_key, provider, model, schema_version, classification_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cache_key,
                        provider.name,
                        provider.model,
                        LINK_CLASSIFICATION_SCHEMA_VERSION,
                        orjson.dumps(classification.model_dump()),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
                store._conn.commit()
            except Exception as exc:
                logger.warning("LLM classify_relation failed for %s->%s: %s", src_id, tgt_id, exc)
                result.unchanged += 1
                continue

        # Apply the classification
        new_status: str | None = None
        if classification.related and classification.confidence >= confidence_threshold:
            new_status = RelationStatus.AUTO_CONFIRMED.value
            result.promoted += 1
        elif not classification.related:
            new_status = RelationStatus.REJECTED.value
            result.rejected += 1
        else:
            # Related but below confidence threshold: stay candidate with rationale
            new_status = RelationStatus.CANDIDATE.value
            result.unchanged += 1

        store._conn.execute(
            """
            UPDATE finding_relation
            SET status = ?, llm_rationale = ?, llm_relation_type = ?, llm_confidence = ?, updated_at = ?
            WHERE id = ? AND status NOT IN ('user_confirmed', 'user_rejected')
            """,
            (
                new_status,
                classification.rationale,
                classification.relation_type,
                classification.confidence,
                datetime.now(timezone.utc).isoformat(),
                edge_id,
            ),
        )
        store._conn.commit()

    return result


async def llm_link_pass_async(
    *,
    provider: LLMExtractionProvider,
    store,  # ChainStoreProtocol
    config: ChainConfig | None = None,
    min_weight: float = 0.3,
    max_weight: float = 1.0,
    dry_run: bool = False,
    user_id: UUID | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
) -> LLMLinkPassResult:
    """Async variant of llm_link_pass running against ``ChainStoreProtocol``.

    Uses the protocol-level async methods (``fetch_relations_in_scope``,
    ``apply_link_classification``, ``get_llm_link_cache``,
    ``put_llm_link_cache``) instead of raw SQL so any conforming backend
    (sqlite aiosqlite, future Postgres) works identically. Classification
    + cache write per edge are wrapped in ``store.transaction()`` for
    atomicity. The existing sync ``llm_link_pass`` is preserved in place
    for CLI callers not yet migrated (Task 30 deletes it).
    """
    from opentools.chain._cache_keys import link_classification_cache_key

    cfg = config or ChainConfig()
    result = LLMLinkPassResult(dry_run=dry_run)

    # Fetch candidate relations via protocol; filter weight in Python
    # because fetch_relations_in_scope doesn't expose weight filtering.
    relations = await store.fetch_relations_in_scope(
        user_id=user_id,
        statuses={RelationStatus.CANDIDATE},
    )
    relations = [r for r in relations if min_weight <= r.weight <= max_weight]
    result.candidates_seen = len(relations)

    if dry_run:
        return result

    confidence_threshold = cfg.llm.link_classification.confidence_threshold

    for i, rel in enumerate(relations):
        if progress_callback:
            try:
                progress_callback(i, len(relations))
            except Exception:
                pass

        src_id = rel.source_finding_id
        tgt_id = rel.target_finding_id

        cache_key = link_classification_cache_key(
            source_id=src_id,
            target_id=tgt_id,
            provider=provider.name,
            model=provider.model,
            schema_version=LINK_CLASSIFICATION_SCHEMA_VERSION,
            user_id=user_id,
        )

        cached_bytes = await store.get_llm_link_cache(cache_key, user_id=user_id)
        classification: LLMLinkClassification | None = None
        if cached_bytes is not None:
            try:
                classification = LLMLinkClassification.model_validate(
                    orjson.loads(cached_bytes)
                )
                result.cache_hits += 1
            except Exception:
                classification = None

        if classification is None:
            findings = await store.fetch_findings_by_ids(
                [src_id, tgt_id], user_id=user_id
            )
            by_id = {f.id: f for f in findings}
            finding_a = by_id.get(src_id)
            finding_b = by_id.get(tgt_id)
            if finding_a is None or finding_b is None:
                result.unchanged += 1
                continue

            # Shared entities: intersect the per-finding entity lists.
            ents_a = await store.entities_for_finding(src_id, user_id=user_id)
            ents_b = await store.entities_for_finding(tgt_id, user_id=user_id)
            b_ids = {e.id for e in ents_b}
            shared = [e for e in ents_a if e.id in b_ids]

            try:
                classification = await provider.classify_relation(
                    finding_a, finding_b, shared
                )
                result.llm_calls += 1
            except Exception as exc:
                logger.warning(
                    "LLM classify_relation failed for %s->%s: %s",
                    src_id,
                    tgt_id,
                    exc,
                )
                result.unchanged += 1
                continue

            async with store.transaction():
                await store.put_llm_link_cache(
                    cache_key=cache_key,
                    provider=provider.name,
                    model=provider.model,
                    schema_version=LINK_CLASSIFICATION_SCHEMA_VERSION,
                    classification_json=orjson.dumps(classification.model_dump()),
                    user_id=user_id,
                )

        # Decide new status based on classification.
        if classification.related and classification.confidence >= confidence_threshold:
            new_status = RelationStatus.AUTO_CONFIRMED
            result.promoted += 1
        elif not classification.related:
            new_status = RelationStatus.REJECTED
            result.rejected += 1
        else:
            new_status = RelationStatus.CANDIDATE
            result.unchanged += 1

        # Preserve sticky user states — apply_link_classification
        # unconditionally updates, so skip when the relation is already
        # user-confirmed or user-rejected.
        if rel.status in (
            RelationStatus.USER_CONFIRMED,
            RelationStatus.USER_REJECTED,
        ):
            continue

        async with store.transaction():
            await store.apply_link_classification(
                relation_id=rel.id,
                status=new_status,
                rationale=classification.rationale,
                relation_type=classification.relation_type,
                confidence=classification.confidence,
                user_id=user_id,
            )

    return result


def _cache_key(src_id: str, tgt_id: str, provider: LLMExtractionProvider, schema_version: int) -> str:
    payload = f"{src_id}|{tgt_id}|{provider.name}|{provider.model}|{schema_version}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _load_finding(store: ChainStore, finding_id: str):
    from opentools.models import Finding, FindingStatus, Severity

    row = store.execute_one(
        "SELECT * FROM findings WHERE id = ?",
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


def _shared_entities(store: ChainStore, fa_id: str, fb_id: str) -> list[Entity]:
    rows = store.execute_all(
        """
        SELECT DISTINCT e.id, e.type, e.canonical_value, e.mention_count,
                        e.first_seen_at, e.last_seen_at
        FROM entity e
        JOIN entity_mention ma ON ma.entity_id = e.id AND ma.finding_id = ?
        JOIN entity_mention mb ON mb.entity_id = e.id AND mb.finding_id = ?
        """,
        (fa_id, fb_id),
    )
    return [
        Entity(
            id=r["id"],
            type=r["type"],
            canonical_value=r["canonical_value"],
            mention_count=r["mention_count"],
            first_seen_at=datetime.fromisoformat(r["first_seen_at"]),
            last_seen_at=datetime.fromisoformat(r["last_seen_at"]),
        )
        for r in rows
    ]
