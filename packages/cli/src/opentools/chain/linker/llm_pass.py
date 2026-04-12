"""On-demand LLM linking pass — classifies candidate edges."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable
from uuid import UUID

import orjson

from opentools.chain.config import ChainConfig
from opentools.chain.extractors.llm.base import LLMExtractionProvider
from opentools.chain.extractors.llm.prompts import LINK_CLASSIFICATION_SCHEMA_VERSION
from opentools.chain.models import LLMLinkClassification
from opentools.chain.types import RelationStatus

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


async def llm_link_pass(
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
    """Classify candidate edges via LLM and update statuses/rationales.

    Runs against ``ChainStoreProtocol`` so any conforming backend
    (sqlite aiosqlite, future Postgres) works identically. Uses the
    protocol-level async methods (``fetch_relations_in_scope``,
    ``apply_link_classification``, ``get_llm_link_cache``,
    ``put_llm_link_cache``) instead of raw SQL. Classification + cache
    write per edge are wrapped in ``store.transaction()`` for atomicity.
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
