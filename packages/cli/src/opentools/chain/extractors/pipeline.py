"""Three-stage extraction pipeline orchestrator.

Runs parser-aware (stage 1), rule-based (stage 2), and optional LLM
(stage 3) extraction against a finding. Handles entity normalization,
deduplication within a run, change detection via extraction_input_hash,
and cascade delete of stale mentions on re-extraction.

Async implementation built on top of :class:`ChainStoreProtocol`.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from opentools.chain.config import ChainConfig
from opentools.chain.extractors.base import ExtractedEntity, ExtractionContext
from opentools.chain.extractors.ioc_finder import IocFinderExtractor
from opentools.chain.extractors.llm.base import LLMExtractionProvider
from opentools.chain.extractors.parser_aware import BUILTIN_PARSER_EXTRACTORS
from opentools.chain.extractors.security_regex import BUILTIN_SECURITY_EXTRACTORS
from opentools.chain.models import (
    Entity,
    EntityMention,
    entity_id_for,
)
from opentools.chain.normalizers import normalize
from opentools.chain.types import MentionField
from opentools.models import Finding

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _extraction_input_hash(finding: Finding) -> str:
    parts = [
        finding.title or "",
        finding.description or "",
        finding.evidence or "",
        finding.file_path or "",
    ]
    blob = "|".join(parts).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


@dataclass
class ExtractionResult:
    entities_created: int
    mentions_created: int
    stage1_count: int
    stage2_count: int
    stage3_count: int
    cache_hit: bool
    was_force: bool


class ExtractionPipeline:
    """Async three-stage extraction pipeline using ChainStoreProtocol.

    Stage 1 is parser-aware (reads finding_parser_output rows via the
    protocol). Stage 2 is rule-based (ioc-finder + security regex
    extractors). Stage 3 is optional LLM extraction (only when
    ``llm_provider`` passed).

    All reads/writes go through ``ChainStoreProtocol`` methods. The
    entity/mention persist step and extraction-state update run inside
    a single ``store.transaction()`` so partial failures roll back
    cleanly.
    """

    def __init__(
        self,
        *,
        store,  # ChainStoreProtocol
        config: ChainConfig,
        security_extractors: list | None = None,
        parser_extractors: list | None = None,
    ) -> None:
        self.store = store
        self.config = config
        self.security_extractors = security_extractors or list(BUILTIN_SECURITY_EXTRACTORS)
        self.security_extractors.insert(0, IocFinderExtractor())
        self.parser_extractors = parser_extractors or list(BUILTIN_PARSER_EXTRACTORS)

    async def extract_for_finding(
        self,
        finding: Finding,
        *,
        user_id=None,
        llm_provider: LLMExtractionProvider | None = None,
        force: bool = False,
    ) -> ExtractionResult:
        new_hash = _extraction_input_hash(finding)
        if not force:
            stored = await self.store.get_extraction_hash(
                finding.id, user_id=user_id,
            )
            if stored == new_hash:
                return ExtractionResult(
                    entities_created=0, mentions_created=0,
                    stage1_count=0, stage2_count=0, stage3_count=0,
                    cache_hit=True, was_force=False,
                )

        # Hard-delete stale mentions so edits don't leak old entities
        await self.store.delete_mentions_for_finding(
            finding.id, user_id=user_id,
        )

        ctx = ExtractionContext(finding=finding)

        # Stage 1 — parser-aware (protocol method, not raw SQL)
        stage1 = await self._run_stage1(finding, ctx, user_id=user_id)
        ctx.already_extracted.extend(stage1)

        # Stage 2 — rule-based (pure Python; no DB access)
        stage2 = self._run_stage2(finding, ctx)
        ctx.already_extracted.extend(stage2)

        # Stage 3 — optional LLM (await native)
        stage3: list[ExtractedEntity] = []
        if llm_provider is not None:
            stage3 = await self._run_stage3(
                finding, ctx, llm_provider,
            )
            ctx.already_extracted.extend(stage3)

        all_raw = stage1 + stage2 + stage3

        async with self.store.transaction():
            entities_created, mentions_created = await self._persist(
                finding, all_raw, user_id=user_id,
            )
            await self.store.upsert_extraction_state(
                finding_id=finding.id,
                extraction_input_hash=new_hash,
                extractor_set=[],  # populated in a later phase
                user_id=user_id,
            )

        return ExtractionResult(
            entities_created=entities_created,
            mentions_created=mentions_created,
            stage1_count=len(stage1),
            stage2_count=len(stage2),
            stage3_count=len(stage3),
            cache_hit=False,
            was_force=force,
        )

    # ─── stages ────────────────────────────────────────────────────────

    async def _run_stage1(
        self,
        finding: Finding,
        ctx: ExtractionContext,
        *,
        user_id,
    ) -> list[ExtractedEntity]:
        rows = await self.store.get_parser_output(
            finding.id, user_id=user_id,
        )
        out: list[ExtractedEntity] = []
        for row in rows:
            # get_parser_output returns FindingParserOutput models with
            # parser_name + already-deserialized data dict.
            parser_name = row.parser_name
            data = row.data
            for ex in self.parser_extractors:
                if ex.tool_name != parser_name:
                    continue
                try:
                    out.extend(ex.extract(finding, data, ctx))
                except Exception as exc:
                    logger.warning(
                        "parser-aware extractor %s failed for finding %s: %s",
                        ex.tool_name, finding.id, exc,
                    )
                    continue
        return out

    def _run_stage2(
        self,
        finding: Finding,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        fields = [
            (MentionField.TITLE, finding.title or ""),
            (MentionField.DESCRIPTION, finding.description or ""),
            (MentionField.EVIDENCE, finding.evidence or ""),
        ]
        for field, text in fields:
            if not text:
                continue
            # Note: prose/code splitting via split_code_blocks() is reserved for a
            # future task where stage-2 extractors can opt to skip code regions.
            # It is intentionally not used here in 3C.1 to keep the pipeline simple.
            for ex in self.security_extractors:
                if hasattr(ex, "applies_to") and not ex.applies_to(finding):
                    continue
                try:
                    out.extend(ex.extract(text, field, ctx))
                except Exception as exc:
                    logger.warning(
                        "security extractor %s failed for finding %s field %s: %s",
                        getattr(ex, "name", type(ex).__name__),
                        finding.id, field.value, exc,
                    )
                    continue
        return out

    async def _run_stage3(
        self,
        finding: Finding,
        ctx: ExtractionContext,
        provider: LLMExtractionProvider,
    ) -> list[ExtractedEntity]:
        prose_fields = [
            finding.title or "",
            finding.description or "",
            finding.evidence or "",
        ]
        combined = "\n".join(p for p in prose_fields if p)
        if not combined:
            return []
        try:
            results = await provider.extract_entities(combined, ctx)
            return list(results)
        except Exception as exc:
            logger.warning(
                "LLM stage3 extraction failed for finding %s: %s",
                finding.id, exc, exc_info=True,
            )
            return []

    # ─── persistence ───────────────────────────────────────────────────

    async def _persist(
        self,
        finding: Finding,
        raw: list[ExtractedEntity],
        *,
        user_id,
    ) -> tuple[int, int]:
        """Normalize, dedupe within-run, upsert entities + mentions.

        The three terminal store writes go through protocol methods
        (``upsert_entities_bulk``, ``add_mentions_bulk``,
        ``recompute_mention_counts``). Mention counts are recomputed
        from ground truth after insert to avoid drift on re-extraction.
        """
        now = _utcnow()
        entities_by_id: dict[str, Entity] = {}
        new_entity_ids: set[str] = set()
        mentions: list[EntityMention] = []

        # Pre-compute normalized values and entity IDs for all raw extractions
        normalized: list[tuple[ExtractedEntity, str, str]] = []  # (ex, canonical, eid)
        unique_eids: set[str] = set()
        for ex in raw:
            try:
                canonical = normalize(ex.type, ex.value)
            except Exception:
                continue
            if not canonical:
                continue
            eid = entity_id_for(ex.type, canonical)
            normalized.append((ex, canonical, eid))
            unique_eids.add(eid)

        # Single batch fetch for all unique entity IDs
        existing_entities = await self.store.get_entities_by_ids(
            unique_eids, user_id=user_id,
        )

        for ex, canonical, eid in normalized:
            if eid not in entities_by_id:
                existing = existing_entities.get(eid)
                if existing is None:
                    new_entity_ids.add(eid)
                    entities_by_id[eid] = Entity(
                        id=eid, type=ex.type, canonical_value=canonical,
                        first_seen_at=now, last_seen_at=now, mention_count=0,
                    )
                else:
                    # Preserve first_seen_at, advance last_seen_at, RESET
                    # count — recomputed from entity_mention after insert
                    entities_by_id[eid] = Entity(
                        id=eid,
                        type=existing.type,
                        canonical_value=existing.canonical_value,
                        first_seen_at=existing.first_seen_at,
                        last_seen_at=now,
                        mention_count=0,  # placeholder — recomputed below
                        user_id=existing.user_id,
                    )
            else:
                entities_by_id[eid].last_seen_at = now

            mentions.append(
                EntityMention(
                    id=f"mnt_{uuid.uuid4().hex[:16]}",
                    entity_id=eid,
                    finding_id=finding.id,
                    field=ex.field,
                    raw_value=ex.value,
                    offset_start=ex.offset_start,
                    offset_end=ex.offset_end,
                    extractor=ex.extractor,
                    confidence=ex.confidence,
                    created_at=now,
                )
            )

        # Upsert entities (mention_count=0 placeholder) and insert mentions
        if entities_by_id:
            await self.store.upsert_entities_bulk(
                list(entities_by_id.values()), user_id=user_id,
            )
        if mentions:
            await self.store.add_mentions_bulk(mentions, user_id=user_id)

        # Recompute mention_count from ground truth for every touched entity
        if entities_by_id:
            await self.store.recompute_mention_counts(
                list(entities_by_id.keys()), user_id=user_id,
            )

        return len(new_entity_ids), len(mentions)
