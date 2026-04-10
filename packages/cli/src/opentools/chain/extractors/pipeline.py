"""Three-stage extraction pipeline orchestrator.

Runs parser-aware (stage 1), rule-based (stage 2), and optional LLM
(stage 3) extraction against a finding. Handles entity normalization,
deduplication within a run, change detection via extraction_input_hash,
and cascade delete of stale mentions on re-extraction.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import orjson

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
from opentools.chain.store_extensions import ChainStore
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
    """Synchronous three-stage extraction pipeline.

    Stage 1 is parser-aware (reads finding_parser_output rows).
    Stage 2 is rule-based (ioc-finder + security regex extractors).
    Stage 3 is optional LLM extraction (only when ``llm_provider`` passed).

    LLM operations are async but the rest of the pipeline is sync. The
    LLM stage is run via ``asyncio.run`` inside the sync method for
    convenience; production callers in a web context should use
    ``extract_for_finding_async`` if needed (not implemented in 3C.1).
    """

    def __init__(
        self,
        *,
        store: ChainStore,
        config: ChainConfig,
        security_extractors: list | None = None,
        parser_extractors: list | None = None,
    ) -> None:
        self.store = store
        self.config = config
        self.security_extractors = security_extractors or list(BUILTIN_SECURITY_EXTRACTORS)
        self.security_extractors.insert(0, IocFinderExtractor())
        self.parser_extractors = parser_extractors or list(BUILTIN_PARSER_EXTRACTORS)

    def extract_for_finding(
        self,
        finding: Finding,
        *,
        llm_provider: LLMExtractionProvider | None = None,
        force: bool = False,
    ) -> ExtractionResult:
        new_hash = _extraction_input_hash(finding)
        if not force and self._hash_matches(finding.id, new_hash):
            return ExtractionResult(
                entities_created=0, mentions_created=0,
                stage1_count=0, stage2_count=0, stage3_count=0,
                cache_hit=True, was_force=False,
            )

        # Hard-delete stale mentions so edits don't leak old entities
        self.store.delete_mentions_for_finding(finding.id)

        ctx = ExtractionContext(finding=finding)

        # Stage 1 — parser-aware
        stage1 = self._run_stage1(finding, ctx)
        ctx.already_extracted.extend(stage1)

        # Stage 2 — rule-based across title/description/evidence
        stage2 = self._run_stage2(finding, ctx)
        ctx.already_extracted.extend(stage2)

        # Stage 3 — optional LLM
        stage3: list[ExtractedEntity] = []
        if llm_provider is not None:
            stage3 = self._run_stage3(finding, ctx, llm_provider)
            ctx.already_extracted.extend(stage3)

        all_raw = stage1 + stage2 + stage3

        # Normalize and upsert entities/mentions
        entities_created, mentions_created = self._persist(finding, all_raw)

        # Update change detection state
        self._update_extraction_state(finding.id, new_hash)

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

    def _run_stage1(self, finding: Finding, ctx: ExtractionContext) -> list[ExtractedEntity]:
        # Look up all parser outputs from SQL side table (finding_parser_output)
        rows = self.store.execute_all(
            "SELECT parser_name, data_json FROM finding_parser_output WHERE finding_id = ?",
            (finding.id,),
        )
        out: list[ExtractedEntity] = []
        for row in rows:
            parser_name = row["parser_name"]
            data = orjson.loads(row["data_json"])
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

    def _run_stage2(self, finding: Finding, ctx: ExtractionContext) -> list[ExtractedEntity]:
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

    def _run_stage3(
        self,
        finding: Finding,
        ctx: ExtractionContext,
        provider: LLMExtractionProvider,
    ) -> list[ExtractedEntity]:
        prose_fields = [finding.title or "", finding.description or "", finding.evidence or ""]
        combined = "\n".join(p for p in prose_fields if p)
        if not combined:
            return []
        try:
            results = asyncio.run(provider.extract_entities(combined, ctx))
            return list(results)
        except Exception as exc:
            logger.warning(
                "LLM stage3 extraction failed for finding %s: %s",
                finding.id, exc, exc_info=True,
            )
            return []

    # ─── persistence ───────────────────────────────────────────────────

    def _persist(
        self,
        finding: Finding,
        raw: list[ExtractedEntity],
    ) -> tuple[int, int]:
        """Normalize, dedupe within-run, and upsert entities + mentions.

        mention_count is recomputed from entity_mention after insert to
        avoid drift on re-extraction.
        """
        now = _utcnow()
        entities_by_id: dict[str, Entity] = {}
        new_entity_ids: set[str] = set()
        mentions: list[EntityMention] = []

        for ex in raw:
            try:
                canonical = normalize(ex.type, ex.value)
            except Exception:
                continue
            if not canonical:
                continue
            eid = entity_id_for(ex.type, canonical)
            if eid not in entities_by_id:
                existing = self.store.get_entity(eid)
                if existing is None:
                    new_entity_ids.add(eid)
                    entities_by_id[eid] = Entity(
                        id=eid, type=ex.type, canonical_value=canonical,
                        first_seen_at=now, last_seen_at=now, mention_count=0,
                    )
                else:
                    # Use existing first_seen_at, advance last_seen_at, RESET count
                    # — count will be recomputed from entity_mention after insert
                    entities_by_id[eid] = Entity(
                        id=eid, type=existing.type, canonical_value=existing.canonical_value,
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

        # Upsert entities (with mention_count=0 placeholder)
        for entity in entities_by_id.values():
            self.store.upsert_entity(entity)

        # Insert new mentions
        self.store.add_mentions(mentions)

        # Recompute mention_count from ground truth for all touched entities
        for eid in entities_by_id.keys():
            self.store._conn.execute(
                "UPDATE entity SET mention_count = (SELECT COUNT(*) FROM entity_mention WHERE entity_id = ?) WHERE id = ?",
                (eid, eid),
            )
        self.store._conn.commit()

        return len(new_entity_ids), len(mentions)

    def _hash_matches(self, finding_id: str, new_hash: str) -> bool:
        row = self.store.execute_one(
            "SELECT extraction_input_hash FROM finding_extraction_state WHERE finding_id = ?",
            (finding_id,),
        )
        return row is not None and row["extraction_input_hash"] == new_hash

    def _update_extraction_state(self, finding_id: str, new_hash: str) -> None:
        # NOTE: Direct access to self.store._conn bypasses ChainStore's public API.
        # This is intentional for Task 17 — a future refactor can expose
        # store.upsert_extraction_state(...) to encapsulate this SQL.
        self.store._conn.execute(
            """
            INSERT INTO finding_extraction_state
                (finding_id, extraction_input_hash, last_extracted_at, last_extractor_set_json, user_id)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(finding_id) DO UPDATE SET
                extraction_input_hash=excluded.extraction_input_hash,
                last_extracted_at=excluded.last_extracted_at,
                last_extractor_set_json=excluded.last_extractor_set_json
            """,
            (
                finding_id,
                new_hash,
                _utcnow().isoformat(),
                orjson.dumps([]),  # populated in later phase
                None,
            ),
        )
        self.store._conn.commit()
