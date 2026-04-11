"""Rule-based linker engine for inline mode.

Given a finding id, finds all candidate partner findings that share at
least one entity via an inverted-index protocol lookup, applies all
enabled rules to each pair, and bulk-upserts the resulting relations.
Produces one LinkerRun row per invocation with aggregate stats.

Async implementation built on top of :class:`ChainStoreProtocol`.
"""
from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from uuid import UUID

from opentools.chain.config import ChainConfig
from opentools.chain.linker.context import LinkerContext, derive_common_entity_threshold
from opentools.chain.linker.rules.base import Rule, RuleContribution
from opentools.chain.linker.rules.cross_engagement_ioc import SharedIOCCrossEngagementRule
from opentools.chain.linker.rules.cve_adjacency import CVEAdjacencyRule
from opentools.chain.linker.rules.kill_chain import KillChainAdjacencyRule
from opentools.chain.linker.rules.shared_entity import (
    SharedStrongEntityRule,
    SharedWeakEntityRule,
)
from opentools.chain.linker.rules.temporal import TemporalProximityRule
from opentools.chain.linker.rules.tool_chain import ToolChainRule
from opentools.chain.models import (
    FindingRelation,
    LinkerRun,
    RelationReason,
)
from opentools.chain.types import LinkerMode, LinkerScope, RelationStatus


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def get_default_rules(config: ChainConfig) -> list[Rule]:
    """Instantiate the 7 built-in rules using weights from config."""
    r = config.linker.rules
    rules: list[Rule] = []
    if r.shared_strong_entity.enabled:
        rules.append(SharedStrongEntityRule(weight=r.shared_strong_entity.weight))
    if r.shared_weak_entity.enabled:
        rules.append(SharedWeakEntityRule(weight=r.shared_weak_entity.weight))
    if r.temporal_proximity.enabled:
        rules.append(TemporalProximityRule(
            weight=r.temporal_proximity.weight,
            window_minutes=r.temporal_proximity.window_minutes or 15,
        ))
    if r.tool_chain.enabled:
        rules.append(ToolChainRule(weight=r.tool_chain.weight))
    if r.shared_ioc_cross_engagement.enabled:
        rules.append(SharedIOCCrossEngagementRule(weight=r.shared_ioc_cross_engagement.weight))
    if r.cve_adjacency.enabled:
        rules.append(CVEAdjacencyRule(weight=r.cve_adjacency.weight))
    if r.kill_chain_adjacency.enabled:
        rules.append(KillChainAdjacencyRule(weight=r.kill_chain_adjacency.weight))
    return rules


def _deterministic_relation_id(src: str, tgt: str, user_id: UUID | None) -> str:
    payload = f"{src}|{tgt}|{user_id or ''}".encode("utf-8")
    return f"rel_{hashlib.sha256(payload).hexdigest()[:16]}"


class LinkerEngine:
    """Async rule-based linker using ChainStoreProtocol.

    All reads/writes go through protocol methods
    (``fetch_findings_by_ids``, ``entities_for_finding``,
    ``fetch_candidate_partners``, ``start_linker_run``,
    ``finish_linker_run``, ``upsert_relations_bulk``).

    Spec G6 optimization: partner findings are batch-fetched with a
    single ``fetch_findings_by_ids`` call instead of one round-trip
    per partner.
    """

    # Minimum scope below which IDF is too noisy to be useful as a weight
    # modifier. Below this count every shared entity has near-zero IDF
    # (it appears in all or most findings), so rules fall back to base weights.
    _MIN_SCOPE_FOR_IDF: int = 5

    def __init__(
        self,
        *,
        store,  # ChainStoreProtocol — typed loosely to avoid import cycle
        config: ChainConfig,
        rules: list[Rule] | None = None,
    ) -> None:
        self.store = store
        self.config = config
        self.rules = rules if rules is not None else get_default_rules(config)

    async def make_context(
        self,
        *,
        user_id: UUID | None,
        is_web: bool = False,
    ) -> LinkerContext:
        """Build a LinkerContext via protocol methods (no raw SQL)."""
        scope_total = await self.store.count_findings_in_scope(user_id=user_id)
        avg_idf = await self.store.compute_avg_idf(
            scope_total=scope_total, user_id=user_id
        )

        # For very small scopes IDF degenerates; disable it so
        # strong-entity contributions are not erroneously suppressed.
        small_scope = scope_total < self._MIN_SCOPE_FOR_IDF
        if small_scope and self.config.linker.idf_enabled:
            adj_linker = self.config.linker.model_copy(
                update={"idf_enabled": False}
            )
            effective_config = self.config.model_copy(
                update={"linker": adj_linker}
            )
        else:
            effective_config = self.config

        # Ensure the common-entity threshold is at least scope_total so
        # shared entities in a small scope are never unconditionally
        # suppressed.
        raw_threshold = derive_common_entity_threshold(
            scope_total, self.config.linker.common_entity_pct
        )
        common_threshold = max(raw_threshold, scope_total)

        # Generation: one more than the highest existing run
        current_gen = await self.store.current_linker_generation(
            user_id=user_id
        )
        generation = current_gen + 1

        return LinkerContext(
            user_id=user_id,
            is_web=is_web,
            scope_total_findings=scope_total,
            avg_idf=avg_idf,
            stopwords_extra=self.config.linker.stopwords_extra,
            common_entity_pct=self.config.linker.common_entity_pct,
            common_entity_threshold=common_threshold,
            config=effective_config,
            generation=generation,
        )

    async def link_finding(
        self,
        finding_id: str,
        *,
        user_id: UUID | None,
        context: LinkerContext | None = None,
    ) -> LinkerRun:
        """Run rule-based linking for a single finding via inverted-index lookup.

        Uses protocol lifecycle methods (``start_linker_run`` /
        ``finish_linker_run`` / ``set_run_status``) so any conforming
        backend works identically.
        """
        start = time.monotonic()
        ctx = context or await self.make_context(user_id=user_id)
        now = _utcnow()

        # Create the linker_run row up front so we have an id to thread
        # through finish/error paths below. The row is initialized with
        # status='pending' by start_linker_run.
        run = await self.store.start_linker_run(
            scope=LinkerScope.FINDING_SINGLE,
            scope_id=None,
            mode=LinkerMode.RULES_ONLY,
            user_id=user_id,
        )

        # 1. Load the source finding via protocol
        source_findings = await self.store.fetch_findings_by_ids(
            [finding_id], user_id=user_id
        )
        if not source_findings:
            return await self._finalize_run(
                run=run,
                now=now,
                findings_processed=0,
                entities_extracted=0,
                relations_created=0,
                relations_updated=0,
                relations_skipped_sticky=0,
                rule_stats={},
                duration_ms=int((time.monotonic() - start) * 1000),
                error=f"finding {finding_id} not found",
                user_id=user_id,
            )
        source_finding = source_findings[0]

        # 2. Source entities via protocol
        source_entities = await self.store.entities_for_finding(
            finding_id, user_id=user_id
        )
        if not source_entities:
            return await self._finalize_run(
                run=run,
                now=now,
                findings_processed=1,
                entities_extracted=0,
                relations_created=0,
                relations_updated=0,
                relations_skipped_sticky=0,
                rule_stats={},
                duration_ms=int((time.monotonic() - start) * 1000),
                user_id=user_id,
            )

        # 3. Inverted-index partner lookup via protocol
        source_entity_ids = {e.id for e in source_entities}
        partner_map = await self.store.fetch_candidate_partners(
            finding_id=finding_id,
            entity_ids=source_entity_ids,
            common_entity_threshold=ctx.common_entity_threshold,
            user_id=user_id,
        )

        # G6: batch-fetch ALL partner findings in one protocol call
        partner_findings = await self.store.fetch_findings_by_ids(
            list(partner_map.keys()), user_id=user_id
        )
        partner_by_id = {p.id: p for p in partner_findings}

        # 4. Apply rules per partner
        relations_to_upsert: list[FindingRelation] = []
        relations_updated = 0
        relations_skipped_sticky = 0
        rule_stats: dict[str, dict] = {}

        for partner_id, shared_entity_ids in partner_map.items():
            partner_finding = partner_by_id.get(partner_id)
            if partner_finding is None:
                continue
            shared_entities = [
                e for e in source_entities if e.id in shared_entity_ids
            ]

            contributions: list[RuleContribution] = []
            for rule in self.rules:
                if rule.requires_shared_entity and not shared_entities:
                    continue
                try:
                    contribs = rule.apply(
                        source_finding, partner_finding, shared_entities, ctx
                    )
                except Exception:
                    continue
                contributions.extend(contribs)
                if contribs:
                    stats = rule_stats.setdefault(
                        rule.name, {"fires": 0, "total_weight": 0.0}
                    )
                    stats["fires"] += len(contribs)
                    stats["total_weight"] += sum(c.weight for c in contribs)

            if not contributions:
                continue

            # Determine edge direction
            asym_dirs = [
                c.direction for c in contributions if c.direction != "symmetric"
            ]
            if asym_dirs:
                direction = asym_dirs[0]
            else:
                direction = "symmetric"

            if direction in ("symmetric", "a_to_b"):
                src, tgt = source_finding.id, partner_finding.id
            else:  # b_to_a
                src, tgt = partner_finding.id, source_finding.id

            total_weight = sum(c.weight for c in contributions)
            capped = min(total_weight, self.config.linker.max_edge_weight)
            status = (
                RelationStatus.AUTO_CONFIRMED
                if capped >= self.config.linker.confirmed_threshold
                else RelationStatus.CANDIDATE
            )

            reasons = [
                RelationReason(
                    rule=c.rule,
                    weight_contribution=c.weight,
                    idf_factor=c.idf_factor,
                    details=c.details,
                )
                for c in contributions
            ]

            rel_id = _deterministic_relation_id(src, tgt, user_id)
            relations_to_upsert.append(
                FindingRelation(
                    id=rel_id,
                    source_finding_id=src,
                    target_finding_id=tgt,
                    weight=capped,
                    weight_model_version="additive_v1",
                    status=status,
                    symmetric=(direction == "symmetric"),
                    reasons=reasons,
                    created_at=now,
                    updated_at=now,
                    user_id=user_id,
                )
            )

        # Wrap the bulk upsert in a transaction for atomicity.
        if relations_to_upsert:
            async with self.store.transaction():
                created, updated = await self.store.upsert_relations_bulk(
                    relations_to_upsert, user_id=user_id
                )
            relations_updated = updated
        else:
            created = 0

        duration_ms = int((time.monotonic() - start) * 1000)
        return await self._finalize_run(
            run=run,
            now=now,
            findings_processed=1,
            entities_extracted=len(source_entities),
            relations_created=created,
            relations_updated=relations_updated,
            relations_skipped_sticky=relations_skipped_sticky,
            rule_stats=rule_stats,
            duration_ms=duration_ms,
            user_id=user_id,
        )

    async def _finalize_run(
        self,
        *,
        run: LinkerRun,
        now: datetime,
        findings_processed: int,
        entities_extracted: int,
        relations_created: int,
        relations_updated: int,
        relations_skipped_sticky: int,
        rule_stats: dict,
        duration_ms: int,
        user_id: UUID | None,
        error: str | None = None,
    ) -> LinkerRun:
        """Finish a linker run via protocol methods and return the hydrated model.

        ``start_linker_run`` returned a LinkerRun for the freshly inserted
        row (status='pending'); after calling ``finish_linker_run`` +
        ``set_run_status`` we patch the in-memory model to reflect the
        post-finish state so callers see consistent values without a
        re-read round-trip.
        """
        await self.store.finish_linker_run(
            run.id,
            findings_processed=findings_processed,
            entities_extracted=entities_extracted,
            relations_created=relations_created,
            relations_updated=relations_updated,
            relations_skipped_sticky=relations_skipped_sticky,
            rule_stats=rule_stats,
            duration_ms=duration_ms,
            error=error,
            user_id=user_id,
        )
        final_status = "failed" if error else "done"
        await self.store.set_run_status(run.id, final_status, user_id=user_id)

        # Patch the local model to match the persisted state.
        run.findings_processed = findings_processed
        run.entities_extracted = entities_extracted
        run.relations_created = relations_created
        run.relations_updated = relations_updated
        run.relations_skipped_sticky = relations_skipped_sticky
        run.rule_stats = rule_stats or {}
        run.duration_ms = duration_ms
        run.error = error
        run.status = final_status
        run.finished_at = now
        return run
