"""Rule-based linker engine for inline mode.

Given a finding id, finds all candidate partner findings that share at least
one entity via an inverted-index SQL lookup, applies all enabled rules to
each pair, and bulk-upserts the resulting relations. Produces one LinkerRun
row per invocation with aggregate stats.
"""
from __future__ import annotations

import hashlib
import time
import uuid
from datetime import datetime, timezone
from typing import Iterable
from uuid import UUID

import orjson

from opentools.chain.config import ChainConfig
from opentools.chain.linker.context import LinkerContext, derive_common_entity_threshold
from opentools.chain.linker.idf import compute_avg_idf
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
    Entity,
    FindingRelation,
    LinkerRun,
    RelationReason,
)
from opentools.chain.store_extensions import ChainStore
from opentools.chain.types import LinkerMode, LinkerScope, RelationStatus
from opentools.models import (
    Finding,
    FindingStatus,
    Severity,
)


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


class LinkerEngine:
    def __init__(
        self,
        *,
        store: ChainStore,
        config: ChainConfig,
        rules: list[Rule],
    ) -> None:
        self.store = store
        self.config = config
        self.rules = rules

    # ─── context construction ──────────────────────────────────────────

    # Minimum scope below which IDF is too noisy to be useful as a weight
    # modifier.  Below this count every shared entity has near-zero IDF
    # (it appears in all or most findings), so rules fall back to base weights.
    _MIN_SCOPE_FOR_IDF: int = 5

    def make_context(
        self,
        *,
        user_id: UUID | None,
        is_web: bool = False,
    ) -> LinkerContext:
        """Build a LinkerContext with scope totals and avg_idf from the DB."""
        row = self.store.execute_one(
            "SELECT COUNT(*) FROM findings WHERE deleted_at IS NULL"
        )
        scope_total = row[0] if row else 0

        # Load entities that have any mentions to compute avg IDF
        rows = self.store.execute_all(
            "SELECT id, type, canonical_value, mention_count, first_seen_at, last_seen_at "
            "FROM entity WHERE mention_count > 0"
        )
        entities = [
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
        avg_idf = compute_avg_idf(entities, scope_total)

        # For very small scopes IDF degenerates: every shared entity appears
        # in all findings (IDF → 0), making strong-entity contributions nearly
        # zero.  Use a scope-adjusted config that disables IDF and raises the
        # common-entity threshold so shared entities are not erroneously
        # suppressed.
        small_scope = scope_total < self._MIN_SCOPE_FOR_IDF
        if small_scope and self.config.linker.idf_enabled:
            from opentools.chain.config import LinkerConfig
            adj_linker = self.config.linker.model_copy(update={"idf_enabled": False})
            effective_config = self.config.model_copy(update={"linker": adj_linker})
        else:
            effective_config = self.config

        # Ensure the common-entity threshold is at least scope_total so that
        # shared entities in a small scope are never unconditionally suppressed.
        raw_threshold = derive_common_entity_threshold(
            scope_total, self.config.linker.common_entity_pct
        )
        common_threshold = max(raw_threshold, scope_total)

        # Generation: one more than the highest existing run for this user
        gen_row = self.store.execute_one(
            "SELECT COALESCE(MAX(generation), 0) FROM linker_run"
        )
        generation = (gen_row[0] if gen_row else 0) + 1

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

    # ─── main entry point ──────────────────────────────────────────────

    def link_finding(
        self,
        finding_id: str,
        *,
        user_id: UUID | None,
        context: LinkerContext | None = None,
    ) -> LinkerRun:
        """Run rule-based linking for a single finding via inverted-index lookup."""
        start = time.monotonic()
        ctx = context or self.make_context(user_id=user_id)

        run_id = f"run_{uuid.uuid4().hex[:12]}"
        now = _utcnow()

        # 1. Load the source finding
        source_finding = self._load_finding(finding_id)
        if source_finding is None:
            return self._record_run(
                run_id, now, 0, 0, 0, 0, 0,
                error=f"finding {finding_id} not found",
                generation=ctx.generation,
            )

        # 2. Load the source finding's entities
        source_entities = self._entities_for_finding(finding_id)
        if not source_entities:
            return self._record_run(
                run_id, now, 1, 0, 0, 0, 0,
                generation=ctx.generation,
            )

        # 3. Inverted-index lookup: find partner findings sharing any entity
        source_entity_ids = {e.id for e in source_entities}
        partner_map = self._find_partners(finding_id, source_entity_ids, user_id)

        # 4. Apply rules per partner
        relations_to_upsert: list[FindingRelation] = []
        relations_updated = 0
        relations_skipped_sticky = 0
        rule_stats: dict[str, dict] = {}

        for partner_id, shared_entity_ids in partner_map.items():
            partner_finding = self._load_finding(partner_id)
            if partner_finding is None:
                continue
            shared_entities = [e for e in source_entities if e.id in shared_entity_ids]

            contributions: list[RuleContribution] = []
            for rule in self.rules:
                if rule.requires_shared_entity and not shared_entities:
                    continue
                try:
                    contribs = rule.apply(source_finding, partner_finding, shared_entities, ctx)
                except Exception:
                    continue
                contributions.extend(contribs)
                if contribs:
                    stats = rule_stats.setdefault(rule.name, {"fires": 0, "total_weight": 0.0})
                    stats["fires"] += len(contribs)
                    stats["total_weight"] += sum(c.weight for c in contribs)

            if not contributions:
                continue

            # Determine edge direction: if any asymmetric rule fired, use its direction
            asym_dirs = [c.direction for c in contributions if c.direction != "symmetric"]
            if asym_dirs:
                direction = asym_dirs[0]
            else:
                direction = "symmetric"

            # Resolve source/target based on direction
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

        if relations_to_upsert:
            self.store.upsert_relations_bulk(relations_to_upsert)

        duration_ms = int((time.monotonic() - start) * 1000)
        return self._record_run(
            run_id, now, 1, len(source_entities),
            len(relations_to_upsert), relations_updated, relations_skipped_sticky,
            duration_ms=duration_ms,
            rule_stats=rule_stats,
            generation=ctx.generation,
        )

    # ─── helpers ───────────────────────────────────────────────────────

    def _load_finding(self, finding_id: str) -> Finding | None:
        row = self.store.execute_one(
            "SELECT * FROM findings WHERE id = ? AND deleted_at IS NULL",
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

    def _entities_for_finding(self, finding_id: str) -> list[Entity]:
        rows = self.store.execute_all(
            """
            SELECT DISTINCT e.id, e.type, e.canonical_value, e.mention_count,
                            e.first_seen_at, e.last_seen_at
            FROM entity e
            JOIN entity_mention m ON m.entity_id = e.id
            WHERE m.finding_id = ?
            """,
            (finding_id,),
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

    def _find_partners(
        self,
        finding_id: str,
        entity_ids: set[str],
        user_id: UUID | None,
    ) -> dict[str, set[str]]:
        """Return {partner_finding_id: {shared_entity_ids}} via inverted-index JOIN."""
        if not entity_ids:
            return {}
        placeholders = ",".join("?" * len(entity_ids))
        sql = f"""
            SELECT DISTINCT m.finding_id, m.entity_id
            FROM entity_mention m
            WHERE m.entity_id IN ({placeholders})
              AND m.finding_id != ?
        """
        params: list = list(entity_ids) + [finding_id]
        if user_id is not None:
            sql += " AND m.user_id = ?"
            params.append(str(user_id))
        rows = self.store.execute_all(sql, tuple(params))
        partners: dict[str, set[str]] = {}
        for r in rows:
            partners.setdefault(r["finding_id"], set()).add(r["entity_id"])
        return partners

    def _record_run(
        self,
        run_id: str,
        started_at: datetime,
        findings_processed: int,
        entities_extracted: int,
        relations_created: int,
        relations_updated: int,
        relations_skipped_sticky: int,
        *,
        duration_ms: int | None = None,
        rule_stats: dict | None = None,
        error: str | None = None,
        generation: int = 1,
    ) -> LinkerRun:
        finished = _utcnow()
        run = LinkerRun(
            id=run_id,
            started_at=started_at,
            finished_at=finished,
            scope=LinkerScope.FINDING_SINGLE,
            scope_id=None,
            mode=LinkerMode.RULES_ONLY,
            findings_processed=findings_processed,
            entities_extracted=entities_extracted,
            relations_created=relations_created,
            relations_updated=relations_updated,
            relations_skipped_sticky=relations_skipped_sticky,
            rule_stats=rule_stats or {},
            duration_ms=duration_ms,
            error=error,
            generation=generation,
        )
        self._persist_run(run)
        return run

    def _persist_run(self, run: LinkerRun) -> None:
        self.store._conn.execute(
            """
            INSERT INTO linker_run
                (id, started_at, finished_at, scope, scope_id, mode, llm_provider,
                 findings_processed, entities_extracted, relations_created,
                 relations_updated, relations_skipped_sticky,
                 extraction_cache_hits, extraction_cache_misses,
                 llm_calls_made, llm_cache_hits, llm_cache_misses,
                 rule_stats_json, duration_ms, error, generation, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run.id,
                run.started_at.isoformat(),
                run.finished_at.isoformat() if run.finished_at else None,
                run.scope.value,
                run.scope_id,
                run.mode.value,
                run.llm_provider,
                run.findings_processed,
                run.entities_extracted,
                run.relations_created,
                run.relations_updated,
                run.relations_skipped_sticky,
                run.extraction_cache_hits,
                run.extraction_cache_misses,
                run.llm_calls_made,
                run.llm_cache_hits,
                run.llm_cache_misses,
                orjson.dumps(run.rule_stats),
                run.duration_ms,
                run.error,
                run.generation,
                str(run.user_id) if run.user_id else None,
            ),
        )
        self.store._conn.commit()


def _deterministic_relation_id(src: str, tgt: str, user_id: UUID | None) -> str:
    payload = f"{src}|{tgt}|{user_id or ''}".encode("utf-8")
    return f"rel_{hashlib.sha256(payload).hexdigest()[:16]}"
