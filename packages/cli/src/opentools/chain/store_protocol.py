"""ChainStoreProtocol — backend-agnostic async interface for chain data.

See docs/superpowers/specs/2026-04-10-phase3c1-5-async-store-refactor-design.md
§4 for contracts and rationale.

Every method is async. Methods return domain objects from
opentools.chain.models, never sqlite3.Row or SQLAlchemy ORM instances.
No raw SQL escape hatch.

User scoping: methods that touch per-user data take user_id as a
required keyword argument. None means "CLI context, unscoped" (accepted
by AsyncChainStore, rejected by PostgresChainStore via @require_user_scope).
"""
from __future__ import annotations

from datetime import datetime
from typing import AsyncContextManager, AsyncIterator, Iterable, Protocol
from uuid import UUID

from opentools.chain.models import (
    Entity,
    EntityMention,
    FindingParserOutput,
    FindingRelation,
    LinkerRun,
)
from opentools.chain.types import (
    LinkerMode,
    LinkerScope,
    RelationStatus,
)
from opentools.models import Finding


class ChainStoreProtocol(Protocol):
    # --- Lifecycle ---

    async def initialize(self) -> None: ...

    async def close(self) -> None: ...

    def transaction(self) -> AsyncContextManager[None]: ...

    def batch_transaction(self) -> AsyncContextManager[None]: ...

    # --- Entity CRUD ---

    async def upsert_entity(
        self, entity: Entity, *, user_id: UUID | None
    ) -> None: ...

    async def upsert_entities_bulk(
        self, entities: Iterable[Entity], *, user_id: UUID | None
    ) -> None: ...

    async def get_entity(
        self, entity_id: str, *, user_id: UUID | None
    ) -> Entity | None: ...

    async def get_entities_by_ids(
        self, entity_ids: Iterable[str], *, user_id: UUID | None
    ) -> dict[str, Entity]: ...

    async def list_entities(
        self,
        *,
        user_id: UUID | None,
        entity_type: str | None = None,
        min_mentions: int = 0,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Entity]: ...

    async def delete_entity(
        self, entity_id: str, *, user_id: UUID | None
    ) -> None: ...

    # --- Mention CRUD ---

    async def add_mentions_bulk(
        self, mentions: Iterable[EntityMention], *, user_id: UUID | None
    ) -> int: ...

    async def mentions_for_finding(
        self, finding_id: str, *, user_id: UUID | None
    ) -> list[EntityMention]: ...

    async def delete_mentions_for_finding(
        self, finding_id: str, *, user_id: UUID | None
    ) -> int: ...

    async def recompute_mention_counts(
        self, entity_ids: Iterable[str], *, user_id: UUID | None
    ) -> None: ...

    async def rewrite_mentions_entity_id(
        self,
        *,
        from_entity_id: str,
        to_entity_id: str,
        user_id: UUID | None,
    ) -> int: ...

    async def rewrite_mentions_by_ids(
        self,
        *,
        mention_ids: list[str],
        to_entity_id: str,
        user_id: UUID | None,
    ) -> int: ...

    async def fetch_mentions_with_engagement(
        self,
        entity_id: str,
        *,
        user_id: UUID | None,
    ) -> list[tuple[str, str]]: ...

    async def fetch_finding_ids_for_entity(
        self,
        entity_id: str,
        *,
        user_id: UUID | None,
    ) -> list[str]:
        """Return distinct finding ids that mention ``entity_id``.

        Used by the query engine's endpoint resolver to map
        ``type:value`` endpoints onto the master-graph node set.
        """
        ...

    async def fetch_entity_mentions_for_engagement(
        self,
        engagement_id: str,
        *,
        entity_type: str,
        user_id: UUID | None,
    ) -> list[tuple[str, str]]:
        """Return ``(finding_id, canonical_value)`` pairs for all
        mentions of entities of ``entity_type`` that belong to
        non-deleted findings in ``engagement_id``.

        Drives the external-to-internal and mitre-coverage presets.
        """
        ...

    # --- Relation CRUD ---

    async def upsert_relations_bulk(
        self,
        relations: Iterable[FindingRelation],
        *,
        user_id: UUID | None,
    ) -> tuple[int, int]: ...

    async def relations_for_finding(
        self, finding_id: str, *, user_id: UUID | None
    ) -> list[FindingRelation]: ...

    async def fetch_relations_in_scope(
        self,
        *,
        user_id: UUID | None,
        statuses: set[RelationStatus] | None = None,
    ) -> list[FindingRelation]: ...

    def stream_relations_in_scope(
        self,
        *,
        user_id: UUID | None,
        statuses: set[RelationStatus] | None = None,
    ) -> AsyncIterator[FindingRelation]: ...

    async def apply_link_classification(
        self,
        *,
        relation_id: str,
        status: RelationStatus,
        rationale: str,
        relation_type: str,
        confidence: float,
        user_id: UUID | None,
    ) -> None: ...

    # --- Linker-specific queries ---

    async def fetch_candidate_partners(
        self,
        *,
        finding_id: str,
        entity_ids: set[str],
        user_id: UUID | None,
        common_entity_threshold: int,
    ) -> dict[str, set[str]]: ...

    async def fetch_findings_by_ids(
        self,
        finding_ids: Iterable[str],
        *,
        user_id: UUID | None,
    ) -> list[Finding]: ...

    async def count_findings_in_scope(
        self,
        *,
        user_id: UUID | None,
        engagement_id: str | None = None,
    ) -> int: ...

    async def compute_avg_idf(
        self,
        *,
        scope_total: int,
        user_id: UUID | None,
    ) -> float: ...

    async def entities_for_finding(
        self, finding_id: str, *, user_id: UUID | None
    ) -> list[Entity]: ...

    # --- LinkerRun lifecycle ---

    async def start_linker_run(
        self,
        *,
        scope: LinkerScope,
        scope_id: str | None,
        mode: LinkerMode,
        user_id: UUID | None,
    ) -> LinkerRun: ...

    async def set_run_status(
        self,
        run_id: str,
        status: str,
        *,
        user_id: UUID | None,
    ) -> None: ...

    async def finish_linker_run(
        self,
        run_id: str,
        *,
        findings_processed: int,
        entities_extracted: int,
        relations_created: int,
        relations_updated: int,
        relations_skipped_sticky: int,
        rule_stats: dict,
        duration_ms: int | None = None,
        error: str | None = None,
        user_id: UUID | None,
    ) -> None: ...

    async def mark_run_failed(
        self,
        run_id: str,
        *,
        error: str,
        user_id: UUID | None,
    ) -> None:
        """Mark a linker run as failed and record the error message.

        Sets ``status_text='failed'``, ``error=<message>``, and
        ``finished_at=<now>``. Used by worker failure handlers to
        finalize a run row without going through ``finish_linker_run``
        (which expects a full set of counters for the success path).

        No-op if the run id doesn't exist; does not raise.
        """
        ...

    async def current_linker_generation(
        self, *, user_id: UUID | None
    ) -> int: ...

    async def fetch_linker_runs(
        self, *, user_id: UUID | None, limit: int = 10
    ) -> list[LinkerRun]: ...

    # --- Extraction state + parser output ---

    async def get_extraction_hash(
        self, finding_id: str, *, user_id: UUID | None
    ) -> str | None: ...

    async def upsert_extraction_state(
        self,
        *,
        finding_id: str,
        extraction_input_hash: str,
        extractor_set: list[str],
        user_id: UUID | None,
    ) -> None: ...

    async def get_parser_output(
        self, finding_id: str, *, user_id: UUID | None
    ) -> list[FindingParserOutput]: ...

    # --- LLM caches (user-scoped) ---

    async def get_extraction_cache(
        self, cache_key: str, *, user_id: UUID | None
    ) -> bytes | None: ...

    async def put_extraction_cache(
        self,
        *,
        cache_key: str,
        provider: str,
        model: str,
        schema_version: int,
        result_json: bytes,
        user_id: UUID | None,
    ) -> None: ...

    async def get_llm_link_cache(
        self, cache_key: str, *, user_id: UUID | None
    ) -> bytes | None: ...

    async def put_llm_link_cache(
        self,
        *,
        cache_key: str,
        provider: str,
        model: str,
        schema_version: int,
        classification_json: bytes,
        user_id: UUID | None,
    ) -> None: ...

    # --- Export ---

    async def fetch_findings_for_engagement(
        self, engagement_id: str, *, user_id: UUID | None
    ) -> list[str]: ...

    async def fetch_all_finding_ids(
        self, *, user_id: UUID | None
    ) -> list[str]: ...

    def export_dump_stream(
        self,
        *,
        finding_ids: Iterable[str],
        user_id: UUID | None,
    ) -> AsyncIterator[dict]: ...
