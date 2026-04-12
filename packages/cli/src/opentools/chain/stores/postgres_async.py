"""PostgresChainStore — SQLAlchemy async implementation of ChainStoreProtocol.

Backs the web dashboard against the SQLModel chain tables defined in
``packages/web/backend/app/models.py``. Mirrors AsyncChainStore's
behavior while using SQLAlchemy Core/ORM against a shared async session.

Construction takes an AsyncSession (request-scoped) or an
``async_sessionmaker`` / callable returning an async context manager
that yields a session. In the CLI conformance suite we run this against
``sqlite+aiosqlite://`` — even without a real Postgres container the
SQLAlchemy ORM catches many dialect-level bugs.

Design notes:

* User scoping is REQUIRED (@require_user_scope) — this backend refuses
  ``user_id=None`` by raising ScopingViolation. This matches spec §4
  and prevents the web dashboard from ever accidentally leaking across
  users. The CLI's AsyncChainStore has the opposite policy (accepts
  None freely).

* Upserts use dialect-specific ``INSERT ... ON CONFLICT`` pulled from
  ``sqlalchemy.dialects.postgresql`` in production and
  ``sqlalchemy.dialects.sqlite`` for the conformance fixture.

* Reason/rule-stats JSON blobs are stored as bytes via orjson, matching
  the aiosqlite backend's wire format. On Postgres the columns are
  JSONB after migration 004; asyncpg will accept ``bytes`` / ``str`` and
  will round-trip lossily only if the payload isn't valid JSON, which
  orjson guarantees.

* Transaction semantics: ``transaction()`` uses savepoints via
  ``session.begin_nested()``. If no outer transaction exists, we open
  one first. Autocommit on completion matches AsyncChainStore when
  called outside an explicit ``transaction()`` block.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Callable, Iterable
from uuid import UUID

import orjson
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from opentools.chain.models import (
    Entity,
    EntityMention,
    FindingParserOutput,
    FindingRelation,
    LinkerRun,
    RelationReason,
)
from opentools.chain.stores._common import (
    StoreNotInitialized,
    require_initialized,
    require_user_scope,
)
from opentools.chain.types import (
    LinkerMode,
    LinkerScope,
    MentionField,
    RelationStatus,
)

logger = logging.getLogger(__name__)


# ─── Row ↔ domain converters ─────────────────────────────────────────────────


def _orm_to_entity(row: Any) -> Entity:
    """Convert a ChainEntity ORM row to an Entity domain object."""
    return Entity(
        id=row.id,
        type=row.type,
        canonical_value=row.canonical_value,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        mention_count=row.mention_count,
        user_id=row.user_id,
    )


def _orm_to_mention(row: Any) -> EntityMention:
    """Convert a ChainEntityMention ORM row to an EntityMention."""
    return EntityMention(
        id=row.id,
        entity_id=row.entity_id,
        finding_id=row.finding_id,
        field=MentionField(row.field),
        raw_value=row.raw_value,
        offset_start=row.offset_start,
        offset_end=row.offset_end,
        extractor=row.extractor,
        confidence=row.confidence,
        created_at=row.created_at,
        user_id=row.user_id,
    )


def _coerce_json_bytes(raw: Any) -> Any:
    """Accept either bytes, str, or already-parsed dict/list from a JSON column.

    Postgres JSONB via asyncpg returns dict/list, SQLite TEXT returns str,
    orjson-serialized writes are bytes. Normalize to the parsed Python object.
    """
    if raw is None:
        return None
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        return orjson.loads(raw)
    if isinstance(raw, str):
        return orjson.loads(raw)
    return raw


def _orm_to_relation(row: Any) -> FindingRelation:
    """Convert a ChainFindingRelation ORM row to a FindingRelation."""
    reasons_raw = _coerce_json_bytes(row.reasons_json) or []
    reasons = [RelationReason.model_validate(r) for r in reasons_raw]

    confirmed = _coerce_json_bytes(row.confirmed_at_reasons_json)
    confirmed_reasons = (
        [RelationReason.model_validate(r) for r in confirmed]
        if confirmed is not None
        else None
    )

    return FindingRelation(
        id=row.id,
        source_finding_id=row.source_finding_id,
        target_finding_id=row.target_finding_id,
        weight=row.weight,
        weight_model_version=row.weight_model_version,
        status=RelationStatus(row.status),
        symmetric=bool(row.symmetric),
        reasons=reasons,
        llm_rationale=row.llm_rationale,
        llm_relation_type=row.llm_relation_type,
        llm_confidence=row.llm_confidence,
        confirmed_at_reasons=confirmed_reasons,
        created_at=row.created_at,
        updated_at=row.updated_at,
        user_id=row.user_id,
    )


def _orm_to_linker_run(row: Any) -> LinkerRun:
    """Convert a ChainLinkerRun ORM row to a LinkerRun."""
    rule_stats: dict = {}
    parsed = _coerce_json_bytes(row.rule_stats_json)
    if isinstance(parsed, dict):
        rule_stats = parsed
    return LinkerRun(
        id=row.id,
        started_at=row.started_at,
        finished_at=row.finished_at,
        scope=LinkerScope(row.scope),
        scope_id=row.scope_id,
        mode=LinkerMode(row.mode),
        llm_provider=row.llm_provider,
        findings_processed=row.findings_processed,
        entities_extracted=row.entities_extracted,
        relations_created=row.relations_created,
        relations_updated=row.relations_updated,
        relations_skipped_sticky=row.relations_skipped_sticky,
        extraction_cache_hits=row.extraction_cache_hits,
        extraction_cache_misses=row.extraction_cache_misses,
        llm_calls_made=row.llm_calls_made,
        llm_cache_hits=row.llm_cache_hits,
        llm_cache_misses=row.llm_cache_misses,
        rule_stats=rule_stats,
        duration_ms=row.duration_ms,
        error=row.error,
        status=row.status_text or "pending",
        generation=row.generation,
        user_id=row.user_id,
    )


def _web_finding_to_cli(row: Any):
    """Convert a web SQLModel Finding row to a CLI Finding domain object.

    The web Finding has a ``user_id`` field the CLI doesn't model. Field
    names otherwise mirror the CLI schema, so mapping is one-to-one.
    """
    from opentools.models import Finding, FindingStatus, Severity

    sev_raw = row.severity
    try:
        severity = sev_raw if isinstance(sev_raw, Severity) else Severity(sev_raw)
    except ValueError:
        severity = Severity.INFO

    status_raw = row.status
    try:
        status = (
            status_raw
            if isinstance(status_raw, FindingStatus)
            else (FindingStatus(status_raw) if status_raw else FindingStatus.DISCOVERED)
        )
    except ValueError:
        status = FindingStatus.DISCOVERED

    return Finding(
        id=row.id,
        engagement_id=row.engagement_id,
        tool=row.tool,
        severity=severity,
        status=status,
        title=row.title,
        description=row.description or "",
        file_path=getattr(row, "file_path", None),
        line_start=getattr(row, "line_start", None),
        line_end=getattr(row, "line_end", None),
        evidence=getattr(row, "evidence", None),
        phase=getattr(row, "phase", None),
        cwe=getattr(row, "cwe", None),
        cvss=getattr(row, "cvss", None),
        remediation=getattr(row, "remediation", None),
        false_positive=bool(getattr(row, "false_positive", False) or False),
        created_at=row.created_at,
    )


# ─── Dialect-aware helpers ───────────────────────────────────────────────────


def _insert_for(session: AsyncSession):
    """Return the dialect-appropriate ``insert(...)`` constructor.

    Works with both ``postgresql+asyncpg`` and ``sqlite+aiosqlite``.
    """
    dialect_name = session.bind.dialect.name
    if dialect_name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as _insert

        return _insert
    # sqlite covers the conformance fixture
    from sqlalchemy.dialects.sqlite import insert as _insert

    return _insert


def _jsonb_dumps(value: Any) -> Any:
    """Serialize a Python value for a Text/JSON column.

    The web SQLModel tables declare reasons_json / confirmed_at_reasons_json
    / rule_stats_json as ``Column(Text)``, which asyncpg binds as
    ``VARCHAR``. asyncpg is strict about bytes vs str (SQLite is lax),
    so we decode orjson's bytes output to a UTF-8 string before binding.
    Returns ``None`` for ``None`` input.
    """
    if value is None:
        return None
    return orjson.dumps(value).decode("utf-8")


# ─── PostgresChainStore ──────────────────────────────────────────────────────


class PostgresChainStore:
    """ChainStoreProtocol backed by SQLAlchemy async against web SQLModel tables.

    Usage:

        store = PostgresChainStore(session=session)
        await store.initialize()
        try:
            await store.upsert_entity(entity, user_id=user_id)
        finally:
            await store.close()

    Or via a session_factory for background tasks:

        store = PostgresChainStore(session_factory=factory)

    The factory is a callable returning an async context manager
    yielding an AsyncSession (``async_sessionmaker`` qualifies).
    """

    def __init__(
        self,
        *,
        session: AsyncSession | None = None,
        session_factory: Callable[[], Any] | None = None,
    ) -> None:
        if session is None and session_factory is None:
            raise ValueError("Provide either session or session_factory")
        if session is not None and session_factory is not None:
            raise ValueError("Provide session OR session_factory, not both")
        self._session: AsyncSession | None = session
        self._session_factory = session_factory
        self._owned_cm: Any = None
        self._initialized = False
        # Nested savepoint depth. Matches AsyncChainStore semantics:
        # commit on every mutating call iff _txn_depth == 0.
        self._txn_depth = 0

    # ─── Module loader ───────────────────────────────────────────────────

    @property
    def _models(self):
        """Lazy import of the web SQLModel module.

        Kept lazy so the CLI doesn't pay the import cost unless a
        PostgresChainStore is actually instantiated.
        """
        import app.models as m  # type: ignore[import-not-found]

        return m

    # ─── Lifecycle ───────────────────────────────────────────────────────

    async def initialize(self) -> None:
        """Resolve the session (if constructed with a factory) and mark
        the store as ready. Idempotent."""
        if self._initialized:
            return
        if self._session is None and self._session_factory is not None:
            cm = self._session_factory()
            # Support both ``async_sessionmaker`` (returns a context
            # manager) and plain factories that already return a session.
            if hasattr(cm, "__aenter__"):
                self._owned_cm = cm
                self._session = await cm.__aenter__()
            else:
                self._session = cm  # type: ignore[assignment]
        self._initialized = True

    async def close(self) -> None:
        """Release the session if we own it. Idempotent."""
        if self._owned_cm is not None:
            try:
                await self._owned_cm.__aexit__(None, None, None)
            except Exception:
                logger.debug("PostgresChainStore: session exit failed", exc_info=True)
            self._owned_cm = None
        self._session = None
        self._initialized = False

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        """Nested transaction via SAVEPOINT (``session.begin_nested``).

        If the session has no outer transaction yet, start one first —
        SQLAlchemy requires that. This matches AsyncChainStore's
        semantics: the inner block is atomic, and commit on the outer
        happens either here (if we opened it) or at autocommit time
        (if _txn_depth dropped to 0 outside any transaction).
        """
        if not self._initialized:
            raise StoreNotInitialized(
                "PostgresChainStore.transaction() called before initialize()"
            )
        assert self._session is not None

        outer_opened = False
        if not self._session.in_transaction():
            await self._session.begin()
            outer_opened = True

        savepoint = await self._session.begin_nested()
        self._txn_depth += 1
        try:
            yield
        except BaseException:
            if savepoint.is_active:
                await savepoint.rollback()
            self._txn_depth -= 1
            if outer_opened and self._session.in_transaction():
                try:
                    await self._session.rollback()
                except Exception:
                    logger.debug("outer rollback failed", exc_info=True)
            raise
        else:
            if savepoint.is_active:
                await savepoint.commit()
            self._txn_depth -= 1
            if outer_opened:
                try:
                    await self._session.commit()
                except Exception:
                    logger.debug("outer commit failed", exc_info=True)
                    raise

    @asynccontextmanager
    async def batch_transaction(self) -> AsyncIterator[None]:
        """Batch atomicity — on Postgres/SQLite this delegates to the
        savepoint-based ``transaction()``. The distinction is semantic."""
        async with self.transaction():
            yield

    # ─── Autocommit helper ───────────────────────────────────────────────

    async def _autocommit(self) -> None:
        """Commit the session iff we're outside any explicit transaction.

        Mirrors ``if self._txn_depth == 0: await self._conn.commit()``
        from the aiosqlite backend. SQLAlchemy requires an active
        transaction for ``commit()`` to be meaningful; if none is active
        we call ``session.commit()`` which is a no-op on an inactive
        session.
        """
        if self._txn_depth == 0:
            assert self._session is not None
            try:
                await self._session.commit()
            except Exception:
                logger.debug("autocommit failed", exc_info=True)
                raise

    # ─── Entity CRUD ─────────────────────────────────────────────────────

    @require_initialized
    @require_user_scope
    async def upsert_entity(self, entity: Entity, *, user_id: UUID) -> None:
        M = self._models
        assert self._session is not None
        ins = _insert_for(self._session)
        stmt = ins(M.ChainEntity).values(
            id=entity.id,
            user_id=user_id,
            type=entity.type,
            canonical_value=entity.canonical_value,
            first_seen_at=entity.first_seen_at,
            last_seen_at=entity.last_seen_at,
            mention_count=entity.mention_count,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[M.ChainEntity.id],
            set_={
                "last_seen_at": entity.last_seen_at,
                "mention_count": entity.mention_count,
            },
        )
        await self._session.execute(stmt)
        await self._autocommit()

    @require_initialized
    @require_user_scope
    async def upsert_entities_bulk(
        self, entities: Iterable[Entity], *, user_id: UUID
    ) -> None:
        rows = list(entities)
        if not rows:
            return
        # Issue a sequence of upserts in a single savepoint so the
        # autocommit at the end is a single round-trip on commit.
        for e in rows:
            await self.upsert_entity_no_commit(e, user_id=user_id)
        await self._autocommit()

    async def upsert_entity_no_commit(
        self, entity: Entity, *, user_id: UUID
    ) -> None:
        """Upsert a single entity without auto-committing. Internal helper
        for ``upsert_entities_bulk`` so the commit happens once at the end."""
        M = self._models
        assert self._session is not None
        ins = _insert_for(self._session)
        stmt = ins(M.ChainEntity).values(
            id=entity.id,
            user_id=user_id,
            type=entity.type,
            canonical_value=entity.canonical_value,
            first_seen_at=entity.first_seen_at,
            last_seen_at=entity.last_seen_at,
            mention_count=entity.mention_count,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[M.ChainEntity.id],
            set_={
                "last_seen_at": entity.last_seen_at,
                "mention_count": entity.mention_count,
            },
        )
        await self._session.execute(stmt)

    @require_initialized
    @require_user_scope
    async def get_entity(
        self, entity_id: str, *, user_id: UUID
    ) -> Entity | None:
        M = self._models
        assert self._session is not None
        stmt = select(M.ChainEntity).where(
            M.ChainEntity.id == entity_id,
            M.ChainEntity.user_id == user_id,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return _orm_to_entity(row) if row else None

    @require_initialized
    @require_user_scope
    async def get_entities_by_ids(
        self, entity_ids: Iterable[str], *, user_id: UUID
    ) -> dict[str, Entity]:
        M = self._models
        assert self._session is not None
        ids = list(entity_ids)
        if not ids:
            return {}
        stmt = select(M.ChainEntity).where(
            M.ChainEntity.id.in_(ids),
            M.ChainEntity.user_id == user_id,
        )
        result = await self._session.execute(stmt)
        out: dict[str, Entity] = {}
        for row in result.scalars():
            out[row.id] = _orm_to_entity(row)
        return out

    @require_initialized
    @require_user_scope
    async def list_entities(
        self,
        *,
        user_id: UUID,
        entity_type: str | None = None,
        min_mentions: int = 0,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Entity]:
        M = self._models
        assert self._session is not None
        stmt = select(M.ChainEntity).where(M.ChainEntity.user_id == user_id)
        if entity_type is not None:
            stmt = stmt.where(M.ChainEntity.type == entity_type)
        if min_mentions > 0:
            stmt = stmt.where(M.ChainEntity.mention_count >= min_mentions)
        stmt = (
            stmt.order_by(
                M.ChainEntity.mention_count.desc(),
                M.ChainEntity.canonical_value.asc(),
            )
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return [_orm_to_entity(r) for r in result.scalars()]

    @require_initialized
    @require_user_scope
    async def delete_entity(
        self, entity_id: str, *, user_id: UUID
    ) -> None:
        M = self._models
        assert self._session is not None
        # Mentions reference entity via FK (ondelete=CASCADE in 003) —
        # but for the sqlite conformance fixture we delete mentions
        # explicitly to avoid relying on sqlite FK pragmas.
        await self._session.execute(
            delete(M.ChainEntityMention).where(
                M.ChainEntityMention.entity_id == entity_id,
                M.ChainEntityMention.user_id == user_id,
            )
        )
        await self._session.execute(
            delete(M.ChainEntity).where(
                M.ChainEntity.id == entity_id,
                M.ChainEntity.user_id == user_id,
            )
        )
        await self._autocommit()

    # ─── Mention CRUD ────────────────────────────────────────────────────

    @require_initialized
    @require_user_scope
    async def add_mentions_bulk(
        self, mentions: Iterable[EntityMention], *, user_id: UUID
    ) -> int:
        M = self._models
        assert self._session is not None
        rows = list(mentions)
        if not rows:
            return 0
        ins = _insert_for(self._session)
        values = [
            {
                "id": m.id,
                "user_id": user_id,
                "entity_id": m.entity_id,
                "finding_id": m.finding_id,
                "field": m.field.value,
                "raw_value": m.raw_value,
                "offset_start": m.offset_start,
                "offset_end": m.offset_end,
                "extractor": m.extractor,
                "confidence": m.confidence,
                "created_at": m.created_at,
            }
            for m in rows
        ]
        stmt = ins(M.ChainEntityMention).values(values)
        # "INSERT OR IGNORE" semantics — skip rows whose unique
        # constraint (entity_id, finding_id, field, offset_start) collides.
        stmt = stmt.on_conflict_do_nothing(index_elements=[M.ChainEntityMention.id])
        await self._session.execute(stmt)
        await self._autocommit()
        return len(rows)

    @require_initialized
    @require_user_scope
    async def mentions_for_finding(
        self, finding_id: str, *, user_id: UUID
    ) -> list[EntityMention]:
        M = self._models
        assert self._session is not None
        stmt = select(M.ChainEntityMention).where(
            M.ChainEntityMention.finding_id == finding_id,
            M.ChainEntityMention.user_id == user_id,
        )
        result = await self._session.execute(stmt)
        return [_orm_to_mention(r) for r in result.scalars()]

    @require_initialized
    @require_user_scope
    async def delete_mentions_for_finding(
        self, finding_id: str, *, user_id: UUID
    ) -> int:
        M = self._models
        assert self._session is not None
        result = await self._session.execute(
            delete(M.ChainEntityMention).where(
                M.ChainEntityMention.finding_id == finding_id,
                M.ChainEntityMention.user_id == user_id,
            )
        )
        await self._autocommit()
        return int(result.rowcount or 0)

    @require_initialized
    @require_user_scope
    async def recompute_mention_counts(
        self, entity_ids: Iterable[str], *, user_id: UUID
    ) -> None:
        M = self._models
        assert self._session is not None
        ids = list(entity_ids)
        if not ids:
            return
        # Portable approach: one SELECT COUNT per entity id. This is
        # slower than a correlated subquery UPDATE but works identically
        # on SQLite and Postgres without dialect branching.
        for eid in ids:
            count_stmt = select(func.count(M.ChainEntityMention.id)).where(
                M.ChainEntityMention.entity_id == eid,
                M.ChainEntityMention.user_id == user_id,
            )
            result = await self._session.execute(count_stmt)
            count = int(result.scalar() or 0)
            await self._session.execute(
                update(M.ChainEntity)
                .where(
                    M.ChainEntity.id == eid,
                    M.ChainEntity.user_id == user_id,
                )
                .values(mention_count=count)
            )
        await self._autocommit()

    @require_initialized
    @require_user_scope
    async def rewrite_mentions_entity_id(
        self,
        *,
        from_entity_id: str,
        to_entity_id: str,
        user_id: UUID,
    ) -> int:
        M = self._models
        assert self._session is not None
        result = await self._session.execute(
            update(M.ChainEntityMention)
            .where(
                M.ChainEntityMention.entity_id == from_entity_id,
                M.ChainEntityMention.user_id == user_id,
            )
            .values(entity_id=to_entity_id)
        )
        await self._autocommit()
        return int(result.rowcount or 0)

    @require_initialized
    @require_user_scope
    async def rewrite_mentions_by_ids(
        self,
        *,
        mention_ids: list[str],
        to_entity_id: str,
        user_id: UUID,
    ) -> int:
        M = self._models
        assert self._session is not None
        if not mention_ids:
            return 0
        result = await self._session.execute(
            update(M.ChainEntityMention)
            .where(
                M.ChainEntityMention.id.in_(mention_ids),
                M.ChainEntityMention.user_id == user_id,
            )
            .values(entity_id=to_entity_id)
        )
        await self._autocommit()
        return int(result.rowcount or 0)

    @require_initialized
    @require_user_scope
    async def fetch_mentions_with_engagement(
        self, entity_id: str, *, user_id: UUID
    ) -> list[tuple[str, str]]:
        M = self._models
        assert self._session is not None
        stmt = (
            select(M.ChainEntityMention.id, M.Finding.engagement_id)
            .join(M.Finding, M.Finding.id == M.ChainEntityMention.finding_id)
            .where(
                M.ChainEntityMention.entity_id == entity_id,
                M.ChainEntityMention.user_id == user_id,
                M.Finding.deleted_at.is_(None),
            )
        )
        result = await self._session.execute(stmt)
        return [(row[0], row[1]) for row in result.all()]

    @require_initialized
    @require_user_scope
    async def fetch_finding_ids_for_entity(
        self, entity_id: str, *, user_id: UUID
    ) -> list[str]:
        M = self._models
        assert self._session is not None
        stmt = (
            select(M.ChainEntityMention.finding_id)
            .join(M.Finding, M.Finding.id == M.ChainEntityMention.finding_id)
            .where(
                M.ChainEntityMention.entity_id == entity_id,
                M.ChainEntityMention.user_id == user_id,
                M.Finding.deleted_at.is_(None),
            )
            .distinct()
        )
        result = await self._session.execute(stmt)
        return [row[0] for row in result.all()]

    @require_initialized
    @require_user_scope
    async def fetch_entity_mentions_for_engagement(
        self,
        engagement_id: str,
        *,
        entity_type: str,
        user_id: UUID,
    ) -> list[tuple[str, str]]:
        M = self._models
        assert self._session is not None
        stmt = (
            select(M.ChainEntityMention.finding_id, M.ChainEntity.canonical_value)
            .join(M.ChainEntity, M.ChainEntity.id == M.ChainEntityMention.entity_id)
            .join(M.Finding, M.Finding.id == M.ChainEntityMention.finding_id)
            .where(
                M.ChainEntity.type == entity_type,
                M.Finding.engagement_id == engagement_id,
                M.Finding.deleted_at.is_(None),
                M.ChainEntityMention.user_id == user_id,
            )
            .distinct()
        )
        result = await self._session.execute(stmt)
        return [(row[0], row[1]) for row in result.all()]

    # ─── Relation CRUD ───────────────────────────────────────────────────

    @require_initialized
    @require_user_scope
    async def upsert_relations_bulk(
        self,
        relations: Iterable[FindingRelation],
        *,
        user_id: UUID,
    ) -> tuple[int, int]:
        M = self._models
        assert self._session is not None
        rel_list = list(relations)
        if not rel_list:
            return (0, 0)

        created = 0
        updated = 0
        sticky = {
            RelationStatus.USER_CONFIRMED.value,
            RelationStatus.USER_REJECTED.value,
        }

        for r in rel_list:
            # Check existing status so we can preserve sticky user
            # classifications the same way sqlite_async does. The
            # aiosqlite backend does this via a CASE expression in the
            # upsert; here we read-modify-write because SQLite's
            # ORM insert builder doesn't expose CASE cleanly across
            # dialects.
            existing_stmt = select(M.ChainFindingRelation.status).where(
                M.ChainFindingRelation.id == r.id,
                M.ChainFindingRelation.user_id == user_id,
            )
            existing_result = await self._session.execute(existing_stmt)
            existing_status = existing_result.scalar_one_or_none()
            is_update = existing_status is not None

            new_status = r.status.value
            if is_update and existing_status in sticky:
                new_status = existing_status

            reasons_blob = _jsonb_dumps(
                [rr.model_dump(mode="json") for rr in r.reasons]
            )
            confirmed_blob = None
            if r.confirmed_at_reasons is not None:
                confirmed_blob = _jsonb_dumps(
                    [rr.model_dump(mode="json") for rr in r.confirmed_at_reasons]
                )

            ins = _insert_for(self._session)
            stmt = ins(M.ChainFindingRelation).values(
                id=r.id,
                user_id=user_id,
                source_finding_id=r.source_finding_id,
                target_finding_id=r.target_finding_id,
                weight=r.weight,
                weight_model_version=r.weight_model_version,
                status=new_status,
                symmetric=bool(r.symmetric),
                reasons_json=reasons_blob,
                llm_rationale=r.llm_rationale,
                llm_relation_type=r.llm_relation_type,
                llm_confidence=r.llm_confidence,
                confirmed_at_reasons_json=confirmed_blob,
                created_at=r.created_at,
                updated_at=r.updated_at,
            )
            stmt = stmt.on_conflict_do_update(
                index_elements=[M.ChainFindingRelation.id],
                set_={
                    "weight": r.weight,
                    "weight_model_version": r.weight_model_version,
                    "status": new_status,
                    "symmetric": bool(r.symmetric),
                    "reasons_json": reasons_blob,
                    "llm_rationale": r.llm_rationale,
                    "llm_relation_type": r.llm_relation_type,
                    "llm_confidence": r.llm_confidence,
                    "updated_at": r.updated_at,
                },
            )
            await self._session.execute(stmt)

            if is_update:
                updated += 1
            else:
                created += 1

        await self._autocommit()
        return (created, updated)

    @require_initialized
    @require_user_scope
    async def relations_for_finding(
        self, finding_id: str, *, user_id: UUID
    ) -> list[FindingRelation]:
        M = self._models
        assert self._session is not None
        stmt = select(M.ChainFindingRelation).where(
            M.ChainFindingRelation.user_id == user_id,
            or_(
                M.ChainFindingRelation.source_finding_id == finding_id,
                M.ChainFindingRelation.target_finding_id == finding_id,
            ),
        )
        result = await self._session.execute(stmt)
        return [_orm_to_relation(r) for r in result.scalars()]

    @require_initialized
    @require_user_scope
    async def fetch_relations_in_scope(
        self,
        *,
        user_id: UUID,
        statuses: set[RelationStatus] | None = None,
    ) -> list[FindingRelation]:
        M = self._models
        assert self._session is not None
        stmt = select(M.ChainFindingRelation).where(
            M.ChainFindingRelation.user_id == user_id
        )
        if statuses:
            stmt = stmt.where(
                M.ChainFindingRelation.status.in_([s.value for s in statuses])
            )
        result = await self._session.execute(stmt)
        return [_orm_to_relation(r) for r in result.scalars()]

    async def stream_relations_in_scope(
        self,
        *,
        user_id: UUID,
        statuses: set[RelationStatus] | None = None,
    ) -> AsyncIterator[FindingRelation]:
        if not self._initialized:
            raise StoreNotInitialized(
                "PostgresChainStore.stream_relations_in_scope called before "
                "initialize() or after close()"
            )
        if user_id is None:
            from opentools.chain.stores._common import ScopingViolation

            raise ScopingViolation(
                "PostgresChainStore.stream_relations_in_scope() requires user_id"
            )
        M = self._models
        assert self._session is not None
        stmt = select(M.ChainFindingRelation).where(
            M.ChainFindingRelation.user_id == user_id
        )
        if statuses:
            stmt = stmt.where(
                M.ChainFindingRelation.status.in_([s.value for s in statuses])
            )
        # ``session.stream`` returns a streaming result. asyncpg streams
        # over a cursor; SQLite/aiosqlite buffers but the async API is
        # the same.
        stream_result = await self._session.stream(stmt)
        async for row in stream_result.scalars():
            yield _orm_to_relation(row)

    @require_initialized
    @require_user_scope
    async def apply_link_classification(
        self,
        *,
        relation_id: str,
        status: RelationStatus,
        rationale: str,
        relation_type: str,
        confidence: float,
        user_id: UUID,
    ) -> None:
        M = self._models
        assert self._session is not None
        now = datetime.now(timezone.utc)
        await self._session.execute(
            update(M.ChainFindingRelation)
            .where(
                M.ChainFindingRelation.id == relation_id,
                M.ChainFindingRelation.user_id == user_id,
            )
            .values(
                status=status.value,
                llm_rationale=rationale,
                llm_relation_type=relation_type,
                llm_confidence=confidence,
                updated_at=now,
            )
        )
        await self._autocommit()

    # ─── Linker queries ──────────────────────────────────────────────────

    @require_initialized
    @require_user_scope
    async def fetch_candidate_partners(
        self,
        *,
        finding_id: str,
        entity_ids: set[str],
        user_id: UUID,
        common_entity_threshold: int,
    ) -> dict[str, set[str]]:
        """Return ``{partner_finding_id: {entity_id, ...}}`` for findings
        that share at least one of ``entity_ids`` via a mention, excluding
        the starting finding, and excluding entities whose total
        ``mention_count`` exceeds ``common_entity_threshold`` (too common
        to be a meaningful signal)."""
        M = self._models
        assert self._session is not None
        if not entity_ids:
            return {}

        stmt = (
            select(M.ChainEntityMention.finding_id, M.ChainEntityMention.entity_id)
            .join(M.ChainEntity, M.ChainEntity.id == M.ChainEntityMention.entity_id)
            .where(
                M.ChainEntityMention.entity_id.in_(list(entity_ids)),
                M.ChainEntityMention.finding_id != finding_id,
                M.ChainEntity.mention_count <= common_entity_threshold,
                M.ChainEntityMention.user_id == user_id,
            )
            .distinct()
        )
        result = await self._session.execute(stmt)
        partners: dict[str, set[str]] = {}
        for row in result.all():
            partners.setdefault(row[0], set()).add(row[1])
        return partners

    @require_initialized
    @require_user_scope
    async def fetch_findings_by_ids(
        self, finding_ids: Iterable[str], *, user_id: UUID
    ) -> list:
        M = self._models
        assert self._session is not None
        ids = list(finding_ids)
        if not ids:
            return []
        stmt = select(M.Finding).where(
            M.Finding.id.in_(ids),
            M.Finding.user_id == user_id,
            M.Finding.deleted_at.is_(None),
        )
        result = await self._session.execute(stmt)
        findings = []
        for row in result.scalars():
            try:
                findings.append(_web_finding_to_cli(row))
            except Exception:
                logger.debug("finding conversion failed", exc_info=True)
                continue
        return findings

    @require_initialized
    @require_user_scope
    async def count_findings_in_scope(
        self,
        *,
        user_id: UUID,
        engagement_id: str | None = None,
    ) -> int:
        M = self._models
        assert self._session is not None
        stmt = select(func.count(M.Finding.id)).where(
            M.Finding.user_id == user_id,
            M.Finding.deleted_at.is_(None),
        )
        if engagement_id is not None:
            stmt = stmt.where(M.Finding.engagement_id == engagement_id)
        result = await self._session.execute(stmt)
        return int(result.scalar() or 0)

    @require_initialized
    @require_user_scope
    async def compute_avg_idf(
        self,
        *,
        scope_total: int,
        user_id: UUID,
    ) -> float:
        """Approximate average IDF across entities with mention_count > 0.

        Uses ``AVG(LOG((scope_total + 1) / (mention_count + 1)))``. SQLite
        has no built-in ``LOG`` in the default build, and Postgres uses
        ``LOG(base, x)``. For portability (and because this is an
        approximation used only for weight scaling) we compute it in
        Python from the raw mention counts. Skip rows with 0 mentions
        to match the aiosqlite backend's ``WHERE mention_count > 0``.
        """
        M = self._models
        assert self._session is not None
        if scope_total <= 0:
            return 1.0
        stmt = select(M.ChainEntity.mention_count).where(
            M.ChainEntity.user_id == user_id,
            M.ChainEntity.mention_count > 0,
        )
        result = await self._session.execute(stmt)
        counts = [int(row[0]) for row in result.all()]
        if not counts:
            return 1.0
        import math

        values = [
            math.log((scope_total + 1.0) / (c + 1.0))
            for c in counts
        ]
        return float(sum(values) / len(values)) if values else 1.0

    @require_initialized
    @require_user_scope
    async def entities_for_finding(
        self, finding_id: str, *, user_id: UUID
    ) -> list[Entity]:
        M = self._models
        assert self._session is not None
        stmt = (
            select(M.ChainEntity)
            .join(
                M.ChainEntityMention,
                M.ChainEntityMention.entity_id == M.ChainEntity.id,
            )
            .where(
                M.ChainEntityMention.finding_id == finding_id,
                M.ChainEntity.user_id == user_id,
            )
            .distinct()
        )
        result = await self._session.execute(stmt)
        return [_orm_to_entity(r) for r in result.scalars()]

    # ─── LinkerRun lifecycle ─────────────────────────────────────────────

    @require_initialized
    @require_user_scope
    async def start_linker_run(
        self,
        *,
        scope: LinkerScope,
        scope_id: str | None,
        mode: LinkerMode,
        user_id: UUID,
    ) -> LinkerRun:
        M = self._models
        assert self._session is not None

        run_id = (
            "run_"
            + hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:12]
        )
        now = datetime.now(timezone.utc)

        # Compute next generation via SELECT MAX+1. There is a race
        # between concurrent linker runs for the same user, but this
        # matches the sqlite backend's within-connection semantics. The
        # web backend's linker runs are serialised through a background
        # task queue upstream, so the race does not manifest in
        # practice.
        gen_stmt = select(func.coalesce(func.max(M.ChainLinkerRun.generation), 0)).where(
            M.ChainLinkerRun.user_id == user_id
        )
        gen_result = await self._session.execute(gen_stmt)
        next_gen = int(gen_result.scalar() or 0) + 1

        run = M.ChainLinkerRun(
            id=run_id,
            user_id=user_id,
            started_at=now,
            scope=scope.value,
            scope_id=scope_id,
            mode=mode.value,
            findings_processed=0,
            entities_extracted=0,
            relations_created=0,
            relations_updated=0,
            relations_skipped_sticky=0,
            extraction_cache_hits=0,
            extraction_cache_misses=0,
            llm_calls_made=0,
            llm_cache_hits=0,
            llm_cache_misses=0,
            status_text="pending",
            generation=next_gen,
        )
        self._session.add(run)
        await self._session.flush()
        await self._autocommit()

        return _orm_to_linker_run(run)

    @require_initialized
    @require_user_scope
    async def set_run_status(
        self, run_id: str, status: str, *, user_id: UUID
    ) -> None:
        M = self._models
        assert self._session is not None
        await self._session.execute(
            update(M.ChainLinkerRun)
            .where(
                M.ChainLinkerRun.id == run_id,
                M.ChainLinkerRun.user_id == user_id,
            )
            .values(status_text=status)
        )
        await self._autocommit()

    @require_initialized
    @require_user_scope
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
        user_id: UUID,
    ) -> None:
        M = self._models
        assert self._session is not None
        rule_stats_blob = _jsonb_dumps(rule_stats)
        await self._session.execute(
            update(M.ChainLinkerRun)
            .where(
                M.ChainLinkerRun.id == run_id,
                M.ChainLinkerRun.user_id == user_id,
            )
            .values(
                finished_at=datetime.now(timezone.utc),
                findings_processed=findings_processed,
                entities_extracted=entities_extracted,
                relations_created=relations_created,
                relations_updated=relations_updated,
                relations_skipped_sticky=relations_skipped_sticky,
                rule_stats_json=rule_stats_blob,
                duration_ms=duration_ms,
                error=error,
            )
        )
        await self._autocommit()

    @require_initialized
    @require_user_scope
    async def mark_run_failed(
        self, run_id: str, *, error: str, user_id: UUID
    ) -> None:
        """Finalize a linker run row with failed status.

        Worker failure path — the protocol's finish_linker_run path
        assumes a clean success with full counters, so we drop straight
        to a single UPDATE here.
        """
        M = self._models
        assert self._session is not None
        await self._session.execute(
            update(M.ChainLinkerRun)
            .where(
                M.ChainLinkerRun.id == run_id,
                M.ChainLinkerRun.user_id == user_id,
            )
            .values(
                status_text="failed",
                error=error,
                finished_at=datetime.now(timezone.utc),
            )
        )
        await self._autocommit()

    @require_initialized
    @require_user_scope
    async def current_linker_generation(self, *, user_id: UUID) -> int:
        M = self._models
        assert self._session is not None
        stmt = select(func.coalesce(func.max(M.ChainLinkerRun.generation), 0)).where(
            M.ChainLinkerRun.user_id == user_id
        )
        result = await self._session.execute(stmt)
        return int(result.scalar() or 0)

    @require_initialized
    @require_user_scope
    async def fetch_linker_runs(
        self, *, user_id: UUID, limit: int = 10
    ) -> list[LinkerRun]:
        M = self._models
        assert self._session is not None
        stmt = (
            select(M.ChainLinkerRun)
            .where(M.ChainLinkerRun.user_id == user_id)
            .order_by(M.ChainLinkerRun.started_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [_orm_to_linker_run(r) for r in result.scalars()]

    # ─── Extraction state + parser output ────────────────────────────────
    #
    # Backed by the chain_finding_extraction_state and
    # chain_finding_parser_output web tables (Alembic migration 005).
    # Mirrors AsyncChainStore's semantics: upsert_extraction_state is
    # a dialect-aware INSERT ... ON CONFLICT DO UPDATE that replaces
    # the row's hash + extractor set; get_extraction_hash returns just
    # the hash; get_parser_output returns all parser output rows for a
    # finding as FindingParserOutput domain objects with the JSON
    # payload decoded via orjson.

    @require_initialized
    @require_user_scope
    async def get_extraction_hash(
        self, finding_id: str, *, user_id: UUID
    ) -> str | None:
        M = self._models
        assert self._session is not None
        stmt = select(M.ChainFindingExtractionState.extraction_input_hash).where(
            M.ChainFindingExtractionState.finding_id == finding_id,
            M.ChainFindingExtractionState.user_id == user_id,
        )
        result = await self._session.execute(stmt)
        row = result.first()
        return row[0] if row else None

    @require_initialized
    @require_user_scope
    async def upsert_extraction_state(
        self,
        *,
        finding_id: str,
        extraction_input_hash: str,
        extractor_set: list[str],
        user_id: UUID,
    ) -> None:
        M = self._models
        assert self._session is not None
        ins = _insert_for(self._session)
        extractor_blob = orjson.dumps(list(extractor_set))
        now = datetime.now(timezone.utc)
        stmt = ins(M.ChainFindingExtractionState).values(
            finding_id=finding_id,
            extraction_input_hash=extraction_input_hash,
            last_extracted_at=now,
            last_extractor_set_json=extractor_blob,
            user_id=user_id,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[M.ChainFindingExtractionState.finding_id],
            set_={
                "extraction_input_hash": extraction_input_hash,
                "last_extracted_at": now,
                "last_extractor_set_json": extractor_blob,
                "user_id": user_id,
            },
        )
        await self._session.execute(stmt)
        await self._autocommit()

    @require_initialized
    @require_user_scope
    async def get_parser_output(
        self, finding_id: str, *, user_id: UUID
    ) -> list[FindingParserOutput]:
        M = self._models
        assert self._session is not None
        stmt = select(M.ChainFindingParserOutput).where(
            M.ChainFindingParserOutput.finding_id == finding_id,
            M.ChainFindingParserOutput.user_id == user_id,
        )
        result = await self._session.execute(stmt)
        rows = result.scalars().all()

        outputs: list[FindingParserOutput] = []
        for row in rows:
            data = _coerce_json_bytes(row.data_json)
            if not isinstance(data, dict):
                data = {}
            outputs.append(
                FindingParserOutput(
                    finding_id=row.finding_id,
                    parser_name=row.parser_name,
                    data=data,
                    created_at=row.created_at,
                    user_id=row.user_id,
                )
            )
        return outputs

    # ─── LLM caches ──────────────────────────────────────────────────────

    @require_initialized
    @require_user_scope
    async def get_extraction_cache(
        self, cache_key: str, *, user_id: UUID
    ) -> bytes | None:
        M = self._models
        assert self._session is not None
        stmt = select(M.ChainExtractionCache.result_json).where(
            M.ChainExtractionCache.cache_key == cache_key,
            M.ChainExtractionCache.user_id == user_id,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return bytes(row) if row is not None else None

    @require_initialized
    @require_user_scope
    async def put_extraction_cache(
        self,
        *,
        cache_key: str,
        provider: str,
        model: str,
        schema_version: int,
        result_json: bytes,
        user_id: UUID,
    ) -> None:
        M = self._models
        assert self._session is not None
        ins = _insert_for(self._session)
        stmt = ins(M.ChainExtractionCache).values(
            cache_key=cache_key,
            provider=provider,
            model=model,
            schema_version=schema_version,
            result_json=result_json,
            created_at=datetime.now(timezone.utc),
            user_id=user_id,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[M.ChainExtractionCache.cache_key],
            set_={
                "provider": provider,
                "model": model,
                "schema_version": schema_version,
                "result_json": result_json,
                "user_id": user_id,
            },
        )
        await self._session.execute(stmt)
        await self._autocommit()

    @require_initialized
    @require_user_scope
    async def get_llm_link_cache(
        self, cache_key: str, *, user_id: UUID
    ) -> bytes | None:
        M = self._models
        assert self._session is not None
        stmt = select(M.ChainLlmLinkCache.classification_json).where(
            M.ChainLlmLinkCache.cache_key == cache_key,
            M.ChainLlmLinkCache.user_id == user_id,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        return bytes(row) if row is not None else None

    @require_initialized
    @require_user_scope
    async def put_llm_link_cache(
        self,
        *,
        cache_key: str,
        provider: str,
        model: str,
        schema_version: int,
        classification_json: bytes,
        user_id: UUID,
    ) -> None:
        M = self._models
        assert self._session is not None
        ins = _insert_for(self._session)
        stmt = ins(M.ChainLlmLinkCache).values(
            cache_key=cache_key,
            provider=provider,
            model=model,
            schema_version=schema_version,
            classification_json=classification_json,
            created_at=datetime.now(timezone.utc),
            user_id=user_id,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=[M.ChainLlmLinkCache.cache_key],
            set_={
                "provider": provider,
                "model": model,
                "schema_version": schema_version,
                "classification_json": classification_json,
                "user_id": user_id,
            },
        )
        await self._session.execute(stmt)
        await self._autocommit()

    # ─── Export ──────────────────────────────────────────────────────────

    @require_initialized
    @require_user_scope
    async def fetch_findings_for_engagement(
        self, engagement_id: str, *, user_id: UUID
    ) -> list[str]:
        M = self._models
        assert self._session is not None
        stmt = select(M.Finding.id).where(
            M.Finding.engagement_id == engagement_id,
            M.Finding.user_id == user_id,
            M.Finding.deleted_at.is_(None),
        )
        result = await self._session.execute(stmt)
        return [row[0] for row in result.all()]

    @require_initialized
    @require_user_scope
    async def fetch_all_finding_ids(self, *, user_id: UUID) -> list[str]:
        M = self._models
        assert self._session is not None
        stmt = select(M.Finding.id).where(
            M.Finding.user_id == user_id,
            M.Finding.deleted_at.is_(None),
        )
        result = await self._session.execute(stmt)
        return [row[0] for row in result.all()]

    async def export_dump_stream(
        self,
        *,
        finding_ids: Iterable[str],
        user_id: UUID,
    ) -> AsyncIterator[dict]:
        """Yield entity/mention/relation rows for export.

        Generator — can't use @require_initialized. Manual checks below.
        """
        if not self._initialized:
            raise StoreNotInitialized(
                "PostgresChainStore.export_dump_stream called before "
                "initialize() or after close()"
            )
        if user_id is None:
            from opentools.chain.stores._common import ScopingViolation

            raise ScopingViolation(
                "PostgresChainStore.export_dump_stream() requires user_id"
            )

        M = self._models
        assert self._session is not None

        ids = list(finding_ids)
        if not ids:
            return

        # Entities via mention join
        ent_stmt = (
            select(M.ChainEntity)
            .join(
                M.ChainEntityMention,
                M.ChainEntityMention.entity_id == M.ChainEntity.id,
            )
            .where(
                M.ChainEntityMention.finding_id.in_(ids),
                M.ChainEntity.user_id == user_id,
            )
            .distinct()
        )
        ent_res = await self._session.execute(ent_stmt)
        for e in ent_res.scalars():
            yield {
                "kind": "entity",
                "data": {
                    "id": e.id,
                    "type": e.type,
                    "canonical_value": e.canonical_value,
                    "first_seen_at": e.first_seen_at.isoformat()
                    if e.first_seen_at
                    else None,
                    "last_seen_at": e.last_seen_at.isoformat()
                    if e.last_seen_at
                    else None,
                    "mention_count": e.mention_count,
                    "user_id": str(e.user_id) if e.user_id else None,
                },
            }

        men_stmt = select(M.ChainEntityMention).where(
            M.ChainEntityMention.finding_id.in_(ids),
            M.ChainEntityMention.user_id == user_id,
        )
        men_res = await self._session.execute(men_stmt)
        for m in men_res.scalars():
            yield {
                "kind": "mention",
                "data": {
                    "id": m.id,
                    "entity_id": m.entity_id,
                    "finding_id": m.finding_id,
                    "field": m.field,
                    "raw_value": m.raw_value,
                    "offset_start": m.offset_start,
                    "offset_end": m.offset_end,
                    "extractor": m.extractor,
                    "confidence": m.confidence,
                    "created_at": m.created_at.isoformat() if m.created_at else None,
                    "user_id": str(m.user_id) if m.user_id else None,
                },
            }

        rel_stmt = select(M.ChainFindingRelation).where(
            M.ChainFindingRelation.user_id == user_id,
            or_(
                M.ChainFindingRelation.source_finding_id.in_(ids),
                M.ChainFindingRelation.target_finding_id.in_(ids),
            ),
        )
        rel_res = await self._session.execute(rel_stmt)
        for r in rel_res.scalars():
            yield {
                "kind": "relation",
                "data": {
                    "id": r.id,
                    "source_finding_id": r.source_finding_id,
                    "target_finding_id": r.target_finding_id,
                    "weight": r.weight,
                    "status": r.status,
                    "symmetric": bool(r.symmetric),
                    "user_id": str(r.user_id) if r.user_id else None,
                },
            }
