"""AsyncChainStore — aiosqlite-backed chain store implementation.

Serves the CLI via a single-user connection. Does NOT enforce user_id
scoping (the CLI has a single user). All CRUD methods are implemented
in later tasks (Phase 1 Tasks 7-14).

Construction: accept either a db_path (store owns the connection and
closes it on close()) or a pre-opened aiosqlite.Connection (borrow,
don't close on close()). Borrowing exists for advanced scenarios; CLI
production code uses db_path.
"""
from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import AsyncIterator, Iterable

import aiosqlite

from opentools.chain.models import Entity, EntityMention
from opentools.chain.stores._common import (
    StoreNotInitialized,
    require_initialized,
)
from opentools.chain.types import MentionField
from opentools.engagement.schema import migrate_async

logger = logging.getLogger(__name__)


def _row_to_entity(row: aiosqlite.Row) -> Entity:
    """Convert an aiosqlite.Row to an Entity model."""
    return Entity(
        id=row["id"],
        type=row["type"],
        canonical_value=row["canonical_value"],
        first_seen_at=datetime.fromisoformat(row["first_seen_at"]),
        last_seen_at=datetime.fromisoformat(row["last_seen_at"]),
        mention_count=row["mention_count"],
        user_id=row["user_id"],
    )


def _row_to_mention(row: aiosqlite.Row) -> EntityMention:
    """Convert an aiosqlite.Row to an EntityMention model."""
    return EntityMention(
        id=row["id"],
        entity_id=row["entity_id"],
        finding_id=row["finding_id"],
        field=MentionField(row["field"]),
        raw_value=row["raw_value"],
        offset_start=row["offset_start"],
        offset_end=row["offset_end"],
        extractor=row["extractor"],
        confidence=row["confidence"],
        created_at=datetime.fromisoformat(row["created_at"]),
        user_id=row["user_id"],
    )


class AsyncChainStore:
    """Async chain store backed by aiosqlite.

    CLI-side backend. Accepts user_id=None freely on every method
    (single-user CLI). Methods are decorated with @require_initialized
    so calling before initialize() or after close() raises a clear error.
    """

    def __init__(
        self,
        *,
        db_path: Path | None = None,
        conn: aiosqlite.Connection | None = None,
    ) -> None:
        if db_path is None and conn is None:
            raise ValueError("Provide either db_path or conn")
        if db_path is not None and conn is not None:
            raise ValueError("Provide db_path OR conn, not both")
        self._db_path = Path(db_path) if db_path is not None else None
        self._conn: aiosqlite.Connection | None = conn
        self._owns_connection = conn is None
        self._initialized = False
        # Transaction depth tracker for nested savepoints
        self._txn_depth = 0

    async def initialize(self) -> None:
        """Open the connection (if owning), apply pragmas, run migrations.

        Idempotent — safe to call multiple times.
        """
        if self._initialized:
            return

        if self._conn is None:
            assert self._db_path is not None
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = await aiosqlite.connect(str(self._db_path))

        self._conn.row_factory = aiosqlite.Row

        # Performance pragmas (spec §5.3 optimization O3)
        for pragma in (
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=NORMAL",
            "PRAGMA cache_size=-64000",
            "PRAGMA mmap_size=268435456",
            "PRAGMA temp_store=MEMORY",
            "PRAGMA foreign_keys=ON",
            "PRAGMA busy_timeout=5000",
        ):
            await self._conn.execute(pragma)

        # Run migrations via the async path
        await migrate_async(self._conn)

        self._initialized = True

    async def close(self) -> None:
        """Close the connection (if owned). Idempotent."""
        if self._conn is not None and self._owns_connection:
            # Passive WAL checkpoint before closing (spec §5.3 optimization O7)
            try:
                await self._conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
            except Exception:
                pass
            await self._conn.close()
        self._conn = None
        self._initialized = False

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        """Single-operation atomicity via SQLite savepoint.

        Each call generates a unique savepoint name so nested usage
        doesn't collide. Rolls back on exception, releases on success.
        """
        if not self._initialized:
            raise StoreNotInitialized(
                "AsyncChainStore.transaction() called before initialize()"
            )
        name = f"txn_{uuid.uuid4().hex[:12]}"
        await self._conn.execute(f"SAVEPOINT {name}")
        self._txn_depth += 1
        try:
            yield
        except BaseException:
            await self._conn.execute(f"ROLLBACK TO SAVEPOINT {name}")
            await self._conn.execute(f"RELEASE SAVEPOINT {name}")
            self._txn_depth -= 1
            raise
        else:
            await self._conn.execute(f"RELEASE SAVEPOINT {name}")
            self._txn_depth -= 1

    @asynccontextmanager
    async def batch_transaction(self) -> AsyncIterator[None]:
        """Batch atomicity for merge/split/import.

        On SQLite this has identical semantics to transaction() — both
        use SAVEPOINT. The distinction is semantic: call sites use
        batch_transaction when they're wrapping a multi-step bulk
        operation (merge, split, import) so readers understand the
        scope of the held lock.
        """
        async with self.transaction():
            yield

    # ─── Entity CRUD ─────────────────────────────────────────────────────

    @require_initialized
    async def upsert_entity(self, entity: Entity, *, user_id) -> None:
        await self._conn.execute(
            """
            INSERT INTO entity (id, type, canonical_value, first_seen_at, last_seen_at,
                                mention_count, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                last_seen_at=excluded.last_seen_at,
                mention_count=excluded.mention_count
            """,
            (
                entity.id,
                entity.type,
                entity.canonical_value,
                entity.first_seen_at.isoformat(),
                entity.last_seen_at.isoformat(),
                entity.mention_count,
                str(entity.user_id) if entity.user_id else None,
            ),
        )
        if self._txn_depth == 0:
            await self._conn.commit()

    @require_initialized
    async def upsert_entities_bulk(
        self, entities: Iterable[Entity], *, user_id
    ) -> None:
        rows = [
            (
                e.id,
                e.type,
                e.canonical_value,
                e.first_seen_at.isoformat(),
                e.last_seen_at.isoformat(),
                e.mention_count,
                str(e.user_id) if e.user_id else None,
            )
            for e in entities
        ]
        if not rows:
            return
        await self._conn.executemany(
            """
            INSERT INTO entity (id, type, canonical_value, first_seen_at, last_seen_at,
                                mention_count, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                last_seen_at=excluded.last_seen_at,
                mention_count=excluded.mention_count
            """,
            rows,
        )
        if self._txn_depth == 0:
            await self._conn.commit()

    @require_initialized
    async def get_entity(self, entity_id: str, *, user_id) -> Entity | None:
        async with self._conn.execute(
            "SELECT * FROM entity WHERE id = ?", (entity_id,)
        ) as cur:
            row = await cur.fetchone()
        return _row_to_entity(row) if row else None

    @require_initialized
    async def get_entities_by_ids(
        self, entity_ids: Iterable[str], *, user_id
    ) -> dict[str, Entity]:
        ids = list(entity_ids)
        if not ids:
            return {}
        placeholders = ",".join("?" for _ in ids)
        async with self._conn.execute(
            f"SELECT * FROM entity WHERE id IN ({placeholders})", ids
        ) as cur:
            rows = await cur.fetchall()
        result: dict[str, Entity] = {}
        for row in rows:
            entity = _row_to_entity(row)
            result[entity.id] = entity
        return result

    @require_initialized
    async def list_entities(
        self,
        *,
        user_id,
        entity_type: str | None = None,
        min_mentions: int = 0,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Entity]:
        clauses: list[str] = []
        params: list = []
        if entity_type is not None:
            clauses.append("type = ?")
            params.append(entity_type)
        if min_mentions > 0:
            clauses.append("mention_count >= ?")
            params.append(min_mentions)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = (
            f"SELECT * FROM entity {where} "
            "ORDER BY mention_count DESC, canonical_value "
            "LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        async with self._conn.execute(sql, params) as cur:
            rows = await cur.fetchall()
        return [_row_to_entity(row) for row in rows]

    @require_initialized
    async def delete_entity(self, entity_id: str, *, user_id) -> None:
        await self._conn.execute(
            "DELETE FROM entity WHERE id = ?", (entity_id,)
        )
        if self._txn_depth == 0:
            await self._conn.commit()

    # ─── Mention CRUD ────────────────────────────────────────────────────

    @require_initialized
    async def add_mentions_bulk(
        self, mentions: Iterable[EntityMention], *, user_id
    ) -> int:
        rows = [
            (
                m.id,
                m.entity_id,
                m.finding_id,
                m.field.value,
                m.raw_value,
                m.offset_start,
                m.offset_end,
                m.extractor,
                m.confidence,
                m.created_at.isoformat(),
                str(m.user_id) if m.user_id else None,
            )
            for m in mentions
        ]
        if not rows:
            return 0
        await self._conn.executemany(
            """
            INSERT OR IGNORE INTO entity_mention
                (id, entity_id, finding_id, field, raw_value, offset_start,
                 offset_end, extractor, confidence, created_at, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        if self._txn_depth == 0:
            await self._conn.commit()
        return len(rows)

    @require_initialized
    async def mentions_for_finding(
        self, finding_id: str, *, user_id
    ) -> list[EntityMention]:
        async with self._conn.execute(
            "SELECT * FROM entity_mention WHERE finding_id = ?",
            (finding_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_mention(row) for row in rows]

    @require_initialized
    async def delete_mentions_for_finding(
        self, finding_id: str, *, user_id
    ) -> int:
        async with self._conn.execute(
            "DELETE FROM entity_mention WHERE finding_id = ?",
            (finding_id,),
        ) as cur:
            deleted = cur.rowcount
        if self._txn_depth == 0:
            await self._conn.commit()
        return deleted

    @require_initialized
    async def recompute_mention_counts(
        self, entity_ids: Iterable[str], *, user_id
    ) -> None:
        id_list = list(entity_ids)
        if not id_list:
            return
        placeholders = ",".join("?" * len(id_list))
        await self._conn.execute(
            f"""
            UPDATE entity
            SET mention_count = (
                SELECT COUNT(*) FROM entity_mention
                WHERE entity_mention.entity_id = entity.id
            )
            WHERE id IN ({placeholders})
            """,
            tuple(id_list),
        )
        if self._txn_depth == 0:
            await self._conn.commit()

    @require_initialized
    async def rewrite_mentions_entity_id(
        self, *, from_entity_id: str, to_entity_id: str, user_id
    ) -> int:
        async with self._conn.execute(
            "UPDATE entity_mention SET entity_id = ? WHERE entity_id = ?",
            (to_entity_id, from_entity_id),
        ) as cur:
            affected = cur.rowcount
        if self._txn_depth == 0:
            await self._conn.commit()
        return affected

    @require_initialized
    async def rewrite_mentions_by_ids(
        self, *, mention_ids: list[str], to_entity_id: str, user_id
    ) -> int:
        if not mention_ids:
            return 0
        placeholders = ",".join("?" * len(mention_ids))
        params = (to_entity_id, *mention_ids)
        async with self._conn.execute(
            f"UPDATE entity_mention SET entity_id = ? WHERE id IN ({placeholders})",
            params,
        ) as cur:
            affected = cur.rowcount
        if self._txn_depth == 0:
            await self._conn.commit()
        return affected

    @require_initialized
    async def fetch_mentions_with_engagement(
        self, entity_id: str, *, user_id
    ) -> list[tuple[str, str]]:
        async with self._conn.execute(
            """
            SELECT m.id, f.engagement_id
            FROM entity_mention m
            JOIN findings f ON f.id = m.finding_id
            WHERE m.entity_id = ? AND f.deleted_at IS NULL
            """,
            (entity_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [(row["id"], row["engagement_id"]) for row in rows]
