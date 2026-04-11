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
)
from opentools.chain.types import LinkerMode, LinkerScope, MentionField, RelationStatus
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


def _row_to_relation(row: aiosqlite.Row) -> FindingRelation:
    """Convert an aiosqlite.Row to a FindingRelation model."""
    import orjson

    reasons = [
        RelationReason.model_validate(r)
        for r in orjson.loads(row["reasons_json"])
    ]
    conf_reasons = None
    if row["confirmed_at_reasons_json"]:
        conf_reasons = [
            RelationReason.model_validate(r)
            for r in orjson.loads(row["confirmed_at_reasons_json"])
        ]
    return FindingRelation(
        id=row["id"],
        source_finding_id=row["source_finding_id"],
        target_finding_id=row["target_finding_id"],
        weight=row["weight"],
        weight_model_version=row["weight_model_version"],
        status=RelationStatus(row["status"]),
        symmetric=bool(row["symmetric"]),
        reasons=reasons,
        llm_rationale=row["llm_rationale"],
        llm_relation_type=row["llm_relation_type"],
        llm_confidence=row["llm_confidence"],
        confirmed_at_reasons=conf_reasons,
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        user_id=row["user_id"],
    )


def _row_to_linker_run(row: aiosqlite.Row) -> LinkerRun:
    """Convert an aiosqlite.Row from linker_run to a LinkerRun model.

    Note: migration v3 does not include a status_text column, and the
    LinkerRun pydantic model does not have a ``status`` field today.
    Task 18 introduces migration v4 to add persisted status text; until
    then, in-memory tracking is kept separately on AsyncChainStore.
    """
    import orjson

    rule_stats: dict = {}
    raw = row["rule_stats_json"]
    if raw:
        try:
            rule_stats = orjson.loads(raw)
        except Exception:
            rule_stats = {}

    return LinkerRun(
        id=row["id"],
        started_at=datetime.fromisoformat(row["started_at"]),
        finished_at=(
            datetime.fromisoformat(row["finished_at"])
            if row["finished_at"]
            else None
        ),
        scope=LinkerScope(row["scope"]),
        scope_id=row["scope_id"],
        mode=LinkerMode(row["mode"]),
        llm_provider=row["llm_provider"],
        findings_processed=row["findings_processed"],
        entities_extracted=row["entities_extracted"],
        relations_created=row["relations_created"],
        relations_updated=row["relations_updated"],
        relations_skipped_sticky=row["relations_skipped_sticky"],
        extraction_cache_hits=row["extraction_cache_hits"],
        extraction_cache_misses=row["extraction_cache_misses"],
        llm_calls_made=row["llm_calls_made"],
        llm_cache_hits=row["llm_cache_hits"],
        llm_cache_misses=row["llm_cache_misses"],
        rule_stats=rule_stats,
        duration_ms=row["duration_ms"],
        error=row["error"],
        generation=row["generation"],
        user_id=row["user_id"],
    )


def _row_to_parser_output(row: aiosqlite.Row) -> FindingParserOutput:
    """Convert an aiosqlite.Row from finding_parser_output to a model."""
    import orjson

    raw = row["data_json"]
    data: dict = {}
    if raw:
        try:
            data = orjson.loads(raw)
        except Exception:
            data = {}
    return FindingParserOutput(
        finding_id=row["finding_id"],
        parser_name=row["parser_name"],
        data=data,
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
        # In-memory linker run status tracking. The v3 linker_run schema
        # has no status column yet — Task 18's migration v4 will add
        # ``status_text``. Until then, set_run_status writes here so that
        # behavior is observable within a single process/session.
        self._run_status: dict[str, str] = {}

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

    # ─── Relation CRUD ───────────────────────────────────────────────────

    @require_initialized
    async def upsert_relations_bulk(
        self, relations: Iterable[FindingRelation], *, user_id
    ) -> tuple[int, int]:
        import orjson

        rel_list = list(relations)
        if not rel_list:
            return (0, 0)

        created_count = 0
        updated_count = 0

        for r in rel_list:
            async with self._conn.execute(
                "SELECT status FROM finding_relation WHERE id = ?", (r.id,)
            ) as cursor:
                existing = await cursor.fetchone()
            is_update = existing is not None

            reasons_json = orjson.dumps(
                [rr.model_dump(mode="json") for rr in r.reasons]
            )
            confirmed_json = None
            if r.confirmed_at_reasons is not None:
                confirmed_json = orjson.dumps(
                    [rr.model_dump(mode="json") for rr in r.confirmed_at_reasons]
                )

            await self._conn.execute(
                """
                INSERT INTO finding_relation (
                    id, source_finding_id, target_finding_id, weight,
                    weight_model_version, status, symmetric, reasons_json,
                    llm_rationale, llm_relation_type, llm_confidence,
                    confirmed_at_reasons_json, created_at, updated_at, user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    weight = excluded.weight,
                    weight_model_version = excluded.weight_model_version,
                    status = CASE
                        WHEN finding_relation.status IN ('user_confirmed', 'user_rejected')
                        THEN finding_relation.status
                        ELSE excluded.status
                    END,
                    symmetric = excluded.symmetric,
                    reasons_json = excluded.reasons_json,
                    llm_rationale = excluded.llm_rationale,
                    llm_relation_type = excluded.llm_relation_type,
                    llm_confidence = excluded.llm_confidence,
                    updated_at = excluded.updated_at
                """,
                (
                    r.id, r.source_finding_id, r.target_finding_id, r.weight,
                    r.weight_model_version, r.status.value,
                    int(r.symmetric), reasons_json,
                    r.llm_rationale, r.llm_relation_type, r.llm_confidence,
                    confirmed_json, r.created_at.isoformat(),
                    r.updated_at.isoformat(),
                    str(r.user_id) if r.user_id else None,
                ),
            )

            if is_update:
                updated_count += 1
            else:
                created_count += 1

        if self._txn_depth == 0:
            await self._conn.commit()

        return (created_count, updated_count)

    @require_initialized
    async def relations_for_finding(
        self, finding_id: str, *, user_id
    ) -> list[FindingRelation]:
        async with self._conn.execute(
            "SELECT * FROM finding_relation "
            "WHERE source_finding_id = ? OR target_finding_id = ?",
            (finding_id, finding_id),
        ) as cursor:
            rows = await cursor.fetchall()
        return [_row_to_relation(row) for row in rows]

    @require_initialized
    async def fetch_relations_in_scope(
        self,
        *,
        user_id,
        statuses: set[RelationStatus] | None = None,
    ) -> list[FindingRelation]:
        sql = "SELECT * FROM finding_relation"
        params: list = []
        if statuses:
            placeholders = ",".join("?" * len(statuses))
            sql += f" WHERE status IN ({placeholders})"
            params.extend(s.value for s in statuses)
        async with self._conn.execute(sql, tuple(params)) as cursor:
            rows = await cursor.fetchall()
        return [_row_to_relation(row) for row in rows]

    async def stream_relations_in_scope(
        self,
        *,
        user_id,
        statuses: set[RelationStatus] | None = None,
    ) -> AsyncIterator[FindingRelation]:
        # Manual init check — @require_initialized can't wrap async
        # generators (it awaits the wrapped coroutine, which a generator
        # isn't). Keep the error message consistent with the decorator.
        if not self._initialized:
            raise StoreNotInitialized(
                "AsyncChainStore.stream_relations_in_scope called before "
                "initialize() or after close()"
            )
        sql = "SELECT * FROM finding_relation"
        params: list = []
        if statuses:
            placeholders = ",".join("?" * len(statuses))
            sql += f" WHERE status IN ({placeholders})"
            params.extend(s.value for s in statuses)
        async with self._conn.execute(sql, tuple(params)) as cursor:
            async for row in cursor:
                yield _row_to_relation(row)

    @require_initialized
    async def apply_link_classification(
        self,
        *,
        relation_id: str,
        status: RelationStatus,
        rationale: str,
        relation_type: str,
        confidence: float,
        user_id,
    ) -> None:
        from datetime import datetime as _dt, timezone as _tz

        await self._conn.execute(
            """
            UPDATE finding_relation
            SET status = ?, llm_rationale = ?, llm_relation_type = ?,
                llm_confidence = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                status.value,
                rationale,
                relation_type,
                confidence,
                _dt.now(_tz.utc).isoformat(),
                relation_id,
            ),
        )
        if self._txn_depth == 0:
            await self._conn.commit()

    # ─── Linker queries ──────────────────────────────────────────────────

    @require_initialized
    async def fetch_candidate_partners(
        self,
        *,
        finding_id: str,
        entity_ids: set[str],
        user_id,
        common_entity_threshold: int,
    ) -> dict[str, set[str]]:
        from opentools.chain.stores._common import pad_in_clause

        if not entity_ids:
            return {}

        ids_list = list(entity_ids)
        if len(ids_list) > 500:
            result: dict[str, set[str]] = {}
            for i in range(0, len(ids_list), 500):
                chunk = ids_list[i : i + 500]
                partial = await self.fetch_candidate_partners(
                    finding_id=finding_id,
                    entity_ids=set(chunk),
                    user_id=user_id,
                    common_entity_threshold=common_entity_threshold,
                )
                for fid, eids in partial.items():
                    result.setdefault(fid, set()).update(eids)
            return result

        padded = pad_in_clause(ids_list, min_size=4)
        placeholders = ",".join("?" * len(padded))

        sql = f"""
            SELECT DISTINCT m.finding_id, m.entity_id
            FROM entity_mention m
            JOIN entity e ON e.id = m.entity_id
            WHERE m.entity_id IN ({placeholders})
              AND m.finding_id != ?
              AND e.mention_count <= ?
        """
        params = tuple(padded) + (finding_id, common_entity_threshold)

        partners: dict[str, set[str]] = {}
        async with self._conn.execute(sql, params) as cursor:
            async for row in cursor:
                partners.setdefault(row["finding_id"], set()).add(
                    row["entity_id"]
                )
        return partners

    @require_initialized
    async def fetch_findings_by_ids(
        self, finding_ids: Iterable[str], *, user_id
    ) -> list:
        from opentools.models import Finding, FindingStatus, Severity

        ids_list = list(finding_ids)
        if not ids_list:
            return []

        placeholders = ",".join("?" * len(ids_list))
        async with self._conn.execute(
            f"""
            SELECT id, engagement_id, tool, severity, status, title,
                   description, file_path, line_start, line_end, evidence,
                   cwe, cvss, remediation, phase, false_positive,
                   created_at, deleted_at
            FROM findings
            WHERE id IN ({placeholders}) AND deleted_at IS NULL
            """,
            tuple(ids_list),
        ) as cursor:
            rows = await cursor.fetchall()

        findings: list = []
        for row in rows:
            try:
                findings.append(
                    Finding(
                        id=row["id"],
                        engagement_id=row["engagement_id"],
                        tool=row["tool"],
                        severity=Severity(row["severity"]),
                        status=(
                            FindingStatus(row["status"])
                            if row["status"]
                            else FindingStatus.DISCOVERED
                        ),
                        title=row["title"],
                        description=row["description"] or "",
                        file_path=row["file_path"],
                        line_start=row["line_start"],
                        line_end=row["line_end"],
                        evidence=row["evidence"],
                        cwe=row["cwe"],
                        cvss=row["cvss"],
                        remediation=row["remediation"],
                        phase=row["phase"],
                        false_positive=bool(row["false_positive"]),
                        created_at=datetime.fromisoformat(row["created_at"]),
                    )
                )
            except Exception:
                continue
        return findings

    @require_initialized
    async def count_findings_in_scope(
        self, *, user_id, engagement_id: str | None = None
    ) -> int:
        if engagement_id is None:
            sql = "SELECT COUNT(*) FROM findings WHERE deleted_at IS NULL"
            params: tuple = ()
        else:
            sql = (
                "SELECT COUNT(*) FROM findings "
                "WHERE deleted_at IS NULL AND engagement_id = ?"
            )
            params = (engagement_id,)
        async with self._conn.execute(sql, params) as cursor:
            row = await cursor.fetchone()
        return int(row[0]) if row else 0

    @require_initialized
    async def compute_avg_idf(
        self, *, scope_total: int, user_id
    ) -> float:
        if scope_total <= 0:
            return 1.0
        async with self._conn.execute(
            """
            SELECT AVG(LOG((? + 1.0) / (mention_count + 1.0)))
            FROM entity
            WHERE mention_count > 0
            """,
            (scope_total,),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None or row[0] is None:
            return 1.0
        return float(row[0])

    @require_initialized
    async def entities_for_finding(
        self, finding_id: str, *, user_id
    ) -> list[Entity]:
        async with self._conn.execute(
            """
            SELECT DISTINCT e.*
            FROM entity e
            JOIN entity_mention m ON m.entity_id = e.id
            WHERE m.finding_id = ?
            """,
            (finding_id,),
        ) as cursor:
            rows = await cursor.fetchall()
        return [_row_to_entity(row) for row in rows]

    # ─── LinkerRun lifecycle ─────────────────────────────────────────────

    @require_initialized
    async def start_linker_run(
        self,
        *,
        scope: LinkerScope,
        scope_id: str | None,
        mode: LinkerMode,
        user_id,
    ) -> LinkerRun:
        """Create a linker_run row with atomic generation increment.

        Uses a single INSERT whose ``generation`` column is filled via a
        ``COALESCE(MAX(generation), 0) + 1`` subquery over ``linker_run``
        (spec G26), keeping the increment race-free within this
        connection.
        """
        import hashlib
        import uuid as _uuid
        from datetime import datetime as _dt, timezone as _tz

        run_id = (
            "run_"
            + hashlib.sha256(str(_uuid.uuid4()).encode()).hexdigest()[:12]
        )
        now = _dt.now(_tz.utc)

        await self._conn.execute(
            """
            INSERT INTO linker_run (
                id, started_at, scope, scope_id, mode, findings_processed,
                entities_extracted, relations_created, relations_updated,
                relations_skipped_sticky, extraction_cache_hits,
                extraction_cache_misses, llm_calls_made, llm_cache_hits,
                llm_cache_misses, generation
            )
            VALUES (
                ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                (SELECT COALESCE(MAX(generation), 0) + 1 FROM linker_run)
            )
            """,
            (run_id, now.isoformat(), scope.value, scope_id, mode.value),
        )
        if self._txn_depth == 0:
            await self._conn.commit()

        async with self._conn.execute(
            "SELECT * FROM linker_run WHERE id = ?", (run_id,)
        ) as cursor:
            row = await cursor.fetchone()
        assert row is not None  # just inserted
        return _row_to_linker_run(row)

    @require_initialized
    async def set_run_status(
        self, run_id: str, status: str, *, user_id
    ) -> None:
        """Record a human-readable status string for a linker run.

        v3 schema has no column to persist this; Task 18 adds
        ``status_text`` via migration v4. Until then, stash the value in
        an in-memory dict so behavior is observable within a session.
        """
        self._run_status[run_id] = status

    @require_initialized
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
        user_id,
    ) -> None:
        import orjson
        from datetime import datetime as _dt, timezone as _tz

        rule_stats_blob = (
            orjson.dumps(rule_stats) if rule_stats is not None else None
        )
        await self._conn.execute(
            """
            UPDATE linker_run
            SET finished_at = ?,
                findings_processed = ?,
                entities_extracted = ?,
                relations_created = ?,
                relations_updated = ?,
                relations_skipped_sticky = ?,
                rule_stats_json = ?,
                duration_ms = ?,
                error = ?
            WHERE id = ?
            """,
            (
                _dt.now(_tz.utc).isoformat(),
                findings_processed,
                entities_extracted,
                relations_created,
                relations_updated,
                relations_skipped_sticky,
                rule_stats_blob,
                duration_ms,
                error,
                run_id,
            ),
        )
        if self._txn_depth == 0:
            await self._conn.commit()

    @require_initialized
    async def current_linker_generation(self, *, user_id) -> int:
        async with self._conn.execute(
            "SELECT COALESCE(MAX(generation), 0) FROM linker_run"
        ) as cursor:
            row = await cursor.fetchone()
        return int(row[0]) if row and row[0] is not None else 0

    @require_initialized
    async def fetch_linker_runs(
        self, *, user_id, limit: int = 10
    ) -> list[LinkerRun]:
        async with self._conn.execute(
            "SELECT * FROM linker_run ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ) as cursor:
            rows = await cursor.fetchall()
        return [_row_to_linker_run(row) for row in rows]

    # ─── Extraction state + parser output ────────────────────────────────

    @require_initialized
    async def get_extraction_hash(
        self, finding_id: str, *, user_id
    ) -> str | None:
        async with self._conn.execute(
            "SELECT extraction_input_hash FROM finding_extraction_state "
            "WHERE finding_id = ?",
            (finding_id,),
        ) as cursor:
            row = await cursor.fetchone()
        return row["extraction_input_hash"] if row else None

    @require_initialized
    async def upsert_extraction_state(
        self,
        *,
        finding_id: str,
        extraction_input_hash: str,
        extractor_set: list[str],
        user_id,
    ) -> None:
        import orjson
        from datetime import datetime as _dt, timezone as _tz

        await self._conn.execute(
            """
            INSERT INTO finding_extraction_state
                (finding_id, extraction_input_hash, last_extracted_at,
                 last_extractor_set_json, user_id)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(finding_id) DO UPDATE SET
                extraction_input_hash = excluded.extraction_input_hash,
                last_extracted_at = excluded.last_extracted_at,
                last_extractor_set_json = excluded.last_extractor_set_json
            """,
            (
                finding_id,
                extraction_input_hash,
                _dt.now(_tz.utc).isoformat(),
                orjson.dumps(list(extractor_set)),
                str(user_id) if user_id else None,
            ),
        )
        if self._txn_depth == 0:
            await self._conn.commit()

    @require_initialized
    async def get_parser_output(
        self, finding_id: str, *, user_id
    ) -> list[FindingParserOutput]:
        async with self._conn.execute(
            "SELECT * FROM finding_parser_output WHERE finding_id = ?",
            (finding_id,),
        ) as cursor:
            rows = await cursor.fetchall()
        return [_row_to_parser_output(row) for row in rows]

    # ─── LLM caches ──────────────────────────────────────────────────────
    #
    # Cache rows are user-scoped (spec G37) to prevent cross-user side
    # channel leaks. Migration v4 added the user_id column to both
    # extraction_cache and llm_link_cache. The filter pattern
    # ``(user_id IS ? OR user_id = ?)`` works in SQLite: when the
    # placeholder is bound to None, ``IS NULL`` matches NULL rows; when
    # bound to a string, ``= ?`` matches that exact user.

    @require_initialized
    async def get_extraction_cache(
        self, cache_key: str, *, user_id
    ) -> bytes | None:
        uid = str(user_id) if user_id else None
        async with self._conn.execute(
            "SELECT result_json FROM extraction_cache "
            "WHERE cache_key = ? AND (user_id IS ? OR user_id = ?)",
            (cache_key, uid, uid),
        ) as cursor:
            row = await cursor.fetchone()
        return bytes(row["result_json"]) if row else None

    @require_initialized
    async def put_extraction_cache(
        self,
        *,
        cache_key: str,
        provider: str,
        model: str,
        schema_version: int,
        result_json: bytes,
        user_id,
    ) -> None:
        from datetime import datetime as _dt, timezone as _tz

        uid = str(user_id) if user_id else None
        await self._conn.execute(
            """
            INSERT INTO extraction_cache
                (cache_key, provider, model, schema_version, result_json,
                 created_at, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                provider = excluded.provider,
                model = excluded.model,
                schema_version = excluded.schema_version,
                result_json = excluded.result_json,
                user_id = excluded.user_id
            """,
            (
                cache_key,
                provider,
                model,
                schema_version,
                result_json,
                _dt.now(_tz.utc).isoformat(),
                uid,
            ),
        )
        if self._txn_depth == 0:
            await self._conn.commit()

    @require_initialized
    async def get_llm_link_cache(
        self, cache_key: str, *, user_id
    ) -> bytes | None:
        uid = str(user_id) if user_id else None
        async with self._conn.execute(
            "SELECT classification_json FROM llm_link_cache "
            "WHERE cache_key = ? AND (user_id IS ? OR user_id = ?)",
            (cache_key, uid, uid),
        ) as cursor:
            row = await cursor.fetchone()
        return bytes(row["classification_json"]) if row else None

    @require_initialized
    async def put_llm_link_cache(
        self,
        *,
        cache_key: str,
        provider: str,
        model: str,
        schema_version: int,
        classification_json: bytes,
        user_id,
    ) -> None:
        from datetime import datetime as _dt, timezone as _tz

        uid = str(user_id) if user_id else None
        await self._conn.execute(
            """
            INSERT INTO llm_link_cache
                (cache_key, provider, model, schema_version,
                 classification_json, created_at, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                provider = excluded.provider,
                model = excluded.model,
                schema_version = excluded.schema_version,
                classification_json = excluded.classification_json,
                user_id = excluded.user_id
            """,
            (
                cache_key,
                provider,
                model,
                schema_version,
                classification_json,
                _dt.now(_tz.utc).isoformat(),
                uid,
            ),
        )
        if self._txn_depth == 0:
            await self._conn.commit()

    # ─── Export ──────────────────────────────────────────────────────────

    @require_initialized
    async def fetch_findings_for_engagement(
        self, engagement_id: str, *, user_id
    ) -> list[str]:
        async with self._conn.execute(
            "SELECT id FROM findings "
            "WHERE engagement_id = ? AND deleted_at IS NULL",
            (engagement_id,),
        ) as cursor:
            rows = await cursor.fetchall()
        return [row["id"] for row in rows]

    async def export_dump_stream(
        self,
        *,
        finding_ids: Iterable[str],
        user_id,
    ) -> AsyncIterator[dict]:
        """Stream entity/mention/relation rows for a set of findings.

        Async generator — @require_initialized can't wrap async
        generators, so check manually. Yields dicts shaped
        ``{"kind": "entity"|"mention"|"relation", "data": {...}}`` so
        exporters can serialise without loading the full graph into
        memory.
        """
        if not self._initialized:
            raise StoreNotInitialized(
                "AsyncChainStore.export_dump_stream called before "
                "initialize() or after close()"
            )

        ids_list = list(finding_ids)
        if not ids_list:
            return

        placeholders = ",".join("?" * len(ids_list))

        # Yield entities joined via mentions
        async with self._conn.execute(
            f"""
            SELECT DISTINCT e.* FROM entity e
            JOIN entity_mention m ON m.entity_id = e.id
            WHERE m.finding_id IN ({placeholders})
            """,
            tuple(ids_list),
        ) as cursor:
            async for row in cursor:
                yield {"kind": "entity", "data": dict(row)}

        # Yield mentions
        async with self._conn.execute(
            f"SELECT * FROM entity_mention WHERE finding_id IN ({placeholders})",
            tuple(ids_list),
        ) as cursor:
            async for row in cursor:
                yield {"kind": "mention", "data": dict(row)}

        # Yield relations (either direction)
        async with self._conn.execute(
            f"""
            SELECT * FROM finding_relation
            WHERE source_finding_id IN ({placeholders})
               OR target_finding_id IN ({placeholders})
            """,
            tuple(ids_list) * 2,
        ) as cursor:
            async for row in cursor:
                yield {"kind": "relation", "data": dict(row)}
