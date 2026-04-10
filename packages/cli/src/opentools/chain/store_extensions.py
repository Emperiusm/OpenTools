"""Chain data store helper.

Thin wrapper around a sqlite3 connection providing chain-specific CRUD.
Chain tables live in the SAME database as findings (created by migration v3
in opentools.engagement.schema). ChainStore does NOT own the connection —
it receives one from the caller, typically EngagementStore._conn.

For tests, a standalone connection can be constructed via tmp_path.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Iterable

import orjson

from opentools.chain.models import (
    Entity,
    EntityMention,
    FindingRelation,
    RelationReason,
)
from opentools.chain.types import MentionField, RelationStatus


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _utcnow().isoformat()


class ChainStore:
    """Chain-specific CRUD helper over a shared sqlite3 connection.

    The caller owns the connection. Schema is created by the engagement
    store's migration system (migration v3).
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._conn.row_factory = sqlite3.Row

    # ─── raw helpers (test utility) ────────────────────────────────────────

    def execute_one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self._conn.execute(sql, params).fetchone()

    def execute_all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return list(self._conn.execute(sql, params).fetchall())

    # ─── entity ────────────────────────────────────────────────────────────

    def upsert_entity(self, entity: Entity) -> None:
        self._conn.execute(
            """
            INSERT INTO entity (id, type, canonical_value, first_seen_at, last_seen_at, mention_count, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                last_seen_at=excluded.last_seen_at,
                mention_count=excluded.mention_count
            """,
            (
                entity.id, entity.type, entity.canonical_value,
                entity.first_seen_at.isoformat(),
                entity.last_seen_at.isoformat(),
                entity.mention_count,
                str(entity.user_id) if entity.user_id else None,
            ),
        )
        self._conn.commit()

    def get_entity(self, entity_id: str) -> Entity | None:
        row = self.execute_one("SELECT * FROM entity WHERE id = ?", (entity_id,))
        return _row_to_entity(row) if row else None

    # ─── entity mentions ──────────────────────────────────────────────────

    def add_mentions(self, mentions: Iterable[EntityMention]) -> None:
        rows = [
            (
                m.id, m.entity_id, m.finding_id, m.field.value, m.raw_value,
                m.offset_start, m.offset_end, m.extractor, m.confidence,
                m.created_at.isoformat(), str(m.user_id) if m.user_id else None,
            )
            for m in mentions
        ]
        self._conn.executemany(
            """
            INSERT OR IGNORE INTO entity_mention
                (id, entity_id, finding_id, field, raw_value, offset_start, offset_end,
                 extractor, confidence, created_at, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self._conn.commit()

    def mentions_for_finding(self, finding_id: str) -> list[EntityMention]:
        rows = self.execute_all(
            "SELECT * FROM entity_mention WHERE finding_id = ?", (finding_id,)
        )
        return [_row_to_mention(r) for r in rows]

    def delete_mentions_for_finding(self, finding_id: str) -> None:
        self._conn.execute("DELETE FROM entity_mention WHERE finding_id = ?", (finding_id,))
        self._conn.commit()

    # ─── relations ─────────────────────────────────────────────────────────

    def upsert_relations_bulk(self, relations: Iterable[FindingRelation]) -> None:
        rows = []
        for r in relations:
            rows.append((
                r.id,
                r.source_finding_id,
                r.target_finding_id,
                r.weight,
                r.weight_model_version,
                r.status.value,
                1 if r.symmetric else 0,
                orjson.dumps([rr.model_dump() for rr in r.reasons]),
                r.llm_rationale,
                r.llm_relation_type,
                r.llm_confidence,
                orjson.dumps([rr.model_dump() for rr in r.confirmed_at_reasons]) if r.confirmed_at_reasons else None,
                r.created_at.isoformat(),
                r.updated_at.isoformat(),
                str(r.user_id) if r.user_id else None,
            ))
        self._conn.executemany(
            """
            INSERT INTO finding_relation
                (id, source_finding_id, target_finding_id, weight, weight_model_version,
                 status, symmetric, reasons_json, llm_rationale, llm_relation_type,
                 llm_confidence, confirmed_at_reasons_json, created_at, updated_at, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_finding_id, target_finding_id, user_id) DO UPDATE SET
                weight=excluded.weight,
                weight_model_version=excluded.weight_model_version,
                status=CASE
                    WHEN finding_relation.status IN ('user_confirmed', 'user_rejected')
                    THEN finding_relation.status
                    ELSE excluded.status
                END,
                symmetric=excluded.symmetric,
                reasons_json=excluded.reasons_json,
                llm_rationale=excluded.llm_rationale,
                llm_relation_type=excluded.llm_relation_type,
                llm_confidence=excluded.llm_confidence,
                updated_at=excluded.updated_at
            """,
            rows,
        )
        self._conn.commit()

    def relations_for_finding(self, finding_id: str) -> list[FindingRelation]:
        rows = self.execute_all(
            "SELECT * FROM finding_relation WHERE source_finding_id = ? OR target_finding_id = ?",
            (finding_id, finding_id),
        )
        return [_row_to_relation(r) for r in rows]


# ─── row → model converters ───────────────────────────────────────────────


def _row_to_entity(row: sqlite3.Row) -> Entity:
    return Entity(
        id=row["id"],
        type=row["type"],
        canonical_value=row["canonical_value"],
        first_seen_at=datetime.fromisoformat(row["first_seen_at"]),
        last_seen_at=datetime.fromisoformat(row["last_seen_at"]),
        mention_count=row["mention_count"],
        user_id=row["user_id"],
    )


def _row_to_mention(row: sqlite3.Row) -> EntityMention:
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


def _row_to_relation(row: sqlite3.Row) -> FindingRelation:
    reasons = [RelationReason.model_validate(r) for r in orjson.loads(row["reasons_json"])]
    conf_reasons = None
    if row["confirmed_at_reasons_json"]:
        conf_reasons = [RelationReason.model_validate(r) for r in orjson.loads(row["confirmed_at_reasons_json"])]
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
