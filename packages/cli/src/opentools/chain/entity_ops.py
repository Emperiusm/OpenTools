"""Entity merge and split operations."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID

from opentools.chain.models import entity_id_for
from opentools.chain.store_extensions import ChainStore


@dataclass
class MergeResult:
    merged_from_id: str
    merged_into_id: str
    mentions_rewritten: int
    affected_findings: list[str] = field(default_factory=list)


@dataclass
class SplitResult:
    source_entity_id: str
    new_entity_ids: list[str] = field(default_factory=list)
    mentions_repartitioned: int = 0


class IncompatibleMerge(ValueError):
    """Raised when two entities cannot be merged (different types or missing)."""


def merge_entities(
    *,
    store: ChainStore,
    a_id: str,
    b_id: str,
    into: Literal["a", "b"] = "b",
    user_id: UUID | None = None,
) -> MergeResult:
    """Merge entity A into entity B (or vice versa via into='a').

    Validates both entities exist and share the same type. Rewrites
    all EntityMention rows from the source to the target entity.
    Deletes the source Entity row. Recomputes mention_count on the target.
    """
    if into not in ("a", "b"):
        raise ValueError("into must be 'a' or 'b'")
    source_id = a_id if into == "b" else b_id
    target_id = b_id if into == "b" else a_id

    a = store.get_entity(a_id)
    b = store.get_entity(b_id)
    if a is None or b is None:
        raise IncompatibleMerge(f"entity not found: {a_id if a is None else b_id}")
    if a.type != b.type:
        raise IncompatibleMerge(
            f"cannot merge entities of different types: {a.type} vs {b.type}"
        )

    # Find affected findings before rewriting
    rows = store.execute_all(
        "SELECT DISTINCT finding_id FROM entity_mention WHERE entity_id = ?",
        (source_id,),
    )
    affected = [r["finding_id"] for r in rows]

    # Rewrite mentions
    cur = store._conn.execute(
        "UPDATE entity_mention SET entity_id = ? WHERE entity_id = ?",
        (target_id, source_id),
    )
    mentions_rewritten = cur.rowcount

    # Delete source entity
    store._conn.execute("DELETE FROM entity WHERE id = ?", (source_id,))

    # Recompute mention_count on target
    store._conn.execute(
        "UPDATE entity SET mention_count = (SELECT COUNT(*) FROM entity_mention WHERE entity_id = ?), "
        "last_seen_at = ? WHERE id = ?",
        (target_id, datetime.now(timezone.utc).isoformat(), target_id),
    )

    store._conn.commit()

    return MergeResult(
        merged_from_id=source_id,
        merged_into_id=target_id,
        mentions_rewritten=mentions_rewritten,
        affected_findings=affected,
    )


def split_entity(
    *,
    store: ChainStore,
    entity_id: str,
    by: Literal["engagement"] = "engagement",
    user_id: UUID | None = None,
) -> SplitResult:
    """Split an entity's mentions into separate entities by criterion.

    For 3C.1 only 'engagement' is supported: one new entity per
    distinct engagement id that has mentions. The canonical_value of
    each new entity becomes "{original}|eng_{engagement_id[:8]}".
    """
    if by != "engagement":
        raise ValueError(f"split criterion '{by}' not supported in 3C.1")

    source = store.get_entity(entity_id)
    if source is None:
        raise ValueError(f"entity not found: {entity_id}")

    # Group mentions by engagement_id (joining through findings)
    rows = store.execute_all(
        """
        SELECT em.id AS mention_id, f.engagement_id
        FROM entity_mention em
        JOIN findings f ON f.id = em.finding_id
        WHERE em.entity_id = ?
        """,
        (entity_id,),
    )
    if not rows:
        return SplitResult(source_entity_id=entity_id)

    partitions: dict[str, list[str]] = {}
    for r in rows:
        partitions.setdefault(r["engagement_id"], []).append(r["mention_id"])

    if len(partitions) <= 1:
        # Nothing to split
        return SplitResult(source_entity_id=entity_id)

    now = datetime.now(timezone.utc)
    new_entity_ids: list[str] = []
    mentions_repartitioned = 0

    for engagement_id, mention_ids in partitions.items():
        new_canonical = f"{source.canonical_value}|eng_{engagement_id[:8]}"
        new_id = entity_id_for(source.type, new_canonical)

        # Insert new entity
        store._conn.execute(
            """
            INSERT OR IGNORE INTO entity
                (id, type, canonical_value, first_seen_at, last_seen_at, mention_count, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id, source.type, new_canonical,
                now.isoformat(), now.isoformat(),
                0, str(user_id) if user_id else None,
            ),
        )

        # Rewrite mentions to new entity_id
        placeholders = ",".join("?" * len(mention_ids))
        store._conn.execute(
            f"UPDATE entity_mention SET entity_id = ? WHERE id IN ({placeholders})",
            (new_id, *mention_ids),
        )
        mentions_repartitioned += len(mention_ids)

        # Recompute mention_count on new entity
        store._conn.execute(
            "UPDATE entity SET mention_count = (SELECT COUNT(*) FROM entity_mention WHERE entity_id = ?) WHERE id = ?",
            (new_id, new_id),
        )
        new_entity_ids.append(new_id)

    # Delete the source entity (all its mentions have been moved)
    store._conn.execute("DELETE FROM entity WHERE id = ?", (entity_id,))

    store._conn.commit()

    return SplitResult(
        source_entity_id=entity_id,
        new_entity_ids=new_entity_ids,
        mentions_repartitioned=mentions_repartitioned,
    )
