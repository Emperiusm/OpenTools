"""Entity merge and split operations (async, protocol-based)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Literal
from uuid import UUID

from opentools.chain.models import Entity, entity_id_for

if TYPE_CHECKING:
    from opentools.chain.store_protocol import ChainStoreProtocol


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


async def merge_entities(
    *,
    store: "ChainStoreProtocol",
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

    a = await store.get_entity(a_id, user_id=user_id)
    b = await store.get_entity(b_id, user_id=user_id)
    if a is None or b is None:
        raise IncompatibleMerge(
            f"entity not found: {a_id if a is None else b_id}"
        )
    if a.type != b.type:
        raise IncompatibleMerge(
            f"cannot merge entities of different types: {a.type} vs {b.type}"
        )

    async with store.batch_transaction():
        # Capture the list of findings that mention the source entity
        # BEFORE rewriting mentions — after the rewrite, the source
        # entity has no mentions and the query would return [].
        affected = await store.fetch_finding_ids_for_entity(
            source_id, user_id=user_id,
        )
        mentions_rewritten = await store.rewrite_mentions_entity_id(
            from_entity_id=source_id,
            to_entity_id=target_id,
            user_id=user_id,
        )
        await store.delete_entity(source_id, user_id=user_id)
        await store.recompute_mention_counts([target_id], user_id=user_id)

    return MergeResult(
        merged_from_id=source_id,
        merged_into_id=target_id,
        mentions_rewritten=mentions_rewritten,
        affected_findings=sorted(affected),
    )


async def split_entity(
    *,
    store: "ChainStoreProtocol",
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

    source = await store.get_entity(entity_id, user_id=user_id)
    if source is None:
        raise ValueError(f"entity not found: {entity_id}")

    mentions = await store.fetch_mentions_with_engagement(
        entity_id, user_id=user_id
    )
    if not mentions:
        return SplitResult(source_entity_id=entity_id)

    # mentions is list[tuple[mention_id, engagement_id]]
    partitions: dict[str, list[str]] = {}
    for mention_id, engagement_id in mentions:
        partitions.setdefault(engagement_id, []).append(mention_id)

    if len(partitions) <= 1:
        # Nothing to split
        return SplitResult(source_entity_id=entity_id)

    now = datetime.now(timezone.utc)
    new_entity_ids: list[str] = []
    mentions_repartitioned = 0

    async with store.batch_transaction():
        for engagement_id, mention_ids in partitions.items():
            new_canonical = f"{source.canonical_value}|eng_{engagement_id[:8]}"
            new_id = entity_id_for(source.type, new_canonical)

            new_entity = Entity(
                id=new_id,
                type=source.type,
                canonical_value=new_canonical,
                first_seen_at=now,
                last_seen_at=now,
                mention_count=0,
                user_id=user_id,
            )
            await store.upsert_entity(new_entity, user_id=user_id)

            await store.rewrite_mentions_by_ids(
                mention_ids=mention_ids,
                to_entity_id=new_id,
                user_id=user_id,
            )
            mentions_repartitioned += len(mention_ids)
            new_entity_ids.append(new_id)

        # Recompute counts for all new entities in one call
        await store.recompute_mention_counts(new_entity_ids, user_id=user_id)

        # Delete the source entity (all its mentions have been moved)
        await store.delete_entity(entity_id, user_id=user_id)

    return SplitResult(
        source_entity_id=entity_id,
        new_entity_ids=new_entity_ids,
        mentions_repartitioned=mentions_repartitioned,
    )
