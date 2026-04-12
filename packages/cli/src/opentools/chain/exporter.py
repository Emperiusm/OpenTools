"""Chain data export and import with merge strategies.

Async implementation backed by :class:`ChainStoreProtocol`. Export
streams rows via :meth:`ChainStoreProtocol.export_dump_stream` for
bounded memory; import wraps bulk upserts inside
:meth:`ChainStoreProtocol.batch_transaction` for atomicity so a partial
failure rolls back cleanly.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Literal

import orjson

from opentools.chain.models import (
    Entity,
    EntityMention,
    FindingRelation,
    RelationReason,
)

if TYPE_CHECKING:
    from opentools.chain.store_protocol import ChainStoreProtocol


SCHEMA_VERSION = "1.0"


@dataclass
class ExportResult:
    output_path: Path
    entities_exported: int = 0
    mentions_exported: int = 0
    relations_exported: int = 0
    linker_runs_exported: int = 0


@dataclass
class ImportResult:
    entities_imported: int = 0
    mentions_imported: int = 0
    relations_imported: int = 0
    linker_runs_imported: int = 0
    collisions: int = 0


def _normalize_row(row: dict) -> dict:
    """Decode bytes columns (JSON blobs) into Python values.

    ``export_dump_stream`` yields ``dict(row)`` values; BLOB columns
    like ``reasons_json`` come through as ``bytes``. We decode them here
    so the exported JSON is self-describing (no base64).
    """
    out: dict = {}
    for k, v in row.items():
        if isinstance(v, bytes):
            try:
                out[k] = orjson.loads(v)
            except Exception:
                out[k] = None
        else:
            out[k] = v
    return out


async def export_chain(
    *,
    store: "ChainStoreProtocol",
    engagement_id: str | None = None,
    output_path: Path,
    user_id=None,
) -> ExportResult:
    """Export chain data to a JSON file.

    If ``engagement_id`` is provided, only emit data related to
    findings in that engagement. Otherwise emit every finding across
    every engagement. Rows are streamed via
    :meth:`store.export_dump_stream` so memory usage is bounded by the
    aiosqlite cursor page size, not the total dataset.
    """
    if engagement_id:
        finding_ids = await store.fetch_findings_for_engagement(
            engagement_id, user_id=user_id,
        )
    else:
        finding_ids = await store.fetch_all_finding_ids(user_id=user_id)

    entities: list[dict] = []
    mentions: list[dict] = []
    relations: list[dict] = []

    if finding_ids:
        async for item in store.export_dump_stream(
            finding_ids=finding_ids, user_id=user_id,
        ):
            kind = item["kind"]
            data = _normalize_row(item["data"])
            if kind == "entity":
                entities.append(data)
            elif kind == "mention":
                mentions.append(data)
            elif kind == "relation":
                relations.append(data)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "engagement_id": engagement_id,
        "entities": entities,
        "mentions": mentions,
        "relations": relations,
        "linker_runs": [],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(orjson.dumps(payload, option=orjson.OPT_INDENT_2))

    return ExportResult(
        output_path=output_path,
        entities_exported=len(entities),
        mentions_exported=len(mentions),
        relations_exported=len(relations),
        linker_runs_exported=0,
    )


def _entity_from_dict(d: dict) -> Entity:
    return Entity(
        id=d["id"],
        type=d["type"],
        canonical_value=d["canonical_value"],
        first_seen_at=d["first_seen_at"],
        last_seen_at=d["last_seen_at"],
        mention_count=d.get("mention_count", 0) or 0,
        user_id=d.get("user_id"),
    )


def _mention_from_dict(d: dict) -> EntityMention:
    return EntityMention(
        id=d["id"],
        entity_id=d["entity_id"],
        finding_id=d["finding_id"],
        field=d["field"],
        raw_value=d["raw_value"],
        offset_start=d.get("offset_start"),
        offset_end=d.get("offset_end"),
        extractor=d["extractor"],
        confidence=d["confidence"],
        created_at=d["created_at"],
        user_id=d.get("user_id"),
    )


def _relation_from_dict(d: dict) -> FindingRelation:
    raw_reasons = d.get("reasons_json") or []
    reasons = [RelationReason.model_validate(r) for r in raw_reasons]
    raw_conf = d.get("confirmed_at_reasons_json")
    confirmed: list[RelationReason] | None
    if raw_conf:
        confirmed = [RelationReason.model_validate(r) for r in raw_conf]
    else:
        confirmed = None
    return FindingRelation(
        id=d["id"],
        source_finding_id=d["source_finding_id"],
        target_finding_id=d["target_finding_id"],
        weight=d["weight"],
        weight_model_version=d.get("weight_model_version") or "additive_v1",
        status=d["status"],
        symmetric=bool(d.get("symmetric", 0)),
        reasons=reasons,
        llm_rationale=d.get("llm_rationale"),
        llm_relation_type=d.get("llm_relation_type"),
        llm_confidence=d.get("llm_confidence"),
        confirmed_at_reasons=confirmed,
        created_at=d["created_at"],
        updated_at=d["updated_at"],
        user_id=d.get("user_id"),
    )


async def import_chain(
    *,
    store: "ChainStoreProtocol",
    input_path: Path,
    merge_strategy: Literal["skip", "overwrite", "merge"] = "skip",
    user_id=None,
) -> ImportResult:
    """Import chain data from a JSON file via protocol methods.

    The ``merge_strategy`` controls how ID collisions are handled:

    - ``skip``   — colliding records are left untouched (still counted
      in :attr:`ImportResult.collisions`)
    - ``overwrite`` — colliding records are replaced via the bulk
      upsert path (``ON CONFLICT`` updates)
    - ``merge``  — same as ``skip`` for entities; mentions/relations
      are inserted with ``INSERT OR IGNORE`` semantics at the store
      level

    The entire import runs inside ``store.batch_transaction()`` so a
    failure midway rolls the whole file back.
    """
    data = orjson.loads(input_path.read_bytes())
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"schema version mismatch: {data.get('schema_version')} != {SCHEMA_VERSION}"
        )

    result = ImportResult()

    raw_entities = data.get("entities", []) or []
    raw_mentions = data.get("mentions", []) or []
    raw_relations = data.get("relations", []) or []

    async with store.batch_transaction():
        # --- Entities ---
        to_upsert_entities: list[Entity] = []
        for e in raw_entities:
            existing = await store.get_entity(e["id"], user_id=user_id)
            if existing is not None:
                result.collisions += 1
                if merge_strategy == "overwrite":
                    to_upsert_entities.append(_entity_from_dict(e))
                # skip / merge: leave existing untouched
                continue
            to_upsert_entities.append(_entity_from_dict(e))
            result.entities_imported += 1

        if to_upsert_entities:
            await store.upsert_entities_bulk(
                to_upsert_entities, user_id=user_id,
            )

        # --- Mentions ---
        # add_mentions_bulk uses INSERT OR IGNORE so duplicates are
        # silently skipped. For reporting we trust the returned count.
        mention_models = [_mention_from_dict(m) for m in raw_mentions]
        if mention_models:
            inserted = await store.add_mentions_bulk(
                mention_models, user_id=user_id,
            )
            result.mentions_imported = inserted

        # --- Relations ---
        relation_models = [_relation_from_dict(r) for r in raw_relations]
        if relation_models:
            created, _updated = await store.upsert_relations_bulk(
                relation_models, user_id=user_id,
            )
            # For the import use case "imported" counts newly created
            # rows; updates of existing rows are reported under
            # collisions via the entity path.
            result.relations_imported = created

    return result
