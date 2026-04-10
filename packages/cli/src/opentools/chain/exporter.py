"""Chain data export and import with merge strategies."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import orjson

from opentools.chain.store_extensions import ChainStore


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


def export_chain(
    *,
    store: ChainStore,
    engagement_id: str | None = None,
    output_path: Path,
) -> ExportResult:
    """Export chain data to a JSON file.

    If engagement_id is provided, only emit data related to findings in that
    engagement. Returns an ExportResult with counts of exported records.
    """
    if engagement_id:
        finding_rows = store.execute_all(
            "SELECT id FROM findings WHERE engagement_id = ?",
            (engagement_id,),
        )
        finding_ids = {r["id"] for r in finding_rows}
    else:
        finding_rows = store.execute_all("SELECT id FROM findings")
        finding_ids = {r["id"] for r in finding_rows}

    if not finding_ids:
        data = {
            "schema_version": SCHEMA_VERSION,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "engagement_id": engagement_id,
            "entities": [],
            "mentions": [],
            "relations": [],
            "linker_runs": [],
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(orjson.dumps(data, option=orjson.OPT_INDENT_2))
        return ExportResult(output_path=output_path)

    placeholders = ",".join("?" * len(finding_ids))
    mention_rows = store.execute_all(
        f"SELECT * FROM entity_mention WHERE finding_id IN ({placeholders})",
        tuple(finding_ids),
    )
    relation_rows = store.execute_all(
        f"""
        SELECT * FROM finding_relation
        WHERE source_finding_id IN ({placeholders})
           OR target_finding_id IN ({placeholders})
        """,
        tuple(finding_ids) * 2,
    )
    # Unique entity IDs referenced by the mentions
    entity_ids = {r["entity_id"] for r in mention_rows}
    if entity_ids:
        ent_placeholders = ",".join("?" * len(entity_ids))
        entity_rows = store.execute_all(
            f"SELECT * FROM entity WHERE id IN ({ent_placeholders})",
            tuple(entity_ids),
        )
    else:
        entity_rows = []

    linker_runs: list = []

    def _row_to_dict(row) -> dict:
        d = {}
        for key in row.keys():
            v = row[key]
            if isinstance(v, bytes):
                try:
                    d[key] = orjson.loads(v)
                except Exception:
                    d[key] = None
            else:
                d[key] = v
        return d

    data = {
        "schema_version": SCHEMA_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "engagement_id": engagement_id,
        "entities": [_row_to_dict(r) for r in entity_rows],
        "mentions": [_row_to_dict(r) for r in mention_rows],
        "relations": [_row_to_dict(r) for r in relation_rows],
        "linker_runs": linker_runs,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(orjson.dumps(data, option=orjson.OPT_INDENT_2))

    return ExportResult(
        output_path=output_path,
        entities_exported=len(entity_rows),
        mentions_exported=len(mention_rows),
        relations_exported=len(relation_rows),
        linker_runs_exported=0,
    )


def import_chain(
    *,
    store: ChainStore,
    input_path: Path,
    merge_strategy: Literal["skip", "overwrite", "merge"] = "skip",
) -> ImportResult:
    """Import chain data from a JSON file.

    The merge_strategy controls how ID collisions are handled:
    - 'skip': skip colliding records (default)
    - 'overwrite': overwrite existing records with imported data
    - 'merge': leave existing records unchanged (same as skip for entities)
    """
    data = orjson.loads(input_path.read_bytes())
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"schema version mismatch: {data.get('schema_version')} != {SCHEMA_VERSION}")

    result = ImportResult()

    # Entities
    for e in data.get("entities", []):
        existing = store.execute_one("SELECT id FROM entity WHERE id = ?", (e["id"],))
        if existing:
            result.collisions += 1
            if merge_strategy == "skip":
                continue
            if merge_strategy == "overwrite":
                store._conn.execute(
                    "UPDATE entity SET type = ?, canonical_value = ?, last_seen_at = ? WHERE id = ?",
                    (e["type"], e["canonical_value"], e["last_seen_at"], e["id"]),
                )
            # merge strategy: leave existing, don't touch
        else:
            store._conn.execute(
                """
                INSERT INTO entity (id, type, canonical_value, first_seen_at, last_seen_at, mention_count, user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    e["id"], e["type"], e["canonical_value"],
                    e["first_seen_at"], e["last_seen_at"],
                    e.get("mention_count", 0), e.get("user_id"),
                ),
            )
            result.entities_imported += 1

    # Mentions
    for m in data.get("mentions", []):
        existing = store.execute_one("SELECT id FROM entity_mention WHERE id = ?", (m["id"],))
        if existing and merge_strategy == "skip":
            continue
        try:
            store._conn.execute(
                """
                INSERT OR IGNORE INTO entity_mention
                    (id, entity_id, finding_id, field, raw_value, offset_start, offset_end,
                     extractor, confidence, created_at, user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    m["id"], m["entity_id"], m["finding_id"], m["field"],
                    m["raw_value"], m.get("offset_start"), m.get("offset_end"),
                    m["extractor"], m["confidence"], m["created_at"], m.get("user_id"),
                ),
            )
            result.mentions_imported += 1
        except Exception:
            pass

    # Relations
    for r in data.get("relations", []):
        existing = store.execute_one("SELECT id FROM finding_relation WHERE id = ?", (r["id"],))
        if existing and merge_strategy == "skip":
            continue
        try:
            store._conn.execute(
                """
                INSERT OR REPLACE INTO finding_relation
                    (id, source_finding_id, target_finding_id, weight, weight_model_version,
                     status, symmetric, reasons_json, llm_rationale, llm_relation_type,
                     llm_confidence, confirmed_at_reasons_json, created_at, updated_at, user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    r["id"], r["source_finding_id"], r["target_finding_id"],
                    r["weight"], r.get("weight_model_version", "additive_v1"),
                    r["status"], r.get("symmetric", 0),
                    orjson.dumps(r.get("reasons_json") or []),
                    r.get("llm_rationale"), r.get("llm_relation_type"),
                    r.get("llm_confidence"),
                    orjson.dumps(r.get("confirmed_at_reasons_json")) if r.get("confirmed_at_reasons_json") else None,
                    r["created_at"], r["updated_at"], r.get("user_id"),
                ),
            )
            result.relations_imported += 1
        except Exception:
            pass

    store._conn.commit()
    return result
