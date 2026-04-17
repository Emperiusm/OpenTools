"""ScanStore protocol and SQLite implementation for persisting scans and tasks.

Provides a runtime-checkable Protocol (ScanStoreProtocol) and an aiosqlite-backed
implementation (SqliteScanStore) that stores models as JSON blobs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import aiosqlite

from opentools.scanner.models import (
    DeduplicatedFinding,
    ProgressEvent,
    RawFinding,
    Scan,
    ScanStatus,
    ScanTask,
    SuppressionRule,
    TaskStatus,
    ToolEffectiveness,
)


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ScanStoreProtocol(Protocol):
    """Async persistence contract for scans, tasks, findings, events, and metadata."""

    # -- Scan CRUD (existing) --
    async def save_scan(self, scan: Scan) -> None: ...
    async def get_scan(self, scan_id: str) -> Scan | None: ...
    async def update_scan_status(self, scan_id: str, status: ScanStatus, **fields) -> None: ...
    async def list_scans(self, engagement_id: str | None = None) -> list[Scan]: ...

    # -- Task CRUD (existing) --
    async def save_task(self, task: ScanTask) -> None: ...
    async def get_scan_tasks(self, scan_id: str) -> list[ScanTask]: ...
    async def update_task_status(self, task_id: str, status: TaskStatus, **fields) -> None: ...

    # -- Raw findings --
    async def save_raw_finding(self, finding: RawFinding) -> None: ...
    async def get_raw_findings(self, scan_id: str) -> list[RawFinding]: ...

    # -- Dedup findings --
    async def save_dedup_finding(self, finding: DeduplicatedFinding) -> None: ...
    async def get_scan_findings(self, scan_id: str) -> list[DeduplicatedFinding]: ...
    async def get_engagement_findings(self, engagement_id: str) -> list[DeduplicatedFinding]: ...

    # -- Events --
    async def save_event(self, event: ProgressEvent) -> None: ...
    async def get_events_after(self, scan_id: str, sequence: int) -> list[ProgressEvent]: ...

    # -- Suppression rules --
    async def save_suppression_rule(self, rule: SuppressionRule) -> None: ...
    async def get_suppression_rules(self, engagement_id: str | None = None) -> list[SuppressionRule]: ...

    # -- FP memory --
    async def get_fp_memory(self, target: str, fingerprint: str, cwe: str) -> bool: ...
    async def save_fp_memory(self, target: str, fingerprint: str, cwe: str) -> None: ...

    # -- Output cache --
    async def get_output_cache(self, cache_key: str) -> dict | None: ...
    async def save_output_cache(self, cache_key: str, output: dict) -> None: ...

    # -- Tool effectiveness --
    async def get_tool_effectiveness(self, tool: str, target_type: str) -> ToolEffectiveness | None: ...
    async def update_tool_effectiveness(self, stats: ToolEffectiveness) -> None: ...


# ---------------------------------------------------------------------------
# SQLite implementation
# ---------------------------------------------------------------------------

_CREATE_SCAN_TABLE = """
CREATE TABLE IF NOT EXISTS scan (
    id   TEXT PRIMARY KEY,
    data TEXT NOT NULL
)
"""

_CREATE_SCAN_TASK_TABLE = """
CREATE TABLE IF NOT EXISTS scan_task (
    id      TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    data    TEXT NOT NULL
)
"""

_CREATE_SCAN_TASK_INDEX = """
CREATE INDEX IF NOT EXISTS idx_scan_task_scan_id ON scan_task (scan_id)
"""

_CREATE_RAW_FINDING_TABLE = """
CREATE TABLE IF NOT EXISTS raw_finding (
    id      TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    data    TEXT NOT NULL
)
"""

_CREATE_RAW_FINDING_INDEX = """
CREATE INDEX IF NOT EXISTS idx_raw_finding_scan_id ON raw_finding (scan_id)
"""

_CREATE_DEDUP_FINDING_TABLE = """
CREATE TABLE IF NOT EXISTS dedup_finding (
    id                TEXT PRIMARY KEY,
    engagement_id     TEXT NOT NULL,
    first_seen_scan_id TEXT NOT NULL,
    data              TEXT NOT NULL
)
"""

_CREATE_DEDUP_FINDING_ENG_INDEX = """
CREATE INDEX IF NOT EXISTS idx_dedup_finding_engagement ON dedup_finding (engagement_id)
"""

_CREATE_DEDUP_FINDING_SCAN_INDEX = """
CREATE INDEX IF NOT EXISTS idx_dedup_finding_scan ON dedup_finding (first_seen_scan_id)
"""

_CREATE_EVENT_TABLE = """
CREATE TABLE IF NOT EXISTS scan_event (
    id       TEXT PRIMARY KEY,
    scan_id  TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    data     TEXT NOT NULL
)
"""

_CREATE_EVENT_INDEX = """
CREATE INDEX IF NOT EXISTS idx_scan_event_scan_seq ON scan_event (scan_id, sequence)
"""

_CREATE_SUPPRESSION_RULE_TABLE = """
CREATE TABLE IF NOT EXISTS suppression_rule (
    id              TEXT PRIMARY KEY,
    scope           TEXT NOT NULL,
    engagement_id   TEXT,
    data            TEXT NOT NULL
)
"""

_CREATE_FP_MEMORY_TABLE = """
CREATE TABLE IF NOT EXISTS fp_memory (
    target      TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    cwe         TEXT NOT NULL,
    PRIMARY KEY (target, fingerprint, cwe)
)
"""

_CREATE_OUTPUT_CACHE_TABLE = """
CREATE TABLE IF NOT EXISTS output_cache (
    cache_key TEXT PRIMARY KEY,
    data      TEXT NOT NULL
)
"""

_CREATE_TOOL_EFFECTIVENESS_TABLE = """
CREATE TABLE IF NOT EXISTS tool_effectiveness (
    tool        TEXT NOT NULL,
    target_type TEXT NOT NULL,
    data        TEXT NOT NULL,
    PRIMARY KEY (tool, target_type)
)
"""


class SqliteScanStore:
    """aiosqlite-backed implementation of ScanStoreProtocol.

    Usage::

        store = SqliteScanStore(db_path)
        await store.initialize()
        try:
            ...
        finally:
            await store.close()
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Open the database connection and create tables if needed."""
        self._conn = await aiosqlite.connect(str(self._db_path))
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.execute(_CREATE_SCAN_TABLE)
        await self._conn.execute(_CREATE_SCAN_TASK_TABLE)
        await self._conn.execute(_CREATE_SCAN_TASK_INDEX)
        await self._conn.execute(_CREATE_RAW_FINDING_TABLE)
        await self._conn.execute(_CREATE_RAW_FINDING_INDEX)
        await self._conn.execute(_CREATE_DEDUP_FINDING_TABLE)
        await self._conn.execute(_CREATE_DEDUP_FINDING_ENG_INDEX)
        await self._conn.execute(_CREATE_DEDUP_FINDING_SCAN_INDEX)
        await self._conn.execute(_CREATE_EVENT_TABLE)
        await self._conn.execute(_CREATE_EVENT_INDEX)
        await self._conn.execute(_CREATE_SUPPRESSION_RULE_TABLE)
        await self._conn.execute(_CREATE_FP_MEMORY_TABLE)
        await self._conn.execute(_CREATE_OUTPUT_CACHE_TABLE)
        await self._conn.execute(_CREATE_TOOL_EFFECTIVENESS_TABLE)
        await self._conn.commit()

    async def close(self) -> None:
        """Close the database connection."""
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError(
                "SqliteScanStore not initialized — call initialize() first"
            )
        return self._conn

    # ------------------------------------------------------------------
    # Scan CRUD
    # ------------------------------------------------------------------

    async def save_scan(self, scan: Scan) -> None:
        """Upsert a scan record (JSON blob).

        Idempotent — safe to call both during plan (initial persist) and
        after execute (terminal state persist). Uses INSERT OR REPLACE so
        subsequent saves overwrite the row with the latest scan state.
        """
        conn = self._require_conn()
        await conn.execute(
            "INSERT OR REPLACE INTO scan (id, data) VALUES (?, ?)",
            (scan.id, scan.model_dump_json()),
        )
        await conn.commit()

    async def get_scan(self, scan_id: str) -> Scan | None:
        """Return a Scan by id, or None if not found."""
        conn = self._require_conn()
        async with conn.execute(
            "SELECT data FROM scan WHERE id = ?", (scan_id,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        return Scan.model_validate_json(row["data"])

    async def update_scan_status(
        self, scan_id: str, status: ScanStatus, **fields
    ) -> None:
        """Read-mutate-write: update status and any additional fields."""
        scan = await self.get_scan(scan_id)
        if scan is None:
            raise KeyError(f"Scan '{scan_id}' not found")
        updated = scan.model_copy(update={"status": status, **fields})
        conn = self._require_conn()
        await conn.execute(
            "UPDATE scan SET data = ? WHERE id = ?",
            (updated.model_dump_json(), scan_id),
        )
        await conn.commit()

    async def list_scans(self, engagement_id: str | None = None) -> list[Scan]:
        """Return all scans, optionally filtered by engagement_id (Python-side filter)."""
        conn = self._require_conn()
        async with conn.execute("SELECT data FROM scan") as cursor:
            rows = await cursor.fetchall()
        scans = [Scan.model_validate_json(row["data"]) for row in rows]
        if engagement_id is not None:
            scans = [s for s in scans if s.engagement_id == engagement_id]
        return scans

    # ------------------------------------------------------------------
    # Task CRUD
    # ------------------------------------------------------------------

    async def save_task(self, task: ScanTask) -> None:
        """Upsert a task record (JSON blob).

        Idempotent — safe to call before execution (to persist planned state)
        and after (to persist terminal state with stdout/stderr/exit_code).
        """
        conn = self._require_conn()
        await conn.execute(
            "INSERT OR REPLACE INTO scan_task (id, scan_id, data) VALUES (?, ?, ?)",
            (task.id, task.scan_id, task.model_dump_json()),
        )
        await conn.commit()

    async def get_scan_tasks(self, scan_id: str) -> list[ScanTask]:
        """Return all tasks belonging to the given scan."""
        conn = self._require_conn()
        async with conn.execute(
            "SELECT data FROM scan_task WHERE scan_id = ?", (scan_id,)
        ) as cursor:
            rows = await cursor.fetchall()
        return [ScanTask.model_validate_json(row["data"]) for row in rows]

    async def update_task_status(
        self, task_id: str, status: TaskStatus, **fields
    ) -> None:
        """Read-mutate-write: update status and any additional fields."""
        conn = self._require_conn()
        async with conn.execute(
            "SELECT data FROM scan_task WHERE id = ?", (task_id,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            raise KeyError(f"ScanTask '{task_id}' not found")
        task = ScanTask.model_validate_json(row["data"])
        updated = task.model_copy(update={"status": status, **fields})
        await conn.execute(
            "UPDATE scan_task SET data = ? WHERE id = ?",
            (updated.model_dump_json(), task_id),
        )
        await conn.commit()

    # ------------------------------------------------------------------
    # Raw findings
    # ------------------------------------------------------------------

    async def save_raw_finding(self, finding: RawFinding) -> None:
        """Insert a raw finding record."""
        conn = self._require_conn()
        await conn.execute(
            "INSERT INTO raw_finding (id, scan_id, data) VALUES (?, ?, ?)",
            (finding.id, finding.scan_id, finding.model_dump_json()),
        )
        await conn.commit()

    async def save_raw_findings_batch(self, findings: list[RawFinding]) -> None:
        """Insert multiple raw findings in a single transaction."""
        if not findings:
            return
        conn = self._require_conn()
        await conn.executemany(
            "INSERT INTO raw_finding (id, scan_id, data) VALUES (?, ?, ?)",
            [(f.id, f.scan_id, f.model_dump_json()) for f in findings],
        )
        await conn.commit()

    async def get_raw_findings(self, scan_id: str) -> list[RawFinding]:
        """Return all raw findings for a scan."""
        conn = self._require_conn()
        async with conn.execute(
            "SELECT data FROM raw_finding WHERE scan_id = ?", (scan_id,)
        ) as cursor:
            rows = await cursor.fetchall()
        return [RawFinding.model_validate_json(row["data"]) for row in rows]

    # ------------------------------------------------------------------
    # Dedup findings
    # ------------------------------------------------------------------

    async def save_dedup_finding(self, finding: DeduplicatedFinding) -> None:
        """Insert a deduplicated finding record."""
        conn = self._require_conn()
        await conn.execute(
            "INSERT INTO dedup_finding (id, engagement_id, first_seen_scan_id, data) VALUES (?, ?, ?, ?)",
            (finding.id, finding.engagement_id, finding.first_seen_scan_id,
             finding.model_dump_json()),
        )
        await conn.commit()

    async def save_dedup_findings_batch(self, findings: list[DeduplicatedFinding]) -> None:
        """Insert multiple deduplicated findings in a single transaction."""
        if not findings:
            return
        conn = self._require_conn()
        await conn.executemany(
            "INSERT INTO dedup_finding (id, engagement_id, first_seen_scan_id, data) VALUES (?, ?, ?, ?)",
            [(f.id, f.engagement_id, f.first_seen_scan_id, f.model_dump_json()) for f in findings],
        )
        await conn.commit()

    async def get_scan_findings(self, scan_id: str) -> list[DeduplicatedFinding]:
        """Return all dedup findings first seen in a given scan."""
        conn = self._require_conn()
        async with conn.execute(
            "SELECT data FROM dedup_finding WHERE first_seen_scan_id = ?", (scan_id,)
        ) as cursor:
            rows = await cursor.fetchall()
        return [DeduplicatedFinding.model_validate_json(row["data"]) for row in rows]

    async def get_engagement_findings(self, engagement_id: str) -> list[DeduplicatedFinding]:
        """Return all dedup findings for an engagement."""
        conn = self._require_conn()
        async with conn.execute(
            "SELECT data FROM dedup_finding WHERE engagement_id = ?", (engagement_id,)
        ) as cursor:
            rows = await cursor.fetchall()
        return [DeduplicatedFinding.model_validate_json(row["data"]) for row in rows]

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    async def save_event(self, event: ProgressEvent) -> None:
        """Insert a progress event."""
        conn = self._require_conn()
        await conn.execute(
            "INSERT INTO scan_event (id, scan_id, sequence, data) VALUES (?, ?, ?, ?)",
            (event.id, event.scan_id, event.sequence, event.model_dump_json()),
        )
        await conn.commit()

    async def get_events_after(self, scan_id: str, sequence: int) -> list[ProgressEvent]:
        """Return events for a scan with sequence > the given value."""
        conn = self._require_conn()
        async with conn.execute(
            "SELECT data FROM scan_event WHERE scan_id = ? AND sequence > ? ORDER BY sequence",
            (scan_id, sequence),
        ) as cursor:
            rows = await cursor.fetchall()
        return [ProgressEvent.model_validate_json(row["data"]) for row in rows]

    # ------------------------------------------------------------------
    # Suppression rules
    # ------------------------------------------------------------------

    async def save_suppression_rule(self, rule: SuppressionRule) -> None:
        """Insert a suppression rule."""
        conn = self._require_conn()
        await conn.execute(
            "INSERT INTO suppression_rule (id, scope, engagement_id, data) VALUES (?, ?, ?, ?)",
            (rule.id, rule.scope, rule.engagement_id, rule.model_dump_json()),
        )
        await conn.commit()

    async def get_suppression_rules(
        self, engagement_id: str | None = None,
    ) -> list[SuppressionRule]:
        """Return suppression rules — global rules always included.

        If engagement_id is provided, also returns rules scoped to that engagement.
        """
        conn = self._require_conn()
        if engagement_id is None:
            async with conn.execute("SELECT data FROM suppression_rule") as cursor:
                rows = await cursor.fetchall()
        else:
            async with conn.execute(
                "SELECT data FROM suppression_rule WHERE scope = 'global' OR engagement_id = ?",
                (engagement_id,),
            ) as cursor:
                rows = await cursor.fetchall()
        return [SuppressionRule.model_validate_json(row["data"]) for row in rows]

    # ------------------------------------------------------------------
    # FP memory
    # ------------------------------------------------------------------

    async def get_fp_memory(self, target: str, fingerprint: str, cwe: str) -> bool:
        """Return True if this finding was previously marked as FP."""
        conn = self._require_conn()
        async with conn.execute(
            "SELECT 1 FROM fp_memory WHERE target = ? AND fingerprint = ? AND cwe = ?",
            (target, fingerprint, cwe),
        ) as cursor:
            return await cursor.fetchone() is not None

    async def save_fp_memory(self, target: str, fingerprint: str, cwe: str) -> None:
        """Record a finding as a known false positive."""
        conn = self._require_conn()
        await conn.execute(
            "INSERT OR IGNORE INTO fp_memory (target, fingerprint, cwe) VALUES (?, ?, ?)",
            (target, fingerprint, cwe),
        )
        await conn.commit()

    # ------------------------------------------------------------------
    # Output cache
    # ------------------------------------------------------------------

    async def get_output_cache(self, cache_key: str) -> dict | None:
        """Return cached output or None."""
        conn = self._require_conn()
        async with conn.execute(
            "SELECT data FROM output_cache WHERE cache_key = ?", (cache_key,)
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        return json.loads(row["data"])

    async def save_output_cache(self, cache_key: str, output: dict) -> None:
        """Save output to cache (upsert)."""
        conn = self._require_conn()
        await conn.execute(
            "INSERT OR REPLACE INTO output_cache (cache_key, data) VALUES (?, ?)",
            (cache_key, json.dumps(output, default=str)),
        )
        await conn.commit()

    # ------------------------------------------------------------------
    # Tool effectiveness
    # ------------------------------------------------------------------

    async def get_tool_effectiveness(
        self, tool: str, target_type: str,
    ) -> ToolEffectiveness | None:
        """Return effectiveness stats or None."""
        conn = self._require_conn()
        async with conn.execute(
            "SELECT data FROM tool_effectiveness WHERE tool = ? AND target_type = ?",
            (tool, target_type),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        return ToolEffectiveness.model_validate_json(row["data"])

    async def update_tool_effectiveness(self, stats: ToolEffectiveness) -> None:
        """Upsert tool effectiveness stats."""
        conn = self._require_conn()
        await conn.execute(
            "INSERT OR REPLACE INTO tool_effectiveness (tool, target_type, data) VALUES (?, ?, ?)",
            (stats.tool, stats.target_type, stats.model_dump_json()),
        )
        await conn.commit()
