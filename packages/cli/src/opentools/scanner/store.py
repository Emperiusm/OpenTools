"""ScanStore protocol and SQLite implementation for persisting scans and tasks.

Provides a runtime-checkable Protocol (ScanStoreProtocol) and an aiosqlite-backed
implementation (SqliteScanStore) that stores models as JSON blobs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

import aiosqlite

from opentools.scanner.models import Scan, ScanStatus, ScanTask, TaskStatus


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ScanStoreProtocol(Protocol):
    """Async persistence contract for scans and scan tasks."""

    async def save_scan(self, scan: Scan) -> None:
        """Persist a new scan record."""
        ...

    async def get_scan(self, scan_id: str) -> Scan | None:
        """Return the scan with the given id, or None if not found."""
        ...

    async def update_scan_status(
        self, scan_id: str, status: ScanStatus, **fields
    ) -> None:
        """Update the status of a scan (and any extra fields provided)."""
        ...

    async def list_scans(
        self, engagement_id: str | None = None
    ) -> list[Scan]:
        """Return all scans, optionally filtered by engagement_id."""
        ...

    async def save_task(self, task: ScanTask) -> None:
        """Persist a new task record."""
        ...

    async def get_scan_tasks(self, scan_id: str) -> list[ScanTask]:
        """Return all tasks belonging to the given scan."""
        ...

    async def update_task_status(
        self, task_id: str, status: TaskStatus, **fields
    ) -> None:
        """Update the status of a task (and any extra fields provided)."""
        ...


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
        """Insert a scan record (JSON blob)."""
        conn = self._require_conn()
        await conn.execute(
            "INSERT INTO scan (id, data) VALUES (?, ?)",
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
        """Insert a task record (JSON blob)."""
        conn = self._require_conn()
        await conn.execute(
            "INSERT INTO scan_task (id, scan_id, data) VALUES (?, ?, ?)",
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
