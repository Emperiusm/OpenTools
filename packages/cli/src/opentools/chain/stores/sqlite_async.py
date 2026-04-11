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
from pathlib import Path
from typing import AsyncIterator

import aiosqlite

from opentools.chain.stores._common import (
    StoreNotInitialized,
    require_initialized,
)
from opentools.engagement.schema import migrate_async

logger = logging.getLogger(__name__)


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

    @require_initialized
    async def get_entity(self, entity_id: str, *, user_id):
        """Stub — real implementation lands in Task 7."""
        return None  # placeholder, replaced in Task 7
