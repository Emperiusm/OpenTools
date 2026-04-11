"""Tests for migrate_async() — the aiosqlite-native migration path."""
import sqlite3

import aiosqlite
import pytest


@pytest.mark.asyncio
async def test_migrate_async_creates_all_expected_tables(tmp_path):
    from opentools.engagement.schema import LATEST_VERSION, migrate_async

    db_path = tmp_path / "test.db"
    async with aiosqlite.connect(str(db_path)) as conn:
        await migrate_async(conn)

    # Inspect with sync sqlite3 to verify tables exist
    sconn = sqlite3.connect(str(db_path))
    try:
        rows = sconn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        names = {r[0] for r in rows}
        # Engagement tables
        assert "engagements" in names
        assert "findings" in names
        # Chain tables from migration v3
        assert "entity" in names
        assert "entity_mention" in names
        assert "finding_relation" in names
        assert "linker_run" in names
        # Schema version tracking
        assert "schema_version" in names

        version = sconn.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()[0]
        assert version == LATEST_VERSION
    finally:
        sconn.close()


@pytest.mark.asyncio
async def test_migrate_async_is_idempotent(tmp_path):
    from opentools.engagement.schema import LATEST_VERSION, migrate_async

    db_path = tmp_path / "test.db"
    async with aiosqlite.connect(str(db_path)) as conn:
        await migrate_async(conn)
        await migrate_async(conn)  # Second run should be a no-op

    sconn = sqlite3.connect(str(db_path))
    try:
        rows = sconn.execute(
            "SELECT version FROM schema_version ORDER BY version"
        ).fetchall()
        # One row per version, no duplicates
        versions = [r[0] for r in rows]
        assert versions == sorted(set(versions))
        assert max(versions) == LATEST_VERSION
    finally:
        sconn.close()


@pytest.mark.asyncio
async def test_migrate_async_produces_same_schema_as_sync(tmp_path):
    """Sync migrate() and async migrate_async() must produce identical
    schemas. Divergence here would be a ship-blocking bug."""
    from opentools.engagement.schema import migrate, migrate_async

    sync_db = tmp_path / "sync.db"
    async_db = tmp_path / "async.db"

    sconn = sqlite3.connect(str(sync_db))
    try:
        migrate(sconn)
    finally:
        sconn.close()

    async with aiosqlite.connect(str(async_db)) as aconn:
        await migrate_async(aconn)

    def _schema_dump(path):
        conn = sqlite3.connect(str(path))
        try:
            rows = conn.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE type IN ('table', 'index', 'trigger') "
                "AND sql IS NOT NULL "
                "ORDER BY type, name"
            ).fetchall()
            return tuple(r[0] for r in rows)
        finally:
            conn.close()

    assert _schema_dump(sync_db) == _schema_dump(async_db)
