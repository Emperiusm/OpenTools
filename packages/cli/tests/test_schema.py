import sqlite3
import pytest
from opentools.engagement.schema import LATEST_VERSION, migrate, get_schema_version


def test_migrate_creates_all_tables():
    conn = sqlite3.connect(":memory:")
    migrate(conn)
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    tables = {row[0] for row in cursor.fetchall()}
    assert "engagements" in tables
    assert "findings" in tables
    assert "timeline_events" in tables
    assert "iocs" in tables
    assert "artifacts" in tables
    assert "audit_log" in tables
    assert "schema_version" in tables
    conn.close()


def test_migrate_sets_version():
    conn = sqlite3.connect(":memory:")
    migrate(conn)
    version = get_schema_version(conn)
    assert version == LATEST_VERSION
    conn.close()


def test_migrate_is_idempotent():
    conn = sqlite3.connect(":memory:")
    migrate(conn)
    migrate(conn)  # should not raise
    version = get_schema_version(conn)
    assert version == LATEST_VERSION
    conn.close()


def test_get_schema_version_on_empty_db():
    conn = sqlite3.connect(":memory:")
    version = get_schema_version(conn)
    assert version == 0
    conn.close()


def test_fts_trigger_exists():
    conn = sqlite3.connect(":memory:")
    migrate(conn)
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'findings_%'"
    )
    triggers = {row[0] for row in cursor.fetchall()}
    assert "findings_ai" in triggers
    assert "findings_ad" in triggers
    assert "findings_au" in triggers
    conn.close()


def test_migration_v2_creates_dedup_indexes():
    conn = sqlite3.connect(":memory:")
    migrate(conn)
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_findings_dedup%'"
    )
    indexes = {row[0] for row in cursor.fetchall()}
    assert "idx_findings_dedup_file" in indexes
    assert "idx_findings_dedup_network" in indexes
    conn.close()


def test_migration_v1_to_latest_upgrade():
    """Verify incremental migration from v1 applies all pending migrations."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
    from opentools.engagement.schema import _migration_v1
    _migration_v1(conn)
    conn.execute("INSERT INTO schema_version (version, applied_at) VALUES (1, '2026-01-01T00:00:00')")
    conn.commit()
    migrate(conn)
    version = get_schema_version(conn)
    assert version == LATEST_VERSION
    # v2 dedup indexes must be present
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_findings_dedup%'"
    )
    assert len(cursor.fetchall()) == 2
    # v3 chain tables must be present
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('entity', 'entity_mention', 'finding_relation')"
    )
    assert len(cursor.fetchall()) == 3
    conn.close()
