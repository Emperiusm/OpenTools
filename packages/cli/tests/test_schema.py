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
