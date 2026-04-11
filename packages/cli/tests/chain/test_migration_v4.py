"""Tests for migration v4 — status_text backfill and cache user_id."""
import sqlite3

import pytest


def test_migration_v4_adds_status_text_column(tmp_path):
    from opentools.engagement.schema import (
        LATEST_VERSION, _apply_statements, migrate,
    )

    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db_path))
    try:
        # Build a v3 database manually
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL
            )
        """)
        for v in [1, 2, 3]:
            _apply_statements(conn, v)
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (v, "2025-01-01"),
            )
        conn.commit()

        # Seed legacy rows without status_text
        conn.execute(
            """INSERT INTO linker_run (
                id, started_at, scope, mode, finished_at, error, generation
            ) VALUES ('r_done', '2025-01-01', 'engagement', 'rules_only',
                      '2025-01-01', NULL, 1)"""
        )
        conn.execute(
            """INSERT INTO linker_run (
                id, started_at, scope, mode, error, generation
            ) VALUES ('r_failed', '2025-01-01', 'engagement', 'rules_only',
                      'oom', 2)"""
        )
        conn.execute(
            """INSERT INTO linker_run (
                id, started_at, scope, mode, generation
            ) VALUES ('r_unknown', '2025-01-01', 'engagement', 'rules_only', 3)"""
        )
        conn.commit()

        # Run migrate() which picks up v4
        migrate(conn)

        assert LATEST_VERSION == 4

        cols = [row[1] for row in conn.execute("PRAGMA table_info(linker_run)").fetchall()]
        assert "status_text" in cols

        done = conn.execute("SELECT status_text FROM linker_run WHERE id = 'r_done'").fetchone()[0]
        assert done == "done"

        failed = conn.execute("SELECT status_text FROM linker_run WHERE id = 'r_failed'").fetchone()[0]
        assert failed == "failed"

        unknown = conn.execute("SELECT status_text FROM linker_run WHERE id = 'r_unknown'").fetchone()[0]
        assert unknown == "unknown"

        ec_cols = [row[1] for row in conn.execute("PRAGMA table_info(extraction_cache)").fetchall()]
        assert "user_id" in ec_cols

        lc_cols = [row[1] for row in conn.execute("PRAGMA table_info(llm_link_cache)").fetchall()]
        assert "user_id" in lc_cols

    finally:
        conn.close()


def test_migration_v4_rolls_back_on_backfill_failure(tmp_path, monkeypatch):
    """If the backfill UPDATE fails, the ALTER TABLE must also roll back."""
    from opentools.engagement.schema import (
        MIGRATION_STATEMENTS, _apply_statements, migrate,
    )

    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL
            )
        """)
        for v in [1, 2, 3]:
            _apply_statements(conn, v)
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (v, "2025-01-01"),
            )
        conn.commit()

        # Monkeypatch v4 statements with an invalid SQL at position 1
        broken = list(MIGRATION_STATEMENTS[4])
        broken[1] = "UPDATE linker_run SET nonexistent_col = 'x'"
        monkeypatch.setattr(
            "opentools.engagement.schema.MIGRATION_STATEMENTS",
            {**MIGRATION_STATEMENTS, 4: broken},
        )

        with pytest.raises(Exception):
            migrate(conn)

        versions = [r[0] for r in conn.execute(
            "SELECT version FROM schema_version ORDER BY version"
        ).fetchall()]
        assert 4 not in versions

        cols = [row[1] for row in conn.execute("PRAGMA table_info(linker_run)").fetchall()]
        assert "status_text" not in cols

    finally:
        conn.close()
