"""
SQLite schema definitions and migration runner for the engagement store.

All IDs are TEXT (UUIDs as strings). Datetimes are TEXT (ISO 8601).
JSON fields (lists, dicts) are stored as TEXT containing JSON.
"""

import sqlite3
from datetime import datetime, timezone


def get_schema_version(conn: sqlite3.Connection) -> int:
    """Return the current schema version (0 if no schema_version table exists)."""
    try:
        row = conn.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()
        return row[0] if row[0] is not None else 0
    except sqlite3.OperationalError:
        return 0


def _migration_v1(conn: sqlite3.Connection) -> None:
    """Execute all DDL for schema version 1."""
    conn.executescript("""
        -- Engagements table
        CREATE TABLE IF NOT EXISTS engagements (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            target      TEXT,
            type        TEXT,
            scope       TEXT,
            status      TEXT NOT NULL DEFAULT 'active',
            skills_used TEXT,  -- JSON array
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        );

        -- Findings table
        CREATE TABLE IF NOT EXISTS findings (
            id                 TEXT PRIMARY KEY,
            engagement_id      TEXT NOT NULL REFERENCES engagements(id),
            tool               TEXT,
            corroborated_by    TEXT,   -- JSON array
            cwe                TEXT,
            severity           TEXT,
            severity_by_tool   TEXT,   -- JSON object
            status             TEXT NOT NULL DEFAULT 'discovered',
            phase              TEXT,
            title              TEXT,
            description        TEXT,
            file_path          TEXT,
            line_start         INTEGER,
            line_end           INTEGER,
            evidence           TEXT,
            remediation        TEXT,
            cvss               REAL,
            false_positive     INTEGER NOT NULL DEFAULT 0,
            dedup_confidence   TEXT,
            created_at         TEXT NOT NULL,
            deleted_at         TEXT
        );

        -- FTS5 virtual table for full-text search over findings
        CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
            title,
            description,
            evidence,
            remediation,
            content='findings',
            content_rowid='rowid'
        );

        -- FTS sync trigger: after insert
        CREATE TRIGGER IF NOT EXISTS findings_ai
        AFTER INSERT ON findings BEGIN
            INSERT INTO findings_fts(rowid, title, description, evidence, remediation)
            VALUES (new.rowid, new.title, new.description, new.evidence, new.remediation);
        END;

        -- FTS sync trigger: after delete
        CREATE TRIGGER IF NOT EXISTS findings_ad
        AFTER DELETE ON findings BEGIN
            INSERT INTO findings_fts(findings_fts, rowid, title, description, evidence, remediation)
            VALUES ('delete', old.rowid, old.title, old.description, old.evidence, old.remediation);
        END;

        -- FTS sync trigger: after update
        CREATE TRIGGER IF NOT EXISTS findings_au
        AFTER UPDATE ON findings BEGIN
            INSERT INTO findings_fts(findings_fts, rowid, title, description, evidence, remediation)
            VALUES ('delete', old.rowid, old.title, old.description, old.evidence, old.remediation);
            INSERT INTO findings_fts(rowid, title, description, evidence, remediation)
            VALUES (new.rowid, new.title, new.description, new.evidence, new.remediation);
        END;

        -- Timeline events table
        CREATE TABLE IF NOT EXISTS timeline_events (
            id            TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL REFERENCES engagements(id),
            timestamp     TEXT NOT NULL,
            source        TEXT,
            event         TEXT NOT NULL,
            details       TEXT,
            confidence    TEXT NOT NULL DEFAULT 'medium',
            finding_id    TEXT REFERENCES findings(id)
        );

        -- IOCs (Indicators of Compromise) table
        CREATE TABLE IF NOT EXISTS iocs (
            id                TEXT PRIMARY KEY,
            engagement_id     TEXT NOT NULL REFERENCES engagements(id),
            ioc_type          TEXT NOT NULL,
            value             TEXT NOT NULL,
            context           TEXT,
            first_seen        TEXT,
            last_seen         TEXT,
            source_finding_id TEXT REFERENCES findings(id),
            UNIQUE(engagement_id, ioc_type, value)
        );

        -- Artifacts table
        CREATE TABLE IF NOT EXISTS artifacts (
            id            TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL REFERENCES engagements(id),
            file_path     TEXT NOT NULL,
            artifact_type TEXT,
            description   TEXT,
            source_tool   TEXT,
            created_at    TEXT NOT NULL
        );

        -- Audit log table
        CREATE TABLE IF NOT EXISTS audit_log (
            id            TEXT PRIMARY KEY,
            timestamp     TEXT NOT NULL,
            command       TEXT NOT NULL,
            args          TEXT,  -- JSON object
            engagement_id TEXT,
            result        TEXT,
            details       TEXT
        );

        -- Indexes for findings
        CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
        CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);
        CREATE INDEX IF NOT EXISTS idx_findings_cwe        ON findings(cwe);
        CREATE INDEX IF NOT EXISTS idx_findings_status     ON findings(status);

        -- Indexes for timeline_events
        CREATE INDEX IF NOT EXISTS idx_timeline_engagement ON timeline_events(engagement_id);
        CREATE INDEX IF NOT EXISTS idx_timeline_timestamp  ON timeline_events(timestamp);

        -- Indexes for iocs
        CREATE INDEX IF NOT EXISTS idx_iocs_engagement  ON iocs(engagement_id);
        CREATE INDEX IF NOT EXISTS idx_iocs_type_value  ON iocs(ioc_type, value);

        -- Index for audit_log
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
    """)


# Registry of all migrations keyed by version number
MIGRATIONS: dict = {1: _migration_v1}

# The highest version number we know about
LATEST_VERSION: int = max(MIGRATIONS.keys())


def migrate(conn: sqlite3.Connection) -> None:
    """
    Bring the database schema up to LATEST_VERSION.

    - Creates the schema_version table if it does not exist.
    - Runs every pending migration in version order.
    - Records each applied version with an ISO 8601 timestamp.
    - Raises RuntimeError if the database is already at a version newer
      than LATEST_VERSION (forward-migration guard).
    """
    # Ensure the version-tracking table exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version    INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
    """)
    conn.commit()

    current = get_schema_version(conn)

    if current > LATEST_VERSION:
        raise RuntimeError(
            f"Database schema version {current} is newer than the "
            f"maximum supported version {LATEST_VERSION}. "
            "Please upgrade the application."
        )

    for version in sorted(MIGRATIONS.keys()):
        if version <= current:
            continue
        MIGRATIONS[version](conn)
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
            (version, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
