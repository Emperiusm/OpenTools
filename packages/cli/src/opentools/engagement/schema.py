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


# Individual DDL statements keyed by migration version.
#
# Each list entry is a single SQL statement executable via conn.execute()
# (not executescript()). This lets both sync migrate() and async
# migrate_async() wrap the full sequence in an explicit transaction:
# executescript implicitly commits, which would break BEGIN IMMEDIATE,
# so every statement must go through execute() inside the transaction.
#
# SQLite parses a CREATE TRIGGER ... BEGIN ... END as a single statement
# even though the trigger body contains internal semicolons.
MIGRATION_STATEMENTS: dict[int, list[str]] = {
    1: [
        # Engagements table
        """CREATE TABLE IF NOT EXISTS engagements (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            target      TEXT NOT NULL,
            type        TEXT NOT NULL,
            scope       TEXT,
            status      TEXT NOT NULL DEFAULT 'active',
            skills_used TEXT,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        )""",
        # Findings table
        """CREATE TABLE IF NOT EXISTS findings (
            id                 TEXT PRIMARY KEY,
            engagement_id      TEXT NOT NULL REFERENCES engagements(id),
            tool               TEXT NOT NULL,
            corroborated_by    TEXT,
            cwe                TEXT,
            severity           TEXT NOT NULL,
            severity_by_tool   TEXT,
            status             TEXT NOT NULL DEFAULT 'discovered',
            phase              TEXT,
            title              TEXT NOT NULL,
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
        )""",
        # FTS5 virtual table for full-text search over findings
        """CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
            title,
            description,
            evidence,
            remediation,
            content='findings',
            content_rowid='rowid'
        )""",
        # FTS sync trigger: after insert
        """CREATE TRIGGER IF NOT EXISTS findings_ai
        AFTER INSERT ON findings BEGIN
            INSERT INTO findings_fts(rowid, title, description, evidence, remediation)
            VALUES (new.rowid, new.title, new.description, new.evidence, new.remediation);
        END""",
        # FTS sync trigger: after delete
        """CREATE TRIGGER IF NOT EXISTS findings_ad
        AFTER DELETE ON findings BEGIN
            INSERT INTO findings_fts(findings_fts, rowid, title, description, evidence, remediation)
            VALUES ('delete', old.rowid, old.title, old.description, old.evidence, old.remediation);
        END""",
        # FTS sync trigger: after update
        """CREATE TRIGGER IF NOT EXISTS findings_au
        AFTER UPDATE ON findings BEGIN
            INSERT INTO findings_fts(findings_fts, rowid, title, description, evidence, remediation)
            VALUES ('delete', old.rowid, old.title, old.description, old.evidence, old.remediation);
            INSERT INTO findings_fts(rowid, title, description, evidence, remediation)
            VALUES (new.rowid, new.title, new.description, new.evidence, new.remediation);
        END""",
        # Timeline events table
        """CREATE TABLE IF NOT EXISTS timeline_events (
            id            TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL REFERENCES engagements(id),
            timestamp     TEXT NOT NULL,
            source        TEXT,
            event         TEXT NOT NULL,
            details       TEXT,
            confidence    TEXT NOT NULL DEFAULT 'medium',
            finding_id    TEXT REFERENCES findings(id)
        )""",
        # IOCs (Indicators of Compromise) table
        """CREATE TABLE IF NOT EXISTS iocs (
            id                TEXT PRIMARY KEY,
            engagement_id     TEXT NOT NULL REFERENCES engagements(id),
            ioc_type          TEXT NOT NULL,
            value             TEXT NOT NULL,
            context           TEXT,
            first_seen        TEXT,
            last_seen         TEXT,
            source_finding_id TEXT REFERENCES findings(id),
            UNIQUE(engagement_id, ioc_type, value)
        )""",
        # Artifacts table
        """CREATE TABLE IF NOT EXISTS artifacts (
            id            TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL REFERENCES engagements(id),
            file_path     TEXT NOT NULL,
            artifact_type TEXT,
            description   TEXT,
            source_tool   TEXT,
            created_at    TEXT NOT NULL
        )""",
        # Audit log table
        """CREATE TABLE IF NOT EXISTS audit_log (
            id            TEXT PRIMARY KEY,
            timestamp     TEXT NOT NULL,
            command       TEXT NOT NULL,
            args          TEXT,
            engagement_id TEXT,
            result        TEXT,
            details       TEXT
        )""",
        # Indexes for findings
        "CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id)",
        "CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity)",
        "CREATE INDEX IF NOT EXISTS idx_findings_cwe        ON findings(cwe)",
        "CREATE INDEX IF NOT EXISTS idx_findings_status     ON findings(status)",
        # Indexes for timeline_events
        "CREATE INDEX IF NOT EXISTS idx_timeline_engagement ON timeline_events(engagement_id)",
        "CREATE INDEX IF NOT EXISTS idx_timeline_timestamp  ON timeline_events(timestamp)",
        # Indexes for iocs
        "CREATE INDEX IF NOT EXISTS idx_iocs_engagement  ON iocs(engagement_id)",
        "CREATE INDEX IF NOT EXISTS idx_iocs_type_value  ON iocs(ioc_type, value)",
        # Index for audit_log
        "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)",
    ],
    2: [
        """CREATE INDEX IF NOT EXISTS idx_findings_dedup_file
        ON findings(engagement_id, file_path, line_start)
        WHERE deleted_at IS NULL""",
        """CREATE INDEX IF NOT EXISTS idx_findings_dedup_network
        ON findings(engagement_id, cwe)
        WHERE file_path IS NULL AND deleted_at IS NULL""",
    ],
    3: [
        # Entity: canonical form of an extracted thing (host, CVE, user, etc.)
        """CREATE TABLE IF NOT EXISTS entity (
            id              TEXT PRIMARY KEY,
            type            TEXT NOT NULL,
            canonical_value TEXT NOT NULL,
            first_seen_at   TEXT NOT NULL,
            last_seen_at    TEXT NOT NULL,
            mention_count   INTEGER NOT NULL DEFAULT 0,
            user_id         TEXT,
            UNIQUE (type, canonical_value, user_id)
        )""",
        "CREATE INDEX IF NOT EXISTS idx_entity_type_value ON entity(type, canonical_value)",
        "CREATE INDEX IF NOT EXISTS idx_entity_user_type ON entity(user_id, type)",
        # EntityMention: one row per occurrence of an entity in a finding
        """CREATE TABLE IF NOT EXISTS entity_mention (
            id              TEXT PRIMARY KEY,
            entity_id       TEXT NOT NULL REFERENCES entity(id) ON DELETE CASCADE,
            finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            field           TEXT NOT NULL,
            raw_value       TEXT NOT NULL,
            offset_start    INTEGER,
            offset_end      INTEGER,
            extractor       TEXT NOT NULL,
            confidence      REAL NOT NULL,
            created_at      TEXT NOT NULL,
            user_id         TEXT,
            UNIQUE (entity_id, finding_id, field, offset_start)
        )""",
        "CREATE INDEX IF NOT EXISTS idx_em_finding ON entity_mention(finding_id)",
        "CREATE INDEX IF NOT EXISTS idx_em_entity ON entity_mention(entity_id)",
        "CREATE INDEX IF NOT EXISTS idx_em_entity_finding ON entity_mention(entity_id, finding_id)",
        # FindingRelation: directed edge in the attack chain graph
        """CREATE TABLE IF NOT EXISTS finding_relation (
            id                        TEXT PRIMARY KEY,
            source_finding_id         TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            target_finding_id         TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            weight                    REAL NOT NULL,
            weight_model_version      TEXT NOT NULL DEFAULT 'additive_v1',
            status                    TEXT NOT NULL,
            symmetric                 INTEGER NOT NULL DEFAULT 0,
            reasons_json              BLOB NOT NULL,
            llm_rationale             TEXT,
            llm_relation_type         TEXT,
            llm_confidence            REAL,
            confirmed_at_reasons_json BLOB,
            created_at                TEXT NOT NULL,
            updated_at                TEXT NOT NULL,
            user_id                   TEXT,
            UNIQUE (source_finding_id, target_finding_id, user_id)
        )""",
        "CREATE INDEX IF NOT EXISTS idx_fr_source ON finding_relation(source_finding_id)",
        "CREATE INDEX IF NOT EXISTS idx_fr_target ON finding_relation(target_finding_id)",
        "CREATE INDEX IF NOT EXISTS idx_fr_status ON finding_relation(status)",
        # LinkerRun: audit trail for linker invocations
        """CREATE TABLE IF NOT EXISTS linker_run (
            id                       TEXT PRIMARY KEY,
            started_at               TEXT NOT NULL,
            finished_at              TEXT,
            scope                    TEXT NOT NULL,
            scope_id                 TEXT,
            mode                     TEXT NOT NULL,
            llm_provider             TEXT,
            findings_processed       INTEGER NOT NULL DEFAULT 0,
            entities_extracted       INTEGER NOT NULL DEFAULT 0,
            relations_created        INTEGER NOT NULL DEFAULT 0,
            relations_updated        INTEGER NOT NULL DEFAULT 0,
            relations_skipped_sticky INTEGER NOT NULL DEFAULT 0,
            extraction_cache_hits    INTEGER NOT NULL DEFAULT 0,
            extraction_cache_misses  INTEGER NOT NULL DEFAULT 0,
            llm_calls_made           INTEGER NOT NULL DEFAULT 0,
            llm_cache_hits           INTEGER NOT NULL DEFAULT 0,
            llm_cache_misses         INTEGER NOT NULL DEFAULT 0,
            rule_stats_json          BLOB,
            duration_ms              INTEGER,
            error                    TEXT,
            generation               INTEGER NOT NULL DEFAULT 0,
            user_id                  TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_lr_scope ON linker_run(scope, scope_id)",
        "CREATE INDEX IF NOT EXISTS idx_lr_generation ON linker_run(generation DESC)",
        # ExtractionCache: content-addressed cache for LLM entity extraction
        """CREATE TABLE IF NOT EXISTS extraction_cache (
            cache_key       TEXT PRIMARY KEY,
            provider        TEXT NOT NULL,
            model           TEXT NOT NULL,
            schema_version  INTEGER NOT NULL,
            result_json     BLOB NOT NULL,
            created_at      TEXT NOT NULL
        )""",
        # LLMLinkCache: content-addressed cache for LLM link classification
        """CREATE TABLE IF NOT EXISTS llm_link_cache (
            cache_key            TEXT PRIMARY KEY,
            provider             TEXT NOT NULL,
            model                TEXT NOT NULL,
            schema_version       INTEGER NOT NULL,
            classification_json  BLOB NOT NULL,
            created_at           TEXT NOT NULL
        )""",
        # FindingExtractionState: change detection for re-extraction
        """CREATE TABLE IF NOT EXISTS finding_extraction_state (
            finding_id              TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
            extraction_input_hash   TEXT NOT NULL,
            last_extracted_at       TEXT NOT NULL,
            last_extractor_set_json BLOB NOT NULL,
            user_id                 TEXT
        )""",
        # FindingParserOutput: structured parser output for parser-aware extractors
        """CREATE TABLE IF NOT EXISTS finding_parser_output (
            finding_id      TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            parser_name     TEXT NOT NULL,
            data_json       BLOB NOT NULL,
            created_at      TEXT NOT NULL,
            user_id         TEXT,
            PRIMARY KEY (finding_id, parser_name)
        )""",
    ],
    4: [
        # Add status_text to linker_run
        "ALTER TABLE linker_run ADD COLUMN status_text TEXT",
        # Backfill legacy rows
        """UPDATE linker_run
        SET status_text = CASE
            WHEN error IS NOT NULL THEN 'failed'
            WHEN finished_at IS NOT NULL THEN 'done'
            ELSE 'unknown'
        END
        WHERE status_text IS NULL""",
        # Add user_id to cache tables (spec G37)
        "ALTER TABLE extraction_cache ADD COLUMN user_id TEXT",
        "ALTER TABLE llm_link_cache ADD COLUMN user_id TEXT",
    ],
}


def _apply_statements(conn: sqlite3.Connection, version: int) -> None:
    """Execute all DDL statements for a given migration version.

    Uses conn.execute() (not executescript) so the caller can wrap the
    whole migration sequence in an explicit transaction — executescript
    implicitly commits any pending transaction, which would break that.
    """
    for stmt in MIGRATION_STATEMENTS[version]:
        conn.execute(stmt)


def _migration_v1(conn: sqlite3.Connection) -> None:
    """Execute all DDL for schema version 1."""
    _apply_statements(conn, 1)


def _migration_v2(conn: sqlite3.Connection) -> None:
    """Add partial indexes optimized for dedup candidate queries."""
    _apply_statements(conn, 2)


def _migration_v3(conn: sqlite3.Connection) -> None:
    """Add chain data layer tables (Phase 3C.1).

    Creates the knowledge graph tables used for entity extraction, finding
    relations, linker runs, and LLM caches. All tables reference findings(id)
    via ON DELETE CASCADE so chain data cleans up when findings are hard-deleted.
    Soft-deletes via findings.deleted_at do NOT cascade — the chain event
    subscription layer handles that path explicitly.
    """
    _apply_statements(conn, 3)


def _migration_v4(conn: sqlite3.Connection) -> None:
    """Add status_text to linker_run, user_id to cache tables (spec G37)."""
    _apply_statements(conn, 4)


# Registry of all migrations keyed by version number
MIGRATIONS: dict = {1: _migration_v1, 2: _migration_v2, 3: _migration_v3, 4: _migration_v4}

# The highest version number we know about
LATEST_VERSION: int = max(MIGRATIONS.keys())


def migrate(conn: sqlite3.Connection) -> None:
    """Bring the database schema up to LATEST_VERSION.

    Wraps the pending-migration sequence in a BEGIN IMMEDIATE transaction
    so a failure in any step rolls back all DDL applied by that run
    (spec §5.7 A3 fix).
    """
    # Ensure the version-tracking table exists (outside the migration txn)
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

    # Wrap pending migrations in a single transaction so partial
    # failures roll back cleanly (A3 in spec §5.7).
    conn.execute("BEGIN IMMEDIATE")
    try:
        for version in sorted(MIGRATIONS.keys()):
            if version <= current:
                continue
            MIGRATIONS[version](conn)
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (version, datetime.now(timezone.utc).isoformat()),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise


async def migrate_async(conn) -> None:
    """Async sibling of migrate() for aiosqlite connections.

    Runs the same migration sequence as sync migrate() but with
    awaited execute calls. Shares MIGRATION_STATEMENTS so the two
    code paths can never drift.

    Wraps the pending-migration sequence in a transaction for atomicity.
    """
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version    INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
    """)
    await conn.commit()

    async with conn.execute(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version"
    ) as cursor:
        row = await cursor.fetchone()
    current = row[0] if row else 0

    if current > LATEST_VERSION:
        raise RuntimeError(
            f"Database schema version {current} is newer than the "
            f"maximum supported version {LATEST_VERSION}. "
            "Please upgrade the application."
        )

    await conn.execute("BEGIN IMMEDIATE")
    try:
        for version in sorted(MIGRATIONS.keys()):
            if version <= current:
                continue
            for stmt in MIGRATION_STATEMENTS[version]:
                await conn.execute(stmt)
            await conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (version, datetime.now(timezone.utc).isoformat()),
            )
        await conn.execute("COMMIT")
    except Exception:
        await conn.execute("ROLLBACK")
        raise
