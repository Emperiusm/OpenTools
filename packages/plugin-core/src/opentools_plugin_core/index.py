"""SQLite index for tracking installed plugins and file integrity."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from opentools_plugin_core.models import InstalledPlugin, IntegrityRecord

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS installed_plugins (
    name TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    repo TEXT NOT NULL,
    registry TEXT NOT NULL,
    installed_at TEXT NOT NULL,
    signature_verified BOOLEAN NOT NULL,
    last_update_check TEXT,
    mode TEXT NOT NULL DEFAULT 'registry'
);

CREATE TABLE IF NOT EXISTS plugin_integrity (
    plugin_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (plugin_name, file_path)
);

CREATE INDEX IF NOT EXISTS idx_integrity_plugin
    ON plugin_integrity(plugin_name);
"""


class PluginIndex:
    """SQLite-backed index of installed plugins."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def register(self, plugin: InstalledPlugin) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO installed_plugins "
            "(name, version, repo, registry, installed_at, signature_verified, "
            "last_update_check, mode) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (plugin.name, plugin.version, plugin.repo, plugin.registry,
             plugin.installed_at, plugin.signature_verified,
             plugin.last_update_check, plugin.mode.value),
        )
        self._conn.commit()

    def get(self, name: str) -> InstalledPlugin | None:
        row = self._conn.execute(
            "SELECT * FROM installed_plugins WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            return None
        return InstalledPlugin(**dict(row))

    def list_all(self) -> list[InstalledPlugin]:
        rows = self._conn.execute(
            "SELECT * FROM installed_plugins ORDER BY name"
        ).fetchall()
        return [InstalledPlugin(**dict(r)) for r in rows]

    def unregister(self, name: str) -> None:
        self._conn.execute(
            "DELETE FROM plugin_integrity WHERE plugin_name = ?", (name,)
        )
        self._conn.execute(
            "DELETE FROM installed_plugins WHERE name = ?", (name,)
        )
        self._conn.commit()

    def update_version(self, name: str, new_version: str) -> None:
        self._conn.execute(
            "UPDATE installed_plugins SET version = ? WHERE name = ?",
            (new_version, name),
        )
        self._conn.commit()

    def record_integrity(self, plugin_name: str, file_path: str, sha256: str) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO plugin_integrity "
            "(plugin_name, file_path, sha256, recorded_at) VALUES (?, ?, ?, ?)",
            (plugin_name, file_path, sha256,
             datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    def get_integrity(self, plugin_name: str) -> list[IntegrityRecord]:
        rows = self._conn.execute(
            "SELECT * FROM plugin_integrity WHERE plugin_name = ?",
            (plugin_name,),
        ).fetchall()
        return [IntegrityRecord(**dict(r)) for r in rows]
