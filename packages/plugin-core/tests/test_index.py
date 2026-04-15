"""Tests for SQLite plugin index."""

import sqlite3
from datetime import datetime, timezone

import pytest


class TestPluginIndex:
    def test_create_tables(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex

        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        conn = sqlite3.connect(str(tmp_opentools_home / "plugins.db"))
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()
        assert "installed_plugins" in tables
        assert "plugin_integrity" in tables

    def test_register_and_get(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex
        from opentools_plugin_core.models import InstalledPlugin

        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        plugin = InstalledPlugin(
            name="test-plugin", version="1.0.0",
            repo="https://github.com/x/y", registry="official",
            installed_at=datetime.now(timezone.utc).isoformat(),
            signature_verified=True,
        )
        idx.register(plugin)
        got = idx.get("test-plugin")
        assert got is not None
        assert got.name == "test-plugin"
        assert got.version == "1.0.0"

    def test_get_nonexistent_returns_none(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex
        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        assert idx.get("nope") is None

    def test_list_all(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex
        from opentools_plugin_core.models import InstalledPlugin

        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        for name in ("alpha", "beta", "gamma"):
            idx.register(InstalledPlugin(
                name=name, version="1.0.0", repo="https://x.com",
                registry="official",
                installed_at=datetime.now(timezone.utc).isoformat(),
                signature_verified=True,
            ))
        all_plugins = idx.list_all()
        assert len(all_plugins) == 3

    def test_unregister(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex
        from opentools_plugin_core.models import InstalledPlugin

        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        idx.register(InstalledPlugin(
            name="to-remove", version="1.0.0", repo="https://x.com",
            registry="official",
            installed_at=datetime.now(timezone.utc).isoformat(),
            signature_verified=True,
        ))
        idx.unregister("to-remove")
        assert idx.get("to-remove") is None

    def test_record_and_check_integrity(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex
        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        idx.record_integrity("test-plugin", "skills/SKILL.md", "abcd1234" * 8)
        hashes = idx.get_integrity("test-plugin")
        assert len(hashes) == 1
        assert hashes[0].file_path == "skills/SKILL.md"

    def test_unregister_cascades_integrity(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex
        from opentools_plugin_core.models import InstalledPlugin

        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        idx.register(InstalledPlugin(
            name="cascade-test", version="1.0.0", repo="https://x.com",
            registry="official",
            installed_at=datetime.now(timezone.utc).isoformat(),
            signature_verified=True,
        ))
        idx.record_integrity("cascade-test", "file.txt", "aaaa" * 16)
        idx.unregister("cascade-test")
        assert idx.get_integrity("cascade-test") == []

    def test_update_version(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex
        from opentools_plugin_core.models import InstalledPlugin

        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        idx.register(InstalledPlugin(
            name="updatable", version="1.0.0", repo="https://x.com",
            registry="official",
            installed_at=datetime.now(timezone.utc).isoformat(),
            signature_verified=True,
        ))
        idx.update_version("updatable", "2.0.0")
        got = idx.get("updatable")
        assert got.version == "2.0.0"
