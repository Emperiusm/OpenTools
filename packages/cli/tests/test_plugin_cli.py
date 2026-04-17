"""Tests for opentools plugin CLI commands."""

import json
import tarfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from typer.testing import CliRunner

runner = CliRunner()

MINIMAL_MANIFEST = """\
name: test-plugin
version: 1.0.0
description: A test plugin
author:
  name: Tester
license: MIT
min_opentools_version: '0.3.0'
tags: []
domain: pentest
provides:
  skills: []
  recipes: []
  containers: []
"""


def make_plugin_dir(base: Path, name: str = "test-plugin", version: str = "1.0.0") -> Path:
    """Create a minimal plugin source directory."""
    d = base / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "opentools-plugin.yaml").write_text(
        f"name: {name}\nversion: {version}\ndescription: T\n"
        f"author:\n  name: t\nlicense: MIT\n"
        f"min_opentools_version: '0.3.0'\ntags: []\ndomain: pentest\n"
        f"provides:\n  skills: []\n  recipes: []\n  containers: []\n"
    )
    return d


@pytest.fixture
def mock_home(tmp_path):
    home = tmp_path / ".opentools"
    (home / "plugins").mkdir(parents=True)
    (home / "staging").mkdir()
    (home / "cache").mkdir()
    (home / "registry-cache").mkdir()
    return home


class TestPluginList:
    def test_list_empty(self, mock_home):
        from opentools.plugin_cli import plugin_app
        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["list"])
        assert result.exit_code == 0
        assert "No plugins installed" in result.stdout

    def test_list_json_empty(self, mock_home):
        from opentools.plugin_cli import plugin_app
        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data == []


class TestPluginSearch:
    def test_search_no_catalog(self, mock_home):
        from opentools.plugin_cli import plugin_app
        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["search", "wifi"])
        assert result.exit_code == 1 or "No catalog" in result.stdout


class TestPluginInfo:
    def test_info_no_catalog(self, mock_home):
        from opentools.plugin_cli import plugin_app
        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["info", "wifi-hacking"])
        assert result.exit_code == 1 or "not found" in result.stdout.lower()


class TestPluginVerify:
    def test_verify_not_installed(self, mock_home):
        from opentools.plugin_cli import plugin_app
        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["verify", "nonexistent"])
        assert result.exit_code == 1 or "not installed" in result.stdout.lower()


class TestPluginRollback:
    def test_rollback_not_installed(self, mock_home):
        from opentools.plugin_cli import plugin_app
        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["rollback", "nonexistent"])
        assert result.exit_code == 1 or "not installed" in result.stdout.lower()


class TestPluginInit:
    def test_init_creates_scaffold(self, tmp_path):
        import os
        os.chdir(str(tmp_path))
        from opentools.plugin_cli import plugin_app
        result = runner.invoke(plugin_app, ["init", "my-scanner"])
        assert result.exit_code == 0
        assert "my-scanner" in result.stdout
        assert (tmp_path / "my-scanner" / "opentools-plugin.yaml").exists()


class TestPluginValidate:
    def test_validate_valid_plugin(self, tmp_path):
        from opentools.plugin_cli import plugin_app
        manifest = tmp_path / "opentools-plugin.yaml"
        manifest.write_text(
            "name: test\nversion: 1.0.0\ndescription: T\n"
            "author:\n  name: t\nlicense: MIT\n"
            "min_opentools_version: '0.3.0'\ntags: []\ndomain: pentest\n"
            "provides:\n  skills: []\n  recipes: []\n  containers: []\n"
        )
        result = runner.invoke(plugin_app, ["validate", str(tmp_path)])
        assert result.exit_code == 0
        assert "valid" in result.stdout.lower()


class TestPluginFreeze:
    def test_freeze_empty(self, mock_home):
        from opentools.plugin_cli import plugin_app
        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["freeze"])
        assert result.exit_code == 0
        assert "generated_at" in result.stdout or "plugins" in result.stdout


class TestPluginPrune:
    def test_prune_no_plugins(self, mock_home):
        from opentools.plugin_cli import plugin_app
        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["prune"])
        assert result.exit_code == 0
        assert "0" in result.stdout


# ---------------------------------------------------------------------------
# New wired-command tests
# ---------------------------------------------------------------------------

class TestInstallFromLocalPath:
    def test_install_from_local_path(self, mock_home, tmp_path):
        """Install a minimal local plugin and verify DB + filesystem."""
        from opentools.plugin_cli import plugin_app

        src = make_plugin_dir(tmp_path)
        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["install", "--yes", str(src)])

        assert result.exit_code == 0, result.output
        assert "Installed" in result.output

        # Filesystem check
        plugin_dir = mock_home / "plugins" / "test-plugin"
        assert plugin_dir.exists()
        assert (plugin_dir / ".active").read_text().strip() == "1.0.0"

        # DB check
        from opentools_plugin_core.index import PluginIndex
        idx = PluginIndex(mock_home / "plugins.db")
        p = idx.get("test-plugin")
        assert p is not None
        assert p.version == "1.0.0"

    def test_install_missing_source(self, mock_home):
        """Error when path does not exist."""
        from opentools.plugin_cli import plugin_app

        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["install", "./no-such-plugin"])

        assert result.exit_code != 0


class TestUpNoCompose:
    def test_up_no_compose(self, mock_home, tmp_path):
        """Error message when plugin has no compose file."""
        from opentools.plugin_cli import plugin_app

        # Install first so the plugin exists
        src = make_plugin_dir(tmp_path)
        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            runner.invoke(plugin_app, ["install", "--yes", str(src)])
            result = runner.invoke(plugin_app, ["up", "test-plugin"])

        assert result.exit_code != 0
        # Error message should mention no compose / no containers
        combined = result.output + (result.stderr if hasattr(result, "stderr") else "")
        assert "compose" in combined.lower() or "container" in combined.lower()


class TestLinkUnlink:
    def test_link_local_plugin(self, mock_home, tmp_path):
        """Link a local plugin dir and verify .active and DB entry."""
        from opentools.plugin_cli import plugin_app

        src = make_plugin_dir(tmp_path)
        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["link", str(src)])

        assert result.exit_code == 0, result.output
        assert "Linked" in result.output

        plugin_dir = mock_home / "plugins" / "test-plugin"
        assert (plugin_dir / ".active").read_text().strip() == "1.0.0"

        from opentools_plugin_core.index import PluginIndex
        idx = PluginIndex(mock_home / "plugins.db")
        p = idx.get("test-plugin")
        assert p is not None
        assert p.mode.value == "linked"

    def test_unlink_linked_plugin(self, mock_home, tmp_path):
        """Link then unlink; verify plugin dir removed from DB."""
        from opentools.plugin_cli import plugin_app

        src = make_plugin_dir(tmp_path)
        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            runner.invoke(plugin_app, ["link", str(src)])
            result = runner.invoke(plugin_app, ["unlink", "test-plugin"])

        assert result.exit_code == 0, result.output
        assert "Unlinked" in result.output

        from opentools_plugin_core.index import PluginIndex
        idx = PluginIndex(mock_home / "plugins.db")
        assert idx.get("test-plugin") is None

    def test_unlink_non_linked_fails(self, mock_home, tmp_path):
        """Trying to unlink a registry-mode plugin should error."""
        from opentools.plugin_cli import plugin_app

        src = make_plugin_dir(tmp_path)
        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            runner.invoke(plugin_app, ["install", "--yes", str(src)])
            result = runner.invoke(plugin_app, ["unlink", "test-plugin"])

        assert result.exit_code != 0


class TestExportImport:
    def test_export_installed_plugin(self, mock_home, tmp_path):
        """Install locally, export, verify archive exists."""
        from opentools.plugin_cli import plugin_app

        src = make_plugin_dir(tmp_path)
        archive_path = tmp_path / "test-plugin-1.0.0.otp"

        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            runner.invoke(plugin_app, ["install", "--yes", str(src)])
            result = runner.invoke(
                plugin_app, ["export", "test-plugin", "--output", str(archive_path)]
            )

        assert result.exit_code == 0, result.output
        assert "Exported" in result.output
        assert archive_path.exists()
        assert archive_path.stat().st_size > 0

        # Verify it's a valid gzipped tar
        with tarfile.open(str(archive_path), "r:gz") as tar:
            names = tar.getnames()
        assert any("manifest.yaml" in n for n in names)

    def test_import_archive(self, mock_home, tmp_path):
        """Export + import round trip."""
        from opentools.plugin_cli import plugin_app

        src = make_plugin_dir(tmp_path, name="round-trip", version="2.0.0")
        archive_path = tmp_path / "round-trip-2.0.0.otp"

        # Use a separate home for import to avoid "already installed" conflicts
        import_home = tmp_path / "import_home"
        (import_home / "plugins").mkdir(parents=True)
        (import_home / "staging").mkdir()
        (import_home / "cache").mkdir()
        (import_home / "registry-cache").mkdir()

        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            runner.invoke(plugin_app, ["install", "--yes", str(src)])
            runner.invoke(
                plugin_app, ["export", "round-trip", "--output", str(archive_path)]
            )

        assert archive_path.exists()

        with patch("opentools.plugin_cli._opentools_home", return_value=import_home):
            result = runner.invoke(plugin_app, ["import", "--yes", str(archive_path)])

        assert result.exit_code == 0, result.output
        assert "Imported" in result.output

        from opentools_plugin_core.index import PluginIndex
        idx = PluginIndex(import_home / "plugins.db")
        p = idx.get("round-trip")
        assert p is not None
        assert p.version == "2.0.0"


class TestSyncWithLockfile:
    def test_sync_with_lockfile_already_installed(self, mock_home, tmp_path):
        """Sync with lockfile where plugin already at correct version is a no-op."""
        from opentools.plugin_cli import plugin_app
        from opentools_plugin_core.index import PluginIndex
        from opentools_plugin_core.models import InstalledPlugin, InstallMode
        from datetime import datetime, timezone

        # Pre-register a plugin
        idx = PluginIndex(mock_home / "plugins.db")
        idx.register(InstalledPlugin(
            name="already-installed",
            version="1.0.0",
            repo="",
            registry="local",
            installed_at=datetime.now(timezone.utc).isoformat(),
            signature_verified=False,
            mode=InstallMode.REGISTRY,
        ))

        # Write a lockfile referencing the same plugin+version with no repo
        lockfile_path = tmp_path / "opentools.lock"
        lockfile_path.write_text(
            "generated_at: '2026-01-01T00:00:00+00:00'\n"
            "opentools_version: '0.3.0'\n"
            "plugins:\n"
            "  already-installed:\n"
            "    version: '1.0.0'\n"
            "    registry: local\n"
            "    repo: ''\n"
            "    ref: v1.0.0\n"
            "    sha256: ''\n"
        )

        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(
                plugin_app, ["sync", "--lockfile", str(lockfile_path), "--yes"]
            )

        assert result.exit_code == 0, result.output
        assert "Sync complete" in result.output
