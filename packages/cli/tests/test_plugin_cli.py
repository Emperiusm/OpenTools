"""Tests for opentools plugin CLI commands."""

import json
from unittest.mock import patch, MagicMock
import pytest
from typer.testing import CliRunner

runner = CliRunner()


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
