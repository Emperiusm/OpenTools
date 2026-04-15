"""Tests for update and rollback logic."""

from pathlib import Path
import pytest


@pytest.fixture
def installed_plugin(tmp_opentools_home):
    plugin_dir = tmp_opentools_home / "plugins" / "test-plugin"
    v1 = plugin_dir / "1.0.0"
    v1.mkdir(parents=True)
    (v1 / "manifest.yaml").write_text("name: test-plugin\nversion: 1.0.0")
    v2 = plugin_dir / "2.0.0"
    v2.mkdir(parents=True)
    (v2 / "manifest.yaml").write_text("name: test-plugin\nversion: 2.0.0")
    (plugin_dir / ".active").write_text("2.0.0")
    return plugin_dir


class TestRollback:
    def test_rollback_to_previous(self, installed_plugin):
        from opentools_plugin_core.updater import rollback, get_available_versions
        versions = get_available_versions(installed_plugin)
        assert versions == ["1.0.0", "2.0.0"]
        rollback(installed_plugin, "1.0.0")
        assert (installed_plugin / ".active").read_text().strip() == "1.0.0"

    def test_rollback_nonexistent_version_raises(self, installed_plugin):
        from opentools_plugin_core.updater import rollback
        from opentools_plugin_core.errors import PluginError
        with pytest.raises(PluginError, match="not installed"):
            rollback(installed_plugin, "99.0.0")


class TestVersionListing:
    def test_available_versions_sorted(self, installed_plugin):
        from opentools_plugin_core.updater import get_available_versions
        assert get_available_versions(installed_plugin) == ["1.0.0", "2.0.0"]

    def test_get_active_version(self, installed_plugin):
        from opentools_plugin_core.updater import get_active_version
        assert get_active_version(installed_plugin) == "2.0.0"


class TestPrune:
    def test_prune_keeps_active_and_n_previous(self, tmp_opentools_home):
        from opentools_plugin_core.updater import prune_old_versions
        plugin_dir = tmp_opentools_home / "plugins" / "many-versions"
        for v in ("1.0.0", "2.0.0", "3.0.0", "4.0.0"):
            d = plugin_dir / v
            d.mkdir(parents=True)
            (d / "manifest.yaml").write_text(f"version: {v}")
        (plugin_dir / ".active").write_text("4.0.0")
        removed = prune_old_versions(plugin_dir, keep=1)
        assert len(removed) == 2
        assert (plugin_dir / "4.0.0").exists()
        assert (plugin_dir / "3.0.0").exists()
        assert not (plugin_dir / "1.0.0").exists()
        assert not (plugin_dir / "2.0.0").exists()
