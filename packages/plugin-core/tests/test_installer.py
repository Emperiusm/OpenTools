"""Tests for transactional install pipeline."""

import os
from pathlib import Path
import pytest


@pytest.fixture
def plugin_home(tmp_opentools_home):
    return tmp_opentools_home


@pytest.fixture
def sample_plugin_source(tmp_path):
    src = tmp_path / "source" / "test-plugin"
    src.mkdir(parents=True)
    manifest = src / "opentools-plugin.yaml"
    manifest.write_text(
        "name: test-plugin\n"
        "version: 1.0.0\n"
        "description: A test plugin\n"
        "author:\n  name: tester\n"
        "license: MIT\n"
        "min_opentools_version: '0.3.0'\n"
        "tags: [test]\n"
        "domain: pentest\n"
        "provides:\n"
        "  skills:\n"
        "    - path: skills/test-skill/SKILL.md\n"
        "  recipes: []\n"
        "  containers: []\n"
    )
    skill_dir = src / "skills" / "test-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# Test Skill\nDo something safe.")
    return src


class TestStaging:
    def test_stage_creates_version_dir(self, plugin_home, sample_plugin_source):
        from opentools_plugin_core.installer import stage_plugin
        staged = stage_plugin(sample_plugin_source, plugin_home)
        assert staged.exists()
        assert (staged / "manifest.yaml").exists()
        assert (staged / "skills" / "test-skill" / "SKILL.md").exists()

    def test_stage_in_staging_dir(self, plugin_home, sample_plugin_source):
        from opentools_plugin_core.installer import stage_plugin
        staged = stage_plugin(sample_plugin_source, plugin_home)
        assert "staging" in str(staged)


class TestPromote:
    def test_promote_moves_to_plugins(self, plugin_home, sample_plugin_source):
        from opentools_plugin_core.installer import stage_plugin, promote_plugin
        staged = stage_plugin(sample_plugin_source, plugin_home)
        final = promote_plugin(staged, plugin_home, "test-plugin", "1.0.0")
        assert final.exists()
        assert final == plugin_home / "plugins" / "test-plugin" / "1.0.0"

    def test_promote_writes_active_pointer(self, plugin_home, sample_plugin_source):
        from opentools_plugin_core.installer import stage_plugin, promote_plugin
        staged = stage_plugin(sample_plugin_source, plugin_home)
        promote_plugin(staged, plugin_home, "test-plugin", "1.0.0")
        active_file = plugin_home / "plugins" / "test-plugin" / ".active"
        assert active_file.exists()
        assert active_file.read_text().strip() == "1.0.0"


class TestCleanup:
    def test_cleanup_removes_staging(self, plugin_home, sample_plugin_source):
        from opentools_plugin_core.installer import stage_plugin, cleanup_staging
        staged = stage_plugin(sample_plugin_source, plugin_home)
        assert staged.exists()
        cleanup_staging(staged)
        assert not staged.exists()

    def test_cleanup_stale_staging(self, plugin_home):
        from opentools_plugin_core.installer import cleanup_stale_staging
        stale = plugin_home / "staging" / "orphan-plugin" / "0.1.0"
        stale.mkdir(parents=True)
        (stale / "marker.txt").write_text("leftover")
        cleaned = cleanup_stale_staging(plugin_home)
        assert cleaned >= 1
        assert not stale.exists()


class TestActivePointer:
    def test_read_active_version(self, plugin_home):
        from opentools_plugin_core.installer import read_active_version
        plugin_dir = plugin_home / "plugins" / "my-plugin"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / ".active").write_text("2.0.0")
        assert read_active_version(plugin_dir) == "2.0.0"

    def test_read_active_missing_returns_none(self, plugin_home):
        from opentools_plugin_core.installer import read_active_version
        plugin_dir = plugin_home / "plugins" / "no-plugin"
        plugin_dir.mkdir(parents=True)
        assert read_active_version(plugin_dir) is None
