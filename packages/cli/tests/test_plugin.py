import os
from pathlib import Path
import pytest
from opentools.plugin import discover_plugin_dir


def test_discover_from_env_var(tmp_path, monkeypatch):
    plugin_dir = tmp_path / "my-plugin"
    plugin_dir.mkdir()
    (plugin_dir / "config").mkdir()
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", str(plugin_dir))
    result = discover_plugin_dir()
    assert result == plugin_dir


def test_discover_from_env_var_invalid_path(monkeypatch):
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", "/nonexistent/path")
    with pytest.raises(FileNotFoundError, match="OPENTOOLS_PLUGIN_DIR"):
        discover_plugin_dir()


def test_discover_relative_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENTOOLS_PLUGIN_DIR", raising=False)
    plugin_dir = tmp_path / "plugin"
    plugin_dir.mkdir()
    (plugin_dir / "config").mkdir()
    result = discover_plugin_dir(cli_package_root=tmp_path / "cli")
    assert result == plugin_dir


def test_discover_fails_when_nothing_found(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENTOOLS_PLUGIN_DIR", raising=False)
    with pytest.raises(FileNotFoundError, match="Plugin directory not found"):
        discover_plugin_dir(cli_package_root=tmp_path / "nonexistent")
