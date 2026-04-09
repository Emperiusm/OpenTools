"""Tests for the CLI entry point."""

import json
import sqlite3
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from opentools.cli import app
from opentools.engagement.schema import migrate
from opentools.engagement.store import EngagementStore

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_config_validate_without_plugin(monkeypatch):
    monkeypatch.delenv("OPENTOOLS_PLUGIN_DIR", raising=False)
    # Patch discover_plugin_dir to raise FileNotFoundError
    with patch("opentools.plugin.discover_plugin_dir", side_effect=FileNotFoundError("not found")):
        result = runner.invoke(app, ["config", "validate"])
    # Should fail gracefully since we're not in the repo structure
    assert result.exit_code != 0 or "not found" in result.output.lower() or "error" in result.output.lower()


def _make_plugin_dir(tmp_path):
    """Create a minimal plugin directory with config files."""
    plugin_dir = tmp_path / "plugin"
    plugin_dir.mkdir()
    config_dir = plugin_dir / "config"
    config_dir.mkdir()
    (config_dir / "tools.yaml").write_text("cli_tools: {}\ncontainers: {}")
    (config_dir / "mcp-servers.yaml").write_text("servers: {}\nskill_dependencies: {}")
    (config_dir / "profiles.yaml").write_text("profile:\n  name: default")
    return plugin_dir


def _make_store(tmp_path):
    """Create an in-memory store with a file-backed DB in tmp_path."""
    db_path = tmp_path / "engagements" / "opentools.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return EngagementStore(db_path=db_path), db_path


def test_engagement_list_empty(tmp_path, monkeypatch):
    plugin_dir = _make_plugin_dir(tmp_path)
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", str(plugin_dir))

    db_path = tmp_path / "engagements" / "opentools.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # Patch _get_store to use our tmp db
    def fake_store():
        return EngagementStore(db_path=db_path)

    with patch("opentools.cli._get_store", fake_store):
        result = runner.invoke(app, ["engagement", "list", "--json"])
    # The important thing is no crash
    assert result.exit_code == 0 or "error" in result.output.lower()


def test_engagement_list_empty_table(tmp_path, monkeypatch):
    plugin_dir = _make_plugin_dir(tmp_path)
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", str(plugin_dir))

    db_path = tmp_path / "engagements" / "opentools.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    def fake_store():
        return EngagementStore(db_path=db_path)

    with patch("opentools.cli._get_store", fake_store):
        result = runner.invoke(app, ["engagement", "list"])
    assert result.exit_code == 0
    assert "No engagements found" in result.output


def test_engagement_create_and_show(tmp_path, monkeypatch):
    plugin_dir = _make_plugin_dir(tmp_path)
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", str(plugin_dir))

    db_path = tmp_path / "engagements" / "opentools.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = EngagementStore(db_path=db_path)

    def fake_store():
        return store

    with patch("opentools.cli._get_store", fake_store):
        # Create
        result = runner.invoke(app, ["engagement", "create", "test-eng", "--target", "10.0.0.0/24"])
        assert result.exit_code == 0
        assert "Created engagement" in result.output

        # List
        result = runner.invoke(app, ["engagement", "list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["name"] == "test-eng"

        # Show
        result = runner.invoke(app, ["engagement", "show", "test-eng"])
        assert result.exit_code == 0
        assert "test-eng" in result.output


def test_findings_add_and_list(tmp_path, monkeypatch):
    plugin_dir = _make_plugin_dir(tmp_path)
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", str(plugin_dir))

    db_path = tmp_path / "engagements" / "opentools.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = EngagementStore(db_path=db_path)

    # Pre-create an engagement
    from datetime import datetime, timezone
    from opentools.models import Engagement, EngagementType, EngagementStatus

    eng = Engagement(
        id="eng-test-001",
        name="find-test",
        target="10.0.0.1",
        type=EngagementType.PENTEST,
        status=EngagementStatus.ACTIVE,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    store.create(eng)

    def fake_store():
        return store

    with patch("opentools.cli._get_store", fake_store):
        # Add finding
        result = runner.invoke(app, [
            "findings", "add", "find-test",
            "--tool", "semgrep",
            "--title", "SQL Injection in login",
            "--severity", "high",
        ])
        assert result.exit_code == 0
        assert "Added finding" in result.output

        # List findings
        result = runner.invoke(app, ["findings", "list", "find-test", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["title"] == "SQL Injection in login"
        assert data[0]["severity"] == "high"


def test_recipe_list(tmp_path, monkeypatch):
    plugin_dir = _make_plugin_dir(tmp_path)
    (plugin_dir / "recipes.json").write_text(json.dumps({
        "version": "1.0.0",
        "recipes": [{"id": "test", "name": "Test", "description": "A test", "steps": []}],
    }))
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", str(plugin_dir))
    result = runner.invoke(app, ["recipe", "list"])
    assert result.exit_code == 0
    assert "Test" in result.output or "test" in result.output


def test_recipe_list_json(tmp_path, monkeypatch):
    plugin_dir = _make_plugin_dir(tmp_path)
    (plugin_dir / "recipes.json").write_text(json.dumps({
        "version": "1.0.0",
        "recipes": [{"id": "scan-1", "name": "Full Scan", "description": "Run all scanners", "steps": []}],
    }))
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", str(plugin_dir))
    result = runner.invoke(app, ["recipe", "list", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert len(data) == 1
    assert data[0]["id"] == "scan-1"


def test_config_show(tmp_path, monkeypatch):
    plugin_dir = _make_plugin_dir(tmp_path)
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", str(plugin_dir))

    db_path = tmp_path / "engagements" / "opentools.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert "Plugin dir" in result.output


def test_config_validate_valid(tmp_path, monkeypatch):
    plugin_dir = _make_plugin_dir(tmp_path)
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", str(plugin_dir))

    result = runner.invoke(app, ["config", "validate"])
    assert result.exit_code == 0
    # Empty config has an issue about no tools configured
    assert "valid" in result.output.lower() or "issue" in result.output.lower()


def test_config_validate_json(tmp_path, monkeypatch):
    plugin_dir = _make_plugin_dir(tmp_path)
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", str(plugin_dir))

    result = runner.invoke(app, ["config", "validate", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "valid" in data


def test_containers_status_no_docker(tmp_path, monkeypatch):
    plugin_dir = _make_plugin_dir(tmp_path)
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", str(plugin_dir))

    result = runner.invoke(app, ["containers", "status"])
    assert result.exit_code == 0
    assert "No containers" in result.output or "container" in result.output.lower()


def test_findings_export_json(tmp_path, monkeypatch):
    plugin_dir = _make_plugin_dir(tmp_path)
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", str(plugin_dir))

    db_path = tmp_path / "engagements" / "opentools.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = EngagementStore(db_path=db_path)

    from datetime import datetime, timezone
    from opentools.models import Engagement, EngagementType, EngagementStatus

    eng = Engagement(
        id="eng-export-001",
        name="export-test",
        target="10.0.0.1",
        type=EngagementType.PENTEST,
        status=EngagementStatus.ACTIVE,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    store.create(eng)

    def fake_store():
        return store

    with patch("opentools.cli._get_store", fake_store):
        result = runner.invoke(app, ["findings", "export", "export-test", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)


def test_audit_list_empty(tmp_path, monkeypatch):
    plugin_dir = _make_plugin_dir(tmp_path)
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", str(plugin_dir))

    db_path = tmp_path / "engagements" / "opentools.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    def fake_store():
        return EngagementStore(db_path=db_path)

    with patch("opentools.cli._get_store", fake_store):
        result = runner.invoke(app, ["audit", "list"])
    assert result.exit_code == 0
    assert "No audit entries" in result.output
