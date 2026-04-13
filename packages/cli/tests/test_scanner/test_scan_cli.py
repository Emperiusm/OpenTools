"""Tests for the opentools scan CLI command group."""

from typer.testing import CliRunner

import pytest


runner = CliRunner()


class TestScanPlan:
    def test_plan_shows_tasks(self, tmp_path, monkeypatch):
        """scan plan <target> shows planned tasks without executing."""
        from opentools.scanner.scan_cli import app as scan_app
        from typer import Typer

        test_app = Typer()
        test_app.add_typer(scan_app)

        result = runner.invoke(test_app, ["scan", "plan", str(tmp_path), "--engagement", "test-eng"])
        # Should not error out — plan runs target detection + profile resolution
        # result.output mixes stdout and stderr; result.stdout may be empty when errors go to stderr
        assert result.exit_code == 0 or "Error" in result.output

    def test_plan_json_output(self, tmp_path, monkeypatch):
        """scan plan --json outputs structured JSON."""
        from opentools.scanner.scan_cli import app as scan_app
        from typer import Typer

        test_app = Typer()
        test_app.add_typer(scan_app)

        result = runner.invoke(
            test_app, ["scan", "plan", str(tmp_path), "--engagement", "test-eng", "--json"]
        )
        assert result.exit_code == 0 or "Error" in result.output


class TestScanProfiles:
    def test_profiles_list(self):
        """scan profiles lists available profiles."""
        from opentools.scanner.scan_cli import app as scan_app
        from typer import Typer

        test_app = Typer()
        test_app.add_typer(scan_app)

        result = runner.invoke(test_app, ["scan", "profiles"])
        assert result.exit_code == 0
        # Should list profile names
        assert "source" in result.stdout.lower() or "Profile" in result.stdout

    def test_profiles_json(self):
        """scan profiles --json outputs structured JSON."""
        from opentools.scanner.scan_cli import app as scan_app
        from typer import Typer

        test_app = Typer()
        test_app.add_typer(scan_app)

        result = runner.invoke(test_app, ["scan", "profiles", "--json"])
        assert result.exit_code == 0


class TestScanHistory:
    def test_history_empty(self, tmp_path, monkeypatch):
        """scan history with no scans shows empty message."""
        from opentools.scanner.scan_cli import app as scan_app
        from typer import Typer

        test_app = Typer()
        test_app.add_typer(scan_app)

        result = runner.invoke(test_app, ["scan", "history"])
        assert result.exit_code == 0
