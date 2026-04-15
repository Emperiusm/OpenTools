"""Tests for the CLI query subcommands."""
from __future__ import annotations
from typer.testing import CliRunner
from opentools.chain.cli import app

runner = CliRunner()

def test_query_run_help():
    result = runner.invoke(app, ["query", "run", "--help"])
    assert result.exit_code == 0
    assert "Execute a Cypher query" in result.output or "cypher" in result.output.lower()

def test_query_explain_help():
    result = runner.invoke(app, ["query", "explain", "--help"])
    assert result.exit_code == 0

def test_query_repl_help():
    result = runner.invoke(app, ["query", "repl", "--help"])
    assert result.exit_code == 0

def test_query_preset_help():
    result = runner.invoke(app, ["query", "preset", "--help"])
    assert result.exit_code == 0
    assert "preset" in result.output.lower()
