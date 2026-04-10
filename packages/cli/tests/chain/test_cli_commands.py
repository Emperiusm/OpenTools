from datetime import datetime, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opentools.chain.cli import app
from opentools.chain.config import ChainConfig
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine, get_default_rules
from opentools.engagement.store import EngagementStore
from opentools.models import Engagement, EngagementStatus, EngagementType, Finding, FindingStatus, Severity


@pytest.fixture
def cli_runner():
    return CliRunner()


@pytest.fixture
def populated_db(tmp_path, monkeypatch):
    """Seed a DB in a tmp path and make the CLI use it via monkeypatched path."""
    db_path = tmp_path / "engagements.db"
    engagement_store = EngagementStore(db_path=db_path)

    now = datetime.now(timezone.utc)
    engagement_store.create(Engagement(
        id="eng_cli", name="cli test", target="x",
        type=EngagementType.PENTEST, status=EngagementStatus.ACTIVE,
        created_at=now, updated_at=now,
    ))

    f1 = Finding(
        id="cli_a", engagement_id="eng_cli", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title="A", description="ssh on 10.0.0.5", created_at=now,
    )
    f2 = Finding(
        id="cli_b", engagement_id="eng_cli", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title="B", description="http on 10.0.0.5", created_at=now,
    )
    engagement_store.add_finding(f1)
    engagement_store.add_finding(f2)

    from opentools.chain.store_extensions import ChainStore
    chain_store = ChainStore(engagement_store._conn)
    pipeline = ExtractionPipeline(store=chain_store, config=ChainConfig())
    pipeline.extract_for_finding(f1)
    pipeline.extract_for_finding(f2)
    engine = LinkerEngine(store=chain_store, config=ChainConfig(), rules=get_default_rules(ChainConfig()))
    ctx = engine.make_context(user_id=None)
    engine.link_finding(f1.id, user_id=None, context=ctx)
    engine.link_finding(f2.id, user_id=None, context=ctx)

    # Monkeypatch the CLI's default db path
    from opentools.chain import cli as chain_cli
    monkeypatch.setattr(chain_cli, "_default_db_path", lambda: db_path)
    # Close our store so the CLI can open it fresh
    engagement_store._conn.close()
    return db_path


def test_cli_status_runs(cli_runner, populated_db):
    result = cli_runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "Chain Status" in result.stdout or "entities" in result.stdout.lower() or "Entities" in result.stdout


def test_cli_entities_runs(cli_runner, populated_db):
    result = cli_runner.invoke(app, ["entities"])
    assert result.exit_code == 0


def test_cli_entities_filter_by_type(cli_runner, populated_db):
    result = cli_runner.invoke(app, ["entities", "--type", "ip"])
    assert result.exit_code == 0


def test_cli_path_runs(cli_runner, populated_db):
    result = cli_runner.invoke(app, ["path", "cli_a", "cli_b"])
    assert result.exit_code == 0


def test_cli_query_mitre_coverage_runs(cli_runner, populated_db):
    result = cli_runner.invoke(app, ["query", "mitre-coverage", "--engagement", "eng_cli"])
    assert result.exit_code == 0


def test_cli_query_unknown_preset_fails(cli_runner, populated_db):
    result = cli_runner.invoke(app, ["query", "not-a-real-preset", "--engagement", "eng_cli"])
    assert result.exit_code != 0


def test_cli_export_runs(cli_runner, populated_db, tmp_path):
    output = tmp_path / "cli_export.json"
    result = cli_runner.invoke(app, ["export", "--engagement", "eng_cli", "--output", str(output)])
    assert result.exit_code == 0
    assert output.exists()
