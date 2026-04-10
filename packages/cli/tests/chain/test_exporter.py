from datetime import datetime, timezone
from pathlib import Path

import orjson
import pytest

from opentools.chain.config import ChainConfig
from opentools.chain.exporter import (
    ExportResult,
    ImportResult,
    SCHEMA_VERSION,
    export_chain,
    import_chain,
)
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.models import Finding, FindingStatus, Severity


def _seed(engagement_store, chain_store):
    f = Finding(
        id="exp_a", engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title="t", description="ssh on 10.0.0.5",
        created_at=datetime.now(timezone.utc),
    )
    engagement_store.add_finding(f)
    ExtractionPipeline(store=chain_store, config=ChainConfig()).extract_for_finding(f)
    return f


def test_export_writes_schema_versioned_file(engagement_store_and_chain, tmp_path):
    engagement_store, chain_store, _ = engagement_store_and_chain
    _seed(engagement_store, chain_store)
    output = tmp_path / "export.json"
    result = export_chain(store=chain_store, output_path=output)
    assert isinstance(result, ExportResult)
    assert output.exists()
    data = orjson.loads(output.read_bytes())
    assert data["schema_version"] == SCHEMA_VERSION
    assert result.entities_exported >= 1
    assert result.mentions_exported >= 1


def test_export_filtered_by_engagement(engagement_store_and_chain, tmp_path):
    engagement_store, chain_store, _ = engagement_store_and_chain
    _seed(engagement_store, chain_store)
    output = tmp_path / "export_scoped.json"
    result = export_chain(store=chain_store, engagement_id="eng_test", output_path=output)
    assert result.entities_exported >= 1


def test_export_nonexistent_engagement_empty(engagement_store_and_chain, tmp_path):
    engagement_store, chain_store, _ = engagement_store_and_chain
    output = tmp_path / "empty.json"
    result = export_chain(store=chain_store, engagement_id="eng_nonexistent", output_path=output)
    assert result.entities_exported == 0
    data = orjson.loads(output.read_bytes())
    assert data["entities"] == []


def test_import_skip_strategy_preserves_existing(engagement_store_and_chain, tmp_path):
    engagement_store, chain_store, _ = engagement_store_and_chain
    _seed(engagement_store, chain_store)
    output = tmp_path / "roundtrip.json"
    export_chain(store=chain_store, output_path=output)

    # Re-import with skip strategy: no new entities added (all collide)
    result = import_chain(store=chain_store, input_path=output, merge_strategy="skip")
    assert isinstance(result, ImportResult)
    assert result.collisions >= 1


def test_import_schema_version_mismatch_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_bytes(orjson.dumps({
        "schema_version": "9.9",
        "entities": [], "mentions": [], "relations": [], "linker_runs": [],
    }))
    # Use a fresh chain store with no fixture
    import sqlite3
    from opentools.chain.store_extensions import ChainStore
    from opentools.engagement.schema import migrate

    db = tmp_path / "bad.db"
    conn = sqlite3.connect(str(db))
    migrate(conn)
    store = ChainStore(conn)

    with pytest.raises(ValueError, match="schema version"):
        import_chain(store=store, input_path=bad)
    conn.close()
