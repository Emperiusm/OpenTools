from datetime import datetime, timezone

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
from opentools.chain.extractors.pipeline import AsyncExtractionPipeline
from opentools.models import Finding, FindingStatus, Severity

pytestmark = pytest.mark.asyncio


async def _seed(engagement_store, chain_store):
    f = Finding(
        id="exp_a", engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title="t", description="ssh on 10.0.0.5",
        created_at=datetime.now(timezone.utc),
    )
    engagement_store.add_finding(f)
    pipeline = AsyncExtractionPipeline(store=chain_store, config=ChainConfig())
    await pipeline.extract_for_finding(f)
    return f


async def test_export_writes_schema_versioned_file(async_chain_stores, tmp_path):
    engagement_store, chain_store, _ = async_chain_stores
    await _seed(engagement_store, chain_store)
    output = tmp_path / "export.json"
    result = await export_chain(store=chain_store, output_path=output)
    assert isinstance(result, ExportResult)
    assert output.exists()
    data = orjson.loads(output.read_bytes())
    assert data["schema_version"] == SCHEMA_VERSION
    assert result.entities_exported >= 1
    assert result.mentions_exported >= 1


async def test_export_filtered_by_engagement(async_chain_stores, tmp_path):
    engagement_store, chain_store, _ = async_chain_stores
    await _seed(engagement_store, chain_store)
    output = tmp_path / "export_scoped.json"
    result = await export_chain(
        store=chain_store, engagement_id="eng_test", output_path=output,
    )
    assert result.entities_exported >= 1


async def test_export_nonexistent_engagement_empty(async_chain_stores, tmp_path):
    engagement_store, chain_store, _ = async_chain_stores
    output = tmp_path / "empty.json"
    result = await export_chain(
        store=chain_store, engagement_id="eng_nonexistent", output_path=output,
    )
    assert result.entities_exported == 0
    data = orjson.loads(output.read_bytes())
    assert data["entities"] == []


async def test_import_skip_strategy_preserves_existing(async_chain_stores, tmp_path):
    engagement_store, chain_store, _ = async_chain_stores
    await _seed(engagement_store, chain_store)
    output = tmp_path / "roundtrip.json"
    await export_chain(store=chain_store, output_path=output)

    # Re-import with skip strategy: no new entities added (all collide)
    result = await import_chain(
        store=chain_store, input_path=output, merge_strategy="skip",
    )
    assert isinstance(result, ImportResult)
    assert result.collisions >= 1


async def test_import_schema_version_mismatch_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_bytes(orjson.dumps({
        "schema_version": "9.9",
        "entities": [], "mentions": [], "relations": [], "linker_runs": [],
    }))
    # Use a fresh async chain store with no fixture
    from opentools.chain.stores.sqlite_async import AsyncChainStore

    store = AsyncChainStore(db_path=tmp_path / "bad.db")
    await store.initialize()
    try:
        with pytest.raises(ValueError, match="schema version"):
            await import_chain(store=store, input_path=bad)
    finally:
        await store.close()
