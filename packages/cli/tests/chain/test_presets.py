from datetime import datetime, timezone

import pytest

from opentools.chain.config import ChainConfig
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine, get_default_rules
from opentools.chain.query.graph_cache import GraphCache
from opentools.chain.query.presets import (
    MitreCoverageResult,
    crown_jewel,
    external_to_internal,
    lateral_movement,
    list_presets,
    mitre_coverage,
    priv_esc_chains,
    register_query_preset,
)
from opentools.models import Finding, FindingStatus, Severity


async def _seed(engagement_store, chain_store, findings_data):
    """Seed findings, extract, link."""
    for f in findings_data:
        engagement_store.add_finding(f)
    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=chain_store, config=cfg)
    for f in findings_data:
        await pipeline.extract_for_finding(f)
    engine = LinkerEngine(
        store=chain_store, config=cfg, rules=get_default_rules(cfg),
    )
    ctx = await engine.make_context(user_id=None)
    for f in findings_data:
        await engine.link_finding(f.id, user_id=None, context=ctx)


def _finding(id_: str, **kwargs) -> Finding:
    defaults = dict(
        id=id_, engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title=f"F {id_}", description="",
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def test_list_presets_has_five_builtins():
    presets = list_presets()
    for name in ["lateral-movement", "priv-esc-chains", "external-to-internal", "crown-jewel", "mitre-coverage"]:
        assert name in presets


def test_register_query_preset_adds_to_list():
    def my_preset(engagement_id: str) -> list:
        return []

    register_query_preset("my-test-preset", my_preset, help="test preset")
    presets = list_presets()
    assert "my-test-preset" in presets
    assert presets["my-test-preset"]["help"] == "test preset"


@pytest.mark.asyncio
async def test_lateral_movement_runs_without_error(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    findings = [
        _finding("lm_a", description="SSH on 10.0.0.5"),
        _finding("lm_b", description="HTTP on 10.0.0.5"),
    ]
    await _seed(engagement_store, chain_store, findings)

    cache = GraphCache(store=chain_store, maxsize=4)
    results = await lateral_movement(
        "eng_test", cache=cache, store=chain_store, config=ChainConfig(),
    )
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_priv_esc_chains_runs(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    findings = [
        _finding("pe_a", severity=Severity.LOW, description="SSH on 10.0.0.5"),
        _finding("pe_b", severity=Severity.HIGH, description="HTTP on 10.0.0.5"),
    ]
    await _seed(engagement_store, chain_store, findings)

    cache = GraphCache(store=chain_store, maxsize=4)
    results = await priv_esc_chains(
        "eng_test", cache=cache, store=chain_store, config=ChainConfig(),
    )
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_external_to_internal_runs(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    findings = [
        _finding("ei_a", description="public 8.8.8.8 via HTTPS"),
        _finding("ei_b", description="internal 10.0.0.5 via SSH"),
    ]
    await _seed(engagement_store, chain_store, findings)

    cache = GraphCache(store=chain_store, maxsize=4)
    results = await external_to_internal(
        "eng_test", cache=cache, store=chain_store, config=ChainConfig(),
    )
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_crown_jewel_runs(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    findings = [_finding("cj_a", description="on 10.0.0.5")]
    await _seed(engagement_store, chain_store, findings)

    cache = GraphCache(store=chain_store, maxsize=4)
    results = await crown_jewel(
        "eng_test", "ip:10.0.0.5",
        cache=cache, store=chain_store, config=ChainConfig(),
    )
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_mitre_coverage_basic(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    f = _finding("mc_a", description="uses T1566 for initial access and T1059 for execution")
    await _seed(engagement_store, chain_store, [f])

    result = await mitre_coverage("eng_test", store=chain_store)
    assert isinstance(result, MitreCoverageResult)
    assert result.engagement_id == "eng_test"
    assert "TA0001" in result.tactics_present  # T1566 → Initial Access
    assert "TA0002" in result.tactics_present  # T1059 → Execution


@pytest.mark.asyncio
async def test_mitre_coverage_empty_engagement(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    f = _finding("mc_e", description="no techniques here")
    await _seed(engagement_store, chain_store, [f])

    result = await mitre_coverage("eng_test", store=chain_store)
    assert result.tactics_present == []
    assert len(result.tactics_missing) > 0
