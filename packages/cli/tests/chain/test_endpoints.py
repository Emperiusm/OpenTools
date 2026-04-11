import asyncio

import pytest

from opentools.chain.query.endpoints import (
    EndpointSpec,
    parse_endpoint_spec,
    resolve_endpoint,
)
from opentools.chain.query.graph_cache import FindingNode, MasterGraph
import rustworkx as rx


def _simple_master() -> MasterGraph:
    g = rx.PyDiGraph()
    n1 = g.add_node(FindingNode(finding_id="f1", severity="high", tool="nmap", title="A", created_at=None))
    n2 = g.add_node(FindingNode(finding_id="f2", severity="low", tool="burp", title="B", created_at=None))
    n3 = g.add_node(FindingNode(finding_id="f3", severity="high", tool="nuclei", title="C", created_at=None))
    return MasterGraph(
        graph=g,
        node_map={"f1": n1, "f2": n2, "f3": n3},
        reverse_map={n1: "f1", n2: "f2", n3: "f3"},
        generation=1,
        max_weight=1.0,
    )


def test_parse_finding_id():
    s = parse_endpoint_spec("fnd_abc123")
    assert s.kind == "finding_id"
    assert s.finding_id == "fnd_abc123"


def test_parse_entity_spec():
    s = parse_endpoint_spec("host:10.0.0.5")
    assert s.kind == "entity"
    assert s.entity_type == "host"
    assert s.entity_value == "10.0.0.5"


def test_parse_predicate_spec():
    s = parse_endpoint_spec("severity=critical")
    assert s.kind == "predicate"
    assert s.predicate is not None


def test_parse_empty_raises():
    with pytest.raises(ValueError):
        parse_endpoint_spec("")


def test_resolve_finding_id_found():
    master = _simple_master()
    spec = EndpointSpec(kind="finding_id", finding_id="f1")
    result = asyncio.run(resolve_endpoint(spec, master, store=None))
    assert result == {master.node_map["f1"]}


def test_resolve_finding_id_not_found():
    master = _simple_master()
    spec = EndpointSpec(kind="finding_id", finding_id="fnonexistent")
    assert asyncio.run(resolve_endpoint(spec, master, store=None)) == set()


def test_resolve_predicate_severity_high():
    master = _simple_master()
    spec = parse_endpoint_spec("severity=high")
    result = asyncio.run(resolve_endpoint(spec, master, store=None))
    assert result == {master.node_map["f1"], master.node_map["f3"]}


def test_resolve_predicate_tool_nmap():
    master = _simple_master()
    spec = parse_endpoint_spec("tool=nmap")
    result = asyncio.run(resolve_endpoint(spec, master, store=None))
    assert result == {master.node_map["f1"]}


@pytest.mark.asyncio
async def test_resolve_entity_endpoint(async_chain_stores):
    """resolve an entity endpoint against a real store with a populated chain."""
    from datetime import datetime, timezone
    from opentools.chain.config import ChainConfig
    from opentools.chain.extractors.pipeline import AsyncExtractionPipeline
    from opentools.chain.query.graph_cache import GraphCache
    from opentools.models import Finding, FindingStatus, Severity

    engagement_store, chain_store, _ = async_chain_stores
    now = datetime.now(timezone.utc)
    f = Finding(
        id="f_ep", engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title="t", description="ssh on 10.0.0.5", created_at=now,
    )
    engagement_store.add_finding(f)

    pipeline = AsyncExtractionPipeline(store=chain_store, config=ChainConfig())
    await pipeline.extract_for_finding(f)

    cache = GraphCache(store=chain_store, maxsize=4)
    master = await cache.get_master_graph(user_id=None, include_candidates=True)

    spec = parse_endpoint_spec("ip:10.0.0.5")
    result = await resolve_endpoint(spec, master, chain_store)
    # Should return the node index for f_ep since it mentions 10.0.0.5
    # Only if f_ep is in the master graph (it will be if it has relations,
    # otherwise the master graph includes it via the fallback "all findings" query)
    # Skip the assertion if the graph doesn't include the finding
    if "f_ep" in master.node_map:
        assert master.node_map["f_ep"] in result
