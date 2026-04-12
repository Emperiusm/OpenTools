import pytest

from opentools.chain.query.graph_cache import PathEdgeRef, PathNode, PathResult
from opentools.chain.query.narration import narrate_path

pytestmark = pytest.mark.asyncio


class _MockProvider:
    name = "mock"
    model = "mock-1"
    call_count = 0

    def __init__(self, text: str = "The attacker moved from A to B to C."):
        self._text = text

    async def extract_entities(self, text, context):
        return []

    async def classify_relation(self, a, b, shared):
        return None

    async def generate_path_narration(self, findings, edges):
        self.call_count += 1
        return self._text


def _make_path() -> PathResult:
    nodes = [
        PathNode(finding_id="n_a", index=0, severity="high", tool="nmap", title="A"),
        PathNode(finding_id="n_b", index=1, severity="high", tool="burp", title="B"),
    ]
    edges = [
        PathEdgeRef(
            source_finding_id="n_a", target_finding_id="n_b",
            weight=1.5, status="auto_confirmed",
            reasons_summary=["shared_strong_entity"],
            llm_rationale=None, llm_relation_type=None,
        )
    ]
    return PathResult(
        nodes=nodes, edges=edges, total_cost=0.5, length=1,
        source_finding_id="n_a", target_finding_id="n_b",
    )


async def test_narrate_path_returns_text(engagement_store_and_chain):
    _engagement_store, chain_store, _ = engagement_store_and_chain
    provider = _MockProvider(text="attack narrative")
    path = _make_path()
    result = await narrate_path(path=path, provider=provider, store=chain_store)
    assert result == "attack narrative"
    assert provider.call_count == 1


async def test_narrate_path_cache_hit_skips_provider(engagement_store_and_chain):
    _engagement_store, chain_store, _ = engagement_store_and_chain
    provider = _MockProvider(text="first call")
    path = _make_path()
    # First call populates cache
    await narrate_path(path=path, provider=provider, store=chain_store)
    assert provider.call_count == 1

    # Second call should hit cache (provider not invoked again)
    result = await narrate_path(path=path, provider=provider, store=chain_store)
    assert provider.call_count == 1
    assert result == "first call"


async def test_narrate_path_empty_path_returns_none(engagement_store_and_chain):
    _engagement_store, chain_store, _ = engagement_store_and_chain
    provider = _MockProvider()
    empty_path = PathResult(
        nodes=[], edges=[], total_cost=0.0, length=0,
        source_finding_id="", target_finding_id="",
    )
    result = await narrate_path(path=empty_path, provider=provider, store=chain_store)
    assert result is None
    assert provider.call_count == 0


async def test_narrate_path_provider_failure_returns_none(engagement_store_and_chain):
    _engagement_store, chain_store, _ = engagement_store_and_chain

    class _BrokenProvider:
        name = "broken"
        model = "broken-1"

        async def extract_entities(self, text, context):
            return []

        async def classify_relation(self, a, b, shared):
            return None

        async def generate_path_narration(self, findings, edges):
            raise RuntimeError("provider error")

    provider = _BrokenProvider()
    path = _make_path()
    result = await narrate_path(path=path, provider=provider, store=chain_store)
    assert result is None
