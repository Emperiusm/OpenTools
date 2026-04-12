from datetime import datetime, timezone

import pytest

from opentools.chain.config import ChainConfig
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine, get_default_rules
from opentools.chain.linker.llm_pass import LLMLinkPassResult, llm_link_pass
from opentools.chain.models import LLMLinkClassification
from opentools.chain.types import RelationStatus
from opentools.models import Finding, FindingStatus, Severity

pytestmark = pytest.mark.asyncio


class _MockProvider:
    name = "mock"
    model = "mock-1"
    _responses: dict[tuple[str, str], LLMLinkClassification] = {}

    def __init__(self, responses=None):
        self._responses = responses or {}

    async def extract_entities(self, text, context):
        return []

    async def classify_relation(self, finding_a, finding_b, shared_entities):
        key = (finding_a.id, finding_b.id)
        reverse = (finding_b.id, finding_a.id)
        return self._responses.get(key) or self._responses.get(reverse) or LLMLinkClassification(
            related=True, relation_type="pivots_to",
            rationale="default mock", confidence=0.9,
        )

    async def generate_path_narration(self, findings, edges):
        return ""


async def _seed_candidate_edge(engagement_store, chain_store):
    now = datetime.now(timezone.utc)
    # Two findings sharing a strong entity (IP) — weight may land at
    # auto_confirmed, but tests manually demote to CANDIDATE via the
    # protocol before calling llm_link_pass.
    a = Finding(
        id="fl_a", engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title="A", description="SSH on 10.0.0.5", created_at=now,
    )
    b = Finding(
        id="fl_b", engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title="B", description="HTTP on 10.0.0.5", created_at=now,
    )
    engagement_store.add_finding(a)
    engagement_store.add_finding(b)

    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=chain_store, config=cfg)
    await pipeline.extract_for_finding(a)
    await pipeline.extract_for_finding(b)

    engine = LinkerEngine(
        store=chain_store, config=cfg, rules=get_default_rules(cfg)
    )
    ctx = await engine.make_context(user_id=None)
    await engine.link_finding(a.id, user_id=None, context=ctx)
    return a, b


async def _demote_all_to_candidate(chain_store):
    """Force every finding_relation row to CANDIDATE status via the protocol.

    The linker may legitimately land an edge at AUTO_CONFIRMED; the LLM
    pass tests need a candidate edge to exercise classification. We
    fetch every relation regardless of status, rewrite its status, and
    upsert it back.
    """
    all_statuses = set(RelationStatus)
    relations = await chain_store.fetch_relations_in_scope(
        user_id=None, statuses=all_statuses
    )
    demoted = [r.model_copy(update={"status": RelationStatus.CANDIDATE}) for r in relations]
    if demoted:
        await chain_store.upsert_relations_bulk(demoted, user_id=None)


async def test_llm_pass_dry_run(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    await _seed_candidate_edge(engagement_store, chain_store)

    provider = _MockProvider()
    result = await llm_link_pass(
        provider=provider, store=chain_store,
        min_weight=0.0, max_weight=5.0,
        dry_run=True,
    )
    assert result.dry_run is True
    assert result.llm_calls == 0


async def test_llm_pass_promotes_related_high_confidence(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    await _seed_candidate_edge(engagement_store, chain_store)
    await _demote_all_to_candidate(chain_store)

    provider = _MockProvider()  # default: related=True, confidence=0.9
    result = await llm_link_pass(
        provider=provider, store=chain_store,
        min_weight=0.0, max_weight=5.0,
    )
    assert result.promoted >= 1

    relations = await chain_store.fetch_relations_in_scope(
        user_id=None, statuses={RelationStatus.AUTO_CONFIRMED}
    )
    assert len(relations) >= 1
    assert relations[0].llm_rationale == "default mock"


async def test_llm_pass_rejects_unrelated(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    await _seed_candidate_edge(engagement_store, chain_store)
    await _demote_all_to_candidate(chain_store)

    provider = _MockProvider(responses={
        ("fl_a", "fl_b"): LLMLinkClassification(
            related=False, relation_type="unrelated",
            rationale="nope", confidence=0.95,
        ),
    })
    result = await llm_link_pass(
        provider=provider, store=chain_store,
        min_weight=0.0, max_weight=5.0,
    )
    assert result.rejected >= 1

    relations = await chain_store.fetch_relations_in_scope(
        user_id=None, statuses={RelationStatus.REJECTED}
    )
    assert len(relations) >= 1


async def test_llm_pass_cache_hit(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    await _seed_candidate_edge(engagement_store, chain_store)
    await _demote_all_to_candidate(chain_store)

    provider = _MockProvider()
    # First run populates the cache.
    await llm_link_pass(
        provider=provider, store=chain_store,
        min_weight=0.0, max_weight=5.0,
    )

    # Reset status to CANDIDATE again and re-run.
    await _demote_all_to_candidate(chain_store)

    result = await llm_link_pass(
        provider=provider, store=chain_store,
        min_weight=0.0, max_weight=5.0,
    )
    assert result.cache_hits >= 1
    assert result.llm_calls == 0


async def test_llm_link_pass_promotes_via_await(engagement_store_and_chain):
    """Baseline: the async variant must promote candidate edges end-to-end."""
    engagement_store, chain_store, _ = engagement_store_and_chain
    await _seed_candidate_edge(engagement_store, chain_store)
    await _demote_all_to_candidate(chain_store)

    provider = _MockProvider()  # default: related=True, confidence=0.9

    result = await llm_link_pass(
        provider=provider, store=chain_store,
        min_weight=0.0, max_weight=5.0,
    )
    assert result.promoted >= 1

    relations = await chain_store.fetch_relations_in_scope(
        user_id=None, statuses={RelationStatus.AUTO_CONFIRMED}
    )
    assert len(relations) >= 1
