import asyncio
from datetime import datetime, timezone

from opentools.chain.config import ChainConfig
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine, get_default_rules
from opentools.chain.linker.llm_pass import llm_link_pass, LLMLinkPassResult
from opentools.chain.models import LLMLinkClassification
from opentools.chain.types import RelationStatus
from opentools.models import Finding, FindingStatus, Severity


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


def _seed_candidate_edge(engagement_store, chain_store):
    now = datetime.now(timezone.utc)
    # Two findings sharing a strong entity (IP) — weight may land at auto_confirmed,
    # but tests manually demote to CANDIDATE via SQL before calling llm_link_pass.
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
    pipeline.extract_for_finding(a)
    pipeline.extract_for_finding(b)

    engine = LinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))
    ctx = engine.make_context(user_id=None)
    engine.link_finding(a.id, user_id=None, context=ctx)
    return a, b


def test_llm_pass_dry_run(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    _seed_candidate_edge(engagement_store, chain_store)

    provider = _MockProvider()
    result = llm_link_pass(
        provider=provider, store=chain_store,
        min_weight=0.0, max_weight=5.0,
        dry_run=True,
    )
    assert result.dry_run is True
    assert result.llm_calls == 0


def test_llm_pass_promotes_related_high_confidence(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    _seed_candidate_edge(engagement_store, chain_store)

    # Manually set the edge to CANDIDATE status (the linker may have already made it AUTO_CONFIRMED)
    chain_store._conn.execute(
        "UPDATE finding_relation SET status = ?",
        (RelationStatus.CANDIDATE.value,),
    )
    chain_store._conn.commit()

    provider = _MockProvider()  # default: related=True, confidence=0.9
    result = llm_link_pass(
        provider=provider, store=chain_store,
        min_weight=0.0, max_weight=5.0,
    )
    assert result.promoted >= 1

    row = chain_store.execute_one("SELECT status, llm_rationale FROM finding_relation LIMIT 1")
    assert row["status"] == RelationStatus.AUTO_CONFIRMED.value
    assert row["llm_rationale"] == "default mock"


def test_llm_pass_rejects_unrelated(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    _seed_candidate_edge(engagement_store, chain_store)

    chain_store._conn.execute(
        "UPDATE finding_relation SET status = ?",
        (RelationStatus.CANDIDATE.value,),
    )
    chain_store._conn.commit()

    provider = _MockProvider(responses={
        ("fl_a", "fl_b"): LLMLinkClassification(
            related=False, relation_type="unrelated",
            rationale="nope", confidence=0.95,
        ),
    })
    result = llm_link_pass(
        provider=provider, store=chain_store,
        min_weight=0.0, max_weight=5.0,
    )
    assert result.rejected >= 1

    row = chain_store.execute_one("SELECT status FROM finding_relation LIMIT 1")
    assert row["status"] == RelationStatus.REJECTED.value


def test_llm_pass_cache_hit(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    _seed_candidate_edge(engagement_store, chain_store)

    chain_store._conn.execute(
        "UPDATE finding_relation SET status = ?",
        (RelationStatus.CANDIDATE.value,),
    )
    chain_store._conn.commit()

    provider = _MockProvider()
    # First run populates the cache
    llm_link_pass(provider=provider, store=chain_store, min_weight=0.0, max_weight=5.0)

    # Reset status to CANDIDATE again and re-run
    chain_store._conn.execute(
        "UPDATE finding_relation SET status = ?",
        (RelationStatus.CANDIDATE.value,),
    )
    chain_store._conn.commit()

    result = llm_link_pass(provider=provider, store=chain_store, min_weight=0.0, max_weight=5.0)
    assert result.cache_hits >= 1
    assert result.llm_calls == 0


def test_llm_link_pass_async_promotes_via_await(engagement_store_and_chain):
    """The async variant must promote candidate edges exactly like the sync one."""
    from opentools.chain.linker.llm_pass import llm_link_pass_async
    from opentools.chain.types import RelationStatus

    engagement_store, chain_store, _ = engagement_store_and_chain
    _seed_candidate_edge(engagement_store, chain_store)

    chain_store._conn.execute(
        "UPDATE finding_relation SET status = ?",
        (RelationStatus.CANDIDATE.value,),
    )
    chain_store._conn.commit()

    provider = _MockProvider()  # default: related=True, confidence=0.9

    async def _run():
        return await llm_link_pass_async(
            provider=provider, store=chain_store,
            min_weight=0.0, max_weight=5.0,
        )

    result = asyncio.run(_run())
    assert result.promoted >= 1

    row = chain_store.execute_one("SELECT status FROM finding_relation LIMIT 1")
    assert row["status"] == RelationStatus.AUTO_CONFIRMED.value
