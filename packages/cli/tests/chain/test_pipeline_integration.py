"""End-to-end pipeline integration tests, parameterized over backends.

Loads the hand-curated ``canonical_findings.json``, runs the full
extraction + linking pipeline against a ChainStoreProtocol-conformant
store, and asserts known entity/relation outcomes within tolerance.

Phase 5B (Task 40): parameterized over both ``sqlite_async``
(AsyncChainStore, via EngagementStore for seed data) and
``postgres_async`` (PostgresChainStore against a
``sqlite+aiosqlite://`` SQLAlchemy session with findings seeded via
SQLModel ORM). Same seed fixtures, same assertions, but the
postgres_async parameter requires a real ``user_id`` so all protocol
calls are user-scoped.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import AsyncIterator

import pytest
import pytest_asyncio

from opentools.chain.config import ChainConfig
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine, get_default_rules
from opentools.chain.query.endpoints import parse_endpoint_spec
from opentools.chain.query.engine import ChainQueryEngine
from opentools.chain.query.graph_cache import GraphCache
from opentools.chain.query.presets import mitre_coverage
from opentools.chain.types import RelationStatus
from opentools.models import (
    Engagement,
    EngagementStatus,
    EngagementType,
    Finding,
    FindingStatus,
    Severity,
)

pytestmark = pytest.mark.asyncio

FIXTURES = Path(__file__).parent / "fixtures"


def _load_fixture(name: str):
    return json.loads((FIXTURES / name).read_text())


def _finding_from_dict(d: dict) -> Finding:
    return Finding(
        id=d["id"],
        engagement_id=d["engagement_id"],
        tool=d["tool"],
        severity=Severity(d["severity"]),
        status=FindingStatus(d["status"]),
        title=d["title"],
        description=d.get("description", ""),
        created_at=datetime.fromisoformat(d["created_at"]),
    )


# ─── Seed helpers: per-backend ──────────────────────────────────────────


async def _seed_canonical_sqlite(tmp_path):
    """Seed the canonical dataset into a file-backed AsyncChainStore.

    Uses the sync ``EngagementStore`` to persist findings, then opens
    an async store over the same sqlite file. Matches the CLI pipeline
    integration path: the store is user_id-agnostic, the linker sees
    ``user_id=None``.
    """
    from opentools.chain.stores.sqlite_async import AsyncChainStore
    from opentools.engagement.store import EngagementStore

    tmp_path.mkdir(parents=True, exist_ok=True)
    db_path = tmp_path / "canonical.db"
    es = EngagementStore(db_path=db_path)
    now = datetime.now()
    for eng_id in ["eng_canonical", "eng_canonical_2"]:
        es.create(Engagement(
            id=eng_id,
            name=eng_id,
            target="canonical",
            type=EngagementType.PENTEST,
            status=EngagementStatus.ACTIVE,
            created_at=now,
            updated_at=now,
        ))
    findings_data = _load_fixture("canonical_findings.json")
    findings = []
    for d in findings_data:
        f = _finding_from_dict(d)
        es.add_finding(f)
        findings.append(f)
    es._conn.close()

    async_store = AsyncChainStore(db_path=db_path)
    await async_store.initialize()
    return async_store, findings, None  # user_id=None for CLI path


async def _seed_canonical_postgres(tmp_path):
    """Seed the canonical dataset into a PostgresChainStore.

    Uses a ``sqlite+aiosqlite://`` SQLAlchemy async engine and the web
    ``SQLModel.metadata`` to stand up the chain tables + Finding +
    User, inserts a user, two engagements, and the canonical findings
    via ORM ``session.add`` calls, and yields a store scoped to the
    new user_id.
    """
    import sys as _sys
    import pathlib as _pathlib

    # Ensure the worktree's web backend is importable (mirrors the
    # conformance suite's _ensure_web_backend_on_path helper).
    here = _pathlib.Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "packages" / "web" / "backend"
        if candidate.is_dir():
            cstr = str(candidate)
            if cstr not in _sys.path:
                _sys.path.insert(0, cstr)
            break

    try:
        import app.models as web_models  # type: ignore[import-not-found]
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"web backend models unavailable: {exc}")

    from sqlalchemy.ext.asyncio import (
        AsyncSession,
        async_sessionmaker,
        create_async_engine,
    )

    from opentools.chain.stores.postgres_async import PostgresChainStore

    tmp_path.mkdir(parents=True, exist_ok=True)
    db_file = tmp_path / "canonical_pg.db"
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_file}", echo=False
    )
    async with engine.begin() as conn:
        await conn.run_sync(web_models.SQLModel.metadata.create_all)

    Session = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    session = Session()

    user_id = uuid.uuid4()
    now = datetime.now()

    # User + engagements
    session.add(
        web_models.User(
            id=user_id,
            email=f"u_{user_id.hex[:8]}@canonical.local",
            hashed_password="x",
        )
    )
    for eng_id in ["eng_canonical", "eng_canonical_2"]:
        session.add(
            web_models.Engagement(
                id=eng_id,
                user_id=user_id,
                name=eng_id,
                target="canonical",
                type=EngagementType.PENTEST.value,
                status=EngagementStatus.ACTIVE.value,
                created_at=now,
                updated_at=now,
            )
        )
    await session.commit()

    # Findings — persist as web Finding rows so the linker's
    # store.fetch_findings_by_ids can resolve them, AND return the
    # CLI Finding domain objects for the pipeline's direct input.
    findings_data = _load_fixture("canonical_findings.json")
    cli_findings: list[Finding] = []
    for d in findings_data:
        cli_f = _finding_from_dict(d)
        cli_findings.append(cli_f)
        session.add(
            web_models.Finding(
                id=cli_f.id,
                user_id=user_id,
                engagement_id=cli_f.engagement_id,
                tool=cli_f.tool,
                severity=cli_f.severity.value,
                status=cli_f.status.value,
                title=cli_f.title,
                description=cli_f.description,
                created_at=cli_f.created_at,
            )
        )
    await session.commit()

    store = PostgresChainStore(session=session)
    await store.initialize()

    # Attach teardown state for the fixture to clean up.
    store._test_owned_engine = engine  # type: ignore[attr-defined]
    store._test_owned_session = session  # type: ignore[attr-defined]
    return store, cli_findings, user_id


@pytest_asyncio.fixture(params=["sqlite_async", "postgres_async"])
async def pipeline_backend(request, tmp_path):
    """Yield ``(store, findings, user_id)`` for the parameterized backend."""
    if request.param == "sqlite_async":
        store, findings, user_id = await _seed_canonical_sqlite(tmp_path)
        try:
            yield store, findings, user_id, request.param
        finally:
            await store.close()
        return

    if request.param == "postgres_async":
        store, findings, user_id = await _seed_canonical_postgres(tmp_path)
        try:
            yield store, findings, user_id, request.param
        finally:
            engine = getattr(store, "_test_owned_engine", None)
            session = getattr(store, "_test_owned_session", None)
            try:
                await store.close()
            finally:
                if session is not None:
                    try:
                        await session.rollback()
                    finally:
                        await session.close()
                if engine is not None:
                    await engine.dispose()
        return

    pytest.skip(f"backend {request.param} not available")


# ─── Protocol-based assertion helpers ──────────────────────────────────


async def _entity_pairs(store, *, user_id) -> tuple[set[tuple[str, str]], dict]:
    """Return (set-of-(type,canonical) pairs, {(t,v): mention_count})."""
    ents = await store.list_entities(user_id=user_id, limit=100000)
    pairs: set[tuple[str, str]] = set()
    counts: dict[tuple[str, str], int] = {}
    for e in ents:
        key = (e.type, e.canonical_value)
        pairs.add(key)
        counts[key] = e.mention_count
    return pairs, counts


async def _relation_rows(store, *, user_id) -> list[tuple[str, str, float]]:
    rels = await store.fetch_relations_in_scope(user_id=user_id)
    return [(r.source_finding_id, r.target_finding_id, r.weight) for r in rels]


async def _count_entities(store, *, user_id) -> int:
    ents = await store.list_entities(user_id=user_id, limit=100000)
    return len(ents)


async def _count_relations(store, *, user_id) -> int:
    rels = await store.fetch_relations_in_scope(user_id=user_id)
    return len(rels)


# ─── Tests ─────────────────────────────────────────────────────────────


async def test_pipeline_full_integration(pipeline_backend):
    store, findings, user_id, backend = pipeline_backend

    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=store, config=cfg)
    for f in findings:
        await pipeline.extract_for_finding(f, user_id=user_id)

    engine = LinkerEngine(store=store, config=cfg, rules=get_default_rules(cfg))
    ctx = await engine.make_context(user_id=user_id)
    for f in findings:
        await engine.link_finding(f.id, user_id=user_id, context=ctx)

    # ── Entity assertions ────────────────────────────────────────────
    expected_ents = _load_fixture("expected_entities.json")
    entity_pairs, mention_counts = await _entity_pairs(store, user_id=user_id)

    assert len(entity_pairs) >= expected_ents["min_total_entities"], (
        f"expected >= {expected_ents['min_total_entities']} entities, "
        f"got {len(entity_pairs)}: {sorted(entity_pairs)}"
    )

    for exp in expected_ents["expected_present"]:
        assert (exp["type"], exp["canonical_value"]) in entity_pairs, (
            f"missing expected entity: {exp['type']}:{exp['canonical_value']}. "
            f"present: {sorted(entity_pairs)}"
        )

    for key, min_count in expected_ents.get(
        "expected_min_mention_count", {}
    ).items():
        etype, evalue = key.split(":", 1)
        count = mention_counts.get((etype, evalue))
        assert count is not None, f"entity {key} not found in DB"
        assert count >= min_count, (
            f"entity {key} has mention_count={count}, expected >= {min_count}"
        )

    # ── Relation assertions ──────────────────────────────────────────
    expected_edges = _load_fixture("expected_edges.json")
    rel_rows = await _relation_rows(store, user_id=user_id)
    assert len(rel_rows) >= expected_edges["min_total_relations"], (
        f"expected >= {expected_edges['min_total_relations']} relations, "
        f"got {len(rel_rows)}"
    )

    # Bidirectional index to handle symmetric relations
    rel_index: dict[tuple[str, str], float] = {}
    for src, tgt, weight in rel_rows:
        rel_index[(src, tgt)] = weight
        rel_index[(tgt, src)] = weight

    for exp in expected_edges["expected_pairs"]:
        key = (exp["source"], exp["target"])
        assert key in rel_index, (
            f"missing expected edge: {exp['source']} - {exp['target']}. "
            f"present pairs: {sorted(set(rel_index))}"
        )
        assert rel_index[key] >= exp["min_weight"], (
            f"edge {exp['source']} - {exp['target']} weight "
            f"{rel_index[key]:.3f} < min {exp['min_weight']}"
        )

    # ── Query sanity: k-shortest path between known-connected findings
    cache = GraphCache(store=store, maxsize=4)
    qe = ChainQueryEngine(store=store, graph_cache=cache, config=cfg)
    first_pair = expected_edges["expected_pairs"][0]
    src_spec = parse_endpoint_spec(first_pair["source"])
    tgt_spec = parse_endpoint_spec(first_pair["target"])
    paths = await qe.k_shortest_paths(
        from_spec=src_spec, to_spec=tgt_spec,
        user_id=user_id, k=3, include_candidates=True,
    )
    assert len(paths) >= 1, (
        f"k_shortest_paths returned no results between "
        f"{first_pair['source']} and {first_pair['target']}"
    )

    # ── MITRE coverage preset sanity (sqlite_async only) ─────────────
    # mitre_coverage hardcodes user_id=None which PostgresChainStore
    # rejects. Keep this as a CLI-scope check only.
    if backend == "sqlite_async":
        mc = await mitre_coverage("eng_canonical", store=store)
        assert len(mc.tactics_present) >= 1, (
            f"mitre_coverage returned no tactics for eng_canonical. "
            f"tactic_counts={mc.tactic_counts}"
        )


async def test_pipeline_resume_matches_single_run(pipeline_backend, tmp_path):
    """Resumability: partial run followed by continuation equals a fresh full run.

    Uses the parameterized fixture for the first store and seeds a
    second store of the same backend type via the local seed helper
    for the reference run. Entity/relation counts must match.
    """
    store1, findings1, user_id1, backend = pipeline_backend

    if backend == "sqlite_async":
        store2, findings2, user_id2 = await _seed_canonical_sqlite(
            tmp_path / "run2"
        )
        teardown_store2 = store2
        teardown_engine2 = None
        teardown_session2 = None
    else:
        store2, findings2, user_id2 = await _seed_canonical_postgres(
            tmp_path / "run2"
        )
        teardown_store2 = store2
        teardown_engine2 = getattr(store2, "_test_owned_engine", None)
        teardown_session2 = getattr(store2, "_test_owned_session", None)

    try:
        cfg = ChainConfig()
        pipeline1 = ExtractionPipeline(store=store1, config=cfg)
        engine1 = LinkerEngine(
            store=store1, config=cfg, rules=get_default_rules(cfg),
        )

        half = len(findings1) // 2
        for f in findings1[:half]:
            await pipeline1.extract_for_finding(f, user_id=user_id1)
        ctx1 = await engine1.make_context(user_id=user_id1)
        for f in findings1[:half]:
            await engine1.link_finding(f.id, user_id=user_id1, context=ctx1)

        # Resume: process second half, then re-link everything
        for f in findings1[half:]:
            await pipeline1.extract_for_finding(f, user_id=user_id1)
        ctx1_v2 = await engine1.make_context(user_id=user_id1)
        for f in findings1:
            await engine1.link_finding(
                f.id, user_id=user_id1, context=ctx1_v2,
            )

        # Reference: run 2 (fresh, all at once)
        pipeline2 = ExtractionPipeline(store=store2, config=cfg)
        engine2 = LinkerEngine(
            store=store2, config=cfg, rules=get_default_rules(cfg),
        )
        for f in findings2:
            await pipeline2.extract_for_finding(f, user_id=user_id2)
        ctx2 = await engine2.make_context(user_id=user_id2)
        for f in findings2:
            await engine2.link_finding(
                f.id, user_id=user_id2, context=ctx2,
            )

        ent_count1 = await _count_entities(store1, user_id=user_id1)
        ent_count2 = await _count_entities(store2, user_id=user_id2)
        assert ent_count1 == ent_count2, (
            f"entity count mismatch: partial+resume={ent_count1}, "
            f"single-run={ent_count2}"
        )

        rel_count1 = await _count_relations(store1, user_id=user_id1)
        rel_count2 = await _count_relations(store2, user_id=user_id2)
        assert rel_count1 == rel_count2, (
            f"relation count mismatch: partial+resume={rel_count1}, "
            f"single-run={rel_count2}"
        )
    finally:
        try:
            await teardown_store2.close()
        finally:
            if teardown_session2 is not None:
                try:
                    await teardown_session2.rollback()
                finally:
                    await teardown_session2.close()
            if teardown_engine2 is not None:
                await teardown_engine2.dispose()
