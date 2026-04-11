"""Shared ChainStoreProtocol conformance tests.

Every protocol method is exercised via a parameterized fixture so that
AsyncChainStore (aiosqlite) and later PostgresChainStore (SQLAlchemy)
are verified to behave identically.

In Phase 1, only the SQLite parameter is active. Phase 5 (Task 42)
adds the Postgres parameter.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import pytest_asyncio

from opentools.chain.models import (
    Entity,
    EntityMention,
    FindingRelation,
    RelationReason,
    entity_id_for,
)
from opentools.chain.stores._common import (
    ScopingViolation,
    StoreNotInitialized,
)
from opentools.chain.types import (
    LinkerMode,
    LinkerScope,
    MentionField,
    RelationStatus,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_web_backend_on_path() -> None:
    """Make sure the worktree's web backend is importable.

    The root pyproject already puts ``packages/web/backend`` on
    ``sys.path``, but we defend against test invocations from inside
    ``packages/cli`` by falling back to an explicit insert. Loading
    ``app.models`` before calling this is safe — the function is a
    no-op when the module is already cached.
    """
    import sys
    import pathlib

    # Walk upward from this file to the repo root (contains
    # ``packages/web/backend``). Stop at filesystem root.
    here = pathlib.Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "packages" / "web" / "backend"
        if candidate.is_dir():
            candidate_str = str(candidate)
            if candidate_str not in sys.path:
                sys.path.insert(0, candidate_str)
            return


@pytest_asyncio.fixture(params=["sqlite_async", "postgres_async"])
async def conformant_store(request, tmp_path):
    """Yield (store, user_id) for the parameterized backend.

    The sqlite_async path uses the CLI's single-user aiosqlite store
    and yields ``user_id=None`` (CLI semantics). The postgres_async
    path uses PostgresChainStore against a ``sqlite+aiosqlite://`` ORM
    session — this catches dialect-independent ORM bugs even without
    a running Postgres container. Real Postgres coverage is gated on
    the WEB_TEST_DB_URL env var in a separate suite (not activated
    here).
    """
    if request.param == "sqlite_async":
        from opentools.chain.stores.sqlite_async import AsyncChainStore
        store = AsyncChainStore(db_path=tmp_path / f"{request.param}.db")
        await store.initialize()
        try:
            yield store, None
        finally:
            await store.close()
        return

    if request.param == "postgres_async":
        import os
        import uuid as _uuid

        _ensure_web_backend_on_path()

        try:
            import app.models as web_models  # type: ignore[import-not-found]
        except Exception as exc:  # pragma: no cover
            pytest.skip(f"web backend models unavailable: {exc}")

        # Verify that the loaded app.models has the chain cache tables
        # this test needs. If it does not (stale editable install from
        # a different worktree), skip rather than silently testing the
        # wrong schema.
        if not hasattr(web_models, "ChainExtractionCache"):
            pytest.skip(
                "loaded app.models is missing ChainExtractionCache — "
                "likely a stale editable install; run 'pip install -e "
                "packages/web/backend' from the worktree to refresh"
            )

        from sqlalchemy.ext.asyncio import (
            AsyncSession,
            async_sessionmaker,
            create_async_engine,
        )

        from opentools.chain.stores.postgres_async import PostgresChainStore

        real_pg_url = os.environ.get("WEB_TEST_DB_URL")
        if real_pg_url:
            # Real Postgres path (CI-only): schema is pre-migrated via
            # alembic upgrade head before pytest runs. Per-test isolation
            # is provided by a fresh random user_id — every protocol
            # method is scoped by user_id, and the teardown block below
            # deletes all rows for this test's user.
            engine = create_async_engine(real_pg_url, echo=False)
        else:
            # Default path: in-process sqlite+aiosqlite via SQLAlchemy.
            # Catches ORM/dialect bugs without a running Postgres.
            db_file = tmp_path / "postgres_conf.db"
            engine = create_async_engine(
                f"sqlite+aiosqlite:///{db_file}", echo=False
            )
            async with engine.begin() as conn:
                await conn.run_sync(web_models.SQLModel.metadata.create_all)

        # Apply the same tz-aware datetime shim the production engine
        # installs in app.database, so the conformance fixture's own
        # User.add() and every protocol method that binds a naive
        # datetime survives asyncpg's TIMESTAMPTZ encoder. Must use
        # retval=True so the listener can replace immutable tuple params.
        try:
            from app.database import stamp_naive_datetimes_utc
            from sqlalchemy import event
            event.listen(
                engine.sync_engine,
                "before_cursor_execute",
                stamp_naive_datetimes_utc,
                retval=True,
            )
        except Exception:  # pragma: no cover
            pass

        Session = async_sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        session = Session()

        # Seed a user row so foreign keys that reference user.id hold.
        user_id = _uuid.uuid4()
        session.add(
            web_models.User(
                id=user_id,
                email=f"u_{user_id.hex[:8]}@example.com",
                hashed_password="x",
            )
        )
        await session.commit()

        store = PostgresChainStore(session=session)
        await store.initialize()
        try:
            yield store, user_id
        finally:
            try:
                await store.close()
            finally:
                try:
                    await session.rollback()
                finally:
                    # For real Postgres, purge every row scoped to this
                    # test's user_id so the shared database does not
                    # accumulate state between tests. For sqlite+aiosqlite
                    # the engine is disposed and the temp file is gone,
                    # so the cleanup is a no-op but still safe.
                    if real_pg_url:
                        try:
                            cleanup = Session()
                            try:
                                from sqlalchemy import delete
                                for model_name in (
                                    "ChainFindingParserOutput",
                                    "ChainFindingExtractionState",
                                    "ChainLlmLinkCache",
                                    "ChainExtractionCache",
                                    "ChainLinkerRun",
                                    "ChainFindingRelation",
                                    "ChainEntityMention",
                                    "ChainEntity",
                                ):
                                    model = getattr(web_models, model_name, None)
                                    if model is None or not hasattr(model, "user_id"):
                                        continue
                                    await cleanup.execute(
                                        delete(model).where(model.user_id == user_id)
                                    )
                                await cleanup.execute(
                                    delete(web_models.User).where(
                                        web_models.User.id == user_id
                                    )
                                )
                                await cleanup.commit()
                            finally:
                                await cleanup.close()
                        except Exception:  # pragma: no cover
                            pass
                    await session.close()
                    await engine.dispose()
        return

    pytest.skip(f"backend {request.param} not available in this phase")


# --- Lifecycle ---


@pytest.mark.asyncio
async def test_method_raises_before_initialize(tmp_path):
    from opentools.chain.stores.sqlite_async import AsyncChainStore
    store = AsyncChainStore(db_path=tmp_path / "no_init.db")
    with pytest.raises(StoreNotInitialized):
        await store.get_entity("eid", user_id=None)


@pytest.mark.asyncio
async def test_transaction_commit_on_success(conformant_store):
    store, user_id = conformant_store
    entity_id = entity_id_for("host", "10.0.0.5")
    async with store.transaction():
        await store.upsert_entity(
            Entity(
                id=entity_id, type="host", canonical_value="10.0.0.5",
                first_seen_at=_now(), last_seen_at=_now(),
                mention_count=0,
            ),
            user_id=user_id,
        )
    result = await store.get_entity(entity_id, user_id=user_id)
    assert result is not None
    assert result.canonical_value == "10.0.0.5"


@pytest.mark.asyncio
async def test_transaction_rollback_on_exception(conformant_store):
    store, user_id = conformant_store
    entity_id = entity_id_for("host", "1.2.3.4")
    with pytest.raises(RuntimeError, match="boom"):
        async with store.transaction():
            await store.upsert_entity(
                Entity(
                    id=entity_id, type="host", canonical_value="1.2.3.4",
                    first_seen_at=_now(), last_seen_at=_now(),
                    mention_count=0,
                ),
                user_id=user_id,
            )
            raise RuntimeError("boom")
    result = await store.get_entity(entity_id, user_id=user_id)
    assert result is None  # rolled back


@pytest.mark.asyncio
async def test_transaction_read_your_writes(conformant_store):
    """A write inside a transaction must be visible to a read in the
    same transaction (spec A10)."""
    store, user_id = conformant_store
    entity_id = entity_id_for("host", "5.6.7.8")
    async with store.transaction():
        await store.upsert_entity(
            Entity(
                id=entity_id, type="host", canonical_value="5.6.7.8",
                first_seen_at=_now(), last_seen_at=_now(),
                mention_count=0,
            ),
            user_id=user_id,
        )
        result = await store.get_entity(entity_id, user_id=user_id)
        assert result is not None
    result = await store.get_entity(entity_id, user_id=user_id)
    assert result is not None


# --- Entity CRUD ---


@pytest.mark.asyncio
async def test_upsert_entity_and_get(conformant_store):
    store, user_id = conformant_store
    e = Entity(
        id=entity_id_for("host", "10.0.0.5"),
        type="host", canonical_value="10.0.0.5",
        first_seen_at=_now(), last_seen_at=_now(),
        mention_count=1,
    )
    await store.upsert_entity(e, user_id=user_id)
    result = await store.get_entity(e.id, user_id=user_id)
    assert result is not None
    assert result.type == "host"


@pytest.mark.asyncio
async def test_list_entities_with_type_filter(conformant_store):
    store, user_id = conformant_store
    for t, v in [("host", "1.1.1.1"), ("host", "2.2.2.2"), ("cve", "CVE-2024-1")]:
        await store.upsert_entity(
            Entity(
                id=entity_id_for(t, v), type=t, canonical_value=v,
                first_seen_at=_now(), last_seen_at=_now(),
                mention_count=1,
            ),
            user_id=user_id,
        )
    hosts = await store.list_entities(user_id=user_id, entity_type="host")
    assert len(hosts) == 2
    cves = await store.list_entities(user_id=user_id, entity_type="cve")
    assert len(cves) == 1


@pytest.mark.asyncio
async def test_upsert_entities_bulk_round_trip(conformant_store):
    store, user_id = conformant_store
    entities = [
        Entity(
            id=entity_id_for("user", f"u{i}"),
            type="user",
            canonical_value=f"u{i}",
            first_seen_at=_now(),
            last_seen_at=_now(),
            mention_count=0,
        )
        for i in range(3)
    ]
    await store.upsert_entities_bulk(entities, user_id=user_id)
    fetched = await store.get_entities_by_ids(
        [e.id for e in entities], user_id=user_id
    )
    # get_entities_by_ids returns dict[str, Entity]
    assert len(fetched) == 3
    for e in entities:
        assert e.id in fetched


@pytest.mark.asyncio
async def test_delete_entity(conformant_store):
    store, user_id = conformant_store
    entity_id = entity_id_for("host", "del-me")
    await store.upsert_entity(
        Entity(
            id=entity_id, type="host", canonical_value="del-me",
            first_seen_at=_now(), last_seen_at=_now(),
            mention_count=0,
        ),
        user_id=user_id,
    )
    await store.delete_entity(entity_id, user_id=user_id)
    assert await store.get_entity(entity_id, user_id=user_id) is None


# --- LinkerRun lifecycle ---


@pytest.mark.asyncio
async def test_start_and_finish_linker_run(conformant_store):
    store, user_id = conformant_store
    run = await store.start_linker_run(
        scope=LinkerScope.ENGAGEMENT,
        scope_id="eng_1",
        mode=LinkerMode.RULES_ONLY,
        user_id=user_id,
    )
    assert run.generation >= 1
    await store.finish_linker_run(
        run.id,
        findings_processed=5,
        entities_extracted=12,
        relations_created=3,
        relations_updated=1,
        relations_skipped_sticky=0,
        rule_stats={"shared_strong": 2},
        duration_ms=150,
        error=None,
        user_id=user_id,
    )
    runs = await store.fetch_linker_runs(user_id=user_id, limit=5)
    assert any(r.id == run.id for r in runs)


@pytest.mark.asyncio
async def test_current_linker_generation_monotone(conformant_store):
    store, user_id = conformant_store
    start_gen = await store.current_linker_generation(user_id=user_id)
    await store.start_linker_run(
        scope=LinkerScope.ENGAGEMENT,
        scope_id="eng_a",
        mode=LinkerMode.RULES_ONLY,
        user_id=user_id,
    )
    new_gen = await store.current_linker_generation(user_id=user_id)
    assert new_gen >= start_gen + 1


# --- Extraction state ---


async def _seed_finding_row(store, *, finding_id: str, user_id):
    """Insert a minimal engagement + finding row for FK holds.

    Dispatches on backend: AsyncChainStore (has ``_conn``) uses raw
    SQLite DML; PostgresChainStore uses the ORM session. The rows are
    the minimum needed to satisfy chain_finding_extraction_state /
    chain_finding_parser_output foreign keys.
    """
    if hasattr(store, "_conn"):
        # AsyncChainStore — single-user CLI, no user_id on engagement/findings rows.
        await store._conn.execute(
            "INSERT OR IGNORE INTO engagements "
            "(id, name, target, type, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("eng_conf", "c", "t", "assess", _now().isoformat(), _now().isoformat()),
        )
        await store._conn.execute(
            "INSERT OR IGNORE INTO findings "
            "(id, engagement_id, tool, severity, title, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (finding_id, "eng_conf", "test", "high", "t", _now().isoformat()),
        )
        await store._conn.commit()
        return

    # PostgresChainStore — web SQLModel tables, user-scoped.
    import app.models as m  # type: ignore[import-not-found]

    session = store._session
    assert session is not None
    session.add(
        m.Engagement(
            id="eng_conf",
            user_id=user_id,
            name="c",
            target="t",
            type="assess",
            created_at=_now(),
            updated_at=_now(),
        )
    )
    session.add(
        m.Finding(
            id=finding_id,
            user_id=user_id,
            engagement_id="eng_conf",
            tool="test",
            severity="high",
            title="t",
            created_at=_now(),
        )
    )
    await session.commit()


@pytest.mark.asyncio
async def test_upsert_and_get_extraction_hash(conformant_store):
    store, user_id = conformant_store
    await _seed_finding_row(store, finding_id="fnd_conf", user_id=user_id)

    await store.upsert_extraction_state(
        finding_id="fnd_conf",
        extraction_input_hash="abc123",
        extractor_set=["ioc", "cve"],
        user_id=user_id,
    )
    got = await store.get_extraction_hash("fnd_conf", user_id=user_id)
    assert got == "abc123"


@pytest.mark.asyncio
async def test_mark_run_failed_sets_status_and_error(conformant_store):
    """mark_run_failed finalizes a run row with status='failed' and the
    error message, matching the worker failure path used by
    chain_rebuild_worker.run_rebuild_shared."""
    store, user_id = conformant_store

    run = await store.start_linker_run(
        scope=LinkerScope.ENGAGEMENT,
        scope_id="eng_mark_failed",
        mode=LinkerMode.RULES_ONLY,
        user_id=user_id,
    )

    await store.mark_run_failed(
        run.id, error="boom: db exploded", user_id=user_id,
    )

    runs = await store.fetch_linker_runs(user_id=user_id, limit=10)
    got = next((r for r in runs if r.id == run.id), None)
    assert got is not None
    assert got.status == "failed"
    assert got.error == "boom: db exploded"
    assert got.finished_at is not None


@pytest.mark.asyncio
async def test_fetch_finding_ids_for_entity_distinct(conformant_store):
    """fetch_finding_ids_for_entity returns distinct finding ids even
    when the same entity is mentioned multiple times in one finding —
    this is what entity_ops.merge_entities relies on to populate
    MergeResult.affected_findings."""
    store, user_id = conformant_store
    await _seed_finding_row(store, finding_id="fnd_conf", user_id=user_id)
    # Second finding so we can assert distinctness across findings too.
    if hasattr(store, "_conn"):
        await store._conn.execute(
            "INSERT OR IGNORE INTO findings "
            "(id, engagement_id, tool, severity, title, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("fnd_conf_2", "eng_conf", "test", "high", "t2", _now().isoformat()),
        )
        await store._conn.commit()
    else:
        import app.models as m  # type: ignore[import-not-found]
        session = store._session
        assert session is not None
        session.add(
            m.Finding(
                id="fnd_conf_2",
                user_id=user_id,
                engagement_id="eng_conf",
                tool="test",
                severity="high",
                title="t2",
                created_at=_now(),
            )
        )
        await session.commit()

    entity_id = entity_id_for("host", "10.0.0.77")
    await store.upsert_entity(
        Entity(
            id=entity_id, type="host", canonical_value="10.0.0.77",
            first_seen_at=_now(), last_seen_at=_now(),
            mention_count=0,
        ),
        user_id=user_id,
    )

    # Three mentions: two in fnd_conf (duplicate finding_id), one in fnd_conf_2.
    mentions = [
        EntityMention(
            id=f"mnt_ffe_{i}",
            entity_id=entity_id,
            finding_id=fid,
            field=MentionField.DESCRIPTION,
            raw_value="10.0.0.77",
            extractor="ioc",
            confidence=0.9,
            created_at=_now(),
        )
        for i, fid in enumerate(["fnd_conf", "fnd_conf", "fnd_conf_2"])
    ]
    await store.add_mentions_bulk(mentions, user_id=user_id)

    ids = await store.fetch_finding_ids_for_entity(entity_id, user_id=user_id)
    # Distinct, sorted for determinism.
    assert sorted(ids) == ["fnd_conf", "fnd_conf_2"]


# --- LLM caches ---


@pytest.mark.asyncio
async def test_put_and_get_extraction_cache(conformant_store):
    store, user_id = conformant_store
    await store.put_extraction_cache(
        cache_key="ckey_a",
        provider="ollama",
        model="llama3.1",
        schema_version=1,
        result_json=b"{}",
        user_id=user_id,
    )
    got = await store.get_extraction_cache("ckey_a", user_id=user_id)
    assert got == b"{}"


@pytest.mark.asyncio
async def test_put_and_get_llm_link_cache(conformant_store):
    store, user_id = conformant_store
    await store.put_llm_link_cache(
        cache_key="lkey_a",
        provider="ollama",
        model="llama3.1",
        schema_version=1,
        classification_json=b"[]",
        user_id=user_id,
    )
    got = await store.get_llm_link_cache("lkey_a", user_id=user_id)
    assert got == b"[]"


# --- Findings / count ---


@pytest.mark.asyncio
async def test_count_findings_in_scope_zero_when_empty(conformant_store):
    store, user_id = conformant_store
    count = await store.count_findings_in_scope(user_id=user_id)
    assert count == 0


@pytest.mark.asyncio
async def test_compute_avg_idf_empty_returns_one(conformant_store):
    store, user_id = conformant_store
    val = await store.compute_avg_idf(scope_total=0, user_id=user_id)
    assert val == 1.0
