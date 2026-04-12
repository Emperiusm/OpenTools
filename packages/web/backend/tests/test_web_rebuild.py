"""Tests for the web chain rebuild background worker.

Phase 5B renamed this file (from ``test_chain_rebuild``) and rewrote
the assertions against the shared-pipeline worker in
``app.services.chain_rebuild_worker``. The tests still cover the same
three concerns — happy-path extraction+linking, error-path status
bookkeeping, and sticky user_confirmed preservation — but the worker
now runs the full CLI pipeline (all 6 linker rules, 3-stage
extraction) instead of a web-specific subset.

Monkeypatches for the failure test target
``LinkerEngine.make_context`` (an early step called before the
per-finding try/except) so the exception escapes to the worker's
outer handler and gets recorded as a failed run.
"""
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models import (
    ChainEntity,
    ChainFindingRelation,
    ChainLinkerRun,
    Engagement,
    Finding,
    User,
)
from app.services.chain_rebuild_worker import run_rebuild_shared

# Import the test session factory the same way other web tests do.
from tests.conftest import test_session_factory


def _user_id() -> uuid.UUID:
    return uuid.uuid4()


async def _seed(session, *, user_id, engagement_id="eng_test"):
    now = datetime.now(timezone.utc)
    session.add(User(id=user_id, email=f"u_{user_id.hex[:8]}@test.local", hashed_password="x"))
    session.add(Engagement(
        id=engagement_id, user_id=user_id, name="t", target="t",
        type="pentest", status="active",
        created_at=now, updated_at=now,
    ))
    for i, desc in enumerate([
        "SSH on 10.0.0.5 exposed",
        "HTTP on 10.0.0.5 running apache",
        "totally unrelated finding",
    ]):
        session.add(Finding(
            id=f"f_{i}", user_id=user_id, engagement_id=engagement_id,
            tool="nmap", severity="high", status="discovered",
            title=f"F{i}", description=desc,
            created_at=now,
        ))
    # Seed a pending linker run matching the id the worker will
    # transition through running -> done.
    run_id = f"run_test_{uuid.uuid4().hex[:8]}"
    session.add(ChainLinkerRun(
        id=run_id, user_id=user_id,
        started_at=now, scope="engagement", scope_id=engagement_id,
        mode="rules_only", status_text="pending",
    ))
    await session.commit()
    return run_id


@pytest.mark.asyncio
async def test_rebuild_extracts_entities_and_creates_relations():
    """Happy path: worker extracts 10.0.0.5 and links f_0 with f_1.

    The shared pipeline runs all 6 linker rules (not just
    shared-strong-entity like the old web-specific worker), so we
    assert on the minimum contract: the IP entity is discovered with
    mentions from at least two findings, and at least one relation
    connects f_0 and f_1. Exact relation counts depend on IDF
    calibration, which for a 3-finding scope is auto-disabled.
    """
    user_id = _user_id()
    async with test_session_factory() as session:
        run_id = await _seed(session, user_id=user_id)

    await run_rebuild_shared(
        session_factory=test_session_factory,
        run_id=run_id,
        user_id=user_id,
        engagement_id="eng_test",
    )

    async with test_session_factory() as session:
        # Run marked as done
        run = await session.get(ChainLinkerRun, run_id)
        assert run is not None
        assert run.status_text == "done", (
            f"expected status done, got {run.status_text!r}"
        )
        assert run.finished_at is not None
        assert run.findings_processed >= 3

        # At least one ChainEntity created (ip 10.0.0.5)
        result = await session.execute(
            select(ChainEntity).where(
                ChainEntity.user_id == user_id,
                ChainEntity.type == "ip",
                ChainEntity.canonical_value == "10.0.0.5",
            )
        )
        ip_entity = result.scalar_one_or_none()
        assert ip_entity is not None, "expected ip:10.0.0.5 entity"
        assert ip_entity.mention_count >= 2  # f_0 and f_1 both mention it

        # At least one relation created between f_0 and f_1 (symmetric —
        # check both orderings).
        result = await session.execute(
            select(ChainFindingRelation).where(
                ChainFindingRelation.user_id == user_id,
            )
        )
        relations = list(result.scalars().all())
        assert len(relations) >= 1, "expected at least one relation"
        assert any(
            {r.source_finding_id, r.target_finding_id} == {"f_0", "f_1"}
            for r in relations
        ), (
            f"expected relation linking f_0 and f_1; "
            f"got {[(r.source_finding_id, r.target_finding_id) for r in relations]}"
        )


@pytest.mark.asyncio
async def test_rebuild_marks_run_failed_on_error(monkeypatch):
    """If a worker stage raises, the run row should be marked failed.

    The new worker wraps per-finding extract and link calls in
    try/except so individual failures are swallowed. To trigger a
    failed-run, we monkeypatch ``LinkerEngine.make_context`` which
    runs before the per-finding try/except — exceptions there escape
    to the worker's outer handler which records the failure on the
    run row.
    """
    user_id = _user_id()
    async with test_session_factory() as session:
        run_id = await _seed(session, user_id=user_id)

    from opentools.chain.linker.engine import LinkerEngine

    async def _boom(self, **kwargs):
        raise RuntimeError("simulated linker context failure")

    monkeypatch.setattr(LinkerEngine, "make_context", _boom)

    await run_rebuild_shared(
        session_factory=test_session_factory,
        run_id=run_id,
        user_id=user_id,
        engagement_id="eng_test",
    )

    async with test_session_factory() as session:
        run = await session.get(ChainLinkerRun, run_id)
        assert run is not None
        assert run.status_text == "failed", (
            f"expected failed status, got {run.status_text!r}"
        )
        assert "simulated" in (run.error or ""), (
            f"expected error text to contain 'simulated', got {run.error!r}"
        )


@pytest.mark.asyncio
async def test_rebuild_preserves_sticky_user_confirmed():
    """User-confirmed relations must survive a rebuild.

    Sticky preservation is protocol-level behavior
    (:meth:`ChainStoreProtocol.upsert_relations_bulk` preserves
    sticky statuses on conflict), so this test asserts the same
    invariant as before but now runs through the shared pipeline
    instead of the old web-specific linker.
    """
    user_id = _user_id()
    async with test_session_factory() as session:
        run_id = await _seed(session, user_id=user_id)
        # Manually insert a sticky relation between f_0 and f_1
        now = datetime.now(timezone.utc)
        session.add(ChainFindingRelation(
            id="rel_sticky",
            user_id=user_id,
            source_finding_id="f_0",
            target_finding_id="f_1",
            weight=0.5,
            status="user_confirmed",
            reasons_json="[]",
            created_at=now, updated_at=now,
        ))
        await session.commit()

    await run_rebuild_shared(
        session_factory=test_session_factory,
        run_id=run_id,
        user_id=user_id,
        engagement_id="eng_test",
    )

    async with test_session_factory() as session:
        sticky = await session.get(ChainFindingRelation, "rel_sticky")
        assert sticky is not None, "sticky relation vanished"
        assert sticky.status == "user_confirmed", (
            f"sticky status changed to {sticky.status!r}"
        )
