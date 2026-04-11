"""Tests for the web chain rebuild background worker."""
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models import (
    ChainEntity,
    ChainEntityMention,
    ChainFindingRelation,
    ChainLinkerRun,
    Engagement,
    Finding,
    User,
)
from app.services.chain_rebuild import run_rebuild

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
    # Seed a pending linker run
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
    user_id = _user_id()
    async with test_session_factory() as session:
        run_id = await _seed(session, user_id=user_id)

    await run_rebuild(
        session_factory=test_session_factory,
        run_id=run_id,
        user_id=user_id,
        engagement_id="eng_test",
    )

    async with test_session_factory() as session:
        # Run marked as done
        run = await session.get(ChainLinkerRun, run_id)
        assert run.status_text == "done"
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
        assert ip_entity is not None
        assert ip_entity.mention_count >= 2  # f_0 and f_1 both mention it

        # At least one relation created between f_0 and f_1
        result = await session.execute(
            select(ChainFindingRelation).where(
                ChainFindingRelation.user_id == user_id,
            )
        )
        relations = list(result.scalars().all())
        assert any(
            {r.source_finding_id, r.target_finding_id} == {"f_0", "f_1"}
            for r in relations
        )


@pytest.mark.asyncio
async def test_rebuild_marks_run_failed_on_error(monkeypatch):
    """If the extract phase raises, the run row should be marked failed."""
    user_id = _user_id()
    async with test_session_factory() as session:
        run_id = await _seed(session, user_id=user_id)

    # Monkeypatch _extract_all to raise
    from app.services import chain_rebuild as rebuild_module

    async def _boom(*args, **kwargs):
        raise RuntimeError("simulated extract failure")

    monkeypatch.setattr(rebuild_module, "_extract_all", _boom)

    await run_rebuild(
        session_factory=test_session_factory,
        run_id=run_id,
        user_id=user_id,
        engagement_id="eng_test",
    )

    async with test_session_factory() as session:
        run = await session.get(ChainLinkerRun, run_id)
        assert run.status_text == "failed"
        assert "simulated" in (run.error or "")


@pytest.mark.asyncio
async def test_rebuild_preserves_sticky_user_confirmed():
    """User-confirmed relations must survive a rebuild."""
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

    await run_rebuild(
        session_factory=test_session_factory,
        run_id=run_id,
        user_id=user_id,
        engagement_id="eng_test",
    )

    async with test_session_factory() as session:
        sticky = await session.get(ChainFindingRelation, "rel_sticky")
        assert sticky is not None
        assert sticky.status == "user_confirmed"
