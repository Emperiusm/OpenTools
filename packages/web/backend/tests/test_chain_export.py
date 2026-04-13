"""Export endpoint tests (Phase 3C.3)."""

import uuid
from datetime import datetime, timezone

import pytest

from app.models import ChainFindingRelation, Engagement, Finding
from tests.conftest import test_session_factory

NOW = datetime.now(timezone.utc)


async def _get_user_id(auth_client) -> uuid.UUID:
    eng_resp = await auth_client.post("/api/v1/engagements", json={
        "name": "_uid_probe", "target": "127.0.0.1", "type": "pentest",
    })
    assert eng_resp.status_code == 201
    eng_id = eng_resp.json()["id"]
    async with test_session_factory() as session:
        from sqlalchemy import select
        from app.models import Engagement as Eng
        result = await session.execute(select(Eng).where(Eng.id == eng_id))
        eng = result.scalar_one()
        return eng.user_id


async def _seed_path(user_id):
    """Seed engagement with a 3-step path."""
    async with test_session_factory() as session:
        session.add(Engagement(
            id="eng-exp", user_id=user_id, name="Export Test", target="10.0.0.1",
            type="pentest", created_at=NOW, updated_at=NOW,
        ))
        await session.flush()
        for i, (sev, title) in enumerate([
            ("critical", "SQL Injection"),
            ("high", "Credential Dump"),
            ("medium", "Lateral Movement"),
        ]):
            session.add(Finding(
                id=f"f-exp-{i}", user_id=user_id, engagement_id="eng-exp",
                tool="test", severity=sev, title=title, created_at=NOW,
                evidence=f"Evidence for step {i}",
                remediation=f"Fix step {i}",
            ))
        await session.flush()
        session.add(ChainFindingRelation(
            id="rel-exp-0", user_id=user_id, source_finding_id="f-exp-0",
            target_finding_id="f-exp-1", weight=0.9, status="auto_confirmed",
            symmetric=False, reasons_json='[{"rule":"shared_strong_entity","weight_contribution":0.9}]',
            created_at=NOW, updated_at=NOW,
        ))
        session.add(ChainFindingRelation(
            id="rel-exp-1", user_id=user_id, source_finding_id="f-exp-1",
            target_finding_id="f-exp-2", weight=0.7, status="auto_confirmed",
            symmetric=False, reasons_json='[{"rule":"temporal_proximity","weight_contribution":0.7}]',
            created_at=NOW, updated_at=NOW,
        ))
        await session.commit()


@pytest.mark.asyncio
async def test_export_path_returns_markdown(auth_client):
    """Valid path returns Markdown with expected sections."""
    user_id = await _get_user_id(auth_client)
    await _seed_path(user_id)

    resp = await auth_client.post("/api/chain/export/path", json={
        "finding_ids": ["f-exp-0", "f-exp-1", "f-exp-2"],
        "engagement_id": "eng-exp",
    })
    assert resp.status_code == 200
    md = resp.json()["markdown"]
    assert "# Attack Path Report" in md
    assert "SQL Injection" in md
    assert "Step 1:" in md
    assert "Step 2:" in md
    assert "Step 3:" in md
    assert "Recommendations" in md


@pytest.mark.asyncio
async def test_export_path_invalid_finding(auth_client):
    """Invalid finding ID returns 404."""
    resp = await auth_client.post("/api/chain/export/path", json={
        "finding_ids": ["f-nonexistent-1", "f-nonexistent-2"],
    })
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_export_path_too_short(auth_client):
    """Path with <2 findings returns 422."""
    resp = await auth_client.post("/api/chain/export/path", json={
        "finding_ids": ["f-exp-0"],
    })
    assert resp.status_code == 422
