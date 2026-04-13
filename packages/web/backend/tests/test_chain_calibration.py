"""Calibration endpoint tests (Phase 3C.3)."""

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


async def _seed_decisions(user_id, count=25, confirmed_ratio=0.8):
    """Seed engagement, findings, and user-decided edges."""
    async with test_session_factory() as session:
        session.add(Engagement(
            id="eng-cal", user_id=user_id, name="Cal Test", target="10.0.0.1",
            type="pentest", created_at=NOW, updated_at=NOW,
        ))
        await session.flush()

        for i in range(count):
            f1_id = f"f-cal-{i}-a"
            f2_id = f"f-cal-{i}-b"
            session.add(Finding(
                id=f1_id, user_id=user_id, engagement_id="eng-cal",
                tool="nmap", severity="high", title=f"Finding {f1_id}", created_at=NOW,
            ))
            session.add(Finding(
                id=f2_id, user_id=user_id, engagement_id="eng-cal",
                tool="nuclei", severity="medium", title=f"Finding {f2_id}", created_at=NOW,
            ))
            await session.flush()

            is_confirmed = i < int(count * confirmed_ratio)
            session.add(ChainFindingRelation(
                id=f"rel-cal-{i}", user_id=user_id,
                source_finding_id=f1_id, target_finding_id=f2_id,
                weight=0.5, status="user_confirmed" if is_confirmed else "user_rejected",
                symmetric=False,
                reasons_json=f'[{{"rule":"shared_strong_entity","weight_contribution":0.5,"idf_factor":null,"details":{{}}}}]',
                created_at=NOW, updated_at=NOW,
            ))

        await session.commit()


@pytest.mark.asyncio
async def test_calibrate_below_threshold(auth_client):
    """Calibration with too few decisions returns 422."""
    resp = await auth_client.post("/api/chain/calibrate", json={"scope": "user"})
    assert resp.status_code == 422
    assert "Need at least" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_calibrate_success(auth_client):
    """Calibration with enough decisions returns posteriors."""
    user_id = await _get_user_id(auth_client)
    await _seed_decisions(user_id, count=25, confirmed_ratio=0.8)

    resp = await auth_client.post("/api/chain/calibrate", json={"scope": "user"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["below_threshold"] is False
    assert len(data["rules"]) > 0

    sse = next(r for r in data["rules"] if r["rule"] == "shared_strong_entity")
    assert sse["posterior"] > 0.5


@pytest.mark.asyncio
async def test_calibrate_dry_run(auth_client):
    """Dry run returns posteriors but edges_updated=0."""
    user_id = await _get_user_id(auth_client)
    await _seed_decisions(user_id, count=25)

    resp = await auth_client.post("/api/chain/calibrate", json={
        "scope": "user", "dry_run": True,
    })
    assert resp.status_code == 200
    assert resp.json()["edges_updated"] == 0


@pytest.mark.asyncio
async def test_calibrate_invalid_scope(auth_client):
    """Invalid scope returns 422."""
    resp = await auth_client.post("/api/chain/calibrate", json={"scope": "global"})
    assert resp.status_code == 422
