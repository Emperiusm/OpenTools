"""Relation curation (PATCH) endpoint tests (Phase 3C.2)."""

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


async def _seed_with_relation(user_id, rel_id="rel-cur", status="candidate"):
    async with test_session_factory() as session:
        session.add(Engagement(
            id="eng-cur", user_id=user_id, name="Test", target="10.0.0.1",
            type="pentest", created_at=NOW, updated_at=NOW,
        ))
        await session.flush()
        session.add(Finding(
            id="f-cur-1", user_id=user_id, engagement_id="eng-cur",
            tool="nmap", severity="high", title="Finding 1", created_at=NOW,
        ))
        session.add(Finding(
            id="f-cur-2", user_id=user_id, engagement_id="eng-cur",
            tool="nuclei", severity="medium", title="Finding 2", created_at=NOW,
        ))
        await session.flush()
        session.add(ChainFindingRelation(
            id=rel_id, user_id=user_id, source_finding_id="f-cur-1",
            target_finding_id="f-cur-2", weight=0.75, status=status,
            symmetric=False,
            reasons_json='[{"rule":"shared_strong_entity","weight_contribution":0.5,"idf_factor":null,"details":{}}]',
            created_at=NOW, updated_at=NOW,
        ))
        await session.commit()


@pytest.mark.asyncio
async def test_confirm_candidate(auth_client):
    """Confirming a candidate relation succeeds."""
    user_id = await _get_user_id(auth_client)
    await _seed_with_relation(user_id, "rel-c1", status="candidate")

    resp = await auth_client.patch(
        "/api/chain/relations/rel-c1",
        json={"status": "user_confirmed"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "user_confirmed"


@pytest.mark.asyncio
async def test_reject_candidate(auth_client):
    """Rejecting a candidate relation succeeds."""
    user_id = await _get_user_id(auth_client)
    await _seed_with_relation(user_id, "rel-c2", status="candidate")

    resp = await auth_client.patch(
        "/api/chain/relations/rel-c2",
        json={"status": "user_rejected"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "user_rejected"


@pytest.mark.asyncio
async def test_toggle_confirmed_to_rejected(auth_client):
    """User can change from confirmed to rejected."""
    user_id = await _get_user_id(auth_client)
    await _seed_with_relation(user_id, "rel-c3", status="user_confirmed")

    resp = await auth_client.patch(
        "/api/chain/relations/rel-c3",
        json={"status": "user_rejected"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "user_rejected"


@pytest.mark.asyncio
async def test_invalid_status_returns_422(auth_client):
    """Setting auto_confirmed via PATCH returns 422."""
    user_id = await _get_user_id(auth_client)
    await _seed_with_relation(user_id, "rel-c4")

    resp = await auth_client.patch(
        "/api/chain/relations/rel-c4",
        json={"status": "auto_confirmed"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_nonexistent_relation_returns_404(auth_client):
    """Patching a nonexistent relation returns 404."""
    resp = await auth_client.patch(
        "/api/chain/relations/rel-does-not-exist",
        json={"status": "user_confirmed"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_confirm_snapshots_reasons(auth_client):
    """Confirming snapshots reasons_json into confirmed_at_reasons_json."""
    user_id = await _get_user_id(auth_client)
    await _seed_with_relation(user_id, "rel-c5", status="candidate")

    await auth_client.patch(
        "/api/chain/relations/rel-c5",
        json={"status": "user_confirmed"},
    )

    # Verify in DB
    async with test_session_factory() as session:
        from sqlalchemy import select
        result = await session.execute(
            select(ChainFindingRelation).where(ChainFindingRelation.id == "rel-c5")
        )
        rel = result.scalar_one()
        assert rel.confirmed_at_reasons_json is not None
        assert rel.confirmed_at_reasons_json == rel.reasons_json


@pytest.mark.asyncio
async def test_unauthenticated_returns_401(client):
    """Unauthenticated curation request returns 401."""
    resp = await client.patch(
        "/api/chain/relations/rel-x",
        json={"status": "user_confirmed"},
    )
    assert resp.status_code == 401
