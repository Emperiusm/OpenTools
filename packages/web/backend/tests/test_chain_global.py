"""Global subgraph endpoint tests (Phase 3C.3)."""

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


async def _seed(user_id):
    """Seed two engagements with findings and a cross-engagement relation."""
    async with test_session_factory() as session:
        session.add(Engagement(
            id="eng-g1", user_id=user_id, name="Pentest Q1", target="10.0.0.0/24",
            type="pentest", created_at=NOW, updated_at=NOW,
        ))
        session.add(Engagement(
            id="eng-g2", user_id=user_id, name="Web App", target="app.example.com",
            type="pentest", created_at=NOW, updated_at=NOW,
        ))
        await session.flush()
        session.add(Finding(
            id="f-g1", user_id=user_id, engagement_id="eng-g1",
            tool="nmap", severity="high", title="Open SSH", created_at=NOW,
        ))
        session.add(Finding(
            id="f-g2", user_id=user_id, engagement_id="eng-g2",
            tool="nuclei", severity="critical", title="RCE in /api", created_at=NOW,
        ))
        await session.flush()
        session.add(ChainFindingRelation(
            id="rel-cross", user_id=user_id, source_finding_id="f-g1",
            target_finding_id="f-g2", weight=0.6, status="auto_confirmed",
            symmetric=False, created_at=NOW, updated_at=NOW,
        ))
        await session.commit()


@pytest.mark.asyncio
async def test_global_subgraph_returns_cross_engagement(auth_client):
    """Omitting engagement_id returns findings from all engagements."""
    user_id = await _get_user_id(auth_client)
    await _seed(user_id)

    resp = await auth_client.get("/api/chain/subgraph?max_nodes=100")
    assert resp.status_code == 200
    data = resp.json()
    node_ids = {n["id"] for n in data["graph"]["nodes"]}
    assert "f-g1" in node_ids
    assert "f-g2" in node_ids
    assert len(data["graph"]["links"]) >= 1


@pytest.mark.asyncio
async def test_global_subgraph_includes_engagements_meta(auth_client):
    """Meta includes engagements array with id and name."""
    user_id = await _get_user_id(auth_client)
    await _seed(user_id)

    resp = await auth_client.get("/api/chain/subgraph?max_nodes=100")
    data = resp.json()
    eng_ids = {e["id"] for e in data["meta"]["engagements"]}
    assert "eng-g1" in eng_ids
    assert "eng-g2" in eng_ids


@pytest.mark.asyncio
async def test_global_subgraph_engagement_ids_filter(auth_client):
    """engagement_ids param filters to specific engagements."""
    user_id = await _get_user_id(auth_client)
    await _seed(user_id)

    resp = await auth_client.get("/api/chain/subgraph?engagement_ids=eng-g1&max_nodes=100")
    data = resp.json()
    for n in data["graph"]["nodes"]:
        assert n["engagement_id"] == "eng-g1"


@pytest.mark.asyncio
async def test_subgraph_nodes_have_created_at(auth_client):
    """Node objects include created_at field."""
    user_id = await _get_user_id(auth_client)
    await _seed(user_id)

    resp = await auth_client.get("/api/chain/subgraph?engagement_id=eng-g1")
    data = resp.json()
    for n in data["graph"]["nodes"]:
        assert "created_at" in n


@pytest.mark.asyncio
async def test_subgraph_nodes_have_pivotality(auth_client):
    """Node objects include pivotality field."""
    user_id = await _get_user_id(auth_client)
    await _seed(user_id)

    resp = await auth_client.get("/api/chain/subgraph?max_nodes=100")
    data = resp.json()
    for n in data["graph"]["nodes"]:
        assert "pivotality" in n
        assert isinstance(n["pivotality"], (int, float))
