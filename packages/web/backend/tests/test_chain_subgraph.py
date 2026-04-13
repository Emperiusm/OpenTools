"""Subgraph endpoint tests (Phase 3C.2)."""

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


async def _seed_engagement(user_id, eng_id):
    async with test_session_factory() as session:
        session.add(Engagement(
            id=eng_id, user_id=user_id, name="Test", target="10.0.0.0/24",
            type="pentest", created_at=NOW, updated_at=NOW,
        ))
        await session.commit()


async def _seed_finding(user_id, eng_id, finding_id, severity="high", phase=None):
    async with test_session_factory() as session:
        session.add(Finding(
            id=finding_id, user_id=user_id, engagement_id=eng_id,
            tool="nmap", severity=severity, title=f"Finding {finding_id}",
            phase=phase, created_at=NOW,
        ))
        await session.commit()


async def _seed_relation(user_id, src_id, tgt_id, rel_id, status="auto_confirmed", weight=0.8):
    async with test_session_factory() as session:
        session.add(ChainFindingRelation(
            id=rel_id, user_id=user_id, source_finding_id=src_id,
            target_finding_id=tgt_id, weight=weight, status=status,
            symmetric=False, created_at=NOW, updated_at=NOW,
        ))
        await session.commit()


@pytest.mark.asyncio
async def test_subgraph_empty_engagement(auth_client):
    """Engagement with no findings returns empty graph."""
    user_id = await _get_user_id(auth_client)
    await _seed_engagement(user_id, "eng-empty")

    resp = await auth_client.get("/api/chain/subgraph?engagement_id=eng-empty")
    assert resp.status_code == 200
    data = resp.json()
    assert data["graph"]["nodes"] == []
    assert data["graph"]["links"] == []
    assert data["meta"]["total_findings"] == 0
    assert data["meta"]["rendered_findings"] == 0


@pytest.mark.asyncio
async def test_subgraph_returns_nodes_and_links(auth_client):
    """Seeded findings and relations appear in subgraph response."""
    user_id = await _get_user_id(auth_client)
    await _seed_engagement(user_id, "eng-sub")
    await _seed_finding(user_id, "eng-sub", "f-1", severity="critical")
    await _seed_finding(user_id, "eng-sub", "f-2", severity="high")
    await _seed_relation(user_id, "f-1", "f-2", "rel-1")

    resp = await auth_client.get("/api/chain/subgraph?engagement_id=eng-sub")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["graph"]["nodes"]) == 2
    assert len(data["graph"]["links"]) == 1
    link = data["graph"]["links"][0]
    assert link["id"] == "rel-1"
    assert link["source"] == "f-1"
    assert link["target"] == "f-2"
    assert "drift" in link


@pytest.mark.asyncio
async def test_subgraph_severity_filter(auth_client):
    """Severity filter excludes non-matching findings."""
    user_id = await _get_user_id(auth_client)
    await _seed_engagement(user_id, "eng-sev")
    await _seed_finding(user_id, "eng-sev", "f-crit", severity="critical")
    await _seed_finding(user_id, "eng-sev", "f-low", severity="low")

    resp = await auth_client.get("/api/chain/subgraph?engagement_id=eng-sev&severity=critical")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["graph"]["nodes"]) == 1
    assert data["graph"]["nodes"][0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_subgraph_status_filter(auth_client):
    """Status filter excludes non-matching relations."""
    user_id = await _get_user_id(auth_client)
    await _seed_engagement(user_id, "eng-stat")
    await _seed_finding(user_id, "eng-stat", "f-a")
    await _seed_finding(user_id, "eng-stat", "f-b")
    await _seed_relation(user_id, "f-a", "f-b", "rel-conf", status="auto_confirmed")
    await _seed_relation(user_id, "f-b", "f-a", "rel-cand", status="candidate")

    # Only auto_confirmed
    resp = await auth_client.get(
        "/api/chain/subgraph?engagement_id=eng-stat&status=auto_confirmed"
    )
    data = resp.json()
    assert len(data["graph"]["links"]) == 1
    assert data["graph"]["links"][0]["status"] == "auto_confirmed"


@pytest.mark.asyncio
async def test_subgraph_max_nodes_cap(auth_client):
    """max_nodes caps the number of returned findings."""
    user_id = await _get_user_id(auth_client)
    await _seed_engagement(user_id, "eng-cap")
    for i in range(10):
        await _seed_finding(user_id, "eng-cap", f"f-cap-{i}")

    resp = await auth_client.get("/api/chain/subgraph?engagement_id=eng-cap&max_nodes=3")
    data = resp.json()
    assert len(data["graph"]["nodes"]) == 3
    assert data["meta"]["total_findings"] == 10
    assert data["meta"]["filtered"] is True


@pytest.mark.asyncio
async def test_subgraph_unauthenticated(client):
    """Unauthenticated request returns 401."""
    resp = await client.get("/api/chain/subgraph?engagement_id=eng-x")
    assert resp.status_code == 401
