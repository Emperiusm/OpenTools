"""Chain API endpoint tests (Task 43).

Tests that each of the 6 chain endpoints returns correct status codes
under valid conditions, rejects unauthenticated requests, and returns
404 for missing resources.

Data is seeded directly via SQLModel inserts — no CLI pipeline required.
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.models import (
    ChainEntity,
    ChainFindingRelation,
    ChainLinkerRun,
    Engagement,
    Finding,
)

# Import the test session factory so we can seed data into the in-memory DB
from tests.conftest import test_session_factory

NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Seeding helpers — write directly to the test in-memory DB
# ---------------------------------------------------------------------------


async def _seed_entity(user_id: uuid.UUID, entity_id: str, value: str = "192.168.1.100") -> ChainEntity:
    async with test_session_factory() as session:
        entity = ChainEntity(
            id=entity_id,
            user_id=user_id,
            type="host",
            canonical_value=value,
            first_seen_at=NOW,
            last_seen_at=NOW,
            mention_count=3,
        )
        session.add(entity)
        await session.commit()
        return entity


async def _seed_engagement(user_id: uuid.UUID, eng_id: str) -> Engagement:
    async with test_session_factory() as session:
        eng = Engagement(
            id=eng_id,
            user_id=user_id,
            name=f"Engagement {eng_id}",
            target="10.0.0.0/24",
            type="pentest",
            created_at=NOW,
            updated_at=NOW,
        )
        session.add(eng)
        await session.commit()
        return eng


async def _seed_finding(user_id: uuid.UUID, eng_id: str, finding_id: str) -> Finding:
    async with test_session_factory() as session:
        finding = Finding(
            id=finding_id,
            user_id=user_id,
            engagement_id=eng_id,
            tool="nmap",
            severity="medium",
            title="Test finding",
            created_at=NOW,
        )
        session.add(finding)
        await session.commit()
        return finding


async def _seed_relation(
    user_id: uuid.UUID,
    src_id: str,
    tgt_id: str,
    rel_id: str,
) -> ChainFindingRelation:
    async with test_session_factory() as session:
        rel = ChainFindingRelation(
            id=rel_id,
            user_id=user_id,
            source_finding_id=src_id,
            target_finding_id=tgt_id,
            weight=0.8,
            status="auto_confirmed",
            symmetric=False,
            created_at=NOW,
            updated_at=NOW,
        )
        session.add(rel)
        await session.commit()
        return rel


async def _seed_linker_run(user_id: uuid.UUID, run_id: str) -> ChainLinkerRun:
    async with test_session_factory() as session:
        run = ChainLinkerRun(
            id=run_id,
            user_id=user_id,
            started_at=NOW,
            scope="cross_engagement",
            mode="rules_only",
            status_text="pending",
        )
        session.add(run)
        await session.commit()
        return run


async def _get_user_id(auth_client) -> uuid.UUID:
    """Get the user_id of the currently logged-in user via the register step.

    We use the engagement creation endpoint as a proxy to confirm auth
    is working, then extract the user id from the register response that
    was stored when the auth_client fixture was built.  Since we don't
    have a /me endpoint, we re-login and capture the user id differently
    by using a sentinel engagement.

    Actually the simplest approach: re-register via client and read the id.
    But auth_client already has a user. We get the user id by creating
    a sentinel engagement and reading who it belongs to via the DB.

    Simplest: create an engagement and use the user_id from the seeded row.
    We exploit the fact that the user was registered at test@example.com.
    """
    # The auth_client fixture registers test@example.com; we re-register
    # and capture the response (which returns the id even on duplicate = 400).
    # But the cleanest approach: create a temporary engagement via HTTP,
    # then query the DB for it to get the user_id.
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


# ---------------------------------------------------------------------------
# GET /api/chain/entities
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_entities_returns_200(auth_client):
    """Authenticated request returns 200 with entity list."""
    response = await auth_client.get("/api/chain/entities")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_list_entities_with_seeded_data(auth_client):
    """Seeded entities appear in the list response."""
    user_id = await _get_user_id(auth_client)
    await _seed_entity(user_id, "ent-list-01")

    response = await auth_client.get("/api/chain/entities")
    assert response.status_code == 200
    data = response.json()
    ids = [e["id"] for e in data]
    assert "ent-list-01" in ids
    assert data[0]["type"] == "host"


@pytest.mark.asyncio
async def test_list_entities_unauthenticated(client):
    """Unauthenticated request is rejected."""
    response = await client.get("/api/chain/entities")
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_entities_type_filter(auth_client):
    """type_ query param filters results."""
    user_id = await _get_user_id(auth_client)
    await _seed_entity(user_id, "ent-host-01", "10.0.0.1")

    async with test_session_factory() as session:
        session.add(ChainEntity(
            id="ent-cve-01",
            user_id=user_id,
            type="cve",
            canonical_value="CVE-2024-0001",
            first_seen_at=NOW,
            last_seen_at=NOW,
            mention_count=1,
        ))
        await session.commit()

    resp_host = await auth_client.get("/api/chain/entities?type_=host")
    assert resp_host.status_code == 200
    assert all(e["type"] == "host" for e in resp_host.json())

    resp_cve = await auth_client.get("/api/chain/entities?type_=cve")
    assert resp_cve.status_code == 200
    assert all(e["type"] == "cve" for e in resp_cve.json())


# ---------------------------------------------------------------------------
# GET /api/chain/entities/{entity_id}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_entity_returns_200(auth_client):
    """Fetching a seeded entity by id returns 200 with correct data."""
    user_id = await _get_user_id(auth_client)
    await _seed_entity(user_id, "ent-get-01")

    response = await auth_client.get("/api/chain/entities/ent-get-01")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == "ent-get-01"
    assert data["canonical_value"] == "192.168.1.100"
    assert data["mention_count"] == 3


@pytest.mark.asyncio
async def test_get_entity_not_found(auth_client):
    """Missing entity returns 404."""
    response = await auth_client.get("/api/chain/entities/missing-entity-id")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_entity_unauthenticated(client):
    """Unauthenticated request is rejected."""
    response = await client.get("/api/chain/entities/some-id")
    assert response.status_code in (401, 403)


# ---------------------------------------------------------------------------
# GET /api/chain/findings/{finding_id}/relations
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relations_for_finding_returns_200_empty(auth_client):
    """Relations endpoint returns 200 and empty list when no relations exist."""
    response = await auth_client.get("/api/chain/findings/nonexistent-finding/relations")
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_relations_for_finding_with_seeded_data(auth_client):
    """Seeded relation appears in response for source and target finding."""
    user_id = await _get_user_id(auth_client)
    await _seed_engagement(user_id, "eng-rel-01")
    await _seed_finding(user_id, "eng-rel-01", "f-rel-src")
    await _seed_finding(user_id, "eng-rel-01", "f-rel-tgt")
    await _seed_relation(user_id, "f-rel-src", "f-rel-tgt", "rel-api-01")

    # Source side
    resp_src = await auth_client.get("/api/chain/findings/f-rel-src/relations")
    assert resp_src.status_code == 200
    data = resp_src.json()
    assert len(data) == 1
    assert data[0]["id"] == "rel-api-01"

    # Target side also appears
    resp_tgt = await auth_client.get("/api/chain/findings/f-rel-tgt/relations")
    assert resp_tgt.status_code == 200
    assert len(resp_tgt.json()) == 1


@pytest.mark.asyncio
async def test_relations_for_finding_unauthenticated(client):
    """Unauthenticated request is rejected."""
    response = await client.get("/api/chain/findings/f-001/relations")
    assert response.status_code in (401, 403)


# ---------------------------------------------------------------------------
# POST /api/chain/path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_path_returns_200_empty_when_no_relations(auth_client):
    """Path query returns 200 with empty paths and total=0 when no graph data."""
    response = await auth_client.post("/api/chain/path", json={
        "from_finding_id": "f-001",
        "to_finding_id": "f-002",
    })
    assert response.status_code == 200
    data = response.json()
    assert "paths" in data
    assert "total" in data
    assert isinstance(data["paths"], list)
    assert data["total"] == 0


@pytest.mark.asyncio
async def test_path_response_shape(auth_client):
    """POST /path returns the correct envelope shape."""
    resp = await auth_client.post("/api/chain/path", json={
        "from_finding_id": "x",
        "to_finding_id": "y",
        "k": 3,
        "max_hops": 4,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert set(data.keys()) >= {"paths", "total"}


@pytest.mark.asyncio
async def test_path_unauthenticated(client):
    """Unauthenticated request is rejected."""
    response = await client.post("/api/chain/path", json={
        "from_finding_id": "f-001",
        "to_finding_id": "f-002",
    })
    assert response.status_code in (401, 403)


# ---------------------------------------------------------------------------
# POST /api/chain/rebuild
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rebuild_returns_202_with_run_id(auth_client):
    """Rebuild returns 202 Accepted with a non-empty run_id and status=pending."""
    response = await auth_client.post("/api/chain/rebuild", json={})
    assert response.status_code == 202
    data = response.json()
    assert "run_id" in data
    assert "status" in data
    assert data["status"] == "pending"
    assert data["run_id"]  # non-empty string


@pytest.mark.asyncio
async def test_rebuild_with_engagement_id(auth_client):
    """Rebuild with an engagement_id still returns 202."""
    response = await auth_client.post("/api/chain/rebuild", json={"engagement_id": "eng-abc"})
    assert response.status_code == 202
    assert "run_id" in response.json()


@pytest.mark.asyncio
async def test_rebuild_unauthenticated(client):
    """Unauthenticated request is rejected."""
    response = await client.post("/api/chain/rebuild", json={})
    assert response.status_code in (401, 403)


# ---------------------------------------------------------------------------
# GET /api/chain/runs/{run_id}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_run_returns_200(auth_client):
    """Fetching a seeded run by id returns 200 with correct shape."""
    user_id = await _get_user_id(auth_client)
    await _seed_linker_run(user_id, "run-get-01")

    response = await auth_client.get("/api/chain/runs/run-get-01")
    assert response.status_code == 200
    data = response.json()
    assert data["run_id"] == "run-get-01"
    assert data["status"] == "pending"
    assert data["findings_processed"] == 0
    assert data["relations_created"] == 0
    assert data["error"] is None


@pytest.mark.asyncio
async def test_get_run_via_rebuild(auth_client):
    """Run created by /rebuild can be retrieved by /runs/{run_id}."""
    rebuild = await auth_client.post("/api/chain/rebuild", json={})
    assert rebuild.status_code == 202
    run_id = rebuild.json()["run_id"]

    response = await auth_client.get(f"/api/chain/runs/{run_id}")
    assert response.status_code == 200
    assert response.json()["run_id"] == run_id


@pytest.mark.asyncio
async def test_get_run_not_found(auth_client):
    """Missing run returns 404."""
    response = await auth_client.get("/api/chain/runs/missing-run-id")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_run_unauthenticated(client):
    """Unauthenticated request is rejected."""
    response = await client.get("/api/chain/runs/some-run")
    assert response.status_code in (401, 403)
