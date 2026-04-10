"""Cross-user isolation tests for chain API (Task 44).

Verifies that Alice's chain data is never visible to Bob and vice-versa.
Each test creates two separate users and seeds data under different user_ids.
A query-scope bug in the service layer would surface here.
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
# Seeding helpers
# ---------------------------------------------------------------------------


async def _seed_entity(user_id: uuid.UUID, entity_id: str, value: str = "10.0.0.1") -> None:
    async with test_session_factory() as session:
        session.add(ChainEntity(
            id=entity_id,
            user_id=user_id,
            type="host",
            canonical_value=value,
            first_seen_at=NOW,
            last_seen_at=NOW,
            mention_count=1,
        ))
        await session.commit()


async def _seed_engagement(user_id: uuid.UUID, eng_id: str) -> None:
    async with test_session_factory() as session:
        session.add(Engagement(
            id=eng_id,
            user_id=user_id,
            name=f"Engagement {eng_id}",
            target="10.0.0.0/24",
            type="pentest",
            created_at=NOW,
            updated_at=NOW,
        ))
        await session.commit()


async def _seed_finding(user_id: uuid.UUID, eng_id: str, finding_id: str) -> None:
    async with test_session_factory() as session:
        session.add(Finding(
            id=finding_id,
            user_id=user_id,
            engagement_id=eng_id,
            tool="nmap",
            severity="high",
            title="Isolation test finding",
            created_at=NOW,
        ))
        await session.commit()


async def _seed_relation(
    user_id: uuid.UUID,
    src_id: str,
    tgt_id: str,
    rel_id: str,
) -> None:
    async with test_session_factory() as session:
        session.add(ChainFindingRelation(
            id=rel_id,
            user_id=user_id,
            source_finding_id=src_id,
            target_finding_id=tgt_id,
            weight=0.9,
            status="auto_confirmed",
            symmetric=False,
            created_at=NOW,
            updated_at=NOW,
        ))
        await session.commit()


async def _seed_linker_run(user_id: uuid.UUID, run_id: str) -> None:
    async with test_session_factory() as session:
        session.add(ChainLinkerRun(
            id=run_id,
            user_id=user_id,
            started_at=NOW,
            scope="cross_engagement",
            mode="rules_only",
            status_text="pending",
        ))
        await session.commit()


# ---------------------------------------------------------------------------
# Auth helpers — two-user fixture pattern (mirrors test_correlation_api.py)
# ---------------------------------------------------------------------------


async def _register_and_login(client, email: str, password: str = "password123") -> dict:
    """Register + login a user, set cookies. Returns the register response JSON."""
    reg = await client.post("/api/v1/auth/register", json={"email": email, "password": password})
    # 201 = new user; 400 = duplicate (acceptable in multi-test scenarios)
    assert reg.status_code in (200, 201, 400), f"Register failed for {email}: {reg.text}"
    user_data = reg.json() if reg.status_code in (200, 201) else {}

    login = await client.post("/api/v1/auth/login", data={"username": email, "password": password})
    assert login.status_code in (200, 204), f"Login failed for {email}: {login.text}"
    for name, value in login.cookies.items():
        client.cookies.set(name, value)
    return user_data


async def _switch_to(client, email: str, password: str = "password123") -> None:
    """Switch the client to a different user (clears old session cookies)."""
    client.cookies.clear()
    login = await client.post("/api/v1/auth/login", data={"username": email, "password": password})
    assert login.status_code in (200, 204), f"Login switch failed for {email}: {login.text}"
    for name, value in login.cookies.items():
        client.cookies.set(name, value)


def _uid_from_reg(reg_data: dict) -> uuid.UUID:
    """Extract uuid from register response."""
    return uuid.UUID(reg_data["id"])


# ---------------------------------------------------------------------------
# Task 44.1: Alice's GET /entities returns only her entities
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entities_list_only_own(client):
    """Alice's GET /entities returns only Alice's entities, not Bob's."""
    alice_data = await _register_and_login(client, "alice-ent@chainiso.com")
    alice_uid = _uid_from_reg(alice_data)

    bob_data = await _register_and_login(client, "bob-ent@chainiso.com")
    bob_uid = _uid_from_reg(bob_data)

    # Seed one entity per user
    await _seed_entity(alice_uid, "iso-ent-alice-01", "192.168.1.1")
    await _seed_entity(bob_uid, "iso-ent-bob-01", "10.10.10.10")

    # Login as Alice and fetch entities
    await _switch_to(client, "alice-ent@chainiso.com")
    resp = await client.get("/api/chain/entities")
    assert resp.status_code == 200
    ids = [e["id"] for e in resp.json()]
    assert "iso-ent-alice-01" in ids, "Alice must see her own entity"
    assert "iso-ent-bob-01" not in ids, "Alice must NOT see Bob's entity"


# ---------------------------------------------------------------------------
# Task 44.2: Alice cannot fetch Bob's entity by id (404)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entity_fetch_by_id_cross_user_404(client):
    """Alice cannot fetch Bob's entity by id — should get 404."""
    alice_data = await _register_and_login(client, "alice-getent@chainiso.com")
    alice_uid = _uid_from_reg(alice_data)

    bob_data = await _register_and_login(client, "bob-getent@chainiso.com")
    bob_uid = _uid_from_reg(bob_data)

    await _seed_entity(alice_uid, "iso-alice-priv-ent", "10.1.1.1")
    await _seed_entity(bob_uid, "iso-bob-priv-ent", "10.2.2.2")

    # Alice tries to fetch Bob's entity — user_id WHERE clause should return None → 404
    await _switch_to(client, "alice-getent@chainiso.com")
    resp = await client.get("/api/chain/entities/iso-bob-priv-ent")
    assert resp.status_code == 404, (
        f"Alice should get 404 for Bob's entity, got {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# Task 44.3: Alice cannot fetch relations for Bob's finding (empty, not 500)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relations_cross_user_returns_empty(client):
    """Alice fetching relations for Bob's finding returns empty list."""
    alice_data = await _register_and_login(client, "alice-rels@chainiso.com")
    alice_uid = _uid_from_reg(alice_data)

    bob_data = await _register_and_login(client, "bob-rels@chainiso.com")
    bob_uid = _uid_from_reg(bob_data)

    # Bob has an engagement, two findings, and a confirmed relation between them
    await _seed_engagement(bob_uid, "iso-eng-bob-rels")
    await _seed_finding(bob_uid, "iso-eng-bob-rels", "iso-f-bob-src")
    await _seed_finding(bob_uid, "iso-eng-bob-rels", "iso-f-bob-tgt")
    await _seed_relation(bob_uid, "iso-f-bob-src", "iso-f-bob-tgt", "iso-rel-bob-01")

    # Alice queries Bob's source finding — her user_id scopes the query to empty
    await _switch_to(client, "alice-rels@chainiso.com")
    resp = await client.get("/api/chain/findings/iso-f-bob-src/relations")
    assert resp.status_code == 200
    assert resp.json() == [], (
        f"Alice must see 0 relations for Bob's finding, got: {resp.json()}"
    )


# ---------------------------------------------------------------------------
# Task 44.4: Alice's POST /path returns no results for Bob's finding ids
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_path_cross_user_returns_empty(client):
    """Alice's POST /path returns no results when Bob's finding ids are passed."""
    alice_data = await _register_and_login(client, "alice-path@chainiso.com")
    alice_uid = _uid_from_reg(alice_data)

    bob_data = await _register_and_login(client, "bob-path@chainiso.com")
    bob_uid = _uid_from_reg(bob_data)

    # Bob has confirmed findings + relation in his user scope
    await _seed_engagement(bob_uid, "iso-eng-bob-path")
    await _seed_finding(bob_uid, "iso-eng-bob-path", "iso-f-bp-src")
    await _seed_finding(bob_uid, "iso-eng-bob-path", "iso-f-bp-tgt")
    await _seed_relation(bob_uid, "iso-f-bp-src", "iso-f-bp-tgt", "iso-rel-bp-01")

    # Alice queries a path between Bob's finding ids — service scopes by user_id
    await _switch_to(client, "alice-path@chainiso.com")
    resp = await client.post("/api/chain/path", json={
        "from_finding_id": "iso-f-bp-src",
        "to_finding_id": "iso-f-bp-tgt",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0, (
        f"Alice must see 0 paths using Bob's finding ids, got total={data['total']}"
    )
    assert data["paths"] == []


# ---------------------------------------------------------------------------
# Task 44.5: Alice's rebuild creates a run scoped to Alice only
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rebuild_run_scoped_to_caller(client):
    """Rebuild creates a run row owned by the calling user only."""
    await _register_and_login(client, "alice-rebuild@chainiso.com")
    await _register_and_login(client, "bob-rebuild@chainiso.com")

    # Alice triggers rebuild
    await _switch_to(client, "alice-rebuild@chainiso.com")
    rebuild_resp = await client.post("/api/chain/rebuild", json={})
    assert rebuild_resp.status_code == 202
    alice_run_id = rebuild_resp.json()["run_id"]

    # Alice can fetch her own run
    run_resp = await client.get(f"/api/chain/runs/{alice_run_id}")
    assert run_resp.status_code == 200
    assert run_resp.json()["run_id"] == alice_run_id

    # Bob cannot fetch Alice's run — user_id filter returns None → 404
    await _switch_to(client, "bob-rebuild@chainiso.com")
    bob_resp = await client.get(f"/api/chain/runs/{alice_run_id}")
    assert bob_resp.status_code == 404, (
        f"Bob must NOT be able to see Alice's run, got {bob_resp.status_code}"
    )


# ---------------------------------------------------------------------------
# Extra: seeded run not visible cross-user
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_seeded_run_not_visible_cross_user(client):
    """A run seeded under Bob's user_id is invisible to Alice."""
    alice_data = await _register_and_login(client, "alice-runs@chainiso.com")
    alice_uid = _uid_from_reg(alice_data)

    bob_data = await _register_and_login(client, "bob-runs@chainiso.com")
    bob_uid = _uid_from_reg(bob_data)

    await _seed_linker_run(bob_uid, "iso-run-bob-priv-01")

    # Alice tries to fetch Bob's run
    await _switch_to(client, "alice-runs@chainiso.com")
    resp = await client.get("/api/chain/runs/iso-run-bob-priv-01")
    assert resp.status_code == 404, (
        f"Alice must get 404 for Bob's run, got {resp.status_code}"
    )
