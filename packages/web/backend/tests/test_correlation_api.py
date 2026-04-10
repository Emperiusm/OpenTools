"""Correlation API endpoint tests."""

import pytest
from datetime import datetime, timezone


@pytest.mark.asyncio
async def test_correlate_empty(auth_client):
    response = await auth_client.get("/api/v1/iocs/correlate?value=nonexistent")
    assert response.status_code == 200
    data = response.json()
    assert data["engagement_count"] == 0


@pytest.mark.asyncio
async def test_correlate_single_engagement(auth_client):
    # Create engagement
    eng = await auth_client.post("/api/v1/engagements", json={
        "name": "test", "target": "10.0.0.1", "type": "pentest",
    })
    eng_id = eng.json()["id"]

    # Add IOC
    await auth_client.post(f"/api/v1/engagements/{eng_id}/iocs", json={
        "ioc_type": "ip", "value": "192.168.1.1", "context": "scan target",
    })

    response = await auth_client.get("/api/v1/iocs/correlate?value=192.168.1.1")
    assert response.status_code == 200
    data = response.json()
    assert data["engagement_count"] == 1
    assert data["ioc_type"] == "ip"


@pytest.mark.asyncio
async def test_trending_empty(auth_client):
    response = await auth_client.get("/api/v1/iocs/trending?limit=10&days=30")
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_trending_returns_iocs(auth_client):
    # Create engagement with IOCs
    eng = await auth_client.post("/api/v1/engagements", json={
        "name": "test", "target": "10.0.0.1", "type": "pentest",
    })
    eng_id = eng.json()["id"]

    for i in range(3):
        await auth_client.post(f"/api/v1/engagements/{eng_id}/iocs", json={
            "ioc_type": "ip", "value": f"10.0.0.{i}", "context": "test",
        })

    response = await auth_client.get("/api/v1/iocs/trending?limit=10&days=365")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 3


@pytest.mark.asyncio
async def test_engagement_correlations(auth_client):
    # Create two engagements with a shared IOC
    eng1 = await auth_client.post("/api/v1/engagements", json={
        "name": "eng-1", "target": "10.0.0.1", "type": "pentest",
    })
    eng1_id = eng1.json()["id"]
    eng2 = await auth_client.post("/api/v1/engagements", json={
        "name": "eng-2", "target": "10.0.0.2", "type": "pentest",
    })
    eng2_id = eng2.json()["id"]

    # Shared IOC
    await auth_client.post(f"/api/v1/engagements/{eng1_id}/iocs", json={
        "ioc_type": "ip", "value": "192.168.1.1", "context": "C2",
    })
    await auth_client.post(f"/api/v1/engagements/{eng2_id}/iocs", json={
        "ioc_type": "ip", "value": "192.168.1.1", "context": "C2",
    })

    response = await auth_client.get(f"/api/v1/engagements/{eng1_id}/correlations")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert data[0]["ioc_value"] == "192.168.1.1"


@pytest.mark.asyncio
async def test_correlation_user_isolation(client):
    """User A cannot see user B's IOC correlations."""
    # User A
    await client.post("/api/v1/auth/register", json={"email": "usera@test.com", "password": "pass123"})
    login_a = await client.post("/api/v1/auth/login", data={"username": "usera@test.com", "password": "pass123"})
    for n, v in login_a.cookies.items():
        client.cookies.set(n, v)
    eng = await client.post("/api/v1/engagements", json={"name": "user-a", "target": "1.1.1.1", "type": "pentest"})
    await client.post(f"/api/v1/engagements/{eng.json()['id']}/iocs", json={
        "ioc_type": "ip", "value": "10.0.0.1",
    })

    # Switch to User B
    client.cookies.clear()
    await client.post("/api/v1/auth/register", json={"email": "userb@test.com", "password": "pass456"})
    login_b = await client.post("/api/v1/auth/login", data={"username": "userb@test.com", "password": "pass456"})
    for n, v in login_b.cookies.items():
        client.cookies.set(n, v)

    # User B should see 0 correlations for user A's IOC
    response = await client.get("/api/v1/iocs/correlate?value=10.0.0.1")
    assert response.status_code == 200
    assert response.json()["engagement_count"] == 0


@pytest.mark.asyncio
async def test_timeline(auth_client):
    eng = await auth_client.post("/api/v1/engagements", json={"name": "test", "target": "10.0.0.1", "type": "pentest"})
    await auth_client.post(f"/api/v1/engagements/{eng.json()['id']}/iocs", json={
        "ioc_type": "ip", "value": "192.168.1.1",
    })
    response = await auth_client.get("/api/v1/iocs/ip/192.168.1.1/timeline")
    assert response.status_code == 200
    data = response.json()
    assert "lifecycle" in data
    assert "frequency" in data
