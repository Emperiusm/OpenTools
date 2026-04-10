"""Engagement CRUD tests."""

import pytest


@pytest.mark.asyncio
async def test_create_engagement(auth_client):
    response = await auth_client.post("/api/v1/engagements", json={
        "name": "test-pentest",
        "target": "192.168.1.0/24",
        "type": "pentest",
    })
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "test-pentest"
    assert data["status"] == "active"
    assert "id" in data


@pytest.mark.asyncio
async def test_list_engagements(auth_client):
    await auth_client.post("/api/v1/engagements", json={
        "name": "test-1", "target": "10.0.0.1", "type": "pentest",
    })
    await auth_client.post("/api/v1/engagements", json={
        "name": "test-2", "target": "10.0.0.2", "type": "forensics",
    })
    response = await auth_client.get("/api/v1/engagements")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 2


@pytest.mark.asyncio
async def test_get_engagement_detail(auth_client):
    create = await auth_client.post("/api/v1/engagements", json={
        "name": "detail-test", "target": "10.0.0.1", "type": "pentest",
    })
    eng_id = create.json()["id"]
    response = await auth_client.get(f"/api/v1/engagements/{eng_id}")
    assert response.status_code == 200
    assert response.json()["engagement"]["name"] == "detail-test"


@pytest.mark.asyncio
async def test_delete_engagement(auth_client):
    create = await auth_client.post("/api/v1/engagements", json={
        "name": "to-delete", "target": "10.0.0.1", "type": "pentest",
    })
    eng_id = create.json()["id"]
    response = await auth_client.delete(f"/api/v1/engagements/{eng_id}")
    assert response.status_code == 204
    # Verify it's gone
    get_response = await auth_client.get(f"/api/v1/engagements/{eng_id}")
    assert get_response.status_code == 404


@pytest.mark.asyncio
async def test_user_isolation(client):
    """User A cannot see User B's engagements."""
    # Register and login as user A
    await client.post("/api/v1/auth/register", json={
        "email": "usera@test.com", "password": "pass123",
    })
    login_a = await client.post("/api/v1/auth/login", data={
        "username": "usera@test.com", "password": "pass123",
    })
    for name, value in login_a.cookies.items():
        client.cookies.set(name, value)

    # Create engagement as user A
    await client.post("/api/v1/engagements", json={
        "name": "user-a-eng", "target": "10.0.0.1", "type": "pentest",
    })

    # Logout (clear cookies)
    client.cookies.clear()

    # Register and login as user B
    await client.post("/api/v1/auth/register", json={
        "email": "userb@test.com", "password": "pass456",
    })
    login_b = await client.post("/api/v1/auth/login", data={
        "username": "userb@test.com", "password": "pass456",
    })
    for name, value in login_b.cookies.items():
        client.cookies.set(name, value)

    # User B should see 0 engagements
    response = await client.get("/api/v1/engagements")
    assert response.status_code == 200
    assert len(response.json()["items"]) == 0
