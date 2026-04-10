"""Auth endpoint tests."""

import pytest


@pytest.mark.asyncio
async def test_register(client):
    response = await client.post("/api/v1/auth/register", json={
        "email": "new@example.com",
        "password": "securepass123",
    })
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "new@example.com"
    assert "id" in data


@pytest.mark.asyncio
async def test_register_duplicate_email(client):
    await client.post("/api/v1/auth/register", json={
        "email": "dup@example.com",
        "password": "pass123",
    })
    response = await client.post("/api/v1/auth/register", json={
        "email": "dup@example.com",
        "password": "pass456",
    })
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_login(client):
    await client.post("/api/v1/auth/register", json={
        "email": "login@example.com",
        "password": "pass123",
    })
    response = await client.post("/api/v1/auth/login", data={
        "username": "login@example.com",
        "password": "pass123",
    })
    assert response.status_code in (200, 204)


@pytest.mark.asyncio
async def test_protected_endpoint_unauthorized(client):
    response = await client.get("/api/v1/engagements")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_protected_endpoint_authorized(auth_client):
    response = await auth_client.get("/api/v1/engagements")
    assert response.status_code == 200
