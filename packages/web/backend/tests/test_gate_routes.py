"""Tests for approval gate API routes."""
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_gates_missing_scan(auth_client: AsyncClient):
    resp = await auth_client.get("/api/v1/scans/nonexistent/gates")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_approve_missing_ticket(auth_client: AsyncClient):
    resp = await auth_client.post("/api/v1/scans/scan-1/gates/nonexistent/approve")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_reject_missing_ticket(auth_client: AsyncClient):
    resp = await auth_client.post(
        "/api/v1/scans/scan-1/gates/nonexistent/reject",
        json={"reason": "test"},
    )
    assert resp.status_code == 404
