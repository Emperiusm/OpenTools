"""Finding CRUD tests."""

import pytest


@pytest.fixture
async def engagement_id(auth_client):
    response = await auth_client.post("/api/v1/engagements", json={
        "name": "finding-test", "target": "10.0.0.1", "type": "pentest",
    })
    return response.json()["id"]


@pytest.mark.asyncio
async def test_create_finding(auth_client, engagement_id):
    response = await auth_client.post(f"/api/v1/engagements/{engagement_id}/findings", json={
        "tool": "semgrep",
        "title": "SQL Injection in login",
        "severity": "high",
        "cwe": "CWE-89",
    })
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "SQL Injection in login"
    assert data["severity"] == "high"


@pytest.mark.asyncio
async def test_list_findings_with_filter(auth_client, engagement_id):
    await auth_client.post(f"/api/v1/engagements/{engagement_id}/findings", json={
        "tool": "semgrep", "title": "High Finding", "severity": "high",
    })
    await auth_client.post(f"/api/v1/engagements/{engagement_id}/findings", json={
        "tool": "nuclei", "title": "Medium Finding", "severity": "medium",
    })

    # Filter by severity
    response = await auth_client.get(
        f"/api/v1/engagements/{engagement_id}/findings?severity=high"
    )
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["severity"] == "high"


@pytest.mark.asyncio
async def test_flag_false_positive(auth_client, engagement_id):
    create = await auth_client.post(f"/api/v1/engagements/{engagement_id}/findings", json={
        "tool": "test", "title": "FP Test", "severity": "low",
    })
    finding_id = create.json()["id"]
    response = await auth_client.patch(f"/api/v1/findings/{finding_id}/false-positive")
    assert response.status_code == 200

    # Verify
    detail = await auth_client.get(f"/api/v1/findings/{finding_id}")
    assert detail.json()["false_positive"] is True


@pytest.mark.asyncio
async def test_bulk_status_update(auth_client, engagement_id):
    ids = []
    for i in range(3):
        r = await auth_client.post(f"/api/v1/engagements/{engagement_id}/findings", json={
            "tool": "test", "title": f"Finding {i}", "severity": "medium",
        })
        ids.append(r.json()["id"])

    response = await auth_client.patch("/api/v1/findings/bulk/status", json={
        "finding_ids": ids,
        "status": "confirmed",
    })
    assert response.status_code == 200
