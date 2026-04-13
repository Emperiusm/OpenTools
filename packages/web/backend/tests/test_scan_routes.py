# packages/web/backend/tests/test_scan_routes.py
"""Tests for the scan API routes."""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient, ASGITransport


@pytest.fixture
def mock_scan():
    """A mock Scan object dict for API responses."""
    return {
        "id": "scan-abc123",
        "engagement_id": "eng-1",
        "target": "/path/to/code",
        "target_type": "source_code",
        "resolved_path": "/path/to/code",
        "target_metadata": {},
        "profile": "source-full",
        "profile_snapshot": {},
        "mode": "auto",
        "status": "pending",
        "config": None,
        "baseline_scan_id": None,
        "tools_planned": ["semgrep", "gitleaks"],
        "tools_completed": [],
        "tools_failed": [],
        "finding_count": 0,
        "estimated_duration_seconds": None,
        "metrics": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None,
        "completed_at": None,
    }


class TestScanRoutesStructure:
    """Verify the route module has expected structure."""

    def test_router_exists(self):
        from app.routes.scans import router
        assert router is not None

    def test_router_has_prefix(self):
        from app.routes.scans import router
        assert router.prefix == "/api/v1/scans"

    def test_list_scans_endpoint_registered(self):
        from app.routes.scans import router
        paths = [r.path for r in router.routes]
        # Paths include the prefix, e.g. "/api/v1/scans"
        assert any(p.endswith("/api/v1/scans") or p == "/" or p == "" for p in paths)

    def test_create_scan_endpoint_registered(self):
        from app.routes.scans import router
        routes = {(r.path, tuple(r.methods)) for r in router.routes if hasattr(r, "methods")}
        assert any("POST" in methods for _, methods in routes)

    def test_sse_endpoint_registered(self):
        from app.routes.scans import router
        paths = [r.path for r in router.routes]
        assert any("stream" in p for p in paths)

    def test_control_endpoints_registered(self):
        from app.routes.scans import router
        paths = [r.path for r in router.routes]
        assert any("pause" in p for p in paths)
        assert any("resume" in p for p in paths)
        assert any("cancel" in p for p in paths)

    def test_findings_endpoint_registered(self):
        from app.routes.scans import router
        paths = [r.path for r in router.routes]
        assert any("findings" in p for p in paths)

    def test_tasks_endpoint_registered(self):
        from app.routes.scans import router
        paths = [r.path for r in router.routes]
        assert any("tasks" in p for p in paths)

    def test_profiles_endpoint_registered(self):
        from app.routes.scans import router
        paths = [r.path for r in router.routes]
        assert any("profiles" in p for p in paths)


class TestScanResponseModels:
    """Verify request/response Pydantic models exist and are correct."""

    def test_scan_create_request_fields(self):
        from app.routes.scans import ScanCreateRequest
        req = ScanCreateRequest(target="/path", engagement_id="eng-1")
        assert req.target == "/path"
        assert req.engagement_id == "eng-1"
        assert req.mode == "auto"
        assert req.concurrency == 8
        assert req.timeout is None

    def test_scan_response_fields(self):
        from app.routes.scans import ScanResponse
        resp = ScanResponse(
            id="scan-1",
            engagement_id="eng-1",
            target="/path",
            target_type="source_code",
            mode="auto",
            status="pending",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        assert resp.id == "scan-1"
        assert resp.finding_count == 0
        assert resp.tools_planned == []

    def test_control_response_fields(self):
        from app.routes.scans import ControlResponse
        resp = ControlResponse(scan_id="scan-1", status="paused", message="ok")
        assert resp.scan_id == "scan-1"
        assert resp.status == "paused"

    def test_profile_response_fields(self):
        from app.routes.scans import ProfileResponse
        resp = ProfileResponse(id="p1", name="Full", description="desc", target_types=["source_code"])
        assert resp.id == "p1"
        assert "source_code" in resp.target_types

    def test_finding_response_fields(self):
        from app.routes.scans import FindingResponse
        resp = FindingResponse(
            id="f1",
            canonical_title="SQL Injection",
            severity_consensus="high",
            confidence_score=0.9,
            location_fingerprint="src/app.py:42",
        )
        assert resp.id == "f1"
        assert resp.suppressed is False

    def test_task_response_fields(self):
        from app.routes.scans import TaskResponse
        resp = TaskResponse(
            id="t1", name="semgrep scan", tool="semgrep",
            task_type="shell", status="pending", priority=50,
        )
        assert resp.id == "t1"
        assert resp.depends_on == []


class TestScanRouterIntegration:
    """Integration tests using the FastAPI app directly (no DB dependency needed for import)."""

    def test_router_imported_cleanly(self):
        """Router can be imported without side effects."""
        import importlib
        import app.routes.scans as scans_mod
        assert hasattr(scans_mod, "router")
        assert hasattr(scans_mod, "ScanCreateRequest")
        assert hasattr(scans_mod, "ScanResponse")
        assert hasattr(scans_mod, "ScanListResponse")
        assert hasattr(scans_mod, "ControlResponse")
        assert hasattr(scans_mod, "ProfileResponse")
        assert hasattr(scans_mod, "FindingResponse")
        assert hasattr(scans_mod, "TaskResponse")

    def test_all_http_methods_present(self):
        """Verify all expected HTTP methods are registered."""
        from app.routes.scans import router
        all_methods = set()
        for route in router.routes:
            if hasattr(route, "methods"):
                all_methods.update(route.methods)
        # Should have GET and POST at minimum
        assert "GET" in all_methods
        assert "POST" in all_methods
