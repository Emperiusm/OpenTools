# packages/cli/tests/test_scanner/test_api.py
"""Tests for ScanAPI — unified entry point."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opentools.scanner.api import ScanAPI
from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.models import (
    Scan,
    ScanConfig,
    ScanMode,
    ScanStatus,
    ScanTask,
    TargetType,
    TaskStatus,
    TaskType,
)


def _make_scan(scan_id: str = "scan-1", status: ScanStatus = ScanStatus.PENDING) -> Scan:
    return Scan(
        id=scan_id,
        engagement_id="eng-1",
        target="/tmp/test",
        target_type=TargetType.SOURCE_CODE,
        status=status,
        created_at=datetime.now(timezone.utc),
    )


class TestScanAPIPlan:
    @pytest.mark.asyncio
    async def test_plan_returns_scan_and_tasks(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        scan, tasks = await api.plan(
            target=str(tmp_path),
            engagement_id="eng-1",
            profile_name="source-quick",
            mode=ScanMode.AUTO,
        )

        assert isinstance(scan, Scan)
        assert scan.target == str(tmp_path)
        assert scan.target_type == TargetType.SOURCE_CODE
        assert scan.status == ScanStatus.PENDING
        assert scan.engagement_id == "eng-1"
        assert isinstance(tasks, list)
        assert len(tasks) >= 1
        for t in tasks:
            assert t.scan_id == scan.id

    @pytest.mark.asyncio
    async def test_plan_auto_detect_profile(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        scan, tasks = await api.plan(
            target=str(tmp_path),
            engagement_id="eng-1",
        )

        assert scan.target_type == TargetType.SOURCE_CODE
        assert len(tasks) >= 1

    @pytest.mark.asyncio
    async def test_plan_with_config(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        config = ScanConfig(max_concurrent_tasks=4)
        scan, tasks = await api.plan(
            target=str(tmp_path),
            engagement_id="eng-1",
            profile_name="source-quick",
            config=config,
        )

        assert scan.config is not None
        assert scan.config.max_concurrent_tasks == 4

    @pytest.mark.asyncio
    async def test_plan_populates_tools_planned(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        scan, tasks = await api.plan(
            target=str(tmp_path),
            engagement_id="eng-1",
            profile_name="source-quick",
        )

        assert len(scan.tools_planned) >= 1
        assert "semgrep" in scan.tools_planned

    @pytest.mark.asyncio
    async def test_plan_with_remove_tools(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        scan, tasks = await api.plan(
            target=str(tmp_path),
            engagement_id="eng-1",
            profile_name="source-quick",
            remove_tools=["gitleaks"],
        )

        tool_names = [t.tool for t in tasks]
        assert "gitleaks" not in tool_names

    @pytest.mark.asyncio
    async def test_plan_assigns_unique_scan_id(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        scan1, _ = await api.plan(target=str(tmp_path), engagement_id="eng-1")
        scan2, _ = await api.plan(target=str(tmp_path), engagement_id="eng-1")

        assert scan1.id != scan2.id

    @pytest.mark.asyncio
    async def test_plan_stores_profile_name(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        scan, _ = await api.plan(
            target=str(tmp_path),
            engagement_id="eng-1",
            profile_name="source-quick",
        )

        assert scan.profile == "source-quick"

    @pytest.mark.asyncio
    async def test_plan_stores_target_metadata(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        api = ScanAPI()
        scan, _ = await api.plan(
            target=str(tmp_path),
            engagement_id="eng-1",
        )

        assert "languages" in scan.target_metadata
        assert "python" in scan.target_metadata["languages"]


class TestScanAPILifecycle:
    @pytest.mark.asyncio
    async def test_cancel_sets_cancelled_status(self):
        api = ScanAPI()
        scan = _make_scan(status=ScanStatus.RUNNING)
        token = CancellationToken()
        api._active_scans[scan.id] = {"scan": scan, "cancel": token}

        await api.cancel(scan.id, reason="user requested")

        assert token.is_cancelled

    @pytest.mark.asyncio
    async def test_cancel_unknown_scan_raises(self):
        api = ScanAPI()
        with pytest.raises(KeyError):
            await api.cancel("nonexistent", reason="test")

    @pytest.mark.asyncio
    async def test_pause_sets_flag(self):
        api = ScanAPI()
        scan = _make_scan(status=ScanStatus.RUNNING)
        engine_mock = MagicMock()
        engine_mock.pause = AsyncMock()
        api._active_scans[scan.id] = {"scan": scan, "engine": engine_mock}

        await api.pause(scan.id)

        engine_mock.pause.assert_called_once()

    @pytest.mark.asyncio
    async def test_resume_clears_flag(self):
        api = ScanAPI()
        scan = _make_scan(status=ScanStatus.PAUSED)
        engine_mock = MagicMock()
        engine_mock.resume = AsyncMock()
        api._active_scans[scan.id] = {"scan": scan, "engine": engine_mock}

        await api.resume(scan.id)

        engine_mock.resume.assert_called_once()
