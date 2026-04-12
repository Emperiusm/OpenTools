"""Tests for ScanStoreProtocol and SqliteScanStore."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
import pytest_asyncio

from opentools.scanner.models import (
    Scan,
    ScanStatus,
    ScanMode,
    TargetType,
    ScanTask,
    TaskStatus,
    TaskType,
)
from opentools.scanner.store import SqliteScanStore


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_scan(
    scan_id: str = "scan-001",
    engagement_id: str = "eng-001",
    target: str = "https://example.com",
    target_type: TargetType = TargetType.URL,
) -> Scan:
    return Scan(
        id=scan_id,
        engagement_id=engagement_id,
        target=target,
        target_type=target_type,
        mode=ScanMode.AUTO,
        status=ScanStatus.PENDING,
        created_at=_now(),
    )


def _make_task(
    task_id: str = "task-001",
    scan_id: str = "scan-001",
) -> ScanTask:
    return ScanTask(
        id=task_id,
        scan_id=scan_id,
        name="nmap-scan",
        tool="nmap",
        task_type=TaskType.SHELL,
        command="nmap -sV example.com",
        status=TaskStatus.PENDING,
    )


@pytest_asyncio.fixture
async def store(tmp_path):
    db_path = tmp_path / "test_scans.db"
    s = SqliteScanStore(db_path)
    await s.initialize()
    yield s
    await s.close()


@pytest.mark.asyncio
async def test_save_and_get_scan(store):
    """Save a scan and retrieve it by id — fields must match."""
    scan = _make_scan(scan_id="scan-abc", engagement_id="eng-xyz")
    await store.save_scan(scan)

    result = await store.get_scan("scan-abc")

    assert result is not None
    assert result.id == "scan-abc"
    assert result.engagement_id == "eng-xyz"
    assert result.target == "https://example.com"
    assert result.target_type == TargetType.URL
    assert result.status == ScanStatus.PENDING
    assert result.mode == ScanMode.AUTO


@pytest.mark.asyncio
async def test_get_scan_not_found(store):
    """get_scan returns None for a non-existent id."""
    result = await store.get_scan("does-not-exist")
    assert result is None


@pytest.mark.asyncio
async def test_update_scan_status(store):
    """Save a scan as PENDING, update to RUNNING with started_at, verify."""
    scan = _make_scan(scan_id="scan-run")
    await store.save_scan(scan)

    started = _now()
    await store.update_scan_status(
        "scan-run",
        ScanStatus.RUNNING,
        started_at=started,
    )

    result = await store.get_scan("scan-run")
    assert result is not None
    assert result.status == ScanStatus.RUNNING
    assert result.started_at is not None


@pytest.mark.asyncio
async def test_list_scans(store):
    """Save 3 scans, list_scans returns all 3."""
    for i in range(3):
        await store.save_scan(_make_scan(scan_id=f"scan-{i}", engagement_id="eng-001"))

    scans = await store.list_scans()
    assert len(scans) == 3


@pytest.mark.asyncio
async def test_list_scans_filter_by_engagement(store):
    """list_scans with engagement_id filters correctly — 2 different engagements, filter returns 1."""
    await store.save_scan(_make_scan(scan_id="scan-a", engagement_id="eng-A"))
    await store.save_scan(_make_scan(scan_id="scan-b", engagement_id="eng-B"))

    results_a = await store.list_scans(engagement_id="eng-A")
    results_b = await store.list_scans(engagement_id="eng-B")
    results_all = await store.list_scans()

    assert len(results_a) == 1
    assert results_a[0].id == "scan-a"
    assert len(results_b) == 1
    assert results_b[0].id == "scan-b"
    assert len(results_all) == 2


@pytest.mark.asyncio
async def test_save_and_get_tasks(store):
    """Save a scan and a task; get_scan_tasks returns the task with correct fields."""
    scan = _make_scan(scan_id="scan-t")
    task = _make_task(task_id="task-t", scan_id="scan-t")
    await store.save_scan(scan)
    await store.save_task(task)

    tasks = await store.get_scan_tasks("scan-t")

    assert len(tasks) == 1
    t = tasks[0]
    assert t.id == "task-t"
    assert t.scan_id == "scan-t"
    assert t.name == "nmap-scan"
    assert t.tool == "nmap"
    assert t.task_type == TaskType.SHELL
    assert t.status == TaskStatus.PENDING


@pytest.mark.asyncio
async def test_update_task_status(store):
    """Save a task, update status to COMPLETED with exit_code/duration_ms/stdout, verify."""
    scan = _make_scan(scan_id="scan-u")
    task = _make_task(task_id="task-u", scan_id="scan-u")
    await store.save_scan(scan)
    await store.save_task(task)

    await store.update_task_status(
        "task-u",
        TaskStatus.COMPLETED,
        exit_code=0,
        duration_ms=1234,
        stdout="scan output here",
    )

    tasks = await store.get_scan_tasks("scan-u")
    assert len(tasks) == 1
    t = tasks[0]
    assert t.status == TaskStatus.COMPLETED
    assert t.exit_code == 0
    assert t.duration_ms == 1234
    assert t.stdout == "scan output here"
