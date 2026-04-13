"""Tests for ScanEngine approval gate integration."""

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable

import pytest

from opentools.scanner.approval import ApprovalRegistry
from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.engine import ScanEngine
from opentools.scanner.executor.base import TaskExecutor, TaskOutput
from opentools.scanner.models import (
    ApprovalRequirement,
    Scan,
    ScanStatus,
    ScanTask,
    TaskStatus,
    TaskType,
    TargetType,
)
from opentools.shared.progress import EventBus
from opentools.shared.resource_pool import AdaptiveResourcePool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class FakeStore:
    """In-memory store implementing update_task_status / get_task_status."""

    def __init__(self) -> None:
        self._task_statuses: dict[str, dict[str, Any]] = {}

    async def update_task_status(
        self, task_id: str, status: str, **fields: Any
    ) -> None:
        self._task_statuses[task_id] = {"status": status, **fields}

    async def get_task_status(self, task_id: str) -> dict[str, Any] | None:
        return self._task_statuses.get(task_id)


class MockExecutor:
    def __init__(self, results: dict[str, TaskOutput] | None = None):
        self._results = results or {}
        self._default = TaskOutput(exit_code=0, stdout="ok", duration_ms=10)
        self.executed: list[str] = []

    async def execute(
        self,
        task: ScanTask,
        on_output: Callable[[bytes], None],
        cancellation: CancellationToken,
    ) -> TaskOutput:
        self.executed.append(task.id)
        on_output(b"mock output")
        return self._results.get(task.id, self._default)


def _make_scan(scan_id: str = "scan1") -> Scan:
    return Scan(
        id=scan_id,
        engagement_id="eng1",
        target="/tmp/test",
        target_type=TargetType.SOURCE_CODE,
        status=ScanStatus.PENDING,
        created_at=datetime.now(timezone.utc),
    )


def _make_task(
    task_id: str,
    scan_id: str = "scan1",
    depends_on: list[str] | None = None,
    priority: int = 50,
    requires_approval: ApprovalRequirement | None = None,
) -> ScanTask:
    return ScanTask(
        id=task_id,
        scan_id=scan_id,
        name=f"task-{task_id}",
        tool="test-tool",
        task_type=TaskType.SHELL,
        command="echo test",
        depends_on=depends_on or [],
        priority=priority,
        requires_approval=requires_approval,
    )


def _make_gated_engine(
    tasks: list[ScanTask],
    executor: MockExecutor | None = None,
    store: FakeStore | None = None,
    registry: ApprovalRegistry | None = None,
) -> tuple[ScanEngine, MockExecutor, FakeStore, ApprovalRegistry]:
    """Create a ScanEngine wired with approval gate support."""
    pool = AdaptiveResourcePool(
        global_limit=4, group_limits={"approval_gate": 9999}
    )
    mock_exec = executor or MockExecutor()
    fake_store = store or FakeStore()
    approval_reg = registry or ApprovalRegistry()

    executors = {
        TaskType.SHELL: mock_exec,
        TaskType.DOCKER_EXEC: mock_exec,
        TaskType.MCP_CALL: mock_exec,
    }
    engine = ScanEngine(
        scan=_make_scan(),
        resource_pool=pool,
        executors=executors,
        event_bus=EventBus(),
        cancellation=CancellationToken(),
    )
    engine.set_approval_registry(approval_reg)
    engine.set_approval_store(fake_store)
    engine.load_tasks(tasks)

    return engine, mock_exec, fake_store, approval_reg


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEngineApprovalGate:
    @pytest.mark.asyncio
    async def test_approved_task_executes(self):
        """Gated task with 5s timeout: approve it concurrently, verify executor ran."""
        task = _make_task(
            "gated",
            requires_approval=ApprovalRequirement(timeout_seconds=5),
        )
        engine, mock_exec, store, registry = _make_gated_engine(tasks=[task])

        async def approve_soon():
            # Wait until the registry has a pending ticket
            for _ in range(200):
                tickets = registry.pending_ticket_ids()
                if tickets:
                    break
                await asyncio.sleep(0.01)
            else:
                raise AssertionError("No pending ticket appeared")

            ticket_id = next(iter(tickets))
            # Write "approved" to store, then signal the event
            await store.update_task_status("gated", "approved")
            registry.signal(ticket_id)

        asyncio.ensure_future(approve_soon())
        await asyncio.wait_for(engine.run(), timeout=10)

        assert "gated" in mock_exec.executed
        assert engine._tasks["gated"].status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_rejected_task_fails(self):
        """Gated task: write 'rejected' to store. Executor must NOT run."""
        task = _make_task(
            "gated",
            requires_approval=ApprovalRequirement(timeout_seconds=5),
        )
        engine, mock_exec, store, registry = _make_gated_engine(tasks=[task])

        async def reject_soon():
            for _ in range(200):
                tickets = registry.pending_ticket_ids()
                if tickets:
                    break
                await asyncio.sleep(0.01)
            else:
                raise AssertionError("No pending ticket appeared")

            ticket_id = next(iter(tickets))
            await store.update_task_status("gated", "rejected")
            registry.signal(ticket_id)

        asyncio.ensure_future(reject_soon())
        await asyncio.wait_for(engine.run(), timeout=10)

        assert "gated" not in mock_exec.executed
        assert engine._tasks["gated"].status == TaskStatus.FAILED

    @pytest.mark.asyncio
    async def test_timeout_rejects_automatically(self):
        """Gated task with 1s timeout. Don't approve. Verify auto-expiry."""
        task = _make_task(
            "gated",
            requires_approval=ApprovalRequirement(timeout_seconds=1),
        )
        engine, mock_exec, store, registry = _make_gated_engine(tasks=[task])

        await asyncio.wait_for(engine.run(), timeout=10)

        assert "gated" not in mock_exec.executed
        assert engine._tasks["gated"].status == TaskStatus.FAILED
        stored = await store.get_task_status("gated")
        assert stored is not None
        assert stored["status"] == "approval_expired"

    @pytest.mark.asyncio
    async def test_non_gated_task_unaffected(self):
        """Normal task without requires_approval executes normally."""
        task = _make_task("normal")
        engine, mock_exec, store, registry = _make_gated_engine(tasks=[task])

        await asyncio.wait_for(engine.run(), timeout=10)

        assert "normal" in mock_exec.executed
        assert engine._tasks["normal"].status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_parallel_branches_continue_during_gate(self):
        """Two tasks: one gated (1s timeout), one normal. Both ready simultaneously.

        Normal task completes while gated task times out."""
        gated = _make_task(
            "gated",
            requires_approval=ApprovalRequirement(timeout_seconds=1),
        )
        normal = _make_task("normal")

        engine, mock_exec, store, registry = _make_gated_engine(
            tasks=[gated, normal]
        )

        await asyncio.wait_for(engine.run(), timeout=10)

        # Normal task executed
        assert "normal" in mock_exec.executed
        assert engine._tasks["normal"].status == TaskStatus.COMPLETED

        # Gated task timed out, never executed
        assert "gated" not in mock_exec.executed
        assert engine._tasks["gated"].status == TaskStatus.FAILED

    @pytest.mark.asyncio
    async def test_no_gate_without_registry(self):
        """Engine without approval registry configured. Gated task executes immediately."""
        task = _make_task(
            "gated",
            requires_approval=ApprovalRequirement(timeout_seconds=5),
        )
        # Build engine WITHOUT approval registry
        pool = AdaptiveResourcePool(global_limit=4)
        mock_exec = MockExecutor()
        executors = {
            TaskType.SHELL: mock_exec,
            TaskType.DOCKER_EXEC: mock_exec,
            TaskType.MCP_CALL: mock_exec,
        }
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors=executors,
            event_bus=EventBus(),
            cancellation=CancellationToken(),
        )
        engine.load_tasks([task])

        await asyncio.wait_for(engine.run(), timeout=10)

        # Task should have executed immediately — no gate phase
        assert "gated" in mock_exec.executed
        assert engine._tasks["gated"].status == TaskStatus.COMPLETED
