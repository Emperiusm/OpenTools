# HITL Approval Gate + Vultr Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a durable Human-In-The-Loop approval gate to the DAG execution engine and a Vultr cloud provider for ephemeral proxy routing.

**Architecture:** The approval gate is an execution wrapper — not a separate TaskType — that inserts a sleep-until-approved phase into `_execute_task` before the real executor fires. Persistence is SQLite-first: the FastAPI route writes decisions to the database before signaling the in-memory `asyncio.Event`. The Vultr provider implements the existing `CloudNodeProvider` ABC with explicit SSH key injection for automated tunnel bootstrapping.

**Tech Stack:** Python 3.12+, Pydantic v2, asyncio, httpx, aiosqlite, FastAPI, pytest + pytest-asyncio

**Spec:** [2026-04-13-hitl-approval-gate-vultr-provider-design.md](../specs/2026-04-13-hitl-approval-gate-vultr-provider-design.md)

**Depends on:** [2026-04-13-dag-mutation-ephemeral-proxy.md](2026-04-13-dag-mutation-ephemeral-proxy.md) (Phase A Tasks 1-4 and Phase B Task 6)

---

## File Structure

### Phase C — HITL Approval Gate

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `packages/cli/src/opentools/scanner/models.py:54-60,201-231` | Add `AWAITING_APPROVAL` to `TaskStatus`, `ApprovalRequirement` model, new fields on `ScanTask` |
| Create | `packages/cli/src/opentools/scanner/approval.py` | `ApprovalRegistry` singleton |
| Modify | `packages/cli/src/opentools/scanner/engine.py:215-251` | Insert gate phase into `_execute_task` |
| Modify | `packages/web/backend/app/models.py:252-284` | Add approval columns to `ScanTaskRecord` |
| Modify | `packages/web/backend/app/routes/scans.py` | Add gate list/approve/reject endpoints |
| Create | `packages/cli/tests/test_scanner/test_approval_registry.py` | Tests for ApprovalRegistry |
| Create | `packages/cli/tests/test_scanner/test_engine_approval.py` | Integration tests for gate in engine |
| Create | `packages/web/backend/tests/test_gate_routes.py` | Tests for FastAPI gate endpoints |

### Task 6b — Vultr Provider

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `packages/cli/src/opentools/scanner/infra/vultr.py` | `VultrProvider` implementation |
| Create | `packages/cli/tests/test_scanner/test_infra_vultr.py` | Tests with httpx MockTransport |

---

## Phase C: HITL Approval Gate

### Task 10: Model Additions — ApprovalRequirement, TaskStatus, ScanTask Fields

**Files:**
- Modify: `packages/cli/src/opentools/scanner/models.py:54-60` (TaskStatus enum)
- Modify: `packages/cli/src/opentools/scanner/models.py:188-231` (new model + ScanTask fields)
- Test: `packages/cli/tests/test_scanner/test_mutation_models.py` (append)

- [ ] **Step 1: Write failing tests for ApprovalRequirement and new ScanTask fields**

```python
# Append to packages/cli/tests/test_scanner/test_mutation_models.py
# OR create packages/cli/tests/test_scanner/test_approval_models.py

from opentools.scanner.models import (
    ApprovalRequirement,
    ScanTask,
    TaskStatus,
    TaskType,
)


class TestApprovalRequirement:
    def test_defaults(self):
        req = ApprovalRequirement()
        assert req.timeout_seconds == 3600
        assert req.description == ""

    def test_custom_values(self):
        req = ApprovalRequirement(
            timeout_seconds=600,
            description="Deploy Sliver agent on 10.0.0.1",
        )
        assert req.timeout_seconds == 600
        assert req.description == "Deploy Sliver agent on 10.0.0.1"


class TestTaskStatusApproval:
    def test_awaiting_approval_value(self):
        assert TaskStatus.AWAITING_APPROVAL == "awaiting_approval"

    def test_awaiting_approval_in_enum(self):
        assert "awaiting_approval" in [s.value for s in TaskStatus]


class TestScanTaskApprovalFields:
    def test_requires_approval_default_none(self):
        task = ScanTask(
            id="t1", scan_id="s1", name="test",
            tool="nmap", task_type=TaskType.SHELL,
        )
        assert task.requires_approval is None
        assert task.approval_ticket_id is None
        assert task.approval_expires_at is None

    def test_requires_approval_set(self):
        req = ApprovalRequirement(
            timeout_seconds=1800,
            description="Dangerous action",
        )
        task = ScanTask(
            id="t1", scan_id="s1", name="test",
            tool="c2", task_type=TaskType.SHELL,
            requires_approval=req,
        )
        assert task.requires_approval.timeout_seconds == 1800
        assert task.requires_approval.description == "Dangerous action"

    def test_approval_ticket_fields(self):
        from datetime import datetime, timezone
        task = ScanTask(
            id="t1", scan_id="s1", name="test",
            tool="nmap", task_type=TaskType.SHELL,
            approval_ticket_id="gate-t1-abc123",
            approval_expires_at=datetime(2026, 4, 13, 15, 0, 0, tzinfo=timezone.utc),
        )
        assert task.approval_ticket_id == "gate-t1-abc123"
        assert task.approval_expires_at.year == 2026
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_approval_models.py::TestApprovalRequirement::test_defaults -v`
Expected: FAIL with `ImportError: cannot import name 'ApprovalRequirement'`

- [ ] **Step 3: Implement model additions**

In `packages/cli/src/opentools/scanner/models.py`, add `AWAITING_APPROVAL` to `TaskStatus` (after line 60):

```python
class TaskStatus(StrEnum):
    PENDING = "pending"
    BLOCKED = "blocked"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    AWAITING_APPROVAL = "awaiting_approval"
```

Add `ApprovalRequirement` model before `ReactiveEdge` (before line 188):

```python
class ApprovalRequirement(BaseModel):
    """Gate metadata for tasks requiring operator approval before execution."""
    timeout_seconds: int = 3600
    description: str = ""
```

Add new fields to `ScanTask` (after line 231, before the closing of the class):

```python
class ScanTask(BaseModel):
    # ... existing fields through completed_at ...
    requires_approval: Optional[ApprovalRequirement] = None
    approval_ticket_id: Optional[str] = None
    approval_expires_at: Optional[datetime] = None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_approval_models.py -v`
Expected: All PASS

- [ ] **Step 5: Run existing model tests for regression check**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_models.py tests/test_scanner/test_engine.py -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/scanner/models.py packages/cli/tests/test_scanner/test_approval_models.py
git commit -m "feat(models): add ApprovalRequirement, AWAITING_APPROVAL status, approval fields on ScanTask"
```

---

### Task 11: ApprovalRegistry — In-Memory Notification Hub

**Files:**
- Create: `packages/cli/src/opentools/scanner/approval.py`
- Test: `packages/cli/tests/test_scanner/test_approval_registry.py`

- [ ] **Step 1: Write failing tests for ApprovalRegistry**

```python
# packages/cli/tests/test_scanner/test_approval_registry.py
"""Tests for ApprovalRegistry — in-memory notification hub."""

import asyncio

import pytest

from opentools.scanner.approval import ApprovalRegistry


class TestApprovalRegistry:
    def test_register_returns_event(self):
        registry = ApprovalRegistry()
        event = registry.register("ticket-1")
        assert isinstance(event, asyncio.Event)
        assert not event.is_set()

    def test_signal_sets_event(self):
        registry = ApprovalRegistry()
        event = registry.register("ticket-1")
        result = registry.signal("ticket-1")
        assert result is True
        assert event.is_set()

    def test_signal_missing_returns_false(self):
        registry = ApprovalRegistry()
        result = registry.signal("nonexistent")
        assert result is False

    def test_remove_cleans_up(self):
        registry = ApprovalRegistry()
        registry.register("ticket-1")
        registry.remove("ticket-1")
        assert registry.signal("ticket-1") is False

    def test_remove_missing_does_not_raise(self):
        registry = ApprovalRegistry()
        registry.remove("nonexistent")  # should not raise

    def test_has_ticket(self):
        registry = ApprovalRegistry()
        assert registry.has_ticket("ticket-1") is False
        registry.register("ticket-1")
        assert registry.has_ticket("ticket-1") is True

    def test_pending_tickets(self):
        registry = ApprovalRegistry()
        registry.register("ticket-1")
        registry.register("ticket-2")
        assert registry.pending_ticket_ids() == {"ticket-1", "ticket-2"}

    @pytest.mark.asyncio
    async def test_event_wakes_awaiter(self):
        """Verify the full async flow: register → await → signal → wake."""
        registry = ApprovalRegistry()
        event = registry.register("ticket-1")
        woke = False

        async def waiter():
            nonlocal woke
            await asyncio.wait_for(event.wait(), timeout=5.0)
            woke = True

        task = asyncio.ensure_future(waiter())
        await asyncio.sleep(0.05)
        assert not woke

        registry.signal("ticket-1")
        await task
        assert woke

    @pytest.mark.asyncio
    async def test_multiple_gates_independent(self):
        """Two gates: signaling one does not wake the other."""
        registry = ApprovalRegistry()
        event_a = registry.register("a")
        event_b = registry.register("b")

        registry.signal("a")
        assert event_a.is_set()
        assert not event_b.is_set()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_approval_registry.py::TestApprovalRegistry::test_register_returns_event -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement ApprovalRegistry**

```python
# packages/cli/src/opentools/scanner/approval.py
"""ApprovalRegistry — in-memory notification hub for HITL approval gates.

NOT the source of truth. The database is always authoritative for gate
decisions. This registry only provides asyncio.Event handles so that
FastAPI routes can wake sleeping gate coroutines.

If a ticket is missing from the registry (e.g., server restarted before
the engine reconstructed it), the route still writes the decision to
SQLite — the executor will pick it up on its next DB read.
"""

from __future__ import annotations

import asyncio


class ApprovalRegistry:
    """In-memory notification hub mapping ticket IDs to asyncio.Events."""

    def __init__(self) -> None:
        self._events: dict[str, asyncio.Event] = {}

    def register(self, ticket_id: str) -> asyncio.Event:
        """Create and store an event for a gate ticket. Returns the event."""
        event = asyncio.Event()
        self._events[ticket_id] = event
        return event

    def signal(self, ticket_id: str) -> bool:
        """Signal the event if it exists. Returns False if not in registry."""
        event = self._events.get(ticket_id)
        if event is None:
            return False
        event.set()
        return True

    def remove(self, ticket_id: str) -> None:
        """Clean up after a gate resolves."""
        self._events.pop(ticket_id, None)

    def has_ticket(self, ticket_id: str) -> bool:
        """Check if a ticket is registered."""
        return ticket_id in self._events

    def pending_ticket_ids(self) -> set[str]:
        """Return all registered ticket IDs."""
        return set(self._events.keys())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_approval_registry.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/approval.py packages/cli/tests/test_scanner/test_approval_registry.py
git commit -m "feat(approval): add ApprovalRegistry in-memory notification hub"
```

---

### Task 12: Engine Integration — Gate Phase in `_execute_task`

**Files:**
- Modify: `packages/cli/src/opentools/scanner/engine.py:35-69` (`__init__` — add registry + store)
- Modify: `packages/cli/src/opentools/scanner/engine.py:215-251` (`_execute_task` — insert gate phase)
- Test: `packages/cli/tests/test_scanner/test_engine_approval.py`

**Context:** The gate phase inserts between resource acquisition and executor dispatch. It persists `AWAITING_APPROVAL` + `expires_at` to the store, registers an event, sleeps, then reads the decision from the store on wake. The resource pool uses an `approval_gate` group with effectively unlimited slots so sleeping gates don't starve real workers.

- [ ] **Step 1: Write failing integration tests**

```python
# packages/cli/tests/test_scanner/test_engine_approval.py
"""Integration tests: ScanEngine + HITL approval gate."""

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable

import pytest

from opentools.scanner.approval import ApprovalRegistry
from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.engine import ScanEngine
from opentools.scanner.executor.base import TaskOutput
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


class MockExecutor:
    def __init__(self, results: dict[str, TaskOutput] | None = None):
        self._results = results or {}
        self._default = TaskOutput(exit_code=0, stdout="ok", duration_ms=10)
        self.executed: list[str] = []

    async def execute(
        self, task: ScanTask, on_output: Callable[[bytes], None],
        cancellation: CancellationToken,
    ) -> TaskOutput:
        self.executed.append(task.id)
        return self._results.get(task.id, self._default)


class FakeStore:
    """Minimal in-memory store for approval gate testing."""

    def __init__(self) -> None:
        self._task_statuses: dict[str, dict[str, Any]] = {}

    async def update_task_status(self, task_id: str, status: str, **fields) -> None:
        self._task_statuses[task_id] = {"status": status, **fields}

    async def get_task_status(self, task_id: str) -> dict[str, Any] | None:
        return self._task_statuses.get(task_id)


def _make_scan() -> Scan:
    return Scan(
        id="scan-1", engagement_id="eng-1", target="10.0.0.1",
        target_type=TargetType.NETWORK, status=ScanStatus.PENDING,
        created_at=datetime.now(timezone.utc),
    )


def _make_gated_task(
    task_id: str = "gated-task",
    timeout_seconds: int = 3600,
    description: str = "Dangerous action",
) -> ScanTask:
    return ScanTask(
        id=task_id, scan_id="scan-1", name="gated",
        tool="c2-agent", task_type=TaskType.SHELL,
        command="echo approved",
        requires_approval=ApprovalRequirement(
            timeout_seconds=timeout_seconds,
            description=description,
        ),
    )


def _make_engine(
    tasks: list[ScanTask],
    executor: MockExecutor,
    store: FakeStore | None = None,
    registry: ApprovalRegistry | None = None,
) -> ScanEngine:
    pool = AdaptiveResourcePool(
        global_limit=4,
        group_limits={"approval_gate": 9999},
    )
    executors = {
        TaskType.SHELL: executor,
        TaskType.DOCKER_EXEC: executor,
        TaskType.MCP_CALL: executor,
    }
    engine = ScanEngine(
        scan=_make_scan(),
        resource_pool=pool,
        executors=executors,
        event_bus=EventBus(),
        cancellation=CancellationToken(),
    )

    if registry is not None:
        engine.set_approval_registry(registry)
    if store is not None:
        engine.set_approval_store(store)

    engine.load_tasks(tasks)
    return engine


class TestEngineApprovalGate:
    @pytest.mark.asyncio
    async def test_approved_task_executes(self):
        """Gate approved → real executor fires → task completes."""
        executor = MockExecutor()
        store = FakeStore()
        registry = ApprovalRegistry()
        task = _make_gated_task(timeout_seconds=5)
        engine = _make_engine([task], executor, store, registry)

        async def approve_soon():
            # Wait for the gate to register, then approve via store + signal
            for _ in range(50):
                await asyncio.sleep(0.05)
                if registry.has_ticket(registry.pending_ticket_ids().pop()) if registry.pending_ticket_ids() else False:
                    break
            tickets = registry.pending_ticket_ids()
            assert len(tickets) == 1
            ticket_id = tickets.pop()
            # Write-before-signal: persist to store first
            await store.update_task_status(
                task.id, "approved",
                approval_ticket_id=ticket_id,
            )
            registry.signal(ticket_id)

        asyncio.ensure_future(approve_soon())
        await engine.run()

        assert "gated-task" in executor.executed
        assert engine._tasks["gated-task"].status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_rejected_task_fails(self):
        """Gate rejected → executor never fires → task fails."""
        executor = MockExecutor()
        store = FakeStore()
        registry = ApprovalRegistry()
        task = _make_gated_task(timeout_seconds=5)
        engine = _make_engine([task], executor, store, registry)

        async def reject_soon():
            for _ in range(50):
                await asyncio.sleep(0.05)
                if registry.pending_ticket_ids():
                    break
            ticket_id = registry.pending_ticket_ids().pop()
            await store.update_task_status(
                task.id, "rejected",
                approval_ticket_id=ticket_id,
            )
            registry.signal(ticket_id)

        asyncio.ensure_future(reject_soon())
        await engine.run()

        assert "gated-task" not in executor.executed
        assert engine._tasks["gated-task"].status == TaskStatus.FAILED

    @pytest.mark.asyncio
    async def test_timeout_rejects_automatically(self):
        """Gate times out → executor never fires → task fails."""
        executor = MockExecutor()
        store = FakeStore()
        registry = ApprovalRegistry()
        task = _make_gated_task(timeout_seconds=1)  # 1 second timeout
        engine = _make_engine([task], executor, store, registry)

        await engine.run()

        assert "gated-task" not in executor.executed
        assert engine._tasks["gated-task"].status == TaskStatus.FAILED
        # Verify store was updated with expiry
        stored = await store.get_task_status("gated-task")
        assert stored is not None
        assert stored["status"] == "approval_expired"

    @pytest.mark.asyncio
    async def test_non_gated_task_unaffected(self):
        """Tasks without requires_approval execute normally."""
        executor = MockExecutor()
        task = ScanTask(
            id="normal", scan_id="scan-1", name="normal",
            tool="nmap", task_type=TaskType.SHELL, command="echo normal",
        )
        engine = _make_engine([task], executor)
        await engine.run()

        assert "normal" in executor.executed
        assert engine._tasks["normal"].status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_parallel_branches_continue_during_gate(self):
        """Safe branch executes while gated branch is sleeping."""
        executor = MockExecutor()
        store = FakeStore()
        registry = ApprovalRegistry()

        safe_task = ScanTask(
            id="safe", scan_id="scan-1", name="safe",
            tool="nmap", task_type=TaskType.SHELL, command="echo safe",
        )
        gated_task = _make_gated_task(timeout_seconds=1)

        engine = _make_engine([safe_task, gated_task], executor, store, registry)
        await engine.run()

        # Safe branch ran immediately; gated branch timed out
        assert "safe" in executor.executed
        assert "gated-task" not in executor.executed
        assert engine._tasks["safe"].status == TaskStatus.COMPLETED
        assert engine._tasks["gated-task"].status == TaskStatus.FAILED

    @pytest.mark.asyncio
    async def test_no_gate_without_registry(self):
        """If no registry set, gated tasks execute immediately (no gate)."""
        executor = MockExecutor()
        task = _make_gated_task(timeout_seconds=5)
        engine = _make_engine([task], executor)  # no registry, no store
        await engine.run()

        assert "gated-task" in executor.executed
        assert engine._tasks["gated-task"].status == TaskStatus.COMPLETED
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine_approval.py::TestEngineApprovalGate::test_non_gated_task_unaffected -v`
Expected: FAIL with `AttributeError: 'ScanEngine' object has no attribute 'set_approval_registry'`

- [ ] **Step 3: Add approval fields to ScanEngine.__init__**

In `packages/cli/src/opentools/scanner/engine.py`, add after the existing `_pipeline_results` field (around line 69):

```python
        # Approval gate (optional — engine works without it)
        self._approval_registry: Any | None = None
        self._approval_store: Any | None = None
```

Add public setters after the existing `set_cache` method:

```python
    def set_approval_registry(self, registry: Any) -> None:
        """Set the ApprovalRegistry for HITL gate support."""
        self._approval_registry = registry

    def set_approval_store(self, store: Any) -> None:
        """Set the store for persisting gate state."""
        self._approval_store = store
```

- [ ] **Step 4: Modify _execute_task — insert gate phase**

Replace the existing `_execute_task` method (lines 215-251) with:

```python
    async def _execute_task(
        self, task: ScanTask, executor: TaskExecutor
    ) -> TaskOutput:
        """Check cache → gate phase → acquire resource → dispatch to executor → release."""
        # Cache check
        if task.cache_key and task.cache_key in self._cache:
            return self._cache[task.cache_key]

        # --- GATE PHASE (if task requires approval and registry is configured) ---
        if (
            task.requires_approval is not None
            and self._approval_registry is not None
            and self._approval_store is not None
        ):
            gate_result = await self._run_approval_gate(task)
            if gate_result is not None:
                return gate_result  # rejected or expired

        # --- NORMAL EXECUTION ---
        resource_group = task.resource_group or task.task_type.value

        if task.retry_policy is not None:
            from opentools.shared.retry import execute_with_retry

            async def _attempt() -> TaskOutput:
                await self._pool.acquire(task.id, task.priority, resource_group)
                try:
                    return await executor.execute(
                        task, lambda _chunk: None, self._cancellation
                    )
                finally:
                    self._pool.release(resource_group)

            output = await execute_with_retry(_attempt, task.retry_policy)
        else:
            await self._pool.acquire(task.id, task.priority, resource_group)
            try:
                output = await executor.execute(
                    task, lambda _chunk: None, self._cancellation
                )
            finally:
                self._pool.release(resource_group)

        # Populate cache on success
        if task.cache_key and output.exit_code == 0:
            self._cache[task.cache_key] = output.model_copy(update={"cached": True})

        return output

    async def _run_approval_gate(self, task: ScanTask) -> TaskOutput | None:
        """Execute the approval gate phase. Returns None if approved (proceed),
        or a TaskOutput if rejected/expired (stop)."""
        import uuid
        from datetime import datetime, timedelta, timezone

        timeout = task.requires_approval.timeout_seconds
        ticket_id = f"gate-{task.id}-{uuid.uuid4().hex[:8]}"
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=timeout)

        # 1. Persist to store (source of truth)
        task.approval_ticket_id = ticket_id
        task.approval_expires_at = expires_at
        await self._approval_store.update_task_status(
            task.id, TaskStatus.AWAITING_APPROVAL.value,
            approval_ticket_id=ticket_id,
            approval_expires_at=expires_at.isoformat(),
        )

        # 2. Publish SSE event (if event bus supports it)
        # The event bus is best-effort; failure here doesn't block the gate.
        try:
            self._event_bus.publish({
                "type": "approval_required",
                "scan_id": self.scan.id,
                "task_id": task.id,
                "ticket_id": ticket_id,
                "tool": task.tool,
                "command": task.command,
                "description": task.requires_approval.description,
                "expires_at": expires_at.isoformat(),
            })
        except Exception:
            pass

        # 3. Register event and sleep
        event = self._approval_registry.register(ticket_id)

        remaining = (expires_at - datetime.now(timezone.utc)).total_seconds()
        if remaining <= 0:
            self._approval_registry.remove(ticket_id)
            await self._approval_store.update_task_status(
                task.id, "approval_expired",
            )
            return TaskOutput(exit_code=2, stderr="approval expired before gate could sleep")

        # Acquire from unlimited approval_gate group while sleeping
        await self._pool.acquire(task.id, task.priority, "approval_gate")
        try:
            try:
                await asyncio.wait_for(event.wait(), timeout=remaining)
            except asyncio.TimeoutError:
                pass  # handled by DB read below
        finally:
            self._pool.release("approval_gate")
            self._approval_registry.remove(ticket_id)

        # 4. READ TRUTH from store (never trust why we woke up)
        stored = await self._approval_store.get_task_status(task.id)
        if stored is not None:
            status = stored.get("status", "")
        else:
            status = ""

        if status == "approved":
            # Gate passed — update task status back to RUNNING and return None
            # to signal _execute_task to proceed to the real executor
            task.status = TaskStatus.RUNNING
            return None

        if status == "rejected":
            return TaskOutput(
                exit_code=1,
                stderr="rejected by operator",
            )

        # Timeout or unknown state
        await self._approval_store.update_task_status(
            task.id, "approval_expired",
        )
        return TaskOutput(
            exit_code=2,
            stderr="approval expired",
        )
```

- [ ] **Step 5: Run integration tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine_approval.py -v`
Expected: All PASS

- [ ] **Step 6: Run existing engine tests for regression check**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine.py -v`
Expected: All PASS — no regressions. Tasks without `requires_approval` are unaffected.

- [ ] **Step 7: Commit**

```bash
git add packages/cli/src/opentools/scanner/engine.py packages/cli/tests/test_scanner/test_engine_approval.py
git commit -m "feat(engine): integrate HITL approval gate phase into _execute_task"
```

---

### Task 13: FastAPI Gate Endpoints — List, Approve, Reject

**Files:**
- Modify: `packages/web/backend/app/models.py:252-284` (add columns to ScanTaskRecord)
- Modify: `packages/web/backend/app/routes/scans.py` (add gate endpoints after cancel endpoint)
- Test: `packages/web/backend/tests/test_gate_routes.py`

**Context:** The approve/reject routes enforce **write-before-signal**: they update the database first, then signal the in-memory event. The `ApprovalRegistry` singleton is stored in `_active_scans[scan_id]` alongside the engine reference, following the existing pattern at [api.py:199](packages/cli/src/opentools/scanner/api.py#L199).

- [ ] **Step 1: Add approval columns to ScanTaskRecord**

In `packages/web/backend/app/models.py`, add after line 284 (after `completed_at`):

```python
class ScanTaskRecord(SQLModel, table=True):
    # ... existing fields ...
    # Approval gate fields
    approval_ticket_id: Optional[str] = None
    approval_expires_at: Optional[datetime] = Field(default=None, **_TZ_KW)
```

- [ ] **Step 2: Add gate request/response models and endpoints to scans.py**

Append to `packages/web/backend/app/routes/scans.py`, after the cancel endpoint (after line 380):

```python
# ---------------------------------------------------------------------------
# Approval gate endpoints
# ---------------------------------------------------------------------------


class GateResponse(BaseModel):
    ticket_id: str
    task_id: str
    tool: str
    command: Optional[str] = None
    description: str
    status: str
    expires_at: Optional[str] = None


class GateDecisionResponse(BaseModel):
    ticket_id: str
    decision: str


class GateRejectRequest(BaseModel):
    reason: str = "operator rejected"


@router.get("/{scan_id}/gates")
async def list_pending_gates(
    scan_id: str,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List tasks awaiting operator approval for a scan."""
    svc = ScanService(session, user)
    scan = await svc.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    tasks = await svc.get_scan_tasks(scan_id)
    gates = []
    for t in tasks:
        if t.status == "awaiting_approval" and t.approval_ticket_id:
            gates.append(GateResponse(
                ticket_id=t.approval_ticket_id,
                task_id=t.id,
                tool=t.tool,
                command=t.command,
                description="",  # extracted from requires_approval JSON if available
                status=t.status,
                expires_at=t.approval_expires_at.isoformat() if t.approval_expires_at else None,
            ))
    return {"scan_id": scan_id, "gates": gates}


@router.post("/{scan_id}/gates/{ticket_id}/approve")
async def approve_gate(
    scan_id: str,
    ticket_id: str,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Approve a pending approval gate. Write-before-signal."""
    svc = ScanService(session, user)

    # 1. Validate
    task_record = await svc.get_task_by_ticket(scan_id, ticket_id)
    if task_record is None:
        raise HTTPException(status_code=404, detail="Gate ticket not found")
    if task_record.status != "awaiting_approval":
        raise HTTPException(
            status_code=409,
            detail=f"Gate already resolved: {task_record.status}",
        )

    # 2. PERSIST FIRST (source of truth)
    await svc.update_task_approval_status(task_record.id, "approved")
    await session.commit()

    # 3. Signal event (best-effort tripwire)
    from opentools.scanner.api import _active_scans
    entry = _active_scans.get(scan_id, {})
    registry = entry.get("approval_registry")
    if registry is not None:
        registry.signal(ticket_id)

    return GateDecisionResponse(ticket_id=ticket_id, decision="approved")


@router.post("/{scan_id}/gates/{ticket_id}/reject")
async def reject_gate(
    scan_id: str,
    ticket_id: str,
    body: GateRejectRequest = GateRejectRequest(),
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Reject a pending approval gate. Write-before-signal."""
    svc = ScanService(session, user)

    # 1. Validate
    task_record = await svc.get_task_by_ticket(scan_id, ticket_id)
    if task_record is None:
        raise HTTPException(status_code=404, detail="Gate ticket not found")
    if task_record.status != "awaiting_approval":
        raise HTTPException(
            status_code=409,
            detail=f"Gate already resolved: {task_record.status}",
        )

    # 2. PERSIST FIRST
    await svc.update_task_approval_status(task_record.id, "rejected")
    await session.commit()

    # 3. Signal event
    from opentools.scanner.api import _active_scans
    entry = _active_scans.get(scan_id, {})
    registry = entry.get("approval_registry")
    if registry is not None:
        registry.signal(ticket_id)

    return GateDecisionResponse(ticket_id=ticket_id, decision="rejected")
```

- [ ] **Step 3: Add helper methods to ScanService**

These are the two new methods the gate routes need. Add to `packages/web/backend/app/services/scan_service.py`:

```python
    async def get_task_by_ticket(
        self, scan_id: str, ticket_id: str
    ) -> ScanTaskRecord | None:
        """Find a task by its approval ticket ID within a scan."""
        from sqlalchemy import select
        stmt = (
            select(ScanTaskRecord)
            .where(ScanTaskRecord.scan_id == scan_id)
            .where(ScanTaskRecord.approval_ticket_id == ticket_id)
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_task_approval_status(
        self, task_id: str, status: str
    ) -> None:
        """Update a task's status (for gate approval/rejection)."""
        from sqlalchemy import update
        stmt = (
            update(ScanTaskRecord)
            .where(ScanTaskRecord.id == task_id)
            .values(status=status)
        )
        await self.session.execute(stmt)
```

- [ ] **Step 4: Write route tests**

```python
# packages/web/backend/tests/test_gate_routes.py
"""Tests for approval gate API routes."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_gates_empty(client: AsyncClient, auth_headers: dict):
    """No pending gates returns empty list."""
    # This test depends on the conftest fixtures creating a scan
    # Minimal smoke test — full integration requires seeded data
    resp = await client.get(
        "/api/v1/scans/nonexistent/gates", headers=auth_headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_approve_missing_ticket(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/v1/scans/scan-1/gates/nonexistent/approve",
        headers=auth_headers,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_reject_missing_ticket(client: AsyncClient, auth_headers: dict):
    resp = await client.post(
        "/api/v1/scans/scan-1/gates/nonexistent/reject",
        headers=auth_headers,
        json={"reason": "test"},
    )
    assert resp.status_code == 404
```

- [ ] **Step 5: Run tests**

Run: `cd packages/web/backend && python -m pytest tests/test_gate_routes.py -v`
Expected: PASS (404 cases)

- [ ] **Step 6: Commit**

```bash
git add packages/web/backend/app/models.py packages/web/backend/app/routes/scans.py packages/web/backend/app/services/scan_service.py packages/web/backend/tests/test_gate_routes.py
git commit -m "feat(api): add HITL gate endpoints — list, approve, reject with write-before-signal"
```

---

## Task 6b: Vultr Provider

### Task 6b: VultrProvider Implementation

**Files:**
- Create: `packages/cli/src/opentools/scanner/infra/vultr.py`
- Test: `packages/cli/tests/test_scanner/test_infra_vultr.py`

**Context:** Implements `CloudNodeProvider` ABC (defined in Phase B Task 6). Uses `httpx.AsyncClient` with `MockTransport` for testing. The `sshkey_id` array is a hard requirement in the creation payload — without it, the instance boots with no authorized keys and the SSH tunnel fails.

- [ ] **Step 1: Write failing tests for VultrProvider**

```python
# packages/cli/tests/test_scanner/test_infra_vultr.py
"""Tests for VultrProvider — ephemeral Vultr instance provisioning."""

import json

import httpx
import pytest

from opentools.scanner.infra.provider import (
    ProvisioningError,
    ProvisioningTimeout,
)
from opentools.scanner.infra.vultr import VultrProvider


class TestVultrProviderCreate:
    @pytest.mark.asyncio
    async def test_create_sends_correct_payload(self):
        captured = {}

        async def handler(request: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(request.content)
            captured["url"] = str(request.url)
            return httpx.Response(202, json={
                "instance": {"id": "vtr-abc123"},
            })

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(
            transport=transport,
            base_url="https://api.vultr.com/v2",
        )
        provider = VultrProvider(client=client)

        result = await provider.create_node(
            region="ewr",
            ssh_public_key="ssh-key-uuid-1234",
            tags=["opentools-ephemeral-proxy", "scan:scan-1"],
        )

        assert result == "vtr-abc123"
        body = captured["body"]
        assert body["region"] == "ewr"
        assert body["plan"] == "vc2-1c-0.5gb"
        assert body["os_id"] == 2284
        assert body["sshkey_id"] == ["ssh-key-uuid-1234"]
        assert "opentools-ephemeral-proxy" in body["tags"]
        assert body["backups"] == "disabled"
        assert body["activation_email"] is False

    @pytest.mark.asyncio
    async def test_create_returns_instance_id(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(202, json={
                "instance": {"id": "vtr-def456"},
            })

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.vultr.com/v2")
        provider = VultrProvider(client=client)

        result = await provider.create_node("lax", "key-id", ["tag"])
        assert result == "vtr-def456"


class TestVultrProviderPoll:
    @pytest.mark.asyncio
    async def test_active_with_ip(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "instance": {
                    "id": "vtr-abc",
                    "status": "active",
                    "power_status": "running",
                    "main_ip": "149.28.1.1",
                },
            })

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.vultr.com/v2")
        provider = VultrProvider(client=client)

        status, ip = await provider.poll_status("vtr-abc")
        assert status == "active"
        assert ip == "149.28.1.1"

    @pytest.mark.asyncio
    async def test_active_with_zero_ip_is_creating(self):
        """Vultr reports active before IP is assigned — treat as creating."""
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "instance": {
                    "id": "vtr-abc",
                    "status": "active",
                    "power_status": "running",
                    "main_ip": "0.0.0.0",
                },
            })

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.vultr.com/v2")
        provider = VultrProvider(client=client)

        status, ip = await provider.poll_status("vtr-abc")
        assert status == "creating"
        assert ip is None

    @pytest.mark.asyncio
    async def test_pending_status(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "instance": {
                    "id": "vtr-abc",
                    "status": "pending",
                    "power_status": "stopped",
                    "main_ip": "0.0.0.0",
                },
            })

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.vultr.com/v2")
        provider = VultrProvider(client=client)

        status, ip = await provider.poll_status("vtr-abc")
        assert status == "creating"
        assert ip is None


class TestVultrProviderDestroy:
    @pytest.mark.asyncio
    async def test_destroy_204(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(204)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.vultr.com/v2")
        provider = VultrProvider(client=client)

        await provider.destroy_node("vtr-abc")  # should not raise

    @pytest.mark.asyncio
    async def test_destroy_404_idempotent(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.vultr.com/v2")
        provider = VultrProvider(client=client)

        await provider.destroy_node("vtr-abc")  # should not raise


class TestVultrProviderListByTag:
    @pytest.mark.asyncio
    async def test_list_nodes_by_tag(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            assert "tag=opentools-ephemeral-proxy" in str(request.url)
            return httpx.Response(200, json={
                "instances": [
                    {"id": "vtr-1"},
                    {"id": "vtr-2"},
                ],
            })

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.vultr.com/v2")
        provider = VultrProvider(client=client)

        ids = await provider.list_nodes_by_tag("opentools-ephemeral-proxy")
        assert ids == ["vtr-1", "vtr-2"]

    @pytest.mark.asyncio
    async def test_list_empty(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"instances": []})

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.vultr.com/v2")
        provider = VultrProvider(client=client)

        ids = await provider.list_nodes_by_tag("opentools-ephemeral-proxy")
        assert ids == []


class TestVultrProviderWaitUntilReady:
    @pytest.mark.asyncio
    async def test_waits_for_ip_assignment(self):
        call_count = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return httpx.Response(200, json={
                    "instance": {
                        "id": "vtr-abc", "status": "active",
                        "power_status": "running", "main_ip": "0.0.0.0",
                    },
                })
            return httpx.Response(200, json={
                "instance": {
                    "id": "vtr-abc", "status": "active",
                    "power_status": "running", "main_ip": "149.28.1.1",
                },
            })

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.vultr.com/v2")
        provider = VultrProvider(client=client)

        ip = await provider.wait_until_ready("vtr-abc", poll_interval=0.01, max_polls=10)
        assert ip == "149.28.1.1"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_timeout_raises(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "instance": {
                    "id": "vtr-abc", "status": "pending",
                    "power_status": "stopped", "main_ip": "0.0.0.0",
                },
            })

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.vultr.com/v2")
        provider = VultrProvider(client=client)

        with pytest.raises(ProvisioningTimeout):
            await provider.wait_until_ready("vtr-abc", poll_interval=0.01, max_polls=3)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_infra_vultr.py::TestVultrProviderCreate::test_create_sends_correct_payload -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement VultrProvider**

```python
# packages/cli/src/opentools/scanner/infra/vultr.py
"""VultrProvider — ephemeral Vultr instance provisioning via REST API.

Implements CloudNodeProvider ABC. Uses httpx.AsyncClient for all HTTP
calls — fully async, never blocks the event loop.

IMPORTANT: The sshkey_id array is REQUIRED in the creation payload.
Without it, the instance boots with no authorized SSH keys and the
automated tunnel establishment will fail with Permission denied.
"""

from __future__ import annotations

import uuid

import httpx

from opentools.scanner.infra.provider import CloudNodeProvider


class VultrProvider(CloudNodeProvider):
    """Provision ephemeral instances via the Vultr API."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    @classmethod
    def from_token(cls, api_token: str) -> VultrProvider:
        """Create a provider with a new httpx client using the given API token."""
        client = httpx.AsyncClient(
            base_url="https://api.vultr.com/v2",
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=30.0,
        )
        return cls(client=client)

    async def create_node(
        self, region: str, ssh_public_key: str, tags: list[str],
    ) -> str:
        """Create a Vultr instance. ssh_public_key must be a Vultr SSH key UUID."""
        resp = await self._client.post("/instances", json={
            "region": region,
            "plan": "vc2-1c-0.5gb",
            "os_id": 2284,  # Ubuntu 24.04 LTS
            "label": f"ot-proxy-{uuid.uuid4().hex[:8]}",
            "sshkey_id": [ssh_public_key],
            "tags": tags,
            "backups": "disabled",
            "activation_email": False,
        })
        resp.raise_for_status()
        return resp.json()["instance"]["id"]

    async def poll_status(self, provider_id: str) -> tuple[str, str | None]:
        """Poll instance status. Returns ("active", ip) only when IP is assigned."""
        resp = await self._client.get(f"/instances/{provider_id}")
        resp.raise_for_status()
        instance = resp.json()["instance"]

        vultr_status = instance.get("status", "")
        power_status = instance.get("power_status", "")
        main_ip = instance.get("main_ip", "0.0.0.0")

        # Vultr can report "active" before IP is assigned
        if (
            vultr_status == "active"
            and power_status == "running"
            and main_ip != "0.0.0.0"
        ):
            return "active", main_ip

        return "creating", None

    async def destroy_node(self, provider_id: str) -> None:
        """Destroy a Vultr instance. Idempotent — 404 is not an error."""
        resp = await self._client.delete(f"/instances/{provider_id}")
        if resp.status_code not in (204, 404):
            resp.raise_for_status()

    async def list_nodes_by_tag(self, tag: str) -> list[str]:
        """List all instance IDs with the given tag (for orphan sweeping)."""
        resp = await self._client.get("/instances", params={"tag": tag})
        resp.raise_for_status()
        instances = resp.json().get("instances", [])
        return [inst["id"] for inst in instances]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_infra_vultr.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/infra/vultr.py packages/cli/tests/test_scanner/test_infra_vultr.py
git commit -m "feat(infra): add VultrProvider with SSH key injection and 0.0.0.0 IP guard"
```

---

## Appendix: Combined Build Order (All Phases)

For reference, here is the complete task sequence across all three phases:

**Phase A — Dynamic DAG Mutation (existing plan)**
1. KillChainState + IntelBundle models
2. OutputAnalyzer protocol + NmapAnalyzer
3. MutationStrategy protocol + RedisProbeStrategy
4. Engine integration (mutation layer in `_mark_completed`)

**Phase B — Ephemeral Proxy Routing (existing plan)**
5. Add `env` param to `run_streaming`
6. CloudNodeProvider ABC + DigitalOcean implementation
6b. **VultrProvider implementation** ← NEW
7. `ephemeral_proxy` context manager + shielded teardown
8. ProxiedShellExecutor
9. Orphan sweeper

**Phase C — HITL Approval Gate** ← NEW
10. Model additions (ApprovalRequirement, AWAITING_APPROVAL, ScanTask fields)
11. ApprovalRegistry (in-memory notification hub)
12. Engine integration (gate phase in `_execute_task`)
13. FastAPI gate endpoints (list, approve, reject)
