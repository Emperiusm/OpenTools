"""ScanEngine — DAG-based task executor for security scans."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any, Callable

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.base import TaskExecutor, TaskOutput
from opentools.scanner.models import (
    ReactiveEdge,
    Scan,
    ScanStatus,
    ScanTask,
    TaskStatus,
    TaskType,
)
from opentools.shared.progress import EventBus
from opentools.shared.resource_pool import AdaptiveResourcePool


class ScanEngine:
    """DAG-based scan task executor.

    Maintains the task graph, schedules ready tasks respecting priority and
    concurrency (via AdaptiveResourcePool), dispatches to the appropriate
    executor, evaluates reactive edges on completion, and supports
    pause/resume/cancellation.
    """

    def __init__(
        self,
        scan: Scan,
        resource_pool: AdaptiveResourcePool,
        executors: dict[TaskType, TaskExecutor],
        event_bus: EventBus,
        cancellation: CancellationToken,
    ) -> None:
        self.scan = scan
        self._pool = resource_pool
        self._executors = executors
        self._event_bus = event_bus
        self._cancellation = cancellation

        # Task graph
        self._tasks: dict[str, ScanTask] = {}
        self._dependents: dict[str, set[str]] = defaultdict(set)
        self._completed: set[str] = set()
        self._failed: set[str] = set()
        self._running: set[str] = set()
        self._skipped: set[str] = set()

        # Pause state
        self._paused = False

        # Edge evaluators: name → callable(task, output, edge) → list[ScanTask]
        self._edge_evaluators: dict[str, Any] = {}

        # Cache: cache_key → TaskOutput (stub for real cache backend)
        self._cache: dict[str, TaskOutput] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def tasks(self) -> dict[str, ScanTask]:
        return dict(self._tasks)

    @property
    def is_paused(self) -> bool:
        return self._paused

    def load_tasks(self, tasks: list[ScanTask]) -> None:
        """Load tasks into the graph and build dependency index."""
        task_ids = {t.id for t in tasks} | set(self._tasks.keys())
        for t in tasks:
            for dep in t.depends_on:
                if dep not in task_ids:
                    raise ValueError(
                        f"Task '{t.id}' depends on '{dep}' which is not in the task graph"
                    )
        for t in tasks:
            self._tasks[t.id] = t
            for dep in t.depends_on:
                self._dependents[dep].add(t.id)

    def ready_task_ids(self) -> set[str]:
        """Return IDs of tasks whose dependencies are all satisfied."""
        ready = set()
        terminal = self._completed | self._skipped
        non_ready = self._running | terminal | self._failed
        for task_id, task in self._tasks.items():
            if task_id in non_ready:
                continue
            if all(dep in terminal for dep in task.depends_on):
                ready.add(task_id)
        return ready

    def ready_tasks_by_priority(self) -> list[ScanTask]:
        """Return ready tasks sorted by priority (lowest number = highest priority)."""
        ready_ids = self.ready_task_ids()
        tasks = [self._tasks[tid] for tid in ready_ids]
        tasks.sort(key=lambda t: t.priority)
        return tasks

    def register_edge_evaluator(self, name: str, evaluator: Any) -> None:
        """Register a reactive edge evaluator."""
        self._edge_evaluators[name] = evaluator

    def set_cache(self, cache: dict[str, TaskOutput]) -> None:
        """Set the in-memory output cache (stub for real cache backend)."""
        self._cache = cache

    async def run(self) -> None:
        """Execute the full task DAG."""
        self.scan = self.scan.model_copy(update={"status": ScanStatus.RUNNING})
        await self._schedule_loop()
        self._finalize()

    async def pause(self) -> None:
        """Stop scheduling new tasks. In-flight tasks run to completion."""
        self._paused = True
        self.scan = self.scan.model_copy(update={"status": ScanStatus.PAUSED})

    async def resume(self) -> None:
        """Resume scheduling from where we left off."""
        self._paused = False
        self.scan = self.scan.model_copy(update={"status": ScanStatus.RUNNING})

    # ------------------------------------------------------------------
    # Scheduling
    # ------------------------------------------------------------------

    async def _schedule_loop(self) -> None:
        """Main scheduling loop: dispatch ready tasks, wait for completion."""
        in_flight: dict[str, asyncio.Task] = {}

        while True:
            if self._cancellation.is_cancelled:
                for task in in_flight.values():
                    task.cancel()
                # Wait for cancelled tasks to finish
                if in_flight:
                    await asyncio.gather(*in_flight.values(), return_exceptions=True)
                break

            if self._paused:
                await asyncio.sleep(0.05)
                continue

            # Dispatch ready tasks
            ready = self.ready_tasks_by_priority()
            for scan_task in ready:
                if scan_task.id in in_flight:
                    continue
                executor = self._executors.get(scan_task.task_type)
                if executor is None:
                    self._mark_failed(scan_task.id, f"No executor for {scan_task.task_type}")
                    self._skip_dependents(scan_task.id)
                    continue
                self._running.add(scan_task.id)
                self._tasks[scan_task.id] = scan_task.model_copy(
                    update={"status": TaskStatus.RUNNING}
                )
                coro = self._execute_task(scan_task, executor)
                in_flight[scan_task.id] = asyncio.ensure_future(coro)

            if not in_flight:
                break

            done, _ = await asyncio.wait(
                in_flight.values(), return_when=asyncio.FIRST_COMPLETED
            )

            for completed_future in done:
                task_id = None
                for tid, fut in in_flight.items():
                    if fut is completed_future:
                        task_id = tid
                        break
                if task_id is None:
                    continue

                del in_flight[task_id]
                self._running.discard(task_id)

                try:
                    output: TaskOutput = completed_future.result()
                except Exception as exc:
                    self._mark_failed(task_id, str(exc))
                    self._skip_dependents(task_id)
                    continue

                if output.exit_code is not None and output.exit_code != 0:
                    self._mark_failed(task_id, output.stderr or f"exit code {output.exit_code}")
                    self._skip_dependents(task_id)
                else:
                    self._mark_completed(task_id, output)

    # ------------------------------------------------------------------
    # Task execution
    # ------------------------------------------------------------------

    async def _execute_task(
        self, task: ScanTask, executor: TaskExecutor
    ) -> TaskOutput:
        """Check cache → acquire resource → dispatch to executor → release."""
        # Cache check
        if task.cache_key and task.cache_key in self._cache:
            return self._cache[task.cache_key]

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

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------

    def _mark_completed(self, task_id: str, output: TaskOutput) -> None:
        task = self._tasks[task_id]
        self._tasks[task_id] = task.model_copy(
            update={
                "status": TaskStatus.COMPLETED,
                "exit_code": output.exit_code,
                "stdout": output.stdout,
                "stderr": output.stderr,
                "duration_ms": output.duration_ms,
                "cached": output.cached,
            }
        )
        self._completed.add(task_id)

        # Evaluate reactive edges
        new_tasks = self._evaluate_edges(task, output)
        if new_tasks:
            self._inject_tasks(new_tasks)

    def _mark_failed(self, task_id: str, reason: str) -> None:
        task = self._tasks[task_id]
        self._tasks[task_id] = task.model_copy(
            update={"status": TaskStatus.FAILED, "stderr": reason}
        )
        self._failed.add(task_id)

    def _skip_dependents(self, failed_task_id: str) -> None:
        """Recursively skip all downstream tasks of a failed task."""
        to_skip = list(self._dependents.get(failed_task_id, set()))
        while to_skip:
            dep_id = to_skip.pop()
            if dep_id in self._skipped or dep_id in self._completed:
                continue
            self._tasks[dep_id] = self._tasks[dep_id].model_copy(
                update={"status": TaskStatus.SKIPPED}
            )
            self._skipped.add(dep_id)
            to_skip.extend(self._dependents.get(dep_id, set()))

    def _finalize(self) -> None:
        """Set final scan status based on task outcomes."""
        if self._cancellation.is_cancelled:
            self.scan = self.scan.model_copy(update={"status": ScanStatus.CANCELLED})
        elif self._completed:
            self.scan = self.scan.model_copy(update={"status": ScanStatus.COMPLETED})
        else:
            self.scan = self.scan.model_copy(update={"status": ScanStatus.FAILED})

    # ------------------------------------------------------------------
    # Reactive edges
    # ------------------------------------------------------------------

    def _evaluate_edges(self, task: ScanTask, output: TaskOutput) -> list[ScanTask]:
        """Evaluate reactive edges for a completed task."""
        new_tasks: list[ScanTask] = []

        for edge in task.reactive_edges:
            evaluator = self._edge_evaluators.get(edge.evaluator)
            if evaluator is None:
                continue

            spawned = evaluator(task, output, edge)
            if not spawned:
                continue

            remaining = edge.max_spawns - len(new_tasks)
            spawned = spawned[:max(0, remaining)]

            for s in spawned:
                if s.id not in self._tasks:
                    new_tasks.append(s)

        return new_tasks

    def _inject_tasks(self, tasks: list[ScanTask]) -> None:
        """Add dynamically spawned tasks to the graph."""
        for t in tasks:
            if t.id in self._tasks:
                continue
            self._tasks[t.id] = t
            for dep in t.depends_on:
                self._dependents[dep].add(t.id)
