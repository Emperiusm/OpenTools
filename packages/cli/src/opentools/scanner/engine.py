"""ScanEngine — DAG-based task executor for security scans."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any, Callable, TYPE_CHECKING

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
from opentools.scanner.mutation.models import KillChainState
from opentools.shared.progress import EventBus
from opentools.shared.resource_pool import AdaptiveResourcePool

if TYPE_CHECKING:
    from opentools.scanner.pipeline import ScanPipeline


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
        pipeline: ScanPipeline | None = None,
    ) -> None:
        self.scan = scan
        self._pool = resource_pool
        self._executors = executors
        self._event_bus = event_bus
        self._cancellation = cancellation
        self._pipeline = pipeline

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

        # Pipeline results: task_id → output, processed during scheduling
        self._pipeline_results: dict[str, TaskOutput] = {}

        # Mutation layer (optional — engine works without it)
        self._analyzer_registry: Any | None = None
        self._mutation_strategies: list[Any] = []
        self._kill_chain = KillChainState()
        self._max_mutation_spawns: int = 100

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

    def set_analyzer_registry(self, registry: Any) -> None:
        """Set the OutputAnalyzer registry for mutation layer."""
        self._analyzer_registry = registry

    def set_mutation_strategies(self, strategies: list[Any]) -> None:
        """Set the mutation strategies for dynamic task injection."""
        self._mutation_strategies = list(strategies)

    def set_max_mutation_spawns(self, limit: int) -> None:
        """Set the global budget for mutation-spawned tasks."""
        self._max_mutation_spawns = limit

    @property
    def kill_chain_state(self) -> KillChainState:
        """Read-only access to accumulated attack surface state."""
        return self._kill_chain

    async def run(self) -> None:
        """Execute the full task DAG."""
        self.scan.status = ScanStatus.RUNNING
        await self._schedule_loop()
        self._finalize()

    async def pause(self) -> None:
        """Stop scheduling new tasks. In-flight tasks run to completion."""
        self._paused = True
        self.scan.status = ScanStatus.PAUSED

    async def resume(self) -> None:
        """Resume scheduling from where we left off."""
        self._paused = False
        self.scan.status = ScanStatus.RUNNING

    # ------------------------------------------------------------------
    # Scheduling
    # ------------------------------------------------------------------

    async def _schedule_loop(self) -> None:
        """Main scheduling loop: dispatch ready tasks, wait for completion."""
        in_flight: dict[str, asyncio.Task] = {}
        future_to_task: dict[asyncio.Task, str] = {}

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

            # Process any pending pipeline results
            await self._process_pipeline_results()

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
                scan_task.status = TaskStatus.RUNNING
                coro = self._execute_task(scan_task, executor)
                in_flight[scan_task.id] = asyncio.ensure_future(coro)
                future_to_task[in_flight[scan_task.id]] = scan_task.id

            if not in_flight:
                # Process remaining pipeline results before exiting
                await self._process_pipeline_results()
                break

            done, _ = await asyncio.wait(
                in_flight.values(), return_when=asyncio.FIRST_COMPLETED
            )

            for completed_future in done:
                task_id = future_to_task.pop(completed_future, None)
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
        task.status = TaskStatus.COMPLETED
        task.exit_code = output.exit_code
        task.stdout = output.stdout
        task.stderr = output.stderr
        task.duration_ms = output.duration_ms
        task.cached = output.cached
        self._completed.add(task_id)

        # Queue output for pipeline processing
        if self._pipeline is not None:
            self._pipeline_results[task_id] = output

        # Mutation layer (new)
        mutation_tasks = self._evaluate_mutations(task, output)

        # Existing reactive edges (backward compatible)
        edge_tasks = self._evaluate_edges(task, output)

        all_new = mutation_tasks + edge_tasks
        if all_new:
            self._inject_tasks(all_new)

    def _mark_failed(self, task_id: str, reason: str) -> None:
        task = self._tasks[task_id]
        task.status = TaskStatus.FAILED
        task.stderr = reason
        self._failed.add(task_id)

    def _skip_dependents(self, failed_task_id: str) -> None:
        """Recursively skip all downstream tasks of a failed task."""
        to_skip = list(self._dependents.get(failed_task_id, set()))
        while to_skip:
            dep_id = to_skip.pop()
            if dep_id in self._skipped or dep_id in self._completed:
                continue
            self._tasks[dep_id].status = TaskStatus.SKIPPED
            self._skipped.add(dep_id)
            to_skip.extend(self._dependents.get(dep_id, set()))

    def _finalize(self) -> None:
        """Set final scan status based on task outcomes."""
        if self._cancellation.is_cancelled:
            self.scan.status = ScanStatus.CANCELLED
        elif self._completed:
            self.scan.status = ScanStatus.COMPLETED
        else:
            self.scan.status = ScanStatus.FAILED

    # ------------------------------------------------------------------
    # Pipeline processing
    # ------------------------------------------------------------------

    async def _process_pipeline_results(self) -> None:
        """Process queued pipeline results."""
        if self._pipeline is None or not self._pipeline_results:
            return

        for task_id, output in list(self._pipeline_results.items()):
            task = self._tasks.get(task_id)
            if task is None:
                continue
            try:
                await self._pipeline.process_task_output(task, output)
            except Exception:
                import logging
                logging.getLogger(__name__).exception(
                    "Pipeline failed for task %s", task_id
                )
            del self._pipeline_results[task_id]

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

    # ------------------------------------------------------------------
    # Mutation layer
    # ------------------------------------------------------------------

    def _evaluate_mutations(
        self, task: ScanTask, output: TaskOutput
    ) -> list[ScanTask]:
        """Run mutation layer: analyze output, update state, evaluate strategies."""
        if self._analyzer_registry is None:
            return []

        # 1. Extract intel from tool output
        analyzer = self._analyzer_registry.get(task.tool)
        if analyzer is not None and output.stdout:
            bundle = analyzer.analyze(output.stdout, output.stderr or "")
            self._kill_chain.ingest(bundle)

        # 2. Evaluate strategies against accumulated state
        new_tasks: list[ScanTask] = []
        if self._kill_chain.total_spawned >= self._max_mutation_spawns:
            return []

        for strategy in self._mutation_strategies:
            budget_used = self._kill_chain.tasks_spawned.get(strategy.name, 0)
            if budget_used >= strategy.max_spawns:
                continue

            remaining_strategy = strategy.max_spawns - budget_used
            remaining_global = self._max_mutation_spawns - self._kill_chain.total_spawned

            spawned = strategy.evaluate(self._kill_chain, self.scan.id, task)

            allowed = min(remaining_strategy, remaining_global, len(spawned))
            accepted: list[ScanTask] = []
            for s in spawned[:allowed]:
                if s.id not in self._tasks:
                    accepted.append(s)

            if accepted:
                self._kill_chain.record_spawn(strategy.name, len(accepted))
                new_tasks.extend(accepted)

        return new_tasks

    # ------------------------------------------------------------------
    # Task injection
    # ------------------------------------------------------------------

    def _inject_tasks(self, tasks: list[ScanTask]) -> None:
        """Add dynamically spawned tasks to the graph.
        Validates that all dependencies exist. Drops tasks with unknown deps."""
        for t in tasks:
            if t.id in self._tasks:
                continue
            valid = True
            for dep in t.depends_on:
                if dep not in self._tasks:
                    import logging
                    logging.getLogger(__name__).warning(
                        "Dropping spawned task %s: depends on unknown task %s",
                        t.id, dep,
                    )
                    valid = False
                    break
            if valid:
                self._tasks[t.id] = t
                for dep in t.depends_on:
                    self._dependents[dep].add(t.id)
