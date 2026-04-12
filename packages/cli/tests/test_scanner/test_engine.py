"""Tests for ScanEngine — DAG executor."""

import asyncio
from datetime import datetime, timezone
from typing import Callable

import pytest

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.engine import ScanEngine
from opentools.scanner.executor.base import TaskExecutor, TaskOutput
from opentools.scanner.models import (
    ReactiveEdge,
    RetryPolicy,
    Scan,
    ScanConfig,
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
    task_type: TaskType = TaskType.SHELL,
    command: str = "echo test",
) -> ScanTask:
    return ScanTask(
        id=task_id,
        scan_id=scan_id,
        name=f"task-{task_id}",
        tool="test-tool",
        task_type=task_type,
        command=command,
        depends_on=depends_on or [],
        priority=priority,
    )


def _make_engine(
    tasks: list[ScanTask] | None = None,
    executor: MockExecutor | None = None,
    scan: Scan | None = None,
) -> ScanEngine:
    pool = AdaptiveResourcePool(global_limit=4)
    mock_exec = executor or MockExecutor()
    executors = {
        TaskType.SHELL: mock_exec,
        TaskType.DOCKER_EXEC: mock_exec,
        TaskType.MCP_CALL: mock_exec,
    }
    event_bus = EventBus()
    cancel = CancellationToken()
    engine_scan = scan or _make_scan()

    engine = ScanEngine(
        scan=engine_scan,
        resource_pool=pool,
        executors=executors,
        event_bus=event_bus,
        cancellation=cancel,
    )

    if tasks:
        engine.load_tasks(tasks)

    return engine


# ---------------------------------------------------------------------------
# Task 7: Initialization and readiness
# ---------------------------------------------------------------------------


class TestEngineInit:
    def test_construction(self):
        engine = _make_engine()
        assert engine.scan.id == "scan1"

    def test_load_tasks(self):
        tasks = [_make_task("a"), _make_task("b")]
        engine = _make_engine(tasks=tasks)
        assert len(engine.tasks) == 2

    def test_ready_tasks_no_deps(self):
        tasks = [_make_task("a"), _make_task("b")]
        engine = _make_engine(tasks=tasks)
        ready = engine.ready_task_ids()
        assert ready == {"a", "b"}

    def test_ready_tasks_with_deps(self):
        tasks = [
            _make_task("a"),
            _make_task("b", depends_on=["a"]),
            _make_task("c", depends_on=["a", "b"]),
        ]
        engine = _make_engine(tasks=tasks)
        ready = engine.ready_task_ids()
        assert ready == {"a"}

    def test_blocked_tasks_excluded(self):
        tasks = [_make_task("a"), _make_task("b", depends_on=["a"])]
        engine = _make_engine(tasks=tasks)
        ready = engine.ready_task_ids()
        assert "b" not in ready

    def test_load_tasks_validates_no_missing_deps(self):
        tasks = [_make_task("a", depends_on=["nonexistent"])]
        engine = _make_engine()
        with pytest.raises(ValueError, match="nonexistent"):
            engine.load_tasks(tasks)

    def test_ready_set_priority_order(self):
        tasks = [
            _make_task("low", priority=90),
            _make_task("high", priority=10),
            _make_task("mid", priority=50),
        ]
        engine = _make_engine(tasks=tasks)
        ordered = engine.ready_tasks_by_priority()
        assert [t.id for t in ordered] == ["high", "mid", "low"]


# ---------------------------------------------------------------------------
# Task 8: Dispatch and completion
# ---------------------------------------------------------------------------


class TestEngineDispatch:
    @pytest.mark.asyncio
    async def test_execute_single_task(self):
        mock_exec = MockExecutor()
        tasks = [_make_task("a")]
        engine = _make_engine(tasks=tasks, executor=mock_exec)
        await engine.run()
        assert "a" in mock_exec.executed
        assert engine._tasks["a"].status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_execute_linear_chain(self):
        mock_exec = MockExecutor()
        tasks = [
            _make_task("a"),
            _make_task("b", depends_on=["a"]),
            _make_task("c", depends_on=["b"]),
        ]
        engine = _make_engine(tasks=tasks, executor=mock_exec)
        await engine.run()
        assert mock_exec.executed == ["a", "b", "c"]

    @pytest.mark.asyncio
    async def test_execute_parallel_tasks(self):
        mock_exec = MockExecutor()
        tasks = [_make_task("a"), _make_task("b"), _make_task("c")]
        engine = _make_engine(tasks=tasks, executor=mock_exec)
        await engine.run()
        assert set(mock_exec.executed) == {"a", "b", "c"}

    @pytest.mark.asyncio
    async def test_diamond_dependency(self):
        mock_exec = MockExecutor()
        tasks = [
            _make_task("a"),
            _make_task("b", depends_on=["a"]),
            _make_task("c", depends_on=["a"]),
            _make_task("d", depends_on=["b", "c"]),
        ]
        engine = _make_engine(tasks=tasks, executor=mock_exec)
        await engine.run()
        assert set(mock_exec.executed) == {"a", "b", "c", "d"}
        d_idx = mock_exec.executed.index("d")
        assert d_idx > mock_exec.executed.index("b")
        assert d_idx > mock_exec.executed.index("c")

    @pytest.mark.asyncio
    async def test_failed_task_blocks_dependents(self):
        mock_exec = MockExecutor(
            results={"a": TaskOutput(exit_code=1, stderr="boom", duration_ms=5)}
        )
        tasks = [_make_task("a"), _make_task("b", depends_on=["a"])]
        engine = _make_engine(tasks=tasks, executor=mock_exec)
        await engine.run()
        assert "a" in mock_exec.executed
        assert "b" not in mock_exec.executed
        assert engine._tasks["b"].status == TaskStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_scan_status_transitions(self):
        tasks = [_make_task("a")]
        engine = _make_engine(tasks=tasks)
        assert engine.scan.status == ScanStatus.PENDING
        await engine.run()
        assert engine.scan.status == ScanStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_all_tasks_fail_scan_fails(self):
        mock_exec = MockExecutor(
            results={"a": TaskOutput(exit_code=1, stderr="fail", duration_ms=5)}
        )
        tasks = [_make_task("a")]
        engine = _make_engine(tasks=tasks, executor=mock_exec)
        await engine.run()
        assert engine.scan.status == ScanStatus.FAILED

    @pytest.mark.asyncio
    async def test_executor_selection_by_task_type(self):
        shell_exec = MockExecutor()
        docker_exec = MockExecutor()
        mcp_exec = MockExecutor()
        pool = AdaptiveResourcePool(global_limit=4)
        executors = {
            TaskType.SHELL: shell_exec,
            TaskType.DOCKER_EXEC: docker_exec,
            TaskType.MCP_CALL: mcp_exec,
        }
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors=executors,
            event_bus=EventBus(),
            cancellation=CancellationToken(),
        )
        engine.load_tasks([
            _make_task("s", task_type=TaskType.SHELL),
            _make_task("d", task_type=TaskType.DOCKER_EXEC, command="echo docker"),
            _make_task("m", task_type=TaskType.MCP_CALL, command="echo mcp"),
        ])
        await engine.run()
        assert "s" in shell_exec.executed
        assert "d" in docker_exec.executed
        assert "m" in mcp_exec.executed


# ---------------------------------------------------------------------------
# Task 9: Cancellation + Pause/Resume
# ---------------------------------------------------------------------------


class TestEngineCancellation:
    @pytest.mark.asyncio
    async def test_cancel_stops_execution(self):
        class CancellingExecutor:
            executed: list[str] = []
            async def execute(self, task, on_output, cancellation):
                self.executed.append(task.id)
                if task.id == "a":
                    await cancellation.cancel("user requested")
                return TaskOutput(exit_code=0, stdout="ok", duration_ms=10)

        cancel_exec = CancellingExecutor()
        tasks = [_make_task("a"), _make_task("b", depends_on=["a"])]
        pool = AdaptiveResourcePool(global_limit=4)
        cancel = CancellationToken()
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors={TaskType.SHELL: cancel_exec},
            event_bus=EventBus(),
            cancellation=cancel,
        )
        engine.load_tasks(tasks)
        await engine.run()
        assert engine.scan.status == ScanStatus.CANCELLED
        assert "b" not in cancel_exec.executed

    @pytest.mark.asyncio
    async def test_external_cancel(self):
        class HangingExecutor:
            executed: list[str] = []
            async def execute(self, task, on_output, cancellation):
                self.executed.append(task.id)
                await asyncio.sleep(10)
                return TaskOutput(exit_code=0, duration_ms=10000)

        hanging = HangingExecutor()
        tasks = [_make_task("a"), _make_task("b")]
        cancel = CancellationToken()
        pool = AdaptiveResourcePool(global_limit=4)
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors={TaskType.SHELL: hanging},
            event_bus=EventBus(),
            cancellation=cancel,
        )
        engine.load_tasks(tasks)

        async def cancel_soon():
            await asyncio.sleep(0.1)
            await cancel.cancel("timeout")

        asyncio.ensure_future(cancel_soon())
        await engine.run()
        assert engine.scan.status == ScanStatus.CANCELLED


class TestEnginePauseResume:
    @pytest.mark.asyncio
    async def test_pause_prevents_new_dispatches(self):
        executed_order: list[str] = []

        class TrackingExecutor:
            async def execute(self, task, on_output, cancellation):
                executed_order.append(task.id)
                return TaskOutput(exit_code=0, duration_ms=10)

        tasks = [_make_task("a"), _make_task("b", depends_on=["a"])]
        cancel = CancellationToken()
        pool = AdaptiveResourcePool(global_limit=4)
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors={TaskType.SHELL: TrackingExecutor()},
            event_bus=EventBus(),
            cancellation=cancel,
        )
        engine.load_tasks(tasks)

        await engine.pause()
        assert engine.is_paused is True

        run_task = asyncio.ensure_future(engine.run())
        await asyncio.sleep(0.15)
        await engine.resume()
        assert engine.is_paused is False

        await asyncio.wait_for(run_task, timeout=5)
        assert set(executed_order) == {"a", "b"}

    @pytest.mark.asyncio
    async def test_pause_sets_scan_status(self):
        tasks = [_make_task("a")]
        engine = _make_engine(tasks=tasks)
        await engine.pause()
        assert engine.scan.status == ScanStatus.PAUSED
        await engine.resume()
        assert engine.scan.status == ScanStatus.RUNNING


# ---------------------------------------------------------------------------
# Task 10: Retry
# ---------------------------------------------------------------------------


class TestEngineRetry:
    @pytest.mark.asyncio
    async def test_retry_on_failure(self):
        attempt = 0

        class RetryingExecutor:
            executed: list[str] = []
            async def execute(self, task, on_output, cancellation):
                nonlocal attempt
                attempt += 1
                self.executed.append(task.id)
                if attempt < 2:
                    raise ConnectionError("connection_error: server refused")
                return TaskOutput(exit_code=0, stdout="success", duration_ms=10)

        task = _make_task("a")
        task = task.model_copy(
            update={"retry_policy": RetryPolicy(max_retries=2, backoff_seconds=0.01, retry_on=["connection_error"])}
        )
        cancel = CancellationToken()
        pool = AdaptiveResourcePool(global_limit=4)
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors={TaskType.SHELL: RetryingExecutor()},
            event_bus=EventBus(),
            cancellation=cancel,
        )
        engine.load_tasks([task])
        await engine.run()
        assert engine._tasks["a"].status == TaskStatus.COMPLETED
        assert attempt == 2

    @pytest.mark.asyncio
    async def test_retry_exhausted_fails(self):
        class AlwaysFailExecutor:
            executed: list[str] = []
            async def execute(self, task, on_output, cancellation):
                self.executed.append(task.id)
                raise ConnectionError("connection_error: always fails")

        task = _make_task("a")
        task = task.model_copy(
            update={"retry_policy": RetryPolicy(max_retries=1, backoff_seconds=0.01, retry_on=["connection_error"])}
        )
        cancel = CancellationToken()
        pool = AdaptiveResourcePool(global_limit=4)
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors={TaskType.SHELL: AlwaysFailExecutor()},
            event_bus=EventBus(),
            cancellation=cancel,
        )
        engine.load_tasks([task])
        await engine.run()
        assert engine._tasks["a"].status == TaskStatus.FAILED

    @pytest.mark.asyncio
    async def test_no_retry_on_non_matching_error(self):
        attempt = 0

        class NonRetryableExecutor:
            executed: list[str] = []
            async def execute(self, task, on_output, cancellation):
                nonlocal attempt
                attempt += 1
                self.executed.append(task.id)
                raise RuntimeError("unexpected crash")

        task = _make_task("a")
        task = task.model_copy(
            update={"retry_policy": RetryPolicy(max_retries=3, backoff_seconds=0.01, retry_on=["connection_error"])}
        )
        cancel = CancellationToken()
        pool = AdaptiveResourcePool(global_limit=4)
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors={TaskType.SHELL: NonRetryableExecutor()},
            event_bus=EventBus(),
            cancellation=cancel,
        )
        engine.load_tasks([task])
        await engine.run()
        assert attempt == 1
        assert engine._tasks["a"].status == TaskStatus.FAILED


# ---------------------------------------------------------------------------
# Task 11: Reactive edges
# ---------------------------------------------------------------------------


class TestEngineReactiveEdges:
    @pytest.mark.asyncio
    async def test_reactive_edge_spawns_task(self):
        mock_exec = MockExecutor()
        spawned_task = _make_task("b")
        edge = ReactiveEdge(
            id="edge1", trigger_task_id="a", evaluator="builtin:always_spawn",
            spawns=[spawned_task],
        )
        trigger = _make_task("a")
        trigger = trigger.model_copy(update={"reactive_edges": [edge]})

        engine = _make_engine(tasks=[trigger], executor=mock_exec)

        def always_spawn(task, output, edge):
            return edge.spawns or []
        engine.register_edge_evaluator("builtin:always_spawn", always_spawn)

        await engine.run()
        assert "a" in mock_exec.executed
        assert "b" in mock_exec.executed
        assert engine._tasks["b"].status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_reactive_edge_respects_max_spawns(self):
        mock_exec = MockExecutor()
        spawned = [_make_task(f"s{i}") for i in range(5)]
        edge = ReactiveEdge(
            id="edge1", trigger_task_id="a", evaluator="builtin:multi_spawn",
            spawns=spawned, max_spawns=2,
        )
        trigger = _make_task("a")
        trigger = trigger.model_copy(update={"reactive_edges": [edge]})

        engine = _make_engine(tasks=[trigger], executor=mock_exec)

        def multi_spawn(task, output, edge):
            return edge.spawns or []
        engine.register_edge_evaluator("builtin:multi_spawn", multi_spawn)

        await engine.run()
        spawned_executed = [t for t in mock_exec.executed if t.startswith("s")]
        assert len(spawned_executed) == 2

    @pytest.mark.asyncio
    async def test_reactive_edge_condition_not_met(self):
        mock_exec = MockExecutor()
        edge = ReactiveEdge(
            id="edge1", trigger_task_id="a", evaluator="builtin:conditional",
            condition="exit_code == 42",
        )
        trigger = _make_task("a")
        trigger = trigger.model_copy(update={"reactive_edges": [edge]})

        engine = _make_engine(tasks=[trigger], executor=mock_exec)

        def conditional(task, output, edge):
            if edge.condition == "exit_code == 42" and output.exit_code != 42:
                return []
            return [_make_task("b")]
        engine.register_edge_evaluator("builtin:conditional", conditional)

        await engine.run()
        assert "b" not in mock_exec.executed

    @pytest.mark.asyncio
    async def test_no_duplicate_spawns(self):
        mock_exec = MockExecutor()
        existing = _make_task("b")
        spawned = _make_task("b")  # same ID
        edge = ReactiveEdge(
            id="edge1", trigger_task_id="a", evaluator="builtin:dup_spawn",
            spawns=[spawned],
        )
        trigger = _make_task("a")
        trigger = trigger.model_copy(update={"reactive_edges": [edge]})

        engine = _make_engine(tasks=[trigger, existing], executor=mock_exec)

        def dup_spawn(task, output, edge):
            return edge.spawns or []
        engine.register_edge_evaluator("builtin:dup_spawn", dup_spawn)

        await engine.run()
        assert mock_exec.executed.count("b") == 1


# ---------------------------------------------------------------------------
# Task 12: Cache
# ---------------------------------------------------------------------------


class TestEngineCache:
    @pytest.mark.asyncio
    async def test_cached_task_skips_executor(self):
        mock_exec = MockExecutor()
        task = _make_task("a")
        task = task.model_copy(update={"cache_key": "key-abc"})
        engine = _make_engine(tasks=[task], executor=mock_exec)
        cached_output = TaskOutput(exit_code=0, stdout="cached result", cached=True, duration_ms=0)
        engine.set_cache({"key-abc": cached_output})
        await engine.run()
        assert "a" not in mock_exec.executed
        assert engine._tasks["a"].status == TaskStatus.COMPLETED
        assert engine._tasks["a"].cached is True

    @pytest.mark.asyncio
    async def test_cache_miss_executes_normally(self):
        mock_exec = MockExecutor()
        task = _make_task("a")
        task = task.model_copy(update={"cache_key": "key-miss"})
        engine = _make_engine(tasks=[task], executor=mock_exec)
        engine.set_cache({})
        await engine.run()
        assert "a" in mock_exec.executed
        assert engine._tasks["a"].status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_no_cache_key_executes_normally(self):
        mock_exec = MockExecutor()
        task = _make_task("a")
        assert task.cache_key is None
        engine = _make_engine(tasks=[task], executor=mock_exec)
        await engine.run()
        assert "a" in mock_exec.executed


# ---------------------------------------------------------------------------
# Task 13: Integration tests
# ---------------------------------------------------------------------------


class TestEngineIntegration:
    @pytest.mark.asyncio
    async def test_complex_dag_with_reactive_edges_and_cache(self):
        """End-to-end: multi-phase DAG with caching, failure, reactive edges.

        Graph:
            preflight → (semgrep, gitleaks) → dedup_merge
            semgrep has a reactive edge that spawns nuclei if findings found
            gitleaks is cached
        """
        execution_log: list[str] = []

        class LoggingExecutor:
            async def execute(self, task, on_output, cancellation):
                execution_log.append(task.id)
                on_output(f"output-{task.id}".encode())
                return TaskOutput(exit_code=0, stdout=f"output-{task.id}", duration_ms=10)

        logging_exec = LoggingExecutor()

        preflight = _make_task("preflight", priority=10)
        semgrep = _make_task("semgrep", depends_on=["preflight"], priority=30)
        gitleaks = _make_task("gitleaks", depends_on=["preflight"], priority=30)
        gitleaks = gitleaks.model_copy(update={"cache_key": "gitleaks-key"})
        dedup = _make_task("dedup_merge", depends_on=["semgrep", "gitleaks"], priority=50)

        nuclei_task = _make_task("nuclei")
        edge = ReactiveEdge(
            id="edge-nuclei",
            trigger_task_id="semgrep",
            evaluator="builtin:findings_to_nuclei",
            spawns=[nuclei_task],
        )
        semgrep = semgrep.model_copy(update={"reactive_edges": [edge]})

        pool = AdaptiveResourcePool(global_limit=4)
        cancel = CancellationToken()
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors={
                TaskType.SHELL: logging_exec,
                TaskType.DOCKER_EXEC: logging_exec,
                TaskType.MCP_CALL: logging_exec,
            },
            event_bus=EventBus(),
            cancellation=cancel,
        )
        engine.load_tasks([preflight, semgrep, gitleaks, dedup])

        engine.set_cache({
            "gitleaks-key": TaskOutput(
                exit_code=0, stdout="no leaks", cached=True, duration_ms=0
            ),
        })

        def findings_to_nuclei(task, output, edge):
            return edge.spawns or []
        engine.register_edge_evaluator("builtin:findings_to_nuclei", findings_to_nuclei)

        await engine.run()

        assert engine.scan.status == ScanStatus.COMPLETED
        assert execution_log[0] == "preflight"
        assert "gitleaks" not in execution_log  # cached
        assert "semgrep" in execution_log
        assert "nuclei" in execution_log
        assert "dedup_merge" in execution_log
        dedup_idx = execution_log.index("dedup_merge")
        semgrep_idx = execution_log.index("semgrep")
        assert dedup_idx > semgrep_idx
        assert engine._tasks["gitleaks"].cached is True

        for tid in ["preflight", "semgrep", "gitleaks", "dedup_merge", "nuclei"]:
            assert engine._tasks[tid].status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_partial_failure_with_independent_branches(self):
        """One branch fails, the other succeeds. Scan still completes.

        Graph:
            root → (branch_a, branch_b)
            branch_a → dep_a (fails)
            branch_b → dep_b (succeeds)
        """
        mock_exec = MockExecutor(
            results={
                "branch_a": TaskOutput(exit_code=1, stderr="segfault", duration_ms=5),
            }
        )
        tasks = [
            _make_task("root"),
            _make_task("branch_a", depends_on=["root"]),
            _make_task("branch_b", depends_on=["root"]),
            _make_task("dep_a", depends_on=["branch_a"]),
            _make_task("dep_b", depends_on=["branch_b"]),
        ]
        engine = _make_engine(tasks=tasks, executor=mock_exec)

        await engine.run()

        assert engine.scan.status == ScanStatus.COMPLETED
        assert engine._tasks["root"].status == TaskStatus.COMPLETED
        assert engine._tasks["branch_a"].status == TaskStatus.FAILED
        assert engine._tasks["branch_b"].status == TaskStatus.COMPLETED
        assert engine._tasks["dep_a"].status == TaskStatus.SKIPPED
        assert engine._tasks["dep_b"].status == TaskStatus.COMPLETED
