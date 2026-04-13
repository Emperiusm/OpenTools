"""Tests for ScanEngine mutation layer integration."""

import asyncio
from datetime import datetime, timezone
from typing import Callable

import pytest

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.engine import ScanEngine
from opentools.scanner.executor.base import TaskExecutor, TaskOutput
from opentools.scanner.models import (
    ReactiveEdge,
    Scan,
    ScanConfig,
    ScanStatus,
    ScanTask,
    TaskStatus,
    TaskType,
    TargetType,
)
from opentools.scanner.mutation.analyzer import AnalyzerRegistry
from opentools.scanner.mutation.strategy import RedisProbeStrategy
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
        target="10.0.0.0/24",
        target_type=TargetType.NETWORK,
        status=ScanStatus.PENDING,
        created_at=datetime.now(timezone.utc),
    )


def _make_engine_with_mutation(
    tasks: list[ScanTask],
    executor: MockExecutor | None = None,
    max_mutation_spawns: int = 100,
) -> tuple[ScanEngine, MockExecutor]:
    """Create a ScanEngine wired with the mutation layer (analyzer + strategies)."""
    pool = AdaptiveResourcePool(global_limit=4)
    mock_exec = executor or MockExecutor()
    executors = {
        TaskType.SHELL: mock_exec,
        TaskType.DOCKER_EXEC: mock_exec,
        TaskType.MCP_CALL: mock_exec,
    }
    event_bus = EventBus()
    cancel = CancellationToken()
    scan = _make_scan()

    engine = ScanEngine(
        scan=scan,
        resource_pool=pool,
        executors=executors,
        event_bus=event_bus,
        cancellation=cancel,
    )

    # Wire up mutation layer
    registry = AnalyzerRegistry()
    registry.register_builtins()
    engine.set_analyzer_registry(registry)
    engine.set_mutation_strategies([RedisProbeStrategy()])
    engine.set_max_mutation_spawns(max_mutation_spawns)

    engine.load_tasks(tasks)
    return engine, mock_exec


# ---------------------------------------------------------------------------
# Nmap XML fixtures
# ---------------------------------------------------------------------------

NMAP_REDIS_XML = '''<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis" product="Redis" version="6.2.7"/>
      </port>
    </ports>
  </host>
</nmaprun>'''

NMAP_HTTP_ONLY_XML = '''<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>'''


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEngineMutationIntegration:
    @pytest.mark.asyncio
    async def test_nmap_redis_spawns_probe(self):
        """Nmap finds Redis -> engine spawns redis-cli probe -> probe runs."""
        nmap_task = ScanTask(
            id="nmap-scan",
            scan_id="scan1",
            name="Nmap network scan",
            tool="nmap",
            task_type=TaskType.SHELL,
            command="nmap -sV -oX - 10.0.0.1",
            depends_on=[],
            priority=10,
        )

        mock_exec = MockExecutor(
            results={
                "nmap-scan": TaskOutput(
                    exit_code=0, stdout=NMAP_REDIS_XML, duration_ms=100
                ),
            }
        )

        engine, _ = _make_engine_with_mutation(
            tasks=[nmap_task], executor=mock_exec
        )

        await engine.run()

        # The redis probe task should have been spawned and executed
        assert "nmap-scan" in mock_exec.executed
        assert "redis-probe-10.0.0.1-6379" in mock_exec.executed

        # Verify spawned task properties
        probe_task = engine._tasks["redis-probe-10.0.0.1-6379"]
        assert probe_task.tool == "redis-cli"
        assert probe_task.spawned_by == "nmap-scan"
        assert probe_task.status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_no_mutation_when_no_interesting_services(self):
        """Nmap finds only HTTP -> no mutations -> only nmap-scan executed."""
        nmap_task = ScanTask(
            id="nmap-scan",
            scan_id="scan1",
            name="Nmap network scan",
            tool="nmap",
            task_type=TaskType.SHELL,
            command="nmap -sV -oX - 10.0.0.1",
            depends_on=[],
            priority=10,
        )

        mock_exec = MockExecutor(
            results={
                "nmap-scan": TaskOutput(
                    exit_code=0, stdout=NMAP_HTTP_ONLY_XML, duration_ms=100
                ),
            }
        )

        engine, _ = _make_engine_with_mutation(
            tasks=[nmap_task], executor=mock_exec
        )

        await engine.run()

        assert mock_exec.executed == ["nmap-scan"]

    @pytest.mark.asyncio
    async def test_mutation_respects_global_budget(self):
        """Set max_mutation_spawns=0 -> no mutations allowed."""
        nmap_task = ScanTask(
            id="nmap-scan",
            scan_id="scan1",
            name="Nmap network scan",
            tool="nmap",
            task_type=TaskType.SHELL,
            command="nmap -sV -oX - 10.0.0.1",
            depends_on=[],
            priority=10,
        )

        mock_exec = MockExecutor(
            results={
                "nmap-scan": TaskOutput(
                    exit_code=0, stdout=NMAP_REDIS_XML, duration_ms=100
                ),
            }
        )

        engine, _ = _make_engine_with_mutation(
            tasks=[nmap_task], executor=mock_exec, max_mutation_spawns=0
        )

        await engine.run()

        # Only nmap-scan should have run — budget of 0 blocks all mutations
        assert mock_exec.executed == ["nmap-scan"]
        assert "redis-probe-10.0.0.1-6379" not in engine._tasks

    @pytest.mark.asyncio
    async def test_mutation_coexists_with_reactive_edges(self):
        """Both mutation AND reactive edge fire on same task."""
        edge_spawned = ScanTask(
            id="edge-spawned",
            scan_id="scan1",
            name="Edge-spawned task",
            tool="test-tool",
            task_type=TaskType.SHELL,
            command="echo edge",
            depends_on=[],
            priority=50,
        )

        edge = ReactiveEdge(
            id="edge1",
            trigger_task_id="nmap-scan",
            evaluator="builtin:always_spawn",
            spawns=[edge_spawned],
        )

        nmap_task = ScanTask(
            id="nmap-scan",
            scan_id="scan1",
            name="Nmap network scan",
            tool="nmap",
            task_type=TaskType.SHELL,
            command="nmap -sV -oX - 10.0.0.1",
            depends_on=[],
            priority=10,
            reactive_edges=[edge],
        )

        mock_exec = MockExecutor(
            results={
                "nmap-scan": TaskOutput(
                    exit_code=0, stdout=NMAP_REDIS_XML, duration_ms=100
                ),
            }
        )

        engine, _ = _make_engine_with_mutation(
            tasks=[nmap_task], executor=mock_exec
        )

        def always_spawn(task, output, edge):
            return edge.spawns or []

        engine.register_edge_evaluator("builtin:always_spawn", always_spawn)

        await engine.run()

        # Both mutation-spawned and edge-spawned tasks should have executed
        assert "nmap-scan" in mock_exec.executed
        assert "redis-probe-10.0.0.1-6379" in mock_exec.executed
        assert "edge-spawned" in mock_exec.executed

    @pytest.mark.asyncio
    async def test_kill_chain_state_accessible(self):
        """After run, engine.kill_chain_state reflects discovered services."""
        nmap_task = ScanTask(
            id="nmap-scan",
            scan_id="scan1",
            name="Nmap network scan",
            tool="nmap",
            task_type=TaskType.SHELL,
            command="nmap -sV -oX - 10.0.0.1",
            depends_on=[],
            priority=10,
        )

        mock_exec = MockExecutor(
            results={
                "nmap-scan": TaskOutput(
                    exit_code=0, stdout=NMAP_REDIS_XML, duration_ms=100
                ),
            }
        )

        engine, _ = _make_engine_with_mutation(
            tasks=[nmap_task], executor=mock_exec
        )

        await engine.run()

        assert engine.kill_chain_state.has_service("redis") is True
        assert engine.kill_chain_state.total_spawned == 1

    @pytest.mark.asyncio
    async def test_no_mutation_without_registry(self):
        """Engine without mutation layer configured -> no mutations."""
        nmap_task = ScanTask(
            id="nmap-scan",
            scan_id="scan1",
            name="Nmap network scan",
            tool="nmap",
            task_type=TaskType.SHELL,
            command="nmap -sV -oX - 10.0.0.1",
            depends_on=[],
            priority=10,
        )

        gated_task = ScanTask(
            id="gated",
            scan_id="scan1",
            name="Gated task",
            tool="test-tool",
            task_type=TaskType.SHELL,
            command="echo gated",
            depends_on=["nmap-scan"],
            priority=50,
        )

        mock_exec = MockExecutor(
            results={
                "nmap-scan": TaskOutput(
                    exit_code=0, stdout=NMAP_REDIS_XML, duration_ms=100
                ),
            }
        )

        # Build engine WITHOUT mutation layer
        pool = AdaptiveResourcePool(global_limit=4)
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
        engine.load_tasks([nmap_task, gated_task])

        await engine.run()

        # Both static tasks execute, no mutations
        assert "nmap-scan" in mock_exec.executed
        assert "gated" in mock_exec.executed
        assert "redis-probe-10.0.0.1-6379" not in mock_exec.executed
        assert "redis-probe-10.0.0.1-6379" not in engine._tasks
