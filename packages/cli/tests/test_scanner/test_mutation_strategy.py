"""Tests for MutationStrategy protocol and RedisProbeStrategy."""
from __future__ import annotations

import pytest

from opentools.scanner.mutation.models import DiscoveredService, IntelBundle, KillChainState
from opentools.scanner.mutation.strategy import (
    MutationStrategy,
    RedisProbeStrategy,
    get_builtin_strategies,
)
from opentools.scanner.models import ExecutionTier, ScanTask, TaskType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_task(
    task_id: str = "task-001",
    scan_id: str = "scan-abc",
    tool: str = "nmap",
) -> ScanTask:
    """Create a minimal ScanTask for use as a completed_task in tests."""
    return ScanTask(
        id=task_id,
        scan_id=scan_id,
        name=f"{tool} task",
        tool=tool,
        task_type=TaskType.SHELL,
    )


def _make_state_with_redis(
    host: str = "10.0.0.1",
    port: int = 6379,
    extra_services: list[DiscoveredService] | None = None,
) -> KillChainState:
    """Build a KillChainState that contains a Redis service."""
    services = [
        DiscoveredService(host=host, port=port, protocol="tcp", service="redis")
    ]
    if extra_services:
        services.extend(extra_services)
    state = KillChainState()
    state.ingest(IntelBundle(services=services))
    return state


def _make_empty_state() -> KillChainState:
    return KillChainState()


# ---------------------------------------------------------------------------
# TestRedisProbeStrategy — attributes
# ---------------------------------------------------------------------------


class TestRedisProbeStrategyAttributes:
    def setup_method(self):
        self.strategy = RedisProbeStrategy()

    def test_name(self):
        assert self.strategy.name == "redis_probe"

    def test_max_spawns(self):
        assert self.strategy.max_spawns == 10

    def test_satisfies_protocol(self):
        assert isinstance(self.strategy, MutationStrategy)


# ---------------------------------------------------------------------------
# TestRedisProbeStrategy — spawning behaviour
# ---------------------------------------------------------------------------


class TestRedisProbeStrategy:
    def setup_method(self):
        self.strategy = RedisProbeStrategy()
        self.scan_id = "scan-xyz"

    # --- happy path ----------------------------------------------------------

    def test_spawns_redis_probe_when_redis_discovered(self):
        state = _make_state_with_redis(host="10.0.0.1", port=6379)
        completed = _make_task(task_id="nmap-001", scan_id=self.scan_id, tool="nmap")

        tasks = self.strategy.evaluate(state, self.scan_id, completed)

        assert len(tasks) == 1
        task = tasks[0]
        assert task.tool == "redis-cli"
        assert task.task_type == TaskType.DOCKER_EXEC
        assert "10.0.0.1" in task.command
        assert "6379" in task.command
        assert task.scan_id == self.scan_id
        assert task.spawned_by == "nmap-001"

    def test_spawned_task_command_format(self):
        state = _make_state_with_redis(host="192.168.1.50", port=6380)
        completed = _make_task(tool="nmap")

        tasks = self.strategy.evaluate(state, self.scan_id, completed)

        assert len(tasks) == 1
        assert tasks[0].command == "redis-cli -h 192.168.1.50 -p 6380 INFO"

    def test_spawned_task_priority_and_tier(self):
        state = _make_state_with_redis()
        completed = _make_task(tool="nmap")

        tasks = self.strategy.evaluate(state, self.scan_id, completed)

        task = tasks[0]
        assert task.priority == 20
        assert task.tier == ExecutionTier.FAST

    def test_spawned_task_depends_on_completed(self):
        state = _make_state_with_redis()
        completed = _make_task(task_id="nmap-scan-001", tool="nmap")

        tasks = self.strategy.evaluate(state, self.scan_id, completed)

        assert "nmap-scan-001" in tasks[0].depends_on

    def test_spawned_reason_mentions_host_and_port(self):
        state = _make_state_with_redis(host="10.10.10.10", port=6379)
        completed = _make_task(tool="nmap")

        tasks = self.strategy.evaluate(state, self.scan_id, completed)

        assert "10.10.10.10" in tasks[0].spawned_reason
        assert "6379" in tasks[0].spawned_reason

    # --- no Redis discovered -------------------------------------------------

    def test_no_spawn_when_no_redis(self):
        state = _make_empty_state()
        state.ingest(
            IntelBundle(
                services=[
                    DiscoveredService(host="10.0.0.1", port=22, protocol="tcp", service="ssh")
                ]
            )
        )
        completed = _make_task(tool="nmap")

        tasks = self.strategy.evaluate(state, self.scan_id, completed)

        assert tasks == []

    def test_no_spawn_when_state_empty(self):
        state = _make_empty_state()
        completed = _make_task(tool="nmap")

        tasks = self.strategy.evaluate(state, self.scan_id, completed)

        assert tasks == []

    # --- idempotency ---------------------------------------------------------

    def test_no_spawn_when_already_spawned(self):
        """Second evaluate() call for the same Redis service returns empty list."""
        state = _make_state_with_redis()
        completed = _make_task(tool="nmap")

        first = self.strategy.evaluate(state, self.scan_id, completed)
        second = self.strategy.evaluate(state, self.scan_id, completed)

        assert len(first) == 1
        assert second == []

    def test_idempotent_across_different_completed_tasks(self):
        """Even with a different completed_task, already-tracked keys are skipped."""
        state = _make_state_with_redis()
        completed1 = _make_task(task_id="nmap-001", tool="nmap")
        completed2 = _make_task(task_id="nmap-002", tool="nmap")

        first = self.strategy.evaluate(state, self.scan_id, completed1)
        second = self.strategy.evaluate(state, self.scan_id, completed2)

        assert len(first) == 1
        assert second == []

    # --- multiple instances --------------------------------------------------

    def test_spawns_for_multiple_redis_instances(self):
        """Each distinct Redis service gets its own probe task."""
        state = KillChainState()
        state.ingest(
            IntelBundle(
                services=[
                    DiscoveredService(host="10.0.0.1", port=6379, protocol="tcp", service="redis"),
                    DiscoveredService(host="10.0.0.2", port=6379, protocol="tcp", service="redis"),
                    DiscoveredService(host="10.0.0.3", port=6380, protocol="tcp", service="redis"),
                ]
            )
        )
        completed = _make_task(tool="nmap")

        tasks = self.strategy.evaluate(state, self.scan_id, completed)

        assert len(tasks) == 3
        hosts = {t.id for t in tasks}
        assert "redis-probe-10.0.0.1-6379" in hosts
        assert "redis-probe-10.0.0.2-6379" in hosts
        assert "redis-probe-10.0.0.3-6380" in hosts

    # --- trigger tool filtering ----------------------------------------------

    def test_ignores_non_nmap_tool(self):
        state = _make_state_with_redis()
        completed = _make_task(tool="nuclei")

        tasks = self.strategy.evaluate(state, self.scan_id, completed)

        assert tasks == []

    def test_fires_for_masscan_tool(self):
        state = _make_state_with_redis()
        completed = _make_task(tool="masscan")

        tasks = self.strategy.evaluate(state, self.scan_id, completed)

        assert len(tasks) == 1

    def test_ignores_redis_cli_tool(self):
        """A redis-cli task completing should not trigger another probe."""
        state = _make_state_with_redis()
        completed = _make_task(tool="redis-cli")

        tasks = self.strategy.evaluate(state, self.scan_id, completed)

        assert tasks == []

    def test_ignores_shell_tool(self):
        state = _make_state_with_redis()
        completed = _make_task(tool="curl")

        tasks = self.strategy.evaluate(state, self.scan_id, completed)

        assert tasks == []

    # --- deterministic IDs ---------------------------------------------------

    def test_task_ids_are_deterministic(self):
        """Two fresh strategy instances produce identical task IDs for the same input."""
        state = _make_state_with_redis(host="10.0.0.5", port=6379)
        completed = _make_task(tool="nmap")

        strategy_a = RedisProbeStrategy()
        strategy_b = RedisProbeStrategy()

        tasks_a = strategy_a.evaluate(state, self.scan_id, completed)
        tasks_b = strategy_b.evaluate(state, self.scan_id, completed)

        assert len(tasks_a) == 1
        assert len(tasks_b) == 1
        assert tasks_a[0].id == tasks_b[0].id

    def test_task_id_format(self):
        state = _make_state_with_redis(host="172.16.0.1", port=6379)
        completed = _make_task(tool="nmap")

        tasks = self.strategy.evaluate(state, self.scan_id, completed)

        assert tasks[0].id == "redis-probe-172.16.0.1-6379"

    def test_task_id_includes_port(self):
        """Non-default port must be reflected in the task ID."""
        state = _make_state_with_redis(host="10.0.0.1", port=6380)
        completed = _make_task(tool="nmap")

        tasks = self.strategy.evaluate(state, self.scan_id, completed)

        assert tasks[0].id == "redis-probe-10.0.0.1-6380"

    # --- mixed services ------------------------------------------------------

    def test_only_redis_services_spawn_probes(self):
        """SSH and HTTP alongside Redis should not produce extra probe tasks."""
        state = KillChainState()
        state.ingest(
            IntelBundle(
                services=[
                    DiscoveredService(host="10.0.0.1", port=22, protocol="tcp", service="ssh"),
                    DiscoveredService(host="10.0.0.1", port=80, protocol="tcp", service="http"),
                    DiscoveredService(host="10.0.0.1", port=6379, protocol="tcp", service="redis"),
                ]
            )
        )
        completed = _make_task(tool="nmap")

        tasks = self.strategy.evaluate(state, self.scan_id, completed)

        assert len(tasks) == 1
        assert tasks[0].tool == "redis-cli"


# ---------------------------------------------------------------------------
# TestGetBuiltinStrategies
# ---------------------------------------------------------------------------


class TestGetBuiltinStrategies:
    def test_returns_list(self):
        result = get_builtin_strategies()
        assert isinstance(result, list)

    def test_contains_redis_probe(self):
        result = get_builtin_strategies()
        names = [s.name for s in result]
        assert "redis_probe" in names

    def test_all_satisfy_protocol(self):
        result = get_builtin_strategies()
        assert len(result) > 0
        for strategy in result:
            assert isinstance(strategy, MutationStrategy), (
                f"{strategy!r} does not satisfy MutationStrategy protocol"
            )

    def test_returns_fresh_instances_each_call(self):
        """Each call returns new instances so state doesn't leak between calls."""
        strategies_a = get_builtin_strategies()
        strategies_b = get_builtin_strategies()
        # Same number, but different objects
        assert len(strategies_a) == len(strategies_b)
        for a, b in zip(strategies_a, strategies_b):
            assert a is not b
