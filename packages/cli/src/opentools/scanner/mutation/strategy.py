"""MutationStrategy protocol and built-in strategy implementations."""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from opentools.scanner.models import ExecutionTier, ScanTask, TaskType
from opentools.scanner.mutation.models import KillChainState


@runtime_checkable
class MutationStrategy(Protocol):
    """Protocol for strategies that synthesize new ScanTasks from accumulated state.

    Each strategy examines the current KillChainState (all accumulated intel)
    and a recently completed task, then returns zero or more new tasks to inject
    into the engine.
    """

    name: str
    max_spawns: int

    def evaluate(
        self,
        state: KillChainState,
        scan_id: str,
        completed_task: ScanTask,
    ) -> list[ScanTask]:
        """Return new tasks to spawn based on current state and the completed task.

        Args:
            state: Accumulated kill-chain intel from all completed tasks so far.
            scan_id: The active scan's ID, used to populate spawned task scan_id.
            completed_task: The task that just completed, triggering this evaluation.

        Returns:
            A list of new ScanTask objects to inject.  May be empty.
        """
        ...


class RedisProbeStrategy:
    """Spawns ``redis-cli INFO`` probe tasks when nmap/masscan discovers Redis.

    Fires only when the completed task's tool is in ``_TRIGGER_TOOLS``.  Uses
    self-tracking (``_spawned_keys``) to avoid emitting duplicate tasks across
    multiple evaluate() calls — idempotent without engine callbacks.
    """

    name: str = "redis_probe"
    max_spawns: int = 10

    _TRIGGER_TOOLS: frozenset[str] = frozenset({"nmap", "masscan"})

    def __init__(self) -> None:
        self._spawned_keys: set[str] = set()

    def evaluate(
        self,
        state: KillChainState,
        scan_id: str,
        completed_task: ScanTask,
    ) -> list[ScanTask]:
        """Inspect state for Redis services and spawn probes for unseen ones.

        Only fires when the triggering task's tool is nmap or masscan.
        Each Redis service is probed at most once per strategy instance.
        """
        if completed_task.tool not in self._TRIGGER_TOOLS:
            return []

        redis_services = state.get_services("redis")
        new_tasks: list[ScanTask] = []

        for svc in redis_services:
            key = f"{svc.host}:{svc.port}"
            if key in self._spawned_keys:
                continue

            # Mark spawned *before* appending so re-entrant calls are safe.
            self._spawned_keys.add(key)

            host = svc.host
            port = svc.port
            task_id = f"redis-probe-{host}-{port}"

            new_tasks.append(
                ScanTask(
                    id=task_id,
                    scan_id=scan_id,
                    name=f"Redis INFO probe {host}:{port}",
                    tool="redis-cli",
                    task_type=TaskType.DOCKER_EXEC,
                    command=f"redis-cli -h {host} -p {port} INFO",
                    depends_on=[completed_task.id],
                    priority=20,
                    tier=ExecutionTier.FAST,
                    spawned_by=completed_task.id,
                    spawned_reason=f"nmap discovered Redis on {host}:{port}",
                )
            )

        return new_tasks


def get_builtin_strategies() -> list[RedisProbeStrategy]:
    """Return a list of all built-in MutationStrategy instances."""
    return [RedisProbeStrategy()]
