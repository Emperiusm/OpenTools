"""In-memory registry of long-running chain tasks."""
from __future__ import annotations

import asyncio
from typing import Any, Awaitable


class ChainTaskRegistry:
    """Track asyncio.Task objects for background chain operations.

    Keyed by run_id (a string identifier shared with ChainLinkerRun.id).
    Tasks are started via .start() and looked up via .get(). .cleanup_completed()
    removes tasks whose future is done.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task] = {}

    def start(self, run_id: str, coro: Awaitable[Any]) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self._tasks[run_id] = task
        return task

    def get(self, run_id: str) -> asyncio.Task | None:
        return self._tasks.get(run_id)

    def cleanup_completed(self) -> int:
        """Remove tasks whose future is done. Returns count removed."""
        done = [rid for rid, t in self._tasks.items() if t.done()]
        for rid in done:
            self._tasks.pop(rid, None)
        return len(done)

    def active_count(self) -> int:
        return sum(1 for t in self._tasks.values() if not t.done())


_registry: ChainTaskRegistry | None = None


def get_chain_task_registry() -> ChainTaskRegistry:
    global _registry
    if _registry is None:
        _registry = ChainTaskRegistry()
    return _registry
