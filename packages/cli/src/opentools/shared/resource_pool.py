"""Adaptive resource pool with priority-based scheduling for concurrency control."""

from __future__ import annotations

import asyncio
import heapq
from collections import defaultdict


class AdaptiveResourcePool:
    """Priority-aware concurrency pool with per-group limits.

    Tasks acquire a slot before executing. When full, tasks wait
    in a priority heap — lowest priority number goes first.
    """

    def __init__(
        self,
        global_limit: int = 8,
        group_limits: dict[str, int] | None = None,
    ) -> None:
        self._global_limit = global_limit
        self._current_limit = global_limit
        self._group_limits = group_limits or {}
        self._active: dict[str, int] = defaultdict(int)  # group → count
        self._total_active = 0
        self._waiters: list[tuple[int, int, asyncio.Future, str]] = []  # priority heap
        self._counter = 0  # tiebreaker for equal priorities

    @property
    def active_count(self) -> int:
        """Return the total number of currently active (acquired) slots."""
        return self._total_active

    async def acquire(self, task_id: str, priority: int, resource_group: str) -> None:
        """Wait until a slot is available. Lower priority number = higher priority."""
        while not self._can_acquire(resource_group):
            loop = asyncio.get_event_loop()
            fut: asyncio.Future[None] = loop.create_future()
            self._counter += 1
            entry = (priority, self._counter, fut, resource_group)
            heapq.heappush(self._waiters, entry)
            try:
                await fut
            except asyncio.CancelledError:
                # Remove the future from the waiter list if cancelled
                try:
                    self._waiters.remove(entry)
                    heapq.heapify(self._waiters)
                except ValueError:
                    pass
                raise
            # Re-check on wake: another waiter may have grabbed the slot

        self._active[resource_group] += 1
        self._total_active += 1

    def release(self, resource_group: str) -> None:
        """Release a slot and wake the highest-priority eligible waiter."""
        self._active[resource_group] -= 1
        self._total_active -= 1
        self._wake_eligible()

    def _can_acquire(self, resource_group: str) -> bool:
        """Return True if both global and per-group limits allow acquisition."""
        if self._total_active >= self._current_limit:
            return False
        group_limit = self._group_limits.get(resource_group)
        if group_limit is not None and self._active[resource_group] >= group_limit:
            return False
        return True

    def _wake_eligible(self) -> None:
        """Pop waiters from heap, wake the first one whose group can acquire.

        Waiters whose group still has no capacity are pushed back onto the heap.
        Only one waiter is woken per call (they will re-check on resume).
        """
        skipped: list[tuple[int, int, asyncio.Future, str]] = []

        while self._waiters:
            entry = heapq.heappop(self._waiters)
            priority, counter, fut, group = entry

            if fut.done():
                # Cancelled or already resolved — skip it
                continue

            if self._can_acquire(group):
                # Wake this waiter; it will complete the acquire after resuming
                fut.set_result(None)
                # Push skipped ineligible waiters back
                for s in skipped:
                    heapq.heappush(self._waiters, s)
                return
            else:
                skipped.append(entry)

        # No eligible waiter found; restore all skipped entries
        for s in skipped:
            heapq.heappush(self._waiters, s)
