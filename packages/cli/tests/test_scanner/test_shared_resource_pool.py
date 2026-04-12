"""Tests for AdaptiveResourcePool — priority heap with per-group limits."""

from __future__ import annotations

import asyncio

import pytest

from opentools.shared.resource_pool import AdaptiveResourcePool


# ===========================================================================
# Task 14: AdaptiveResourcePool tests
# ===========================================================================


class TestAcquireAndRelease:
    @pytest.mark.asyncio
    async def test_acquire_and_release(self):
        """Acquire 2 slots (limit=2), release one, then acquire a third."""
        pool = AdaptiveResourcePool(global_limit=2)

        # Acquire two slots immediately (below limit)
        await asyncio.wait_for(pool.acquire("t1", priority=1, resource_group="g"), timeout=0.5)
        await asyncio.wait_for(pool.acquire("t2", priority=1, resource_group="g"), timeout=0.5)
        assert pool.active_count == 2

        # Release one slot
        pool.release("g")
        assert pool.active_count == 1

        # Third acquire should now succeed
        await asyncio.wait_for(pool.acquire("t3", priority=1, resource_group="g"), timeout=0.5)
        assert pool.active_count == 2

        # Clean up
        pool.release("g")
        pool.release("g")
        assert pool.active_count == 0


class TestPriorityOrdering:
    @pytest.mark.asyncio
    async def test_priority_ordering(self):
        """Fill pool (limit=1), queue low-pri then high-pri waiter; release → high-pri goes first."""
        pool = AdaptiveResourcePool(global_limit=1)

        # Fill the single slot
        await asyncio.wait_for(pool.acquire("holder", priority=1, resource_group="g"), timeout=0.5)
        assert pool.active_count == 1

        order: list[str] = []

        async def low_pri_task():
            await pool.acquire("low", priority=10, resource_group="g")
            order.append("low")
            pool.release("g")

        async def high_pri_task():
            await pool.acquire("high", priority=1, resource_group="g")
            order.append("high")
            pool.release("g")

        # Schedule both waiters — they will block since pool is full
        low_task = asyncio.create_task(low_pri_task())
        # Yield so low_task gets onto the heap before high_task
        await asyncio.sleep(0)
        high_task = asyncio.create_task(high_pri_task())
        await asyncio.sleep(0)

        # Release the holder — should wake the highest-priority (low number) waiter
        pool.release("g")

        await asyncio.wait_for(asyncio.gather(low_task, high_task), timeout=0.5)

        # high_pri (priority=1) must execute before low_pri (priority=10)
        assert order == ["high", "low"]


class TestGroupLimits:
    @pytest.mark.asyncio
    async def test_group_limits(self):
        """Group limit of 1 for 'mcp:codebadger'; second acquire blocks until release."""
        pool = AdaptiveResourcePool(
            global_limit=8,
            group_limits={"mcp:codebadger": 1},
        )

        # First acquire for the group should succeed immediately
        await asyncio.wait_for(
            pool.acquire("t1", priority=1, resource_group="mcp:codebadger"),
            timeout=0.5,
        )
        assert pool.active_count == 1

        acquired_second = False

        async def second_acquire():
            nonlocal acquired_second
            await pool.acquire("t2", priority=1, resource_group="mcp:codebadger")
            acquired_second = True

        task = asyncio.create_task(second_acquire())
        await asyncio.sleep(0)  # let task attempt and block

        # Second acquire should still be waiting (group at limit)
        assert not acquired_second

        # Release the first slot — second should now acquire
        pool.release("mcp:codebadger")
        await asyncio.wait_for(task, timeout=0.5)
        assert acquired_second
        assert pool.active_count == 1

        # Clean up
        pool.release("mcp:codebadger")
        assert pool.active_count == 0


class TestActiveCount:
    @pytest.mark.asyncio
    async def test_active_count(self):
        """active_count tracks acquires and releases correctly."""
        pool = AdaptiveResourcePool(global_limit=5)

        assert pool.active_count == 0

        await pool.acquire("t1", priority=1, resource_group="a")
        assert pool.active_count == 1

        await pool.acquire("t2", priority=2, resource_group="b")
        assert pool.active_count == 2

        await pool.acquire("t3", priority=3, resource_group="a")
        assert pool.active_count == 3

        pool.release("a")
        assert pool.active_count == 2

        pool.release("b")
        assert pool.active_count == 1

        pool.release("a")
        assert pool.active_count == 0
