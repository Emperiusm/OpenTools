"""Tests for ApprovalRegistry."""
import asyncio
import pytest
from opentools.scanner.approval import ApprovalRegistry

class TestApprovalRegistry:
    def test_register_returns_event(self):
        r = ApprovalRegistry()
        event = r.register("t1")
        assert isinstance(event, asyncio.Event)
        assert not event.is_set()

    def test_signal_sets_event(self):
        r = ApprovalRegistry()
        event = r.register("t1")
        assert r.signal("t1") is True
        assert event.is_set()

    def test_signal_missing_returns_false(self):
        r = ApprovalRegistry()
        assert r.signal("nope") is False

    def test_remove_cleans_up(self):
        r = ApprovalRegistry()
        r.register("t1")
        r.remove("t1")
        assert r.signal("t1") is False

    def test_remove_missing_no_raise(self):
        ApprovalRegistry().remove("nope")

    def test_has_ticket(self):
        r = ApprovalRegistry()
        assert r.has_ticket("t1") is False
        r.register("t1")
        assert r.has_ticket("t1") is True

    def test_pending_ticket_ids(self):
        r = ApprovalRegistry()
        r.register("a")
        r.register("b")
        assert r.pending_ticket_ids() == {"a", "b"}

    @pytest.mark.asyncio
    async def test_event_wakes_awaiter(self):
        r = ApprovalRegistry()
        event = r.register("t1")
        woke = False
        async def waiter():
            nonlocal woke
            await asyncio.wait_for(event.wait(), timeout=5.0)
            woke = True
        task = asyncio.ensure_future(waiter())
        await asyncio.sleep(0.05)
        assert not woke
        r.signal("t1")
        await task
        assert woke

    @pytest.mark.asyncio
    async def test_multiple_gates_independent(self):
        r = ApprovalRegistry()
        ea = r.register("a")
        eb = r.register("b")
        r.signal("a")
        assert ea.is_set()
        assert not eb.is_set()
