"""Tests for the shared EventBus — async progress event fan-out."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from opentools.shared.progress import EventBus
from opentools.scanner.models import ProgressEvent, ProgressEventType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    scan_id: str,
    seq: int,
    event_type: ProgressEventType = ProgressEventType.TASK_COMPLETED,
) -> ProgressEvent:
    return ProgressEvent(
        id=f"evt-{seq}",
        type=event_type,
        timestamp=datetime.now(timezone.utc),
        scan_id=scan_id,
        sequence=seq,
        data={},
        tasks_total=10,
        tasks_completed=seq,
        tasks_running=1,
        findings_total=0,
        elapsed_seconds=float(seq),
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestEventBus:
    @pytest.mark.asyncio
    async def test_publish_and_subscribe(self) -> None:
        """Publish one regular event + SCAN_COMPLETED; subscriber receives both and stops."""
        bus = EventBus()
        scan_id = "scan-1"

        evt_regular = _make_event(scan_id, 1, ProgressEventType.TASK_COMPLETED)
        evt_terminal = _make_event(scan_id, 2, ProgressEventType.SCAN_COMPLETED)

        received: list[ProgressEvent] = []

        async def _collect() -> None:
            async for event in bus.subscribe(scan_id):
                received.append(event)

        collector = asyncio.create_task(_collect())

        # Give subscriber time to register
        await asyncio.sleep(0)

        await bus.publish(evt_regular)
        await bus.publish(evt_terminal)

        await asyncio.wait_for(collector, timeout=2.0)

        assert len(received) == 2
        assert received[0].id == "evt-1"
        assert received[1].id == "evt-2"
        assert received[1].type == ProgressEventType.SCAN_COMPLETED

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self) -> None:
        """Two subscribers both receive the same published event."""
        bus = EventBus()
        scan_id = "scan-multi"

        evt = _make_event(scan_id, 1, ProgressEventType.TASK_COMPLETED)
        terminal = _make_event(scan_id, 2, ProgressEventType.SCAN_COMPLETED)

        received_a: list[ProgressEvent] = []
        received_b: list[ProgressEvent] = []

        async def _collect(store: list[ProgressEvent]) -> None:
            async for event in bus.subscribe(scan_id):
                store.append(event)

        task_a = asyncio.create_task(_collect(received_a))
        task_b = asyncio.create_task(_collect(received_b))

        # Give both subscribers time to register
        await asyncio.sleep(0)

        await bus.publish(evt)
        await bus.publish(terminal)

        await asyncio.wait_for(asyncio.gather(task_a, task_b), timeout=2.0)

        assert len(received_a) == 2
        assert len(received_b) == 2
        assert received_a[0].id == received_b[0].id == "evt-1"

    @pytest.mark.asyncio
    async def test_different_scan_ids_isolated(self) -> None:
        """A subscriber for scan-1 does NOT receive events published to scan-2."""
        bus = EventBus()

        received_scan1: list[ProgressEvent] = []

        async def _collect() -> None:
            async for event in bus.subscribe("scan-1"):
                received_scan1.append(event)

        collector = asyncio.create_task(_collect())
        await asyncio.sleep(0)

        # Publish to scan-2 only — scan-1 subscriber must not see these
        await bus.publish(_make_event("scan-2", 1, ProgressEventType.TASK_COMPLETED))
        await bus.publish(_make_event("scan-2", 2, ProgressEventType.SCAN_COMPLETED))

        # Now terminate scan-1 so the subscriber stops
        await bus.publish(_make_event("scan-1", 3, ProgressEventType.SCAN_COMPLETED))

        await asyncio.wait_for(collector, timeout=2.0)

        # Only the scan-1 terminal event should be received
        assert len(received_scan1) == 1
        assert received_scan1[0].scan_id == "scan-1"
        assert received_scan1[0].type == ProgressEventType.SCAN_COMPLETED
