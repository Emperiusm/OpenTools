"""Async progress event fan-out via EventBus.

Each subscriber for a given scan_id gets its own asyncio.Queue.
Slow subscribers drop oldest events (backpressure) rather than
blocking the publisher.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import AsyncIterator

from opentools.scanner.models import ProgressEvent, ProgressEventType

_TERMINAL_TYPES: frozenset[ProgressEventType] = frozenset(
    {ProgressEventType.SCAN_COMPLETED, ProgressEventType.SCAN_FAILED}
)


class EventBus:
    """Fan-out progress events to multiple async subscribers.

    Each subscriber gets its own queue. Slow subscribers drop oldest
    events (backpressure) rather than blocking the publisher.
    """

    def __init__(self, max_queue_size: int = 1000) -> None:
        self._subscribers: dict[str, list[asyncio.Queue[ProgressEvent]]] = defaultdict(list)
        self._max_queue_size = max_queue_size

    async def publish(self, event: ProgressEvent) -> None:
        """Publish event to all subscribers for this scan."""
        queues = self._subscribers.get(event.scan_id, [])
        for queue in queues:
            if queue.full():
                # Backpressure: drop the oldest event to make room
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            await queue.put(event)

    async def subscribe(
        self,
        scan_id: str,
        from_sequence: int | None = None,
    ) -> AsyncIterator[ProgressEvent]:
        """Subscribe to events for a scan.

        Yields events until a terminal event (SCAN_COMPLETED or SCAN_FAILED)
        is received, then stops. The subscriber is automatically cleaned up.
        """
        queue: asyncio.Queue[ProgressEvent] = asyncio.Queue(
            maxsize=self._max_queue_size
        )
        self._subscribers[scan_id].append(queue)
        try:
            while True:
                event = await queue.get()
                yield event
                if event.type in _TERMINAL_TYPES:
                    break
        finally:
            try:
                self._subscribers[scan_id].remove(queue)
            except ValueError:
                pass
            # Clean up empty scan_id entry
            if not self._subscribers[scan_id]:
                self._subscribers.pop(scan_id, None)
