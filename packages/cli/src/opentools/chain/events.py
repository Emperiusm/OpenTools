"""Minimal in-process event bus for chain-related store events.

The chain package subscribes to finding.created / finding.updated / finding.deleted
at init time (Task 23b). The engagement store emits these events after successful
state changes. Handler exceptions are logged and swallowed so a broken subscriber
cannot break finding CRUD.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Callable

logger = logging.getLogger(__name__)

EventName = str
Handler = Callable[..., None]


class StoreEventBus:
    def __init__(self) -> None:
        self._subscribers: dict[EventName, list[Handler]] = defaultdict(list)

    def subscribe(self, event: EventName, handler: Handler) -> None:
        self._subscribers[event].append(handler)

    def emit(self, event: EventName, **kwargs) -> None:
        for handler in list(self._subscribers.get(event, [])):
            try:
                handler(**kwargs)
            except Exception:  # noqa: BLE001
                logger.exception("StoreEventBus handler failed for event=%s", event)


_bus_singleton: StoreEventBus | None = None


def get_event_bus() -> StoreEventBus:
    global _bus_singleton
    if _bus_singleton is None:
        _bus_singleton = StoreEventBus()
    return _bus_singleton


def reset_event_bus() -> None:
    """Test helper."""
    global _bus_singleton
    _bus_singleton = None
