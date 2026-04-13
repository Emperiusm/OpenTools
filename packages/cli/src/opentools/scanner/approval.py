"""ApprovalRegistry — in-memory notification hub for HITL approval gates.

NOT the source of truth. The database is always authoritative.
This registry only holds asyncio.Event handles for waking sleeping gates.
"""
from __future__ import annotations
import asyncio

class ApprovalRegistry:
    def __init__(self) -> None:
        self._events: dict[str, asyncio.Event] = {}

    def register(self, ticket_id: str) -> asyncio.Event:
        event = asyncio.Event()
        self._events[ticket_id] = event
        return event

    def signal(self, ticket_id: str) -> bool:
        event = self._events.get(ticket_id)
        if event is None:
            return False
        event.set()
        return True

    def remove(self, ticket_id: str) -> None:
        self._events.pop(ticket_id, None)

    def has_ticket(self, ticket_id: str) -> bool:
        return ticket_id in self._events

    def pending_ticket_ids(self) -> set[str]:
        return set(self._events.keys())
