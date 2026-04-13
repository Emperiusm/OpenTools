"""Cooperative async cancellation token for the scan engine."""

from __future__ import annotations

import asyncio


class CancellationToken:
    """Thread-safe, async-aware cancellation signal."""

    def __init__(self) -> None:
        self._event = asyncio.Event()
        self._reason: str | None = None

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str | None:
        return self._reason

    async def cancel(self, reason: str) -> None:
        """Signal cancellation. Idempotent — first reason wins."""
        if not self._event.is_set():
            self._reason = reason
            self._event.set()

    async def wait_for_cancellation(self) -> None:
        """Block until cancellation is signalled."""
        await self._event.wait()
