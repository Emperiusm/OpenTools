"""Tests for CancellationToken — cooperative async cancellation."""

from __future__ import annotations

import asyncio

import pytest

from opentools.scanner.cancellation import CancellationToken


# ===========================================================================
# Task 5: CancellationToken tests
# ===========================================================================


class TestCancellationToken:
    def test_initial_state(self):
        """Token starts not cancelled with no reason."""
        token = CancellationToken()
        assert token.is_cancelled is False
        assert token.reason is None

    @pytest.mark.asyncio
    async def test_cancel(self):
        """After cancel(), is_cancelled is True and reason matches."""
        token = CancellationToken()
        await token.cancel("user requested stop")
        assert token.is_cancelled is True
        assert token.reason == "user requested stop"

    @pytest.mark.asyncio
    async def test_cancel_is_idempotent(self):
        """Second cancel() call does not overwrite the first reason."""
        token = CancellationToken()
        await token.cancel("first reason")
        await token.cancel("second reason")
        assert token.is_cancelled is True
        assert token.reason == "first reason"

    @pytest.mark.asyncio
    async def test_wait_for_cancellation(self):
        """wait_for_cancellation() unblocks once cancel() is called."""
        token = CancellationToken()

        async def _cancel_after_delay() -> None:
            await asyncio.sleep(0.05)
            await token.cancel("delayed cancel")

        task = asyncio.create_task(_cancel_after_delay())
        await token.wait_for_cancellation()
        await task  # ensure task is done cleanly

        assert token.is_cancelled is True
        assert token.reason == "delayed cancel"

    @pytest.mark.asyncio
    async def test_wait_returns_immediately_if_already_cancelled(self):
        """wait_for_cancellation() returns immediately when already cancelled."""
        token = CancellationToken()
        await token.cancel("pre-set")

        # Should not block; wrap with a short timeout to guard against hangs.
        await asyncio.wait_for(token.wait_for_cancellation(), timeout=1.0)

        assert token.is_cancelled is True
