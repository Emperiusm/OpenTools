"""Tests for the shared async retry module."""

from __future__ import annotations

import pytest

from opentools.shared.retry import execute_with_retry, _is_retryable
from opentools.scanner.models import RetryPolicy


# ===========================================================================
# Task 10: Shared Retry tests
# ===========================================================================


class TestIsRetryable:
    def test_matches_type_name(self):
        assert _is_retryable(TimeoutError("timed out"), ["timeout"]) is True

    def test_matches_str_error(self):
        assert _is_retryable(ValueError("connection_error occurred"), ["connection_error"]) is True

    def test_case_insensitive(self):
        assert _is_retryable(TimeoutError("TIMED OUT"), ["timeout"]) is True

    def test_no_match(self):
        assert _is_retryable(ValueError("bad value"), ["timeout"]) is False

    def test_empty_retry_on(self):
        assert _is_retryable(TimeoutError("timed out"), []) is False


class TestExecuteWithRetry:
    @pytest.mark.asyncio
    async def test_success_no_retry(self):
        """Function succeeds on first try; call_count is 1."""
        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            return "ok"

        policy = RetryPolicy(max_retries=3, backoff_seconds=0.01, retry_on=["timeout"])
        result = await execute_with_retry(fn, policy)

        assert result == "ok"
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_retry_on_failure(self):
        """Function fails twice with TimeoutError then succeeds; call_count is 3."""
        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise TimeoutError("timed out")
            return "success"

        policy = RetryPolicy(max_retries=3, backoff_seconds=0.01, retry_on=["timeout"])
        result = await execute_with_retry(fn, policy)

        assert result == "success"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_exhausted_retries_raises(self):
        """Always fails with TimeoutError; max_retries=2 → raises TimeoutError after 3 total calls."""
        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            raise TimeoutError("always times out")

        policy = RetryPolicy(max_retries=2, backoff_seconds=0.01, retry_on=["timeout"])

        with pytest.raises(TimeoutError):
            await execute_with_retry(fn, policy)

        # 1 initial attempt + 2 retries = 3 total calls
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_non_retryable_error_raises_immediately(self):
        """Raises ValueError (not in retry_on=['timeout']) → raises immediately, call_count=1."""
        call_count = 0

        async def fn():
            nonlocal call_count
            call_count += 1
            raise ValueError("bad input")

        policy = RetryPolicy(max_retries=3, backoff_seconds=0.01, retry_on=["timeout"])

        with pytest.raises(ValueError):
            await execute_with_retry(fn, policy)

        assert call_count == 1
