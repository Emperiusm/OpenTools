"""Retry-with-backoff utility for async functions."""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Coroutine

from opentools.scanner.models import RetryPolicy


def _is_retryable(error: Exception, retry_on: list[str]) -> bool:
    """Check if error matches any retryable pattern.

    Performs a case-insensitive match against the exception type name and
    the string representation of the error.
    """
    type_name = type(error).__name__.lower()
    error_str = str(error).lower()
    for pattern in retry_on:
        p = pattern.lower()
        if p in type_name or p in error_str:
            return True
    return False


async def execute_with_retry(
    fn: Callable[[], Coroutine[Any, Any, Any]],
    policy: RetryPolicy,
) -> Any:
    """Execute async function with retry on matching errors.

    Retries up to policy.max_retries times with exponential backoff
    (backoff_seconds * 2^attempt).  Only retries errors matching
    policy.retry_on patterns.  Non-matching errors propagate immediately.
    """
    last_error: Exception | None = None

    for attempt in range(policy.max_retries + 1):
        try:
            return await fn()
        except Exception as exc:
            if not _is_retryable(exc, policy.retry_on):
                raise
            last_error = exc
            if attempt < policy.max_retries:
                delay = policy.backoff_seconds * (2 ** attempt)
                await asyncio.sleep(delay)

    # All retries exhausted — re-raise the last retryable error
    raise last_error  # type: ignore[misc]
