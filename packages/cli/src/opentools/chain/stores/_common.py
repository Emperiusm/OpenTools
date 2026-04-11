"""Shared helpers for chain store implementations.

Contains the error types, method decorators, and small utility helpers
used by both AsyncChainStore (aiosqlite) and PostgresChainStore
(SQLAlchemy async).
"""
from __future__ import annotations

import functools
import logging
from typing import Awaitable, Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class StoreNotInitialized(RuntimeError):
    """Raised when a chain store method is called before initialize()
    or after close()."""


class ScopingViolation(RuntimeError):
    """Raised when a user-scoped backend receives a None user_id.

    PostgresChainStore raises this when any query is attempted without
    an explicit user_id. AsyncChainStore (single-user CLI) accepts
    None freely.
    """


def require_initialized(
    fn: Callable[..., Awaitable[T]],
) -> Callable[..., Awaitable[T]]:
    """Decorator that raises StoreNotInitialized if the store isn't ready.

    Applied to every public async method on both backends. Zero runtime
    cost when initialized (one attribute check).
    """

    @functools.wraps(fn)
    async def wrapper(self, *args, **kwargs):
        if not getattr(self, "_initialized", False):
            raise StoreNotInitialized(
                f"{type(self).__name__}.{fn.__name__}() called before "
                f"initialize() or after close()"
            )
        return await fn(self, *args, **kwargs)

    return wrapper


def require_user_scope(
    fn: Callable[..., Awaitable[T]],
) -> Callable[..., Awaitable[T]]:
    """Decorator that enforces non-None user_id on PostgresChainStore
    methods.

    AsyncChainStore does NOT use this decorator — it accepts None freely
    because the CLI has a single user. Applied only in postgres_async.py.
    """

    @functools.wraps(fn)
    async def wrapper(self, *args, user_id=None, **kwargs):
        if user_id is None:
            raise ScopingViolation(
                f"{type(self).__name__}.{fn.__name__}() requires user_id "
                f"(web backend refuses None for privacy)"
            )
        return await fn(self, *args, user_id=user_id, **kwargs)

    return wrapper


def pad_in_clause(values: list, *, min_size: int = 4) -> list:
    """Pad a list for a SQL IN-clause to the next power of 2 using None.

    This keeps SQL prepared-statement cache keys hitting repeatedly
    instead of recompiling for every unique parameter count.
    ``IN (?, ?, NULL, NULL)`` still filters correctly because nothing
    equals NULL in SQL.

    Empty input returns an empty list (no clause to pad).
    """
    if not values:
        return []
    size = max(min_size, 1)
    while size < len(values):
        size *= 2
    return list(values) + [None] * (size - len(values))
