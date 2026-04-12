"""Factory for constructing PostgresChainStore from web dependencies.

Phase 5B of the chain async-store refactor: the web backend no longer
touches the chain tables directly via SQLModel. Instead, every service
method delegates to the shared ``PostgresChainStore`` which implements
``ChainStoreProtocol`` against the web SQLModel tables.

This module provides two helpers:

* :func:`chain_store_from_session` — request-scoped. Wraps an
  ``AsyncSession`` from FastAPI dependency injection. The caller
  (typically ``ChainService``) is responsible for ``await
  store.initialize()``. Closing the session is handled by the DI
  layer on request teardown.

* :func:`chain_store_from_factory` — background-task-scoped. Wraps an
  ``async_sessionmaker``-style factory. ``initialize()`` opens the
  session via the factory and ``close()`` releases it.
"""
from __future__ import annotations

from typing import Any, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from opentools.chain.stores.postgres_async import PostgresChainStore


def chain_store_from_session(session: AsyncSession) -> PostgresChainStore:
    """Construct a :class:`PostgresChainStore` around a request-scoped session.

    The caller must ``await store.initialize()`` before using any
    methods. The session itself is managed by FastAPI's DI and closed
    at request teardown, so there is no need to call ``store.close()``.
    """
    return PostgresChainStore(session=session)


def chain_store_from_factory(
    session_factory: Callable[[], Any],
) -> PostgresChainStore:
    """Construct a :class:`PostgresChainStore` around a session factory.

    ``session_factory`` is a callable that returns an async context
    manager yielding an ``AsyncSession`` — ``async_sessionmaker``
    qualifies. ``store.initialize()`` enters the context manager and
    ``store.close()`` exits it.
    """
    return PostgresChainStore(session_factory=session_factory)
