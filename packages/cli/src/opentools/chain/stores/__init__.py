"""Chain store backends.

Two implementations of ChainStoreProtocol:
- AsyncChainStore (aiosqlite) for CLI
- PostgresChainStore (SQLAlchemy async) for web backend
"""
from opentools.chain.stores.sqlite_async import AsyncChainStore

__all__ = ["AsyncChainStore"]


def __getattr__(name):
    """Lazy import of PostgresChainStore so the CLI doesn't pay the web
    SQLModel import cost unless a caller actually asks for it."""
    if name == "PostgresChainStore":
        from opentools.chain.stores.postgres_async import PostgresChainStore

        return PostgresChainStore
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
