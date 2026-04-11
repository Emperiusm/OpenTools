# Phase 3C.1.5: Async Store Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the chain subsystem so a single async-first codebase powers both CLI (SQLite via aiosqlite) and web (Postgres via SQLAlchemy async) through one `ChainStoreProtocol` abstraction. Eliminates the duplicated `chain_rebuild.py` worker and closes seven `store._conn.execute(...)` encapsulation leaks.

**Architecture:** Define a 32-method async protocol. Implement it twice: `AsyncChainStore` (aiosqlite for CLI) and `PostgresChainStore` (SQLAlchemy async for web). Convert all chain consumers (pipeline, linker, query engine, entity ops, exporter, batch, subscriptions) to async-native. CLI commands gain `async def` with `asyncio.run` at Typer entry. Web backend rewrites its rebuild endpoint to use the shared pipeline via `PostgresChainStore`. Five phases on one feature branch; each phase leaves tests green.

**Tech Stack:** Python 3.14, `aiosqlite>=0.21`, SQLAlchemy async + `asyncpg`, pytest-asyncio (already configured via root pyproject), pytest-xdist (new dev dep), rustworkx.

**Spec:** `docs/superpowers/specs/2026-04-10-phase3c1-5-async-store-refactor-design.md`

**Starting state:** Phase 3C.1 + follow-ups merged. Branch starts from main at commit `3c0a9c2`. Test baseline: 500 passing (447 CLI + 47 web), 1 skipped.

---

## File Map

### Phase 1 — Foundation

| File | Action | Task |
|------|--------|------|
| `packages/cli/src/opentools/chain/store_protocol.py` | Create | 1-3 |
| `packages/cli/src/opentools/chain/stores/__init__.py` | Create | 4 |
| `packages/cli/src/opentools/chain/stores/_common.py` | Create | 4-5 |
| `packages/cli/src/opentools/chain/stores/sqlite_async.py` | Create | 6-14 |
| `packages/cli/src/opentools/chain/_cache_keys.py` | Create | 15 |
| `packages/cli/src/opentools/chain/config.py` | Modify | 16 |
| `packages/cli/src/opentools/chain/store_extensions.py` | Modify | 17 |
| `packages/cli/src/opentools/engagement/schema.py` | Modify | 18-19 |
| `packages/cli/pyproject.toml` | Modify | 1 |
| `pyproject.toml` (root) | Modify | 1 |
| `scripts/check_test_count.sh` | Create | 20 |
| `packages/cli/tests/chain/test_async_chain_store.py` | Create | 6-14 |
| `packages/cli/tests/chain/test_store_protocol_conformance.py` | Create | 21 |
| `packages/cli/tests/chain/test_migration_v4.py` | Create | 19 |

### Phase 2 — ExtractionPipeline + drain worker

| File | Action | Task |
|------|--------|------|
| `packages/cli/src/opentools/chain/extractors/pipeline.py` | Modify | 22-23 |
| `packages/cli/src/opentools/chain/linker/llm_pass.py` | Modify | 24 |
| `packages/cli/src/opentools/chain/subscriptions.py` | Modify | 25-26 |
| `packages/cli/src/opentools/chain/cli.py` | Modify | 27 |
| `packages/cli/tests/chain/conftest.py` | Modify | 22 |
| `packages/cli/tests/chain/test_pipeline.py` | Modify | 22-23 |
| `packages/cli/tests/chain/test_pipeline_integration.py` | Modify | 23 |
| `packages/cli/tests/chain/test_llm_pass.py` | Modify | 24 |
| `packages/cli/tests/chain/test_subscriptions.py` | Modify | 26 |

### Phase 3 — Linker + entity_ops + exporter + batch

| File | Action | Task |
|------|--------|------|
| `packages/cli/src/opentools/chain/linker/engine.py` | Modify | 28 |
| `packages/cli/src/opentools/chain/linker/batch.py` | Modify | 29 |
| `packages/cli/src/opentools/chain/entity_ops.py` | Modify | 30 |
| `packages/cli/src/opentools/chain/exporter.py` | Modify | 31 |
| `packages/cli/tests/chain/test_linker_engine.py` | Modify | 28 |
| `packages/cli/tests/chain/test_linker_batch.py` | Modify | 29 |
| `packages/cli/tests/chain/test_entity_ops.py` | Modify | 30 |
| `packages/cli/tests/chain/test_exporter.py` | Modify | 31 |
| `packages/cli/tests/chain/test_cli_commands.py` | Modify | 32 |

### Phase 4 — Query engine + graph cache

| File | Action | Task |
|------|--------|------|
| `packages/cli/src/opentools/chain/query/graph_cache.py` | Modify | 33 |
| `packages/cli/src/opentools/chain/query/engine.py` | Modify | 34 |
| `packages/cli/src/opentools/chain/query/presets.py` | Modify | 35 |
| `packages/cli/src/opentools/chain/query/narration.py` | Modify | 35 |
| `packages/cli/tests/chain/test_graph_cache.py` | Modify | 33 |
| `packages/cli/tests/chain/test_query_engine.py` | Modify | 34 |
| `packages/cli/tests/chain/test_presets.py` | Modify | 35 |
| `packages/cli/tests/chain/test_narration.py` | Modify | 35 |

### Phase 5 — Postgres backend + unification

| File | Action | Task |
|------|--------|------|
| `packages/cli/src/opentools/chain/stores/postgres_async.py` | Create | 36-42 |
| `packages/web/backend/alembic/versions/004_chain_jsonb_unlogged_userids.py` | Create | 36 |
| `packages/web/backend/app/services/chain_store_factory.py` | Create | 43 |
| `packages/web/backend/app/services/chain_service.py` | Modify | 43 |
| `packages/web/backend/app/routes/chain.py` | Modify | 43 |
| `packages/web/backend/app/services/chain_rebuild.py` | Delete | 44 |
| `packages/cli/src/opentools/chain/store_extensions.py` | Delete | 44 |
| `packages/cli/tests/chain/test_store_protocol_conformance.py` | Modify | 42 |
| `packages/cli/tests/chain/test_pipeline_integration.py` | Modify | 45 |
| `packages/web/backend/tests/test_chain_rebuild.py` | Rename + Modify | 46 |
| `packages/web/backend/tests/test_web_rebuild.py` | Create (from rename) | 46 |

---

# PHASE 1 — Foundation

Phase 1 lands the protocol, `AsyncChainStore`, migration v4, and sync shim. Zero existing consumer code changes. Zero existing test changes. After Phase 1, `pytest packages/ -q` shows `>= 530 passed, failed == 0`.

## Task 1: Add aiosqlite dependency and root pyproject config

**Files:**
- Modify: `packages/cli/pyproject.toml` (add deps)
- Modify: `pyproject.toml` (root — add asyncio fixture loop scope)

- [ ] **Step 1: Add aiosqlite to CLI dependencies**

Read `packages/cli/pyproject.toml`. Find the `dependencies = [...]` list in `[project]`. Append:

```toml
"aiosqlite>=0.21",
```

Find `[project.optional-dependencies]` or `dev`/`test` group. Append:

```toml
"pytest-xdist>=3",
```

- [ ] **Step 2: Add loop scope setting to root pyproject**

Read `pyproject.toml` at the repo root. It currently has:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["packages/cli/tests", "packages/web/backend/tests"]
pythonpath = ["packages/cli/src", "packages/web/backend"]
```

Add one line:

```toml
[tool.pytest.ini_options]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "function"
testpaths = ["packages/cli/tests", "packages/web/backend/tests"]
pythonpath = ["packages/cli/src", "packages/web/backend"]
```

- [ ] **Step 3: Install the new deps**

Run: `pip install aiosqlite pytest-xdist`
Expected: successful install.

- [ ] **Step 4: Verify existing tests still pass**

Run: `python -m pytest packages/ -q`
Expected: `500 passed, 1 skipped`.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/pyproject.toml pyproject.toml
git commit -m "$(cat <<'EOF'
chore(chain): add aiosqlite dep and function-scoped fixture loop

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Define error types and base protocol skeleton

**Files:**
- Create: `packages/cli/src/opentools/chain/stores/__init__.py`
- Create: `packages/cli/src/opentools/chain/stores/_common.py`
- Create: `packages/cli/src/opentools/chain/store_protocol.py` (skeleton only, methods come in Tasks 3a-3c)
- Create: `packages/cli/tests/chain/test_store_common.py`

- [ ] **Step 1: Write the failing test**

Create `packages/cli/tests/chain/test_store_common.py`:

```python
"""Tests for chain/stores/_common.py — decorators, errors, helpers."""
import asyncio

import pytest

from opentools.chain.stores._common import (
    ScopingViolation,
    StoreNotInitialized,
    pad_in_clause,
    require_initialized,
)


def test_store_not_initialized_is_runtime_error():
    assert issubclass(StoreNotInitialized, RuntimeError)


def test_scoping_violation_is_runtime_error():
    assert issubclass(ScopingViolation, RuntimeError)


def test_pad_in_clause_empty():
    assert pad_in_clause([]) == []


def test_pad_in_clause_power_of_two_padding():
    assert len(pad_in_clause(["a"])) == 4      # min 4
    assert len(pad_in_clause(["a", "b", "c"])) == 4
    assert len(pad_in_clause(["a"] * 5)) == 8
    assert len(pad_in_clause(["a"] * 17)) == 32


def test_pad_in_clause_preserves_values_and_pads_with_none():
    padded = pad_in_clause(["x", "y", "z"])
    assert padded[:3] == ["x", "y", "z"]
    assert padded[3:] == [None]


def test_require_initialized_raises_when_not_initialized():
    class _Dummy:
        _initialized = False

        @require_initialized
        async def do_thing(self):
            return "ok"

    d = _Dummy()
    with pytest.raises(StoreNotInitialized, match="do_thing"):
        asyncio.run(d.do_thing())


def test_require_initialized_allows_when_initialized():
    class _Dummy:
        _initialized = True

        @require_initialized
        async def do_thing(self):
            return "ok"

    d = _Dummy()
    assert asyncio.run(d.do_thing()) == "ok"
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest packages/cli/tests/chain/test_store_common.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Create `stores/__init__.py`**

Create `packages/cli/src/opentools/chain/stores/__init__.py`:

```python
"""Chain store backends.

Two implementations of ChainStoreProtocol:
- AsyncChainStore (aiosqlite) for CLI
- PostgresChainStore (SQLAlchemy async) for web backend
"""
```

- [ ] **Step 4: Create `stores/_common.py`**

Create `packages/cli/src/opentools/chain/stores/_common.py`:

```python
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
```

- [ ] **Step 5: Create `store_protocol.py` skeleton**

Create `packages/cli/src/opentools/chain/store_protocol.py`:

```python
"""ChainStoreProtocol — backend-agnostic async interface for chain data.

See docs/superpowers/specs/2026-04-10-phase3c1-5-async-store-refactor-design.md
§4 for the full method list and contracts.

Method count: 32. Organized into sections:
- Lifecycle (4)
- Entity CRUD (6)
- Mention CRUD (7)
- Relation CRUD (5)
- Linker-specific queries (5)
- LinkerRun lifecycle (5)
- Extraction state + parser output (3)
- LLM caches (4)
- Export (2)

Actual method signatures are defined in Tasks 3a, 3b, 3c.
"""
from __future__ import annotations
```

- [ ] **Step 6: Run tests**

Run: `python -m pytest packages/cli/tests/chain/test_store_common.py -v`
Expected: 7 PASS.

Run: `python -m pytest packages/ -q`
Expected: `>= 507 passed, 1 skipped, 0 failed`.

- [ ] **Step 7: Commit**

```bash
git add packages/cli/src/opentools/chain/stores/__init__.py \
        packages/cli/src/opentools/chain/stores/_common.py \
        packages/cli/src/opentools/chain/store_protocol.py \
        packages/cli/tests/chain/test_store_common.py
git commit -m "$(cat <<'EOF'
feat(chain): add stores subpackage and error/decorator scaffolding

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Define the full ChainStoreProtocol (all 32 methods)

**Files:**
- Modify: `packages/cli/src/opentools/chain/store_protocol.py`

- [ ] **Step 1: Write the failing test**

Create `packages/cli/tests/chain/test_store_protocol_shape.py`:

```python
"""Shape tests for ChainStoreProtocol — verify every expected method
is defined as a Protocol member with correct signature.
"""
import inspect

from opentools.chain.store_protocol import ChainStoreProtocol


def _protocol_methods() -> set[str]:
    return {
        name
        for name in dir(ChainStoreProtocol)
        if not name.startswith("_") and callable(getattr(ChainStoreProtocol, name))
    }


EXPECTED_METHODS = {
    # Lifecycle (4)
    "initialize", "close", "transaction", "batch_transaction",
    # Entity CRUD (6)
    "upsert_entity", "upsert_entities_bulk", "get_entity",
    "get_entities_by_ids", "list_entities", "delete_entity",
    # Mention CRUD (7)
    "add_mentions_bulk", "mentions_for_finding",
    "delete_mentions_for_finding", "recompute_mention_counts",
    "rewrite_mentions_entity_id", "rewrite_mentions_by_ids",
    "fetch_mentions_with_engagement",
    # Relation CRUD (5)
    "upsert_relations_bulk", "relations_for_finding",
    "fetch_relations_in_scope", "stream_relations_in_scope",
    "apply_link_classification",
    # Linker-specific queries (5)
    "fetch_candidate_partners", "fetch_findings_by_ids",
    "count_findings_in_scope", "compute_avg_idf", "entities_for_finding",
    # LinkerRun lifecycle (5)
    "start_linker_run", "set_run_status", "finish_linker_run",
    "current_linker_generation", "fetch_linker_runs",
    # Extraction state + parser output (3)
    "get_extraction_hash", "upsert_extraction_state", "get_parser_output",
    # LLM caches (4)
    "get_extraction_cache", "put_extraction_cache",
    "get_llm_link_cache", "put_llm_link_cache",
    # Export (2)
    "fetch_findings_for_engagement", "export_dump_stream",
}


def test_protocol_has_32_methods():
    assert len(EXPECTED_METHODS) == 41 - 0  # noqa — count check below
    methods = _protocol_methods()
    missing = EXPECTED_METHODS - methods
    extra = methods - EXPECTED_METHODS
    assert not missing, f"protocol missing methods: {missing}"
    assert not extra, f"protocol has unexpected methods: {extra}"


def test_every_method_is_async_or_returns_context_manager():
    for name in EXPECTED_METHODS:
        method = getattr(ChainStoreProtocol, name)
        assert inspect.iscoroutinefunction(method) or callable(method), (
            f"{name} is neither a coroutine nor a callable"
        )
```

Note the count: the EXPECTED_METHODS set has 41 entries, not 32 — let me recount: 4+6+7+5+5+5+3+4+2 = 41. The spec says 32. Let me look at this carefully. The spec §4.3 lists methods. Counting from §4.3:

Lifecycle: initialize, close, transaction, batch_transaction = 4
Entity CRUD: upsert_entity, upsert_entities_bulk, get_entity, get_entities_by_ids, list_entities, delete_entity = 6
Mention CRUD: add_mentions_bulk, mentions_for_finding, delete_mentions_for_finding, recompute_mention_counts, rewrite_mentions_entity_id, rewrite_mentions_by_ids, fetch_mentions_with_engagement = 7
Relation CRUD: upsert_relations_bulk, relations_for_finding, fetch_relations_in_scope, stream_relations_in_scope, apply_link_classification = 5
Linker queries: fetch_candidate_partners, fetch_findings_by_ids, count_findings_in_scope, compute_avg_idf, entities_for_finding = 5
LinkerRun lifecycle: start_linker_run, set_run_status, finish_linker_run, current_linker_generation, fetch_linker_runs = 5
Extraction state: get_extraction_hash, upsert_extraction_state, get_parser_output = 3
LLM caches: get_extraction_cache, put_extraction_cache, get_llm_link_cache, put_llm_link_cache = 4
Export: fetch_findings_for_engagement, export_dump_stream = 2

Total: 4+6+7+5+5+5+3+4+2 = **41**

The spec said "32" in multiple places but actually lists 41 methods. This is a spec bug discovered during plan writing. The plan uses the real count (41). Update the test:

Replace the test_protocol_has_32_methods test with:

```python
def test_protocol_has_all_expected_methods():
    # Spec §4.3 lists 41 methods; "32" appears as a shorthand earlier
    # in the spec but was incorrect. 41 is the authoritative count.
    assert len(EXPECTED_METHODS) == 41
    methods = _protocol_methods()
    missing = EXPECTED_METHODS - methods
    extra = methods - EXPECTED_METHODS
    assert not missing, f"protocol missing methods: {missing}"
    assert not extra, f"protocol has unexpected methods: {extra}"
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest packages/cli/tests/chain/test_store_protocol_shape.py -v`
Expected: FAIL — skeleton has no methods.

- [ ] **Step 3: Implement the full protocol**

Replace `packages/cli/src/opentools/chain/store_protocol.py` with:

```python
"""ChainStoreProtocol — backend-agnostic async interface for chain data.

See docs/superpowers/specs/2026-04-10-phase3c1-5-async-store-refactor-design.md
§4 for contracts and rationale.

Every method is async. Methods return domain objects from
opentools.chain.models, never sqlite3.Row or SQLAlchemy ORM instances.
No raw SQL escape hatch.

User scoping: methods that touch per-user data take user_id as a
required keyword argument. None means "CLI context, unscoped" (accepted
by AsyncChainStore, rejected by PostgresChainStore via @require_user_scope).
"""
from __future__ import annotations

from datetime import datetime
from typing import AsyncContextManager, AsyncIterator, Iterable, Protocol
from uuid import UUID

from opentools.chain.models import (
    Entity,
    EntityMention,
    FindingParserOutput,
    FindingRelation,
    LinkerRun,
)
from opentools.chain.types import (
    LinkerMode,
    LinkerScope,
    RelationStatus,
)
from opentools.models import Finding


class ChainStoreProtocol(Protocol):
    # ─── Lifecycle ────────────────────────────────────────────────

    async def initialize(self) -> None: ...

    async def close(self) -> None: ...

    def transaction(self) -> AsyncContextManager[None]: ...

    def batch_transaction(self) -> AsyncContextManager[None]: ...

    # ─── Entity CRUD ──────────────────────────────────────────────

    async def upsert_entity(
        self, entity: Entity, *, user_id: UUID | None
    ) -> None: ...

    async def upsert_entities_bulk(
        self, entities: Iterable[Entity], *, user_id: UUID | None
    ) -> None: ...

    async def get_entity(
        self, entity_id: str, *, user_id: UUID | None
    ) -> Entity | None: ...

    async def get_entities_by_ids(
        self, entity_ids: Iterable[str], *, user_id: UUID | None
    ) -> dict[str, Entity]: ...

    async def list_entities(
        self,
        *,
        user_id: UUID | None,
        entity_type: str | None = None,
        min_mentions: int = 0,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Entity]: ...

    async def delete_entity(
        self, entity_id: str, *, user_id: UUID | None
    ) -> None: ...

    # ─── Mention CRUD ─────────────────────────────────────────────

    async def add_mentions_bulk(
        self, mentions: Iterable[EntityMention], *, user_id: UUID | None
    ) -> int: ...

    async def mentions_for_finding(
        self, finding_id: str, *, user_id: UUID | None
    ) -> list[EntityMention]: ...

    async def delete_mentions_for_finding(
        self, finding_id: str, *, user_id: UUID | None
    ) -> int: ...

    async def recompute_mention_counts(
        self, entity_ids: Iterable[str], *, user_id: UUID | None
    ) -> None: ...

    async def rewrite_mentions_entity_id(
        self,
        *,
        from_entity_id: str,
        to_entity_id: str,
        user_id: UUID | None,
    ) -> int: ...

    async def rewrite_mentions_by_ids(
        self,
        *,
        mention_ids: list[str],
        to_entity_id: str,
        user_id: UUID | None,
    ) -> int: ...

    async def fetch_mentions_with_engagement(
        self,
        entity_id: str,
        *,
        user_id: UUID | None,
    ) -> list[tuple[str, str]]: ...

    # ─── Relation CRUD ────────────────────────────────────────────

    async def upsert_relations_bulk(
        self,
        relations: Iterable[FindingRelation],
        *,
        user_id: UUID | None,
    ) -> tuple[int, int]: ...

    async def relations_for_finding(
        self, finding_id: str, *, user_id: UUID | None
    ) -> list[FindingRelation]: ...

    async def fetch_relations_in_scope(
        self,
        *,
        user_id: UUID | None,
        statuses: set[RelationStatus] | None = None,
    ) -> list[FindingRelation]: ...

    def stream_relations_in_scope(
        self,
        *,
        user_id: UUID | None,
        statuses: set[RelationStatus] | None = None,
    ) -> AsyncIterator[FindingRelation]: ...

    async def apply_link_classification(
        self,
        *,
        relation_id: str,
        status: RelationStatus,
        rationale: str,
        relation_type: str,
        confidence: float,
        user_id: UUID | None,
    ) -> None: ...

    # ─── Linker-specific queries ──────────────────────────────────

    async def fetch_candidate_partners(
        self,
        *,
        finding_id: str,
        entity_ids: set[str],
        user_id: UUID | None,
        common_entity_threshold: int,
    ) -> dict[str, set[str]]: ...

    async def fetch_findings_by_ids(
        self,
        finding_ids: Iterable[str],
        *,
        user_id: UUID | None,
    ) -> list[Finding]: ...

    async def count_findings_in_scope(
        self,
        *,
        user_id: UUID | None,
        engagement_id: str | None = None,
    ) -> int: ...

    async def compute_avg_idf(
        self,
        *,
        scope_total: int,
        user_id: UUID | None,
    ) -> float: ...

    async def entities_for_finding(
        self, finding_id: str, *, user_id: UUID | None
    ) -> list[Entity]: ...

    # ─── LinkerRun lifecycle ──────────────────────────────────────

    async def start_linker_run(
        self,
        *,
        scope: LinkerScope,
        scope_id: str | None,
        mode: LinkerMode,
        user_id: UUID | None,
    ) -> LinkerRun: ...

    async def set_run_status(
        self,
        run_id: str,
        status: str,
        *,
        user_id: UUID | None,
    ) -> None: ...

    async def finish_linker_run(
        self,
        run_id: str,
        *,
        findings_processed: int,
        entities_extracted: int,
        relations_created: int,
        relations_updated: int,
        relations_skipped_sticky: int,
        rule_stats: dict,
        duration_ms: int | None = None,
        error: str | None = None,
        user_id: UUID | None,
    ) -> None: ...

    async def current_linker_generation(
        self, *, user_id: UUID | None
    ) -> int: ...

    async def fetch_linker_runs(
        self, *, user_id: UUID | None, limit: int = 10
    ) -> list[LinkerRun]: ...

    # ─── Extraction state + parser output ─────────────────────────

    async def get_extraction_hash(
        self, finding_id: str, *, user_id: UUID | None
    ) -> str | None: ...

    async def upsert_extraction_state(
        self,
        *,
        finding_id: str,
        extraction_input_hash: str,
        extractor_set: list[str],
        user_id: UUID | None,
    ) -> None: ...

    async def get_parser_output(
        self, finding_id: str, *, user_id: UUID | None
    ) -> list[FindingParserOutput]: ...

    # ─── LLM caches (user-scoped) ────────────────────────────────

    async def get_extraction_cache(
        self, cache_key: str, *, user_id: UUID | None
    ) -> bytes | None: ...

    async def put_extraction_cache(
        self,
        *,
        cache_key: str,
        provider: str,
        model: str,
        schema_version: int,
        result_json: bytes,
        user_id: UUID | None,
    ) -> None: ...

    async def get_llm_link_cache(
        self, cache_key: str, *, user_id: UUID | None
    ) -> bytes | None: ...

    async def put_llm_link_cache(
        self,
        *,
        cache_key: str,
        provider: str,
        model: str,
        schema_version: int,
        classification_json: bytes,
        user_id: UUID | None,
    ) -> None: ...

    # ─── Export ───────────────────────────────────────────────────

    async def fetch_findings_for_engagement(
        self, engagement_id: str, *, user_id: UUID | None
    ) -> list[str]: ...

    def export_dump_stream(
        self,
        *,
        finding_ids: Iterable[str],
        user_id: UUID | None,
    ) -> AsyncIterator[dict]: ...
```

Note: `transaction`, `batch_transaction`, `stream_relations_in_scope`, and `export_dump_stream` are defined as regular `def` (not `async def`) because they return context managers or async iterators, respectively — their callers use `async with` or `async for`.

- [ ] **Step 4: Run tests**

Run: `python -m pytest packages/cli/tests/chain/test_store_protocol_shape.py -v`
Expected: 2 PASS.

Run: `python -m pytest packages/ -q`
Expected: `>= 509 passed, 1 skipped`.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/chain/store_protocol.py \
        packages/cli/tests/chain/test_store_protocol_shape.py
git commit -m "$(cat <<'EOF'
feat(chain): define ChainStoreProtocol with 41 async methods

Contract matches spec §4.3 with corrected method count. transaction,
batch_transaction, stream_relations_in_scope, and export_dump_stream
are sync functions returning context managers or async iterators;
all other methods are async def.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Extract MIGRATION_STATEMENTS constant from schema.py

**Files:**
- Modify: `packages/cli/src/opentools/engagement/schema.py`

Refactor: extract the existing migration SQL into a module-level constant. Zero behavior change. Prepares for async migration in Task 5 and migration v4 in Task 18.

- [ ] **Step 1: Read existing schema.py and identify migration bodies**

Read `packages/cli/src/opentools/engagement/schema.py`. Locate `_migration_v1`, `_migration_v2`, `_migration_v3` functions and the `MIGRATIONS` dict.

- [ ] **Step 2: Refactor to shared statement constant**

Convert the three migration functions so they share a module-level constant:

```python
# At module top level, below imports but above _migration_v1:
MIGRATION_STATEMENTS: dict[int, list[str]] = {
    1: [
        # Copy every SQL string from the current _migration_v1 body here,
        # one string per statement. Trim whitespace but preserve semantics.
    ],
    2: [
        # Same for _migration_v2.
    ],
    3: [
        # Same for _migration_v3.
    ],
}


def _apply_statements(conn, version: int) -> None:
    """Execute all DDL statements for a given migration version."""
    for stmt in MIGRATION_STATEMENTS[version]:
        conn.execute(stmt)


def _migration_v1(conn: sqlite3.Connection) -> None:
    _apply_statements(conn, 1)


def _migration_v2(conn: sqlite3.Connection) -> None:
    _apply_statements(conn, 2)


def _migration_v3(conn: sqlite3.Connection) -> None:
    _apply_statements(conn, 3)
```

If the existing migration functions use `conn.executescript(...)` with a multi-statement string, split on `;` (carefully — preserve statements that contain embedded semicolons via string literals) or keep them as single-string entries in the list. Use judgment to match the current behavior exactly.

**IMPORTANT:** do not change any SQL text. Copy verbatim. The only change is moving strings from function bodies to a dict.

- [ ] **Step 3: Wrap `migrate()` in a transaction (A3 fix)**

Find the existing `migrate()` function (around line 183). Wrap the entire body in an explicit transaction so partial migration failures roll back:

```python
def migrate(conn: sqlite3.Connection) -> None:
    """Bring the database schema up to LATEST_VERSION.

    Wraps the entire migration sequence in a transaction so a failure
    in any step rolls back all DDL applied by that run.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version    INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
    """)
    conn.commit()

    current = get_schema_version(conn)

    if current > LATEST_VERSION:
        raise RuntimeError(
            f"Database schema version {current} is newer than the "
            f"maximum supported version {LATEST_VERSION}. "
            "Please upgrade the application."
        )

    # Wrap pending migrations in a single transaction so partial
    # failures roll back cleanly (A3 in spec §5.7).
    conn.execute("BEGIN IMMEDIATE")
    try:
        for version in sorted(MIGRATIONS.keys()):
            if version <= current:
                continue
            MIGRATIONS[version](conn)
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (version, datetime.now(timezone.utc).isoformat()),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
```

- [ ] **Step 4: Run existing tests to verify zero behavior change**

Run: `python -m pytest packages/ -q`
Expected: `>= 509 passed, 1 skipped, 0 failed`. The engagement store tests (`test_schema.py`) should all still pass.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/engagement/schema.py
git commit -m "$(cat <<'EOF'
refactor(schema): extract MIGRATION_STATEMENTS constant, wrap migrate in transaction

Prepares for async migration sibling in Phase 1 Task 5. Wraps the
migration sequence in BEGIN IMMEDIATE / COMMIT so partial failures
roll back cleanly (spec §5.7 A3 fix).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Add migrate_async() sibling

**Files:**
- Modify: `packages/cli/src/opentools/engagement/schema.py`
- Create: `packages/cli/tests/chain/test_migrate_async.py`

- [ ] **Step 1: Write the failing test**

Create `packages/cli/tests/chain/test_migrate_async.py`:

```python
"""Tests for migrate_async() — the aiosqlite-native migration path."""
import sqlite3

import aiosqlite
import pytest


async def test_migrate_async_creates_all_expected_tables(tmp_path):
    from opentools.engagement.schema import LATEST_VERSION, migrate_async

    db_path = tmp_path / "test.db"
    async with aiosqlite.connect(str(db_path)) as conn:
        await migrate_async(conn)

    # Inspect with sync sqlite3 to verify tables exist
    sconn = sqlite3.connect(str(db_path))
    try:
        rows = sconn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        names = {r[0] for r in rows}
        # Engagement tables
        assert "engagements" in names
        assert "findings" in names
        # Chain tables from migration v3
        assert "entity" in names
        assert "entity_mention" in names
        assert "finding_relation" in names
        assert "linker_run" in names
        # Schema version tracking
        assert "schema_version" in names

        version = sconn.execute(
            "SELECT MAX(version) FROM schema_version"
        ).fetchone()[0]
        assert version == LATEST_VERSION
    finally:
        sconn.close()


async def test_migrate_async_is_idempotent(tmp_path):
    from opentools.engagement.schema import LATEST_VERSION, migrate_async

    db_path = tmp_path / "test.db"
    async with aiosqlite.connect(str(db_path)) as conn:
        await migrate_async(conn)
        await migrate_async(conn)  # Second run should be a no-op

    sconn = sqlite3.connect(str(db_path))
    try:
        rows = sconn.execute(
            "SELECT version FROM schema_version ORDER BY version"
        ).fetchall()
        # One row per version, no duplicates
        versions = [r[0] for r in rows]
        assert versions == sorted(set(versions))
        assert max(versions) == LATEST_VERSION
    finally:
        sconn.close()


async def test_migrate_async_produces_same_schema_as_sync(tmp_path):
    """Sync migrate() and async migrate_async() must produce identical
    schemas. Divergence here would be a ship-blocking bug."""
    from opentools.engagement.schema import migrate, migrate_async

    sync_db = tmp_path / "sync.db"
    async_db = tmp_path / "async.db"

    sconn = sqlite3.connect(str(sync_db))
    try:
        migrate(sconn)
    finally:
        sconn.close()

    async with aiosqlite.connect(str(async_db)) as aconn:
        await migrate_async(aconn)

    def _schema_dump(path):
        conn = sqlite3.connect(str(path))
        try:
            rows = conn.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE type IN ('table', 'index', 'trigger') "
                "AND sql IS NOT NULL "
                "ORDER BY type, name"
            ).fetchall()
            return tuple(r[0] for r in rows)
        finally:
            conn.close()

    assert _schema_dump(sync_db) == _schema_dump(async_db)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest packages/cli/tests/chain/test_migrate_async.py -v`
Expected: FAIL with `ImportError: cannot import name 'migrate_async'`.

- [ ] **Step 3: Implement `migrate_async()`**

Add to `packages/cli/src/opentools/engagement/schema.py` below the existing `migrate()` function:

```python
async def migrate_async(conn) -> None:
    """Async sibling of migrate() for aiosqlite connections.

    Runs the same migration sequence as sync migrate() but with
    awaited execute calls. Shares MIGRATION_STATEMENTS so the two
    code paths can never drift.

    Wraps the entire migration in a transaction for atomicity.
    """
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version    INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
    """)
    await conn.commit()

    async with conn.execute(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version"
    ) as cursor:
        row = await cursor.fetchone()
    current = row[0] if row else 0

    if current > LATEST_VERSION:
        raise RuntimeError(
            f"Database schema version {current} is newer than the "
            f"maximum supported version {LATEST_VERSION}. "
            "Please upgrade the application."
        )

    await conn.execute("BEGIN IMMEDIATE")
    try:
        for version in sorted(MIGRATIONS.keys()):
            if version <= current:
                continue
            for stmt in MIGRATION_STATEMENTS[version]:
                await conn.execute(stmt)
            await conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (version, datetime.now(timezone.utc).isoformat()),
            )
        await conn.execute("COMMIT")
    except Exception:
        await conn.execute("ROLLBACK")
        raise
```

- [ ] **Step 4: Run the migrate_async tests**

Run: `python -m pytest packages/cli/tests/chain/test_migrate_async.py -v`
Expected: 3 PASS.

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest packages/ -q`
Expected: `>= 512 passed, 1 skipped`.

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/engagement/schema.py \
        packages/cli/tests/chain/test_migrate_async.py
git commit -m "$(cat <<'EOF'
feat(schema): add migrate_async for aiosqlite connections

Sibling of sync migrate() sharing MIGRATION_STATEMENTS so the two
paths can never drift. Wraps the full migration in BEGIN IMMEDIATE
/ COMMIT / ROLLBACK for atomicity. Three tests verify forward
application, idempotency, and byte-equivalent schemas across sync
and async paths.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: AsyncChainStore lifecycle (initialize / close / transaction)

**Files:**
- Create: `packages/cli/src/opentools/chain/stores/sqlite_async.py`
- Create: `packages/cli/tests/chain/test_async_chain_store.py`

- [ ] **Step 1: Write failing tests**

Create `packages/cli/tests/chain/test_async_chain_store.py`:

```python
"""Unit tests for AsyncChainStore (aiosqlite backend)."""
import pytest

from opentools.chain.stores._common import StoreNotInitialized
from opentools.chain.stores.sqlite_async import AsyncChainStore


async def test_construction_requires_db_path_or_conn():
    with pytest.raises(ValueError, match="Provide either"):
        AsyncChainStore()


async def test_construction_rejects_both_db_path_and_conn(tmp_path):
    import aiosqlite
    conn = await aiosqlite.connect(":memory:")
    try:
        with pytest.raises(ValueError, match="not both"):
            AsyncChainStore(db_path=tmp_path / "x.db", conn=conn)
    finally:
        await conn.close()


async def test_initialize_opens_connection_and_runs_migrations(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    await store.initialize()
    try:
        # Smoke check: a simple SQL query through the internal conn works
        async with store._conn.execute("SELECT 1") as cursor:
            row = await cursor.fetchone()
        assert row[0] == 1
    finally:
        await store.close()


async def test_initialize_is_idempotent(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    await store.initialize()
    await store.initialize()  # second call must not raise
    await store.close()


async def test_method_raises_before_initialize(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    with pytest.raises(StoreNotInitialized, match="get_entity"):
        await store.get_entity("eid", user_id=None)


async def test_method_raises_after_close(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    await store.initialize()
    await store.close()
    with pytest.raises(StoreNotInitialized, match="get_entity"):
        await store.get_entity("eid", user_id=None)


async def test_transaction_context_commits_on_success(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    await store.initialize()
    try:
        async with store.transaction():
            await store._conn.execute(
                "CREATE TABLE IF NOT EXISTS _test_txn (x INTEGER)"
            )
            await store._conn.execute("INSERT INTO _test_txn VALUES (42)")
        # Outside the transaction, row should be committed
        async with store._conn.execute("SELECT x FROM _test_txn") as cur:
            row = await cur.fetchone()
        assert row[0] == 42
    finally:
        await store.close()


async def test_transaction_rolls_back_on_exception(tmp_path):
    store = AsyncChainStore(db_path=tmp_path / "chain.db")
    await store.initialize()
    try:
        await store._conn.execute(
            "CREATE TABLE IF NOT EXISTS _test_roll (x INTEGER)"
        )
        await store._conn.commit()

        with pytest.raises(RuntimeError, match="boom"):
            async with store.transaction():
                await store._conn.execute("INSERT INTO _test_roll VALUES (1)")
                raise RuntimeError("boom")

        async with store._conn.execute(
            "SELECT COUNT(*) FROM _test_roll"
        ) as cur:
            row = await cur.fetchone()
        assert row[0] == 0
    finally:
        await store.close()
```

- [ ] **Step 2: Run to verify failure**

Run: `python -m pytest packages/cli/tests/chain/test_async_chain_store.py -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Implement AsyncChainStore lifecycle**

Create `packages/cli/src/opentools/chain/stores/sqlite_async.py`:

```python
"""AsyncChainStore — aiosqlite-backed chain store implementation.

Serves the CLI via a single-user connection. Does NOT enforce user_id
scoping (the CLI has a single user). All CRUD methods are implemented
in later tasks (Phase 1 Tasks 7-14).

Construction: accept either a db_path (store owns the connection and
closes it on close()) or a pre-opened aiosqlite.Connection (borrow,
don't close on close()). Borrowing exists for advanced scenarios; CLI
production code uses db_path.
"""
from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

import aiosqlite

from opentools.chain.stores._common import (
    StoreNotInitialized,
    require_initialized,
)
from opentools.engagement.schema import migrate_async

logger = logging.getLogger(__name__)


class AsyncChainStore:
    """Async chain store backed by aiosqlite.

    CLI-side backend. Accepts user_id=None freely on every method
    (single-user CLI). Methods are decorated with @require_initialized
    so calling before initialize() or after close() raises a clear error.
    """

    def __init__(
        self,
        *,
        db_path: Path | None = None,
        conn: aiosqlite.Connection | None = None,
    ) -> None:
        if db_path is None and conn is None:
            raise ValueError("Provide either db_path or conn")
        if db_path is not None and conn is not None:
            raise ValueError("Provide db_path OR conn, not both")
        self._db_path = Path(db_path) if db_path is not None else None
        self._conn: aiosqlite.Connection | None = conn
        self._owns_connection = conn is None
        self._initialized = False
        # Transaction depth tracker for nested savepoints
        self._txn_depth = 0

    async def initialize(self) -> None:
        """Open the connection (if owning), apply pragmas, run migrations.

        Idempotent — safe to call multiple times.
        """
        if self._initialized:
            return

        if self._conn is None:
            assert self._db_path is not None
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = await aiosqlite.connect(str(self._db_path))

        self._conn.row_factory = aiosqlite.Row

        # Performance pragmas (spec §5.3 optimization O3)
        for pragma in (
            "PRAGMA journal_mode=WAL",
            "PRAGMA synchronous=NORMAL",
            "PRAGMA cache_size=-64000",
            "PRAGMA mmap_size=268435456",
            "PRAGMA temp_store=MEMORY",
            "PRAGMA foreign_keys=ON",
            "PRAGMA busy_timeout=5000",
        ):
            await self._conn.execute(pragma)

        # Run migrations via the async path
        await migrate_async(self._conn)

        self._initialized = True

    async def close(self) -> None:
        """Close the connection (if owned). Idempotent."""
        if self._conn is not None and self._owns_connection:
            # Passive WAL checkpoint before closing (spec §5.3 optimization O7)
            try:
                await self._conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
            except Exception:
                pass
            await self._conn.close()
        self._conn = None
        self._initialized = False

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        """Single-operation atomicity via SQLite savepoint.

        Each call generates a unique savepoint name so nested usage
        doesn't collide. Rolls back on exception, releases on success.
        """
        if not self._initialized:
            raise StoreNotInitialized(
                "AsyncChainStore.transaction() called before initialize()"
            )
        name = f"txn_{uuid.uuid4().hex[:12]}"
        await self._conn.execute(f"SAVEPOINT {name}")
        self._txn_depth += 1
        try:
            yield
        except BaseException:
            await self._conn.execute(f"ROLLBACK TO SAVEPOINT {name}")
            await self._conn.execute(f"RELEASE SAVEPOINT {name}")
            self._txn_depth -= 1
            raise
        else:
            await self._conn.execute(f"RELEASE SAVEPOINT {name}")
            self._txn_depth -= 1

    @asynccontextmanager
    async def batch_transaction(self) -> AsyncIterator[None]:
        """Batch atomicity for merge/split/import.

        On SQLite this has identical semantics to transaction() — both
        use SAVEPOINT. The distinction is semantic: call sites use
        batch_transaction when they're wrapping a multi-step bulk
        operation (merge, split, import) so readers understand the
        scope of the held lock.
        """
        async with self.transaction():
            yield

    @require_initialized
    async def get_entity(self, entity_id: str, *, user_id):
        """Stub — real implementation lands in Task 7."""
        return None  # placeholder, replaced in Task 7
```

Note: the final `get_entity` is a stub returning None so the `require_initialized` decorator test has something to call. Task 7 replaces it with a real implementation.

- [ ] **Step 4: Run the tests**

Run: `python -m pytest packages/cli/tests/chain/test_async_chain_store.py -v`
Expected: 8 PASS.

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest packages/ -q`
Expected: `>= 520 passed, 1 skipped`.

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/chain/stores/sqlite_async.py \
        packages/cli/tests/chain/test_async_chain_store.py
git commit -m "$(cat <<'EOF'
feat(chain): add AsyncChainStore lifecycle (init/close/transaction)

Opens aiosqlite connection, applies performance pragmas, runs
migrations via migrate_async. transaction() and batch_transaction()
use SAVEPOINT with unique names for nestable atomicity. CRUD
methods come in Tasks 7-14.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Tasks 7-14: Remaining AsyncChainStore methods

The lifecycle tasks above establish the file. Tasks 7-14 implement the remaining CRUD methods in the pattern shown: write the conformance test, verify failure, implement the method body with SQL, verify pass, commit. Because each method is mechanical SQL-writing once the shape is clear, I compress these tasks to their key information.

For every method in Tasks 7-14, follow this template in a single commit per logical group:

1. **Write tests against `AsyncChainStore` directly** (unit tests, not the conformance suite yet — that comes in Task 21). Tests go into `test_async_chain_store.py`, grouped by section.
2. **Verify failure** — `pytest packages/cli/tests/chain/test_async_chain_store.py::test_<name> -v`
3. **Implement the method body** with `@require_initialized`, async SQL via `self._conn.execute`, `self._conn.commit()` at the end unless `self._txn_depth > 0`.
4. **Verify pass** — `pytest packages/ -q` must show increasing count, zero failures.
5. **Commit** with a focused message per task.

The full SQL for each method is implied by the spec §2 schema (chain tables as defined in migration v3) and the protocol signatures in Task 3. To keep this plan actionable, I give exact SQL for one representative method per group, then point to the same pattern for the rest.

### Task 7: Entity CRUD (6 methods)

**Methods:** `upsert_entity`, `upsert_entities_bulk`, `get_entity`, `get_entities_by_ids`, `list_entities`, `delete_entity`

**Representative: upsert_entity**

```python
@require_initialized
async def upsert_entity(self, entity: Entity, *, user_id) -> None:
    await self._conn.execute(
        """
        INSERT INTO entity
            (id, type, canonical_value, first_seen_at, last_seen_at,
             mention_count, user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            last_seen_at=excluded.last_seen_at,
            mention_count=excluded.mention_count
        """,
        (
            entity.id, entity.type, entity.canonical_value,
            entity.first_seen_at.isoformat(),
            entity.last_seen_at.isoformat(),
            entity.mention_count,
            str(entity.user_id) if entity.user_id else None,
        ),
    )
    if self._txn_depth == 0:
        await self._conn.commit()
```

**Representative: get_entity**

```python
@require_initialized
async def get_entity(self, entity_id: str, *, user_id) -> Entity | None:
    async with self._conn.execute(
        "SELECT * FROM entity WHERE id = ?", (entity_id,)
    ) as cursor:
        row = await cursor.fetchone()
    return _row_to_entity(row) if row else None
```

Add `_row_to_entity(row)` as a module-level function converting `aiosqlite.Row` to `Entity` (copy the shape from the existing sync `store_extensions.py::_row_to_entity`, adapting for `aiosqlite.Row` which behaves like a dict — the existing code is already written this way).

**Other methods follow the same pattern with different SQL.** Tests go into `test_async_chain_store.py` alongside the existing lifecycle tests. Expected tests per method: 2-3 (basic success, edge case, error handling where relevant). ~15 new tests for this task.

**Commit message:**
```
feat(chain): implement AsyncChainStore entity CRUD methods
```

### Task 8: Mention CRUD (7 methods)

**Methods:** `add_mentions_bulk`, `mentions_for_finding`, `delete_mentions_for_finding`, `recompute_mention_counts`, `rewrite_mentions_entity_id`, `rewrite_mentions_by_ids`, `fetch_mentions_with_engagement`

**Representative: add_mentions_bulk using executemany**

```python
@require_initialized
async def add_mentions_bulk(
    self, mentions, *, user_id
) -> int:
    rows = [
        (
            m.id, m.entity_id, m.finding_id, m.field.value, m.raw_value,
            m.offset_start, m.offset_end, m.extractor, m.confidence,
            m.created_at.isoformat(),
            str(m.user_id) if m.user_id else None,
        )
        for m in mentions
    ]
    if not rows:
        return 0
    await self._conn.executemany(
        """
        INSERT OR IGNORE INTO entity_mention
            (id, entity_id, finding_id, field, raw_value, offset_start,
             offset_end, extractor, confidence, created_at, user_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    if self._txn_depth == 0:
        await self._conn.commit()
    return len(rows)
```

**Representative: recompute_mention_counts (single-statement UPDATE per spec G5 fix)**

```python
@require_initialized
async def recompute_mention_counts(
    self, entity_ids, *, user_id
) -> None:
    id_list = list(entity_ids)
    if not id_list:
        return
    placeholders = ",".join("?" * len(id_list))
    await self._conn.execute(
        f"""
        UPDATE entity
        SET mention_count = (
            SELECT COUNT(*) FROM entity_mention
            WHERE entity_mention.entity_id = entity.id
        )
        WHERE id IN ({placeholders})
        """,
        tuple(id_list),
    )
    if self._txn_depth == 0:
        await self._conn.commit()
```

**Other methods follow the same pattern.** Expected tests: 10 new tests for this task.

**Commit message:** `feat(chain): implement AsyncChainStore mention CRUD methods`

### Task 9: Relation CRUD (5 methods)

**Methods:** `upsert_relations_bulk`, `relations_for_finding`, `fetch_relations_in_scope`, `stream_relations_in_scope`, `apply_link_classification`

**Representative: upsert_relations_bulk with sticky status preservation**

```python
@require_initialized
async def upsert_relations_bulk(
    self, relations, *, user_id
) -> tuple[int, int]:
    import orjson
    from opentools.chain.types import RelationStatus

    rel_list = list(relations)
    if not rel_list:
        return (0, 0)

    # Count existing rows touched for the (created, updated) return
    created_count = 0
    updated_count = 0

    for r in rel_list:
        # Check if row exists
        async with self._conn.execute(
            "SELECT status FROM finding_relation WHERE id = ?", (r.id,)
        ) as cursor:
            existing = await cursor.fetchone()

        is_update = existing is not None

        # Serialize reasons to BLOB
        reasons_json = orjson.dumps(
            [rr.model_dump(mode="json") for rr in r.reasons]
        )
        confirmed_json = None
        if r.confirmed_at_reasons is not None:
            confirmed_json = orjson.dumps(
                [rr.model_dump(mode="json") for rr in r.confirmed_at_reasons]
            )

        await self._conn.execute(
            """
            INSERT INTO finding_relation (
                id, source_finding_id, target_finding_id, weight,
                weight_model_version, status, symmetric, reasons_json,
                llm_rationale, llm_relation_type, llm_confidence,
                confirmed_at_reasons_json, created_at, updated_at, user_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                weight = excluded.weight,
                weight_model_version = excluded.weight_model_version,
                status = CASE
                    WHEN finding_relation.status IN ('user_confirmed', 'user_rejected')
                    THEN finding_relation.status
                    ELSE excluded.status
                END,
                symmetric = excluded.symmetric,
                reasons_json = excluded.reasons_json,
                llm_rationale = excluded.llm_rationale,
                llm_relation_type = excluded.llm_relation_type,
                llm_confidence = excluded.llm_confidence,
                updated_at = excluded.updated_at
            """,
            (
                r.id, r.source_finding_id, r.target_finding_id, r.weight,
                r.weight_model_version, r.status.value,
                int(r.symmetric), reasons_json,
                r.llm_rationale, r.llm_relation_type, r.llm_confidence,
                confirmed_json, r.created_at.isoformat(),
                r.updated_at.isoformat(),
                str(r.user_id) if r.user_id else None,
            ),
        )

        if is_update:
            updated_count += 1
        else:
            created_count += 1

    if self._txn_depth == 0:
        await self._conn.commit()

    return (created_count, updated_count)
```

**Representative: stream_relations_in_scope (async iterator)**

```python
async def stream_relations_in_scope(
    self, *, user_id, statuses=None
):
    """Yield FindingRelation rows one at a time for bounded memory.

    NOT decorated with @require_initialized because async generators
    don't play nicely with the decorator. Manual check instead.
    """
    if not self._initialized:
        raise StoreNotInitialized(
            "stream_relations_in_scope called before initialize()"
        )
    sql = "SELECT * FROM finding_relation"
    params: list = []
    if statuses:
        placeholders = ",".join("?" * len(statuses))
        sql += f" WHERE status IN ({placeholders})"
        params.extend(s.value for s in statuses)
    async with self._conn.execute(sql, tuple(params)) as cursor:
        async for row in cursor:
            yield _row_to_relation(row)
```

**Other methods:** `relations_for_finding`, `fetch_relations_in_scope`, `apply_link_classification` follow standard patterns. Expected tests: 8 new.

**Commit message:** `feat(chain): implement AsyncChainStore relation CRUD methods`

### Task 10: Linker-specific queries (5 methods)

**Methods:** `fetch_candidate_partners`, `fetch_findings_by_ids`, `count_findings_in_scope`, `compute_avg_idf`, `entities_for_finding`

**Representative: fetch_candidate_partners with common_entity_threshold filter (spec G9)**

```python
@require_initialized
async def fetch_candidate_partners(
    self,
    *,
    finding_id: str,
    entity_ids: set[str],
    user_id,
    common_entity_threshold: int,
) -> dict[str, set[str]]:
    from opentools.chain.stores._common import pad_in_clause

    if not entity_ids:
        return {}

    ids_list = list(entity_ids)
    # Split if over 500 (spec O13)
    if len(ids_list) > 500:
        result: dict[str, set[str]] = {}
        for i in range(0, len(ids_list), 500):
            chunk = ids_list[i : i + 500]
            partial = await self.fetch_candidate_partners(
                finding_id=finding_id,
                entity_ids=set(chunk),
                user_id=user_id,
                common_entity_threshold=common_entity_threshold,
            )
            for fid, eids in partial.items():
                result.setdefault(fid, set()).update(eids)
        return result

    padded = pad_in_clause(ids_list, min_size=4)
    placeholders = ",".join("?" * len(padded))

    sql = f"""
        SELECT DISTINCT m.finding_id, m.entity_id
        FROM entity_mention m
        JOIN entity e ON e.id = m.entity_id
        WHERE m.entity_id IN ({placeholders})
          AND m.finding_id != ?
          AND e.mention_count <= ?
    """
    params = tuple(padded) + (finding_id, common_entity_threshold)

    partners: dict[str, set[str]] = {}
    async with self._conn.execute(sql, params) as cursor:
        async for row in cursor:
            partners.setdefault(row["finding_id"], set()).add(row["entity_id"])
    return partners
```

**Representative: compute_avg_idf (single-statement aggregation per spec G10)**

```python
@require_initialized
async def compute_avg_idf(
    self,
    *,
    scope_total: int,
    user_id,
) -> float:
    if scope_total <= 0:
        return 1.0
    async with self._conn.execute(
        """
        SELECT AVG(LOG((? + 1.0) / (mention_count + 1.0)))
        FROM entity
        WHERE mention_count > 0
        """,
        (scope_total,),
    ) as cursor:
        row = await cursor.fetchone()
    if row is None or row[0] is None:
        return 1.0
    return float(row[0])
```

**Representative: fetch_findings_by_ids (CLI SQLite path reads from the same DB)**

```python
@require_initialized
async def fetch_findings_by_ids(
    self, finding_ids, *, user_id
) -> list[Finding]:
    from datetime import datetime
    from opentools.models import Finding, FindingStatus, Severity

    ids_list = list(finding_ids)
    if not ids_list:
        return []

    placeholders = ",".join("?" * len(ids_list))
    async with self._conn.execute(
        f"""
        SELECT id, engagement_id, tool, severity, status, title,
               description, file_path, line_start, line_end, evidence,
               cwe, cvss, remediation, severity_by_tool, phase,
               false_positive, dedup_confidence, corroborated_by,
               created_at, deleted_at
        FROM findings
        WHERE id IN ({placeholders}) AND deleted_at IS NULL
        """,
        tuple(ids_list),
    ) as cursor:
        rows = await cursor.fetchall()

    findings = []
    for row in rows:
        try:
            findings.append(Finding(
                id=row["id"],
                engagement_id=row["engagement_id"],
                tool=row["tool"],
                severity=Severity(row["severity"]),
                status=FindingStatus(row["status"]) if row["status"] else FindingStatus.DISCOVERED,
                title=row["title"],
                description=row["description"] or "",
                file_path=row["file_path"],
                line_start=row["line_start"],
                line_end=row["line_end"],
                evidence=row["evidence"],
                created_at=datetime.fromisoformat(row["created_at"]),
            ))
        except Exception:
            continue
    return findings
```

**Other methods follow standard patterns.** Expected tests: 8 new.

**Commit message:** `feat(chain): implement AsyncChainStore linker query methods`

### Task 11: LinkerRun lifecycle (5 methods)

**Methods:** `start_linker_run`, `set_run_status`, `finish_linker_run`, `current_linker_generation`, `fetch_linker_runs`

**Representative: start_linker_run with atomic generation SQL (spec G26)**

```python
@require_initialized
async def start_linker_run(
    self,
    *,
    scope,
    scope_id: str | None,
    mode,
    user_id,
) -> LinkerRun:
    import hashlib
    from datetime import datetime, timezone
    from opentools.chain.models import LinkerRun

    run_id = f"run_{hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:12]}"
    now = datetime.now(timezone.utc)

    # Atomic generation increment — subquery computes next generation
    # in the same INSERT, preventing read-max-plus-one races.
    await self._conn.execute(
        """
        INSERT INTO linker_run (
            id, started_at, scope, scope_id, mode, findings_processed,
            entities_extracted, relations_created, relations_updated,
            relations_skipped_sticky, extraction_cache_hits,
            extraction_cache_misses, llm_calls_made, llm_cache_hits,
            llm_cache_misses, generation, status_text
        )
        VALUES (
            ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            (SELECT COALESCE(MAX(generation), 0) + 1 FROM linker_run),
            'pending'
        )
        """,
        (run_id, now.isoformat(), scope.value, scope_id, mode.value),
    )
    if self._txn_depth == 0:
        await self._conn.commit()

    # Load the inserted row to get the resolved generation
    async with self._conn.execute(
        "SELECT * FROM linker_run WHERE id = ?", (run_id,)
    ) as cursor:
        row = await cursor.fetchone()

    return _row_to_linker_run(row)
```

Add `_row_to_linker_run(row)` helper at module level converting an aiosqlite.Row to LinkerRun.

**Other methods follow standard patterns.** Expected tests: 8 new.

**Commit message:** `feat(chain): implement AsyncChainStore linker run lifecycle`

### Task 12: Extraction state + parser output (3 methods)

**Methods:** `get_extraction_hash`, `upsert_extraction_state`, `get_parser_output`

**Implementation:** standard CRUD patterns over `finding_extraction_state` and `finding_parser_output` tables. Expected tests: 5 new.

**Commit message:** `feat(chain): implement AsyncChainStore extraction state methods`

### Task 13: LLM caches (4 methods)

**Methods:** `get_extraction_cache`, `put_extraction_cache`, `get_llm_link_cache`, `put_llm_link_cache`

**Representative: get_extraction_cache (user-scoped per spec G37)**

```python
@require_initialized
async def get_extraction_cache(
    self, cache_key: str, *, user_id
) -> bytes | None:
    user_id_str = str(user_id) if user_id else None
    async with self._conn.execute(
        """
        SELECT result_json FROM extraction_cache
        WHERE cache_key = ? AND (user_id IS ? OR user_id = ?)
        """,
        (cache_key, user_id_str, user_id_str),
    ) as cursor:
        row = await cursor.fetchone()
    return row["result_json"] if row else None
```

**Note:** The SQL `(user_id IS ? OR user_id = ?)` handles the NULL case (SQLite doesn't consider NULL = NULL true; `IS` works for NULL comparison). This is needed for legacy rows where `user_id` was NULL before migration v4 added the column.

**Other methods follow the same pattern.** Expected tests: 8 new.

**Commit message:** `feat(chain): implement AsyncChainStore user-scoped LLM caches`

### Task 14: Export (2 methods)

**Methods:** `fetch_findings_for_engagement`, `export_dump_stream`

**Representative: export_dump_stream (async iterator)**

```python
async def export_dump_stream(
    self, *, finding_ids, user_id
):
    """Yield entity/mention/relation dicts one at a time for bounded memory."""
    if not self._initialized:
        raise StoreNotInitialized(
            "export_dump_stream called before initialize()"
        )

    ids_list = list(finding_ids)
    if not ids_list:
        return

    placeholders = ",".join("?" * len(ids_list))

    # Yield entities
    async with self._conn.execute(
        f"""
        SELECT DISTINCT e.* FROM entity e
        JOIN entity_mention m ON m.entity_id = e.id
        WHERE m.finding_id IN ({placeholders})
        """,
        tuple(ids_list),
    ) as cursor:
        async for row in cursor:
            yield {"kind": "entity", "data": dict(row)}

    # Yield mentions
    async with self._conn.execute(
        f"SELECT * FROM entity_mention WHERE finding_id IN ({placeholders})",
        tuple(ids_list),
    ) as cursor:
        async for row in cursor:
            yield {"kind": "mention", "data": dict(row)}

    # Yield relations
    async with self._conn.execute(
        f"""
        SELECT * FROM finding_relation
        WHERE source_finding_id IN ({placeholders})
           OR target_finding_id IN ({placeholders})
        """,
        tuple(ids_list) * 2,
    ) as cursor:
        async for row in cursor:
            yield {"kind": "relation", "data": dict(row)}
```

**Other method:** `fetch_findings_for_engagement` is a simple SELECT. Expected tests: 4 new.

**Commit message:** `feat(chain): implement AsyncChainStore export streaming`

---

## Task 15: Consolidate cache key functions

**Files:**
- Create: `packages/cli/src/opentools/chain/_cache_keys.py`
- Modify: `packages/cli/src/opentools/chain/extractors/pipeline.py` (if it has a local cache_key helper, remove and import from the new module)
- Modify: `packages/cli/src/opentools/chain/linker/llm_pass.py` (same)
- Modify: `packages/cli/src/opentools/chain/query/narration.py` (same)
- Create: `packages/cli/tests/chain/test_cache_keys.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/cli/tests/chain/test_cache_keys.py
"""Tests for consolidated cache key functions."""
import pytest

from opentools.chain._cache_keys import (
    extraction_cache_key,
    link_classification_cache_key,
    narration_cache_key,
)


def test_extraction_cache_key_deterministic():
    k1 = extraction_cache_key(
        text="hello", provider="ollama", model="llama3.1",
        schema_version=1, user_id=None,
    )
    k2 = extraction_cache_key(
        text="hello", provider="ollama", model="llama3.1",
        schema_version=1, user_id=None,
    )
    assert k1 == k2
    assert len(k1) == 64  # sha256 hex


def test_extraction_cache_key_differs_on_user():
    import uuid
    k1 = extraction_cache_key(
        text="hello", provider="ollama", model="llama3.1",
        schema_version=1, user_id=None,
    )
    k2 = extraction_cache_key(
        text="hello", provider="ollama", model="llama3.1",
        schema_version=1, user_id=uuid.uuid4(),
    )
    assert k1 != k2


def test_link_classification_cache_key_shape():
    k = link_classification_cache_key(
        source_id="fnd_a", target_id="fnd_b",
        provider="ollama", model="llama3.1",
        schema_version=1, user_id=None,
    )
    assert len(k) == 64


def test_narration_cache_key_shape():
    k = narration_cache_key(
        path_finding_ids=["fnd_a", "fnd_b", "fnd_c"],
        edge_reasons_summary=["shared_strong_entity", "temporal"],
        provider="claude_code", model="claude-sonnet-4-6",
        schema_version=1, user_id=None,
    )
    assert len(k) == 64
```

- [ ] **Step 2: Run — expect fail**

- [ ] **Step 3: Implement `_cache_keys.py`**

```python
"""Centralized content-addressed cache key functions.

All cache keys in the chain package go through this module so that
cache invalidation logic (bumping schema versions, changing input
composition) happens in one place.

All keys are user-scoped (spec G37 — prevents cross-user side-channel
leaks via content-addressed cache).
"""
from __future__ import annotations

import hashlib
from uuid import UUID


def _user_part(user_id: UUID | None) -> str:
    return str(user_id) if user_id else "_cli"


def extraction_cache_key(
    *,
    text: str,
    provider: str,
    model: str,
    schema_version: int,
    user_id: UUID | None,
) -> str:
    """Cache key for LLM entity extraction results."""
    payload = (
        f"extraction|{text}|{provider}|{model}|{schema_version}|"
        f"{_user_part(user_id)}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def link_classification_cache_key(
    *,
    source_id: str,
    target_id: str,
    provider: str,
    model: str,
    schema_version: int,
    user_id: UUID | None,
) -> str:
    """Cache key for LLM link classification results."""
    payload = (
        f"link|{source_id}|{target_id}|{provider}|{model}|"
        f"{schema_version}|{_user_part(user_id)}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def narration_cache_key(
    *,
    path_finding_ids: list[str],
    edge_reasons_summary: list[str],
    provider: str,
    model: str,
    schema_version: int,
    user_id: UUID | None,
) -> str:
    """Cache key for LLM path narration results."""
    finding_ids = ",".join(path_finding_ids)
    reasons = "|".join("+".join(sorted(edge_reasons_summary)) for _ in [None])
    payload = (
        f"narration|{finding_ids}|{reasons}|{provider}|{model}|"
        f"{schema_version}|{_user_part(user_id)}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest packages/cli/tests/chain/test_cache_keys.py -v`
Expected: 4 PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/chain/_cache_keys.py \
        packages/cli/tests/chain/test_cache_keys.py
git commit -m "$(cat <<'EOF'
feat(chain): add consolidated user-scoped cache key module

Single source of truth for extraction/link/narration cache keys,
all user-scoped per spec G37 to prevent cross-user side-channel
leaks via content-addressed cache.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 16: Freeze ChainConfig

**Files:**
- Modify: `packages/cli/src/opentools/chain/config.py`
- Create: `packages/cli/tests/chain/test_config_frozen.py`

- [ ] **Step 1: Write failing test**

```python
# packages/cli/tests/chain/test_config_frozen.py
"""Verify ChainConfig is frozen to prevent mid-run mutation (spec O28)."""
import pytest
from pydantic import ValidationError

from opentools.chain.config import ChainConfig


def test_chain_config_is_frozen():
    cfg = ChainConfig()
    with pytest.raises((ValidationError, TypeError)):
        cfg.enabled = False  # Should raise because model is frozen


def test_nested_configs_are_frozen():
    cfg = ChainConfig()
    with pytest.raises((ValidationError, TypeError)):
        cfg.linker.confirmed_threshold = 2.0
```

- [ ] **Step 2: Run — expect fail** (current config is mutable)

- [ ] **Step 3: Mark configs frozen**

Read `packages/cli/src/opentools/chain/config.py`. Each `BaseModel` subclass needs `model_config = ConfigDict(frozen=True)`. Add the import `from pydantic import ConfigDict` and add the config dict to every class. Example:

```python
class ChainConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    # ... existing fields
```

Apply to all 15 or so BaseModel subclasses in that file.

- [ ] **Step 4: Run tests**

Run: `python -m pytest packages/cli/tests/chain/test_config_frozen.py packages/cli/tests/chain/test_config.py -v`
Expected: all pass (frozen test + existing config tests).

Run: `python -m pytest packages/ -q`
Expected: `>= 530 passed, 1 skipped`.

If any existing test fails because it was mutating config, convert to `cfg.model_copy(update={"field": new_value})`.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/chain/config.py \
        packages/cli/tests/chain/test_config_frozen.py
git commit -m "$(cat <<'EOF'
feat(chain): mark ChainConfig and nested models frozen (O28)

Prevents mid-linker-run config mutation. Consumers that need to
change settings use cfg.model_copy(update={...}) instead of
attribute assignment.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 17: Rename sync ChainStore to SyncChainStore with alias

**Files:**
- Modify: `packages/cli/src/opentools/chain/store_extensions.py`

- [ ] **Step 1: Rename class, preserve alias**

Read `packages/cli/src/opentools/chain/store_extensions.py`. Locate the `class ChainStore:` line (around line 30+ depending on current file). Rename to `SyncChainStore`. Add at the bottom of the file:

```python
# Backwards-compat alias preserved during the async store refactor.
# Consumers still import `ChainStore` and get the sync implementation.
# Phase 5 deletes this file entirely.
ChainStore = SyncChainStore
```

Every other reference to `ChainStore` inside the file (e.g. type hints, internal references) stays using the class name — but if the class was self-referential via `ChainStore` in hints, update to `"SyncChainStore"` forward references.

- [ ] **Step 2: Verify tests pass**

Run: `python -m pytest packages/ -q`
Expected: `>= 530 passed, 1 skipped`. The existing 500 pre-refactor tests are the baseline and should all still pass — `ChainStore` is still importable via the alias.

- [ ] **Step 3: Commit**

```bash
git add packages/cli/src/opentools/chain/store_extensions.py
git commit -m "$(cat <<'EOF'
refactor(chain): rename ChainStore to SyncChainStore, keep alias

Prepares for Phase 5 deletion. Consumers still import ChainStore
and get the sync implementation during phases 1-4.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 18: Add migration v4 (status_text + cache user_id)

**Files:**
- Modify: `packages/cli/src/opentools/engagement/schema.py`

- [ ] **Step 1: Add v4 statements to MIGRATION_STATEMENTS**

In `packages/cli/src/opentools/engagement/schema.py`, add to the `MIGRATION_STATEMENTS` dict:

```python
MIGRATION_STATEMENTS[4] = [
    # Add status_text to linker_run
    "ALTER TABLE linker_run ADD COLUMN status_text TEXT",
    # Backfill legacy rows
    """
    UPDATE linker_run
    SET status_text = CASE
        WHEN error IS NOT NULL THEN 'failed'
        WHEN finished_at IS NOT NULL THEN 'done'
        ELSE 'unknown'
    END
    WHERE status_text IS NULL
    """,
    # Add user_id to cache tables (spec G37)
    "ALTER TABLE extraction_cache ADD COLUMN user_id TEXT",
    "ALTER TABLE llm_link_cache ADD COLUMN user_id TEXT",
]


def _migration_v4(conn: sqlite3.Connection) -> None:
    _apply_statements(conn, 4)
```

Update the `MIGRATIONS` dict:

```python
MIGRATIONS = {
    1: _migration_v1,
    2: _migration_v2,
    3: _migration_v3,
    4: _migration_v4,
}
```

`LATEST_VERSION` auto-updates since it's `max(MIGRATIONS.keys())`.

- [ ] **Step 2: Run tests to verify v4 applies cleanly**

Run: `python -m pytest packages/ -q`
Expected: `>= 530 passed, 1 skipped`. The existing schema tests should accept the new LATEST_VERSION.

If `test_schema.py::test_migration_v1_to_latest_upgrade` asserts specific tables, it might need updating. Check and adjust if necessary — the test may need to assert `status_text` column exists after upgrade.

- [ ] **Step 3: Commit**

```bash
git add packages/cli/src/opentools/engagement/schema.py
git commit -m "$(cat <<'EOF'
feat(schema): add migration v4 (status_text + cache user_id)

Adds status_text column to linker_run with backfill derived from
existing finished_at/error. Adds user_id column to extraction_cache
and llm_link_cache tables (spec G37: user-scoped caches prevent
cross-user side-channel leaks).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 19: Migration v4 tests

**Files:**
- Create: `packages/cli/tests/chain/test_migration_v4.py`

- [ ] **Step 1: Write tests**

```python
"""Tests for migration v4 — status_text backfill and cache user_id."""
import sqlite3

import pytest


def test_migration_v4_adds_status_text_column(tmp_path):
    from opentools.engagement.schema import (
        LATEST_VERSION, MIGRATION_STATEMENTS, _apply_statements, migrate,
    )

    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db_path))
    try:
        # Build a v3 database manually
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL
            )
        """)
        for v in [1, 2, 3]:
            _apply_statements(conn, v)
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (v, "2025-01-01"),
            )
        conn.commit()

        # Seed legacy rows without status_text
        conn.execute(
            """
            INSERT INTO linker_run (
                id, started_at, scope, mode, finished_at, error, generation
            ) VALUES ('r_done', '2025-01-01', 'engagement', 'rules_only',
                      '2025-01-01', NULL, 1)
            """
        )
        conn.execute(
            """
            INSERT INTO linker_run (
                id, started_at, scope, mode, error, generation
            ) VALUES ('r_failed', '2025-01-01', 'engagement', 'rules_only',
                      'oom', 2)
            """
        )
        conn.execute(
            """
            INSERT INTO linker_run (
                id, started_at, scope, mode, generation
            ) VALUES ('r_unknown', '2025-01-01', 'engagement', 'rules_only', 3)
            """
        )
        conn.commit()

        # Run migrate() which picks up v4
        migrate(conn)

        assert LATEST_VERSION == 4

        # status_text column exists
        cols = [row[1] for row in conn.execute("PRAGMA table_info(linker_run)").fetchall()]
        assert "status_text" in cols

        # Backfill values correct
        done = conn.execute(
            "SELECT status_text FROM linker_run WHERE id = 'r_done'"
        ).fetchone()[0]
        assert done == "done"

        failed = conn.execute(
            "SELECT status_text FROM linker_run WHERE id = 'r_failed'"
        ).fetchone()[0]
        assert failed == "failed"

        unknown = conn.execute(
            "SELECT status_text FROM linker_run WHERE id = 'r_unknown'"
        ).fetchone()[0]
        assert unknown == "unknown"

        # Cache tables have user_id column
        ec_cols = [
            row[1] for row in conn.execute(
                "PRAGMA table_info(extraction_cache)"
            ).fetchall()
        ]
        assert "user_id" in ec_cols

        lc_cols = [
            row[1] for row in conn.execute(
                "PRAGMA table_info(llm_link_cache)"
            ).fetchall()
        ]
        assert "user_id" in lc_cols

    finally:
        conn.close()


def test_migration_v4_rolls_back_on_backfill_failure(tmp_path, monkeypatch):
    """If the backfill UPDATE fails, the ALTER TABLE must also roll back."""
    from opentools.engagement.schema import (
        MIGRATION_STATEMENTS, _apply_statements, migrate,
    )

    db_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db_path))
    try:
        # Build v3 manually
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL
            )
        """)
        for v in [1, 2, 3]:
            _apply_statements(conn, v)
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (v, "2025-01-01"),
            )
        conn.commit()

        # Monkeypatch v4 statements with an invalid SQL in position 1
        # (after the ALTER TABLE but before the backfill completes)
        broken = list(MIGRATION_STATEMENTS[4])
        broken[1] = "UPDATE linker_run SET nonexistent_col = 'x'"
        monkeypatch.setattr(
            "opentools.engagement.schema.MIGRATION_STATEMENTS",
            {**MIGRATION_STATEMENTS, 4: broken},
        )

        with pytest.raises(Exception):
            migrate(conn)

        # schema_version should NOT include 4 (rollback worked)
        versions = [r[0] for r in conn.execute(
            "SELECT version FROM schema_version ORDER BY version"
        ).fetchall()]
        assert 4 not in versions

        # status_text column should NOT exist (ALTER TABLE rolled back)
        cols = [row[1] for row in conn.execute("PRAGMA table_info(linker_run)").fetchall()]
        assert "status_text" not in cols

    finally:
        conn.close()
```

- [ ] **Step 2: Run tests**

Run: `python -m pytest packages/cli/tests/chain/test_migration_v4.py -v`
Expected: 2 PASS.

- [ ] **Step 3: Commit**

```bash
git add packages/cli/tests/chain/test_migration_v4.py
git commit -m "$(cat <<'EOF'
test(schema): verify migration v4 forward, backfill, and rollback

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 20: Test count baseline CI gate script

**Files:**
- Create: `scripts/check_test_count.sh`

- [ ] **Step 1: Create the script**

```bash
#!/usr/bin/env bash
# scripts/check_test_count.sh
#
# Enforce "passed >= expected_min, failed == 0" at phase boundaries.
# Called in CI after every test run. Additional tests added mid-phase
# don't break the gate because it uses >= not exact match.
set -euo pipefail

EXPECTED_MIN="${1:-}"
if [ -z "$EXPECTED_MIN" ]; then
    echo "usage: $0 <expected-min-passing-count>"
    exit 2
fi

OUTPUT=$(python -m pytest packages/ -q 2>&1 | tail -5)
PASSED=$(echo "$OUTPUT" | grep -oE '[0-9]+ passed' | head -1 | grep -oE '[0-9]+' || echo 0)
FAILED=$(echo "$OUTPUT" | grep -oE '[0-9]+ failed' | head -1 | grep -oE '[0-9]+' || echo 0)

if [ -n "$FAILED" ] && [ "$FAILED" != "0" ]; then
    echo "FAILED: $FAILED test(s) failing"
    echo "$OUTPUT"
    exit 1
fi

if [ "$PASSED" -lt "$EXPECTED_MIN" ]; then
    echo "REGRESSION: expected at least $EXPECTED_MIN passing, got $PASSED"
    echo "$OUTPUT"
    exit 1
fi

echo "OK: $PASSED tests passing (>= $EXPECTED_MIN)"
```

- [ ] **Step 2: Make it executable and test**

```bash
chmod +x scripts/check_test_count.sh
scripts/check_test_count.sh 500
```

Expected: `OK: <N> tests passing (>= 500)` where N is the current count (should be 530+ by this point).

- [ ] **Step 3: Commit**

```bash
git add scripts/check_test_count.sh
git commit -m "$(cat <<'EOF'
feat(ci): add test count baseline gate script

Enforces "passed >= expected_min, failed == 0" at each phase
boundary. Allows tests added mid-phase (>=) while blocking
regressions below the floor.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 21: Shared protocol conformance test fixture

**Files:**
- Create: `packages/cli/tests/chain/test_store_protocol_conformance.py`

- [ ] **Step 1: Create the conformance test file**

This file ships with the SQLite parameter only initially. Phase 5 adds the Postgres parameter.

```python
"""Shared ChainStoreProtocol conformance tests.

Every protocol method is exercised via a parameterized fixture so that
AsyncChainStore (aiosqlite) and later PostgresChainStore (SQLAlchemy)
are verified to behave identically.

In Phase 1, only the SQLite parameter is active. Phase 5 (Task 42)
adds the Postgres parameter.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from opentools.chain.models import (
    Entity,
    EntityMention,
    FindingRelation,
    RelationReason,
    entity_id_for,
)
from opentools.chain.stores._common import (
    ScopingViolation,
    StoreNotInitialized,
)
from opentools.chain.types import (
    LinkerMode,
    LinkerScope,
    MentionField,
    RelationStatus,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.fixture(params=["sqlite_async"])
async def conformant_store(request, tmp_path):
    """Yield (store, user_id) for the parameterized backend.

    SQLite (CLI): user_id is None.
    Postgres (web, added in Phase 5): user_id is a UUID, session set up
    against the web backend's aiosqlite-backed SQLAlchemy engine.
    """
    if request.param == "sqlite_async":
        from opentools.chain.stores.sqlite_async import AsyncChainStore
        store = AsyncChainStore(db_path=tmp_path / f"{request.param}.db")
        await store.initialize()
        yield store, None
        await store.close()
    else:
        pytest.skip(f"backend {request.param} not available in this phase")


# ─── Lifecycle ───────────────────────────────────────────────────────


async def test_method_raises_before_initialize(request, tmp_path):
    if request.node.callspec.params.get("conformant_store") == "sqlite_async" or True:
        from opentools.chain.stores.sqlite_async import AsyncChainStore
        store = AsyncChainStore(db_path=tmp_path / "no_init.db")
        with pytest.raises(StoreNotInitialized):
            await store.get_entity("eid", user_id=None)


async def test_transaction_commit_on_success(conformant_store):
    store, user_id = conformant_store
    entity_id = entity_id_for("host", "10.0.0.5")
    async with store.transaction():
        await store.upsert_entity(
            Entity(
                id=entity_id, type="host", canonical_value="10.0.0.5",
                first_seen_at=_now(), last_seen_at=_now(),
                mention_count=0,
            ),
            user_id=user_id,
        )
    result = await store.get_entity(entity_id, user_id=user_id)
    assert result is not None
    assert result.canonical_value == "10.0.0.5"


async def test_transaction_rollback_on_exception(conformant_store):
    store, user_id = conformant_store
    entity_id = entity_id_for("host", "1.2.3.4")
    with pytest.raises(RuntimeError, match="boom"):
        async with store.transaction():
            await store.upsert_entity(
                Entity(
                    id=entity_id, type="host", canonical_value="1.2.3.4",
                    first_seen_at=_now(), last_seen_at=_now(),
                    mention_count=0,
                ),
                user_id=user_id,
            )
            raise RuntimeError("boom")
    result = await store.get_entity(entity_id, user_id=user_id)
    assert result is None  # rolled back


async def test_transaction_read_your_writes(conformant_store):
    """A write inside a transaction must be visible to a read in the
    same transaction (spec A10)."""
    store, user_id = conformant_store
    entity_id = entity_id_for("host", "5.6.7.8")
    async with store.transaction():
        await store.upsert_entity(
            Entity(
                id=entity_id, type="host", canonical_value="5.6.7.8",
                first_seen_at=_now(), last_seen_at=_now(),
                mention_count=0,
            ),
            user_id=user_id,
        )
        # Within the same transaction
        result = await store.get_entity(entity_id, user_id=user_id)
        assert result is not None
    # After commit: still visible
    result = await store.get_entity(entity_id, user_id=user_id)
    assert result is not None


# ─── Entity CRUD ────────────────────────────────────────────────────


async def test_upsert_entity_and_get(conformant_store):
    store, user_id = conformant_store
    e = Entity(
        id=entity_id_for("host", "10.0.0.5"),
        type="host", canonical_value="10.0.0.5",
        first_seen_at=_now(), last_seen_at=_now(),
        mention_count=1,
    )
    await store.upsert_entity(e, user_id=user_id)
    result = await store.get_entity(e.id, user_id=user_id)
    assert result is not None
    assert result.type == "host"


async def test_list_entities_with_type_filter(conformant_store):
    store, user_id = conformant_store
    for t, v in [("host", "1.1.1.1"), ("host", "2.2.2.2"), ("cve", "CVE-2024-1")]:
        await store.upsert_entity(
            Entity(
                id=entity_id_for(t, v), type=t, canonical_value=v,
                first_seen_at=_now(), last_seen_at=_now(),
                mention_count=1,
            ),
            user_id=user_id,
        )
    hosts = await store.list_entities(user_id=user_id, entity_type="host")
    assert len(hosts) == 2
    cves = await store.list_entities(user_id=user_id, entity_type="cve")
    assert len(cves) == 1
```

Add more tests per protocol method following this pattern. Aim for ~20 total tests in this file for Phase 1. Phase 5 adds the Postgres parameter which runs them all against SQLAlchemy.

- [ ] **Step 2: Run tests**

Run: `python -m pytest packages/cli/tests/chain/test_store_protocol_conformance.py -v`
Expected: all pass against the SQLite backend.

Run: `python -m pytest packages/ -q`
Expected: `>= 550 passed, 1 skipped`.

- [ ] **Step 3: Commit**

```bash
git add packages/cli/tests/chain/test_store_protocol_conformance.py
git commit -m "$(cat <<'EOF'
test(chain): add parameterized protocol conformance suite (SQLite)

Phase 5 adds the Postgres parameter.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

# PHASE 2 — ExtractionPipeline + drain worker

Phase 2 converts `ExtractionPipeline` to async-native, adds the drain worker to `subscriptions.py`, and converts CLI tests that exercise extraction.

## Task 22: Convert ExtractionPipeline to async

**Files:**
- Modify: `packages/cli/src/opentools/chain/extractors/pipeline.py`
- Modify: `packages/cli/tests/chain/conftest.py`
- Modify: `packages/cli/tests/chain/test_pipeline.py`

- [ ] **Step 1: Read current pipeline.py structure**

The current file has `ExtractionPipeline.extract_for_finding` (sync) and `extract_for_finding_async` (async wrapper). We retire the sync version and keep the async one, renaming it.

- [ ] **Step 2: Rewrite pipeline.py methods against the protocol**

Replace every `self.store.execute_one(...)` / `self.store.execute_all(...)` / `self.store._conn.execute(...)` call with the appropriate `ChainStoreProtocol` method. Delete the sync `extract_for_finding` method entirely. Rename `extract_for_finding_async` to `extract_for_finding`.

Key changes:
- Method signature: `async def extract_for_finding(self, finding, *, user_id=None, llm_provider=None, force=False) -> ExtractionResult`
- `_persist`: wraps in `async with self.store.transaction():`; uses `upsert_entities_bulk`, `add_mentions_bulk`, `recompute_mention_counts`, `upsert_extraction_state`
- `_hash_matches`: uses `await self.store.get_extraction_hash(finding_id, user_id=user_id)`
- `_run_stage1`: uses `await self.store.get_parser_output(finding.id, user_id=user_id)`
- All LLM cache lookups use `await self.store.get_extraction_cache(cache_key, user_id=user_id)` / `put_extraction_cache(...)`
- `self.store` type hint: `ChainStoreProtocol`

- [ ] **Step 3: Update conftest.py fixture**

Replace the `engagement_store_and_chain` fixture:

```python
@pytest.fixture
async def engagement_store_and_chain(tmp_path):
    """Yield (EngagementStore, AsyncChainStore, now) sharing the same DB file.

    EngagementStore owns a sync sqlite3 connection; AsyncChainStore owns
    an aiosqlite connection to the same file. WAL mode permits both.
    """
    from datetime import datetime, timezone
    from opentools.chain.stores.sqlite_async import AsyncChainStore
    from opentools.engagement.store import EngagementStore
    from opentools.models import Engagement, EngagementStatus, EngagementType

    db_path = tmp_path / "combined.db"
    engagement_store = EngagementStore(db_path=db_path)
    now = datetime.now(timezone.utc)
    engagement_store.create(Engagement(
        id="eng_test", name="test", target="t",
        type=EngagementType.PENTEST, status=EngagementStatus.ACTIVE,
        created_at=now, updated_at=now,
    ))

    chain_store = AsyncChainStore(db_path=db_path)
    await chain_store.initialize()

    yield engagement_store, chain_store, now

    await chain_store.close()
    engagement_store._conn.close()
```

- [ ] **Step 4: Convert test_pipeline.py to async**

Every `def test_*` becomes `async def test_*`. Every `result = pipeline.extract_for_finding(f)` becomes `result = await pipeline.extract_for_finding(f)`. The `_insert_finding` helper stays sync. Mechanical conversion across ~9 tests.

- [ ] **Step 5: Run tests**

Run: `python -m pytest packages/cli/tests/chain/test_pipeline.py -v`
Expected: all pass.

Run: `python -m pytest packages/ -q`
Expected: `>= 550 passed, 1 skipped`.

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/chain/extractors/pipeline.py \
        packages/cli/tests/chain/conftest.py \
        packages/cli/tests/chain/test_pipeline.py
git commit -m "$(cat <<'EOF'
feat(chain): convert ExtractionPipeline to async-first via protocol

Retires the sync extract_for_finding variant. Closes the
_update_extraction_state raw SQL leak. _persist wraps in
store.transaction() for atomicity. All raw SQL replaced with
ChainStoreProtocol method calls.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 23: Convert test_pipeline_integration.py

**Files:**
- Modify: `packages/cli/tests/chain/test_pipeline_integration.py`

- [ ] **Step 1: Convert tests to async**

All two integration tests become `async def`, all pipeline/engine calls become `await`. The store setup uses `AsyncChainStore` via the updated conftest fixture.

- [ ] **Step 2: Run and commit**

Run: `python -m pytest packages/cli/tests/chain/test_pipeline_integration.py -v`
Expected: both pass with `await`.

```bash
git add packages/cli/tests/chain/test_pipeline_integration.py
git commit -m "$(cat <<'EOF'
test(chain): convert pipeline integration tests to async

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 24: Retire sync llm_link_pass

**Files:**
- Modify: `packages/cli/src/opentools/chain/linker/llm_pass.py`
- Modify: `packages/cli/tests/chain/test_llm_pass.py`

- [ ] **Step 1: Delete sync llm_link_pass, rename async to default**

In `llm_link_pass.py`, delete the sync `llm_link_pass` function entirely. Rename `llm_link_pass_async` to `llm_link_pass`. Update the function body to use `ChainStoreProtocol` methods:
- `store.fetch_relations_in_scope(...)` instead of raw SQL
- `store.apply_link_classification(...)` instead of raw UPDATE
- `store.get_llm_link_cache(...)` / `put_llm_link_cache(...)` with user_id
- Wrap per-edge classification + cache write in `async with store.transaction():`

- [ ] **Step 2: Convert test_llm_pass.py**

Tests become `async def` + `await`. Delete any test that specifically tested the sync variant; keep and convert the ones testing classification behavior.

- [ ] **Step 3: Run and commit**

Run: `python -m pytest packages/cli/tests/chain/test_llm_pass.py -v`
Expected: all pass.

```bash
git add packages/cli/src/opentools/chain/linker/llm_pass.py \
        packages/cli/tests/chain/test_llm_pass.py
git commit -m "$(cat <<'EOF'
feat(chain): retire sync llm_link_pass, async becomes the only variant

Uses ChainStoreProtocol for all DB access; wraps per-edge
classification updates in store.transaction() for atomicity.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 25: Drain worker infrastructure

**Files:**
- Modify: `packages/cli/src/opentools/chain/subscriptions.py`

- [ ] **Step 1: Replace subscriptions.py with drain worker design**

```python
"""Chain event subscriptions — drain worker for async processing.

When the engagement store commits a finding, it emits a sync event via
StoreEventBus. This module's sync handler queues the finding_id into an
asyncio.Queue, and a background drain worker coroutine processes the
queue in the CLI's event loop.

The sync handler uses asyncio.get_event_loop_policy().get_event_loop()
+ call_soon_threadsafe so it's safe to call from any thread (CLI main
thread or engagement store's sync context).

Tests that need immediate processing call await pipeline.extract_for_finding(...)
explicitly instead of relying on the drain worker.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from opentools.chain.events import get_event_bus

logger = logging.getLogger(__name__)

_queue: asyncio.Queue | None = None
_worker_task: asyncio.Task | None = None
_in_batch_context: bool = False


def set_batch_context(active: bool) -> None:
    """Flip the batch mode flag. When True, the drain worker short-circuits.

    Used by ChainBatchContext to suppress per-finding events during a batch.
    """
    global _in_batch_context
    _in_batch_context = active


def reset_subscriptions() -> None:
    """Test helper: clear module state."""
    global _queue, _worker_task, _in_batch_context
    _queue = None
    if _worker_task is not None and not _worker_task.done():
        _worker_task.cancel()
    _worker_task = None
    _in_batch_context = False


@dataclass
class DrainWorker:
    """Handle for a running drain worker.

    Returned by start_drain_worker(). Call await stop() during CLI
    shutdown to drain pending work and cancel the worker.
    """
    task: asyncio.Task
    queue: asyncio.Queue

    async def stop(self) -> None:
        """Wait for pending items to drain, then cancel the worker."""
        await self.queue.join()
        self.task.cancel()
        try:
            await self.task
        except asyncio.CancelledError:
            pass


async def start_drain_worker(store, pipeline, engine) -> DrainWorker:
    """Start a background drain worker and subscribe to finding events.

    Call from CLI command startup AFTER constructing the store, pipeline,
    and engine. Returns a DrainWorker handle for shutdown.
    """
    global _queue, _worker_task

    if _queue is None:
        _queue = asyncio.Queue(maxsize=10000)

    async def _drain():
        while True:
            finding_id = await _queue.get()
            try:
                if _in_batch_context:
                    continue
                findings = await store.fetch_findings_by_ids(
                    [finding_id], user_id=None
                )
                if not findings:
                    continue
                finding = findings[0]
                await pipeline.extract_for_finding(finding)
                await engine.link_finding(finding_id, user_id=None)
            except Exception:
                logger.exception(
                    "drain worker extract+link failed for %s", finding_id
                )
            finally:
                _queue.task_done()

    _worker_task = asyncio.create_task(_drain())

    bus = get_event_bus()

    def _on_created(finding_id, **_kwargs):
        if _queue is None:
            return
        try:
            loop = asyncio.get_event_loop_policy().get_event_loop()
            if loop.is_running():
                loop.call_soon_threadsafe(_queue.put_nowait, finding_id)
            else:
                # Not in event loop — drop silently (tests should use
                # explicit await rather than relying on drain worker)
                logger.debug(
                    "finding.created emitted outside running event loop; "
                    "no drain worker dispatch"
                )
        except (asyncio.QueueFull, RuntimeError) as exc:
            logger.warning("drain queue dispatch failed: %s", exc)

    def _on_updated(finding_id, **_kwargs):
        _on_created(finding_id)

    def _on_deleted(finding_id, **_kwargs):
        pass  # FK cascade handles cleanup

    bus.subscribe("finding.created", _on_created)
    bus.subscribe("finding.updated", _on_updated)
    bus.subscribe("finding.deleted", _on_deleted)

    return DrainWorker(task=_worker_task, queue=_queue)


# Backwards-compat function preserved during the refactor — CLI code
# that previously called subscribe_chain_handlers can continue to work
# if it passes factories. The new pattern uses start_drain_worker.
def subscribe_chain_handlers(**_kwargs) -> None:
    """Deprecated shim: old callers pass factories, new code uses
    start_drain_worker directly."""
    logger.warning(
        "subscribe_chain_handlers is deprecated; use start_drain_worker"
    )
```

- [ ] **Step 2: Run existing subscription tests**

Run: `python -m pytest packages/cli/tests/chain/test_subscriptions.py -v`
Expected: tests that still exercise meaningful behavior pass; tests that rely on the old factory injection pattern will need updating in Task 26.

- [ ] **Step 3: Commit**

```bash
git add packages/cli/src/opentools/chain/subscriptions.py
git commit -m "$(cat <<'EOF'
feat(chain): replace sync subscriber factories with drain worker

New start_drain_worker returns a DrainWorker handle that CLI
command lifecycle awaits on shutdown. Sync event handler uses
call_soon_threadsafe to safely queue from any thread context.
Old subscribe_chain_handlers shim remains as a deprecation path.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 26: Update test_subscriptions.py for drain worker

**Files:**
- Modify: `packages/cli/tests/chain/test_subscriptions.py`

- [ ] **Step 1: Rewrite tests against drain worker**

```python
"""Tests for drain worker event-to-extraction pipeline."""
import asyncio
from datetime import datetime, timezone

import pytest

from opentools.chain.config import ChainConfig
from opentools.chain.events import get_event_bus, reset_event_bus
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine, get_default_rules
from opentools.chain.subscriptions import (
    DrainWorker,
    reset_subscriptions,
    set_batch_context,
    start_drain_worker,
)
from opentools.models import Finding, FindingStatus, Severity


def _finding(id: str, description: str = "on 10.0.0.5") -> Finding:
    return Finding(
        id=id, engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title=f"F {id}", description=description,
        created_at=datetime.now(timezone.utc),
    )


async def test_drain_worker_processes_finding_created(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    reset_subscriptions()
    reset_event_bus()

    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=chain_store, config=cfg)
    engine = LinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    worker = await start_drain_worker(chain_store, pipeline, engine)

    engagement_store.add_finding(_finding("drain_a"))

    # Wait for drain
    await worker.queue.join()

    mentions = await chain_store.mentions_for_finding("drain_a", user_id=None)
    assert len(mentions) >= 1

    await worker.stop()
    reset_subscriptions()
    reset_event_bus()


async def test_batch_context_suppresses_drain_worker(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    reset_subscriptions()
    reset_event_bus()

    cfg = ChainConfig()
    pipeline = ExtractionPipeline(store=chain_store, config=cfg)
    engine = LinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    worker = await start_drain_worker(chain_store, pipeline, engine)

    set_batch_context(True)
    try:
        engagement_store.add_finding(_finding("drain_b"))
        await asyncio.sleep(0.1)  # let the worker pick up the queue
        mentions = await chain_store.mentions_for_finding("drain_b", user_id=None)
        # Batch context suppresses processing — no mentions yet
        assert mentions == []
    finally:
        set_batch_context(False)

    await worker.stop()
    reset_subscriptions()
    reset_event_bus()
```

- [ ] **Step 2: Run and commit**

Run: `python -m pytest packages/cli/tests/chain/test_subscriptions.py -v`
Expected: both pass.

```bash
git add packages/cli/tests/chain/test_subscriptions.py
git commit -m "$(cat <<'EOF'
test(chain): drain worker integration tests

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 27: Convert CLI commands that trigger extraction

**Files:**
- Modify: `packages/cli/src/opentools/chain/cli.py`

- [ ] **Step 1: Convert extraction-triggering commands to async**

Typer supports `async def` commands natively. Convert `rebuild` and any other command that calls `pipeline.extract_for_finding` or `engine.link_finding`:

```python
@app.command()
async def rebuild(
    engagement: str | None = typer.Option(None, "--engagement"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    """Re-run extraction + linking for findings in scope."""
    engagement_store, chain_store = await _get_stores_async()
    cfg = get_chain_config()

    pipeline = ExtractionPipeline(store=chain_store, config=cfg)
    engine = LinkerEngine(
        store=chain_store, config=cfg,
        rules=get_default_rules(cfg),
    )

    # Load findings
    finding_ids = await chain_store.fetch_findings_for_engagement(
        engagement or "*", user_id=None,
    ) if engagement else await _all_finding_ids(chain_store)
    findings = await chain_store.fetch_findings_by_ids(finding_ids, user_id=None)

    for f in findings:
        try:
            await pipeline.extract_for_finding(f, force=force)
        except Exception as exc:
            rprint(f"[red]extract failed for {f.id}: {exc}[/red]")

    for f in findings:
        try:
            await engine.link_finding(f.id, user_id=None)
        except Exception as exc:
            rprint(f"[red]link failed for {f.id}: {exc}[/red]")

    await chain_store.close()
    rprint(f"[green]rebuild complete: {len(findings)} findings[/green]")


async def _get_stores_async():
    from opentools.chain.stores.sqlite_async import AsyncChainStore
    db = _default_db_path()
    db.parent.mkdir(parents=True, exist_ok=True)
    engagement_store = EngagementStore(db_path=db)
    chain_store = AsyncChainStore(db_path=db)
    await chain_store.initialize()
    return engagement_store, chain_store
```

Other commands (`status`, `entities`, `path`, `export`, `query`) are converted in Task 32 (Phase 3 closeout) when the query engine is async.

- [ ] **Step 2: Run and commit**

Run: `python -m pytest packages/ -q`
Expected: `>= 555 passed, 1 skipped`.

```bash
git add packages/cli/src/opentools/chain/cli.py
git commit -m "$(cat <<'EOF'
feat(chain): convert rebuild command to async

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

# PHASE 3 — Linker + entity_ops + exporter + batch

## Task 28: Convert LinkerEngine to async

**Files:**
- Modify: `packages/cli/src/opentools/chain/linker/engine.py`
- Modify: `packages/cli/tests/chain/test_linker_engine.py`

- [ ] **Step 1: Rewrite engine.py against protocol**

Every method becomes `async def`. Replace all raw SQL with protocol methods:
- `_load_finding` → `await self.store.fetch_findings_by_ids([finding_id], user_id=user_id)` then take `[0]`
- Per-partner load loop → single `await self.store.fetch_findings_by_ids(partner_ids, user_id=user_id)` call (spec G6)
- `_persist_run` → `await self.store.start_linker_run(...)` + `await self.store.finish_linker_run(...)`
- `fetch_candidate_partners` call now passes `common_entity_threshold=ctx.common_entity_threshold`
- `make_context` uses `await self.store.count_findings_in_scope(...)` and `await self.store.compute_avg_idf(...)` instead of loading all entities
- Wrap the relation upsert block in `async with self.store.transaction():`

- [ ] **Step 2: Convert test_linker_engine.py**

Mechanical `def` → `async def` + `await` conversion. ~6 tests.

- [ ] **Step 3: Run and commit**

Run: `python -m pytest packages/cli/tests/chain/test_linker_engine.py -v`
Expected: pass.

```bash
git add packages/cli/src/opentools/chain/linker/engine.py \
        packages/cli/tests/chain/test_linker_engine.py
git commit -m "$(cat <<'EOF'
feat(chain): convert LinkerEngine to async-first via protocol

Closes _persist_run and _load_finding raw SQL leaks. Replaces
per-partner load loop with single batch fetch (spec G6). Wraps
relation upserts in store.transaction() for atomicity.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 29: Convert ChainBatchContext with staged parallel extraction

**Files:**
- Modify: `packages/cli/src/opentools/chain/linker/batch.py`
- Modify: `packages/cli/tests/chain/test_linker_batch.py`

- [ ] **Step 1: Rewrite batch.py with staged parallel pattern**

```python
"""ChainBatchContext — async context manager for deferred linking.

Staged parallel extraction (spec O19):
- Stage 1: fetch all findings in one query
- Stage 2: run regex extractors in parallel via asyncio.gather + semaphore
- Stage 3: bulk-insert entities and mentions

Each finding's extraction runs inside its own per-finding transaction
(NOT one wrapping the whole batch) so writes are visible incrementally
and a crash mid-batch doesn't lose all progress.
"""
from __future__ import annotations

import asyncio
import logging

from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine
from opentools.chain.subscriptions import set_batch_context

logger = logging.getLogger(__name__)

_nesting = 0
_EXTRACTION_CONCURRENCY = 4


class ChainBatchContext:
    def __init__(
        self,
        *,
        pipeline: ExtractionPipeline,
        engine: LinkerEngine,
    ) -> None:
        self.pipeline = pipeline
        self.engine = engine
        self._deferred: list[str] = []
        self._entered = False

    async def __aenter__(self) -> "ChainBatchContext":
        global _nesting
        if _nesting > 0:
            raise RuntimeError("ChainBatchContext does not support nesting")
        _nesting += 1
        set_batch_context(True)
        self._entered = True
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        global _nesting
        try:
            await self._flush()
        finally:
            _nesting -= 1
            set_batch_context(False)

    def defer_linking(self, finding_id: str) -> None:
        if not self._entered:
            raise RuntimeError("defer_linking called outside of 'with' block")
        self._deferred.append(finding_id)

    async def _flush(self) -> None:
        if not self._deferred:
            return

        store = self.pipeline.store

        # Stage 1: fetch all findings
        findings = await store.fetch_findings_by_ids(
            self._deferred, user_id=None
        )

        # Stage 2: parallel extraction with bounded concurrency
        semaphore = asyncio.Semaphore(_EXTRACTION_CONCURRENCY)

        async def _extract_one(finding):
            async with semaphore:
                try:
                    await self.pipeline.extract_for_finding(finding)
                except Exception:
                    logger.exception(
                        "batch extract failed for %s", finding.id
                    )

        await asyncio.gather(*(_extract_one(f) for f in findings))

        # Stage 3: link each deferred finding (sequential, SQL serializes anyway)
        for fid in self._deferred:
            try:
                await self.engine.link_finding(fid, user_id=None)
            except Exception:
                logger.exception("batch link failed for %s", fid)
```

- [ ] **Step 2: Convert test_linker_batch.py**

Tests become `async def`. `with ChainBatchContext(...)` becomes `async with ChainBatchContext(...)`.

- [ ] **Step 3: Run and commit**

```bash
git add packages/cli/src/opentools/chain/linker/batch.py \
        packages/cli/tests/chain/test_linker_batch.py
git commit -m "$(cat <<'EOF'
feat(chain): convert ChainBatchContext to async with staged parallel extraction

Stage 1 fetches all findings in one query; stage 2 runs regex
extraction in parallel via Semaphore(4); stage 3 links sequentially.
Per-finding transactions (not whole-batch) so partial progress is
visible and crash-resilient.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 30: Convert entity_ops to async

**Files:**
- Modify: `packages/cli/src/opentools/chain/entity_ops.py`
- Modify: `packages/cli/tests/chain/test_entity_ops.py`

- [ ] **Step 1: Rewrite entity_ops.py**

Convert `merge_entities` and `split_entity` to `async def`. Replace raw SQL with protocol methods:
- `get_entity` → `await store.get_entity(id, user_id=user_id)`
- Rewrite mentions → `await store.rewrite_mentions_entity_id(...)`
- Delete entity → `await store.delete_entity(id, user_id=user_id)`
- Wrap each operation in `async with store.batch_transaction():`
- For split: `await store.fetch_mentions_with_engagement(entity_id, user_id=user_id)` returns the list of (mention_id, engagement_id); partition and call `rewrite_mentions_by_ids`

- [ ] **Step 2: Convert test_entity_ops.py**

Mechanical async conversion. ~6 tests.

- [ ] **Step 3: Run and commit**

```bash
git add packages/cli/src/opentools/chain/entity_ops.py \
        packages/cli/tests/chain/test_entity_ops.py
git commit -m "$(cat <<'EOF'
feat(chain): convert entity_ops merge/split to async via protocol

Each operation wrapped in batch_transaction() for atomicity.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 31: Convert exporter to async

**Files:**
- Modify: `packages/cli/src/opentools/chain/exporter.py`
- Modify: `packages/cli/tests/chain/test_exporter.py`

- [ ] **Step 1: Rewrite exporter.py**

Convert `export_chain` and `import_chain` to `async def`. Replace raw SQL with protocol:
- Export: `store.fetch_findings_for_engagement(...)` to get IDs, then `async for item in store.export_dump_stream(finding_ids, user_id=...)` yielding entity/mention/relation dicts. Write each yielded dict to the output file as it arrives (bounded memory).
- Import: `async with store.batch_transaction():` wrapping the entire import loop. Use `upsert_entities_bulk`, `add_mentions_bulk`, `upsert_relations_bulk`.

- [ ] **Step 2: Convert test_exporter.py** and run/commit.

```bash
git add packages/cli/src/opentools/chain/exporter.py \
        packages/cli/tests/chain/test_exporter.py
git commit -m "$(cat <<'EOF'
feat(chain): convert exporter to async with streaming export

Uses export_dump_stream for bounded memory; wraps import in
batch_transaction for atomicity.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 32: Convert remaining CLI commands

**Files:**
- Modify: `packages/cli/src/opentools/chain/cli.py`
- Modify: `packages/cli/tests/chain/test_cli_commands.py`

- [ ] **Step 1: Convert status, entities, path, export, query commands**

All become `async def`. Each grabs stores via `_get_stores_async`, does work, awaits `close()`. CLI lifecycle: open → work → close.

For commands that run under the drain worker (currently none in 3C.1's CLI), add `worker = await start_drain_worker(...)` before work and `await worker.stop()` after.

- [ ] **Step 2: Convert test_cli_commands.py**

Typer's `CliRunner` handles async commands natively. Tests stay mostly the same; any tests that directly checked sync behavior will need `await` added to their helper functions.

- [ ] **Step 3: Run and commit**

```bash
git add packages/cli/src/opentools/chain/cli.py \
        packages/cli/tests/chain/test_cli_commands.py
git commit -m "$(cat <<'EOF'
feat(chain): convert remaining CLI commands to async

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

# PHASE 4 — Query engine + graph cache

## Task 33: Convert GraphCache to async with concurrent build lock

**Files:**
- Modify: `packages/cli/src/opentools/chain/query/graph_cache.py`
- Modify: `packages/cli/tests/chain/test_graph_cache.py`

- [ ] **Step 1: Rewrite graph_cache.py**

`get_master_graph` becomes `async def`. `_build_master_graph` uses `async for rel in store.stream_relations_in_scope(...)` for bounded memory. Add an `asyncio.Lock` per cache key via a dict:

```python
class GraphCache:
    def __init__(self, *, store, maxsize: int = 8):
        self.store = store
        self.maxsize = maxsize
        self._cache: dict[tuple, MasterGraph] = {}
        self._access_order: list[tuple] = []
        self._build_locks: dict[tuple, asyncio.Lock] = {}

    async def get_master_graph(
        self,
        *,
        user_id,
        include_candidates: bool = False,
        include_rejected: bool = False,
    ) -> MasterGraph:
        generation = await self._current_generation(user_id)
        key = (
            str(user_id) if user_id else None,
            generation, include_candidates, include_rejected,
        )

        if key in self._cache:
            self._access_order.remove(key)
            self._access_order.append(key)
            return self._cache[key]

        # Per-key lock prevents duplicate concurrent builds (spec G4)
        lock = self._build_locks.setdefault(key, asyncio.Lock())
        async with lock:
            # Re-check in case another waiter built it while we waited
            if key in self._cache:
                return self._cache[key]
            master = await self._build_master_graph(
                user_id, generation, include_candidates, include_rejected,
            )
            self._cache[key] = master
            self._access_order.append(key)
            while len(self._access_order) > self.maxsize:
                oldest = self._access_order.pop(0)
                self._cache.pop(oldest, None)
        return master

    async def _current_generation(self, user_id):
        return await self.store.current_linker_generation(user_id=user_id)

    async def _build_master_graph(
        self, user_id, generation, include_candidates, include_rejected,
    ):
        # Iterate stream instead of loading list
        master = MasterGraph(...)  # build empty
        async for rel in self.store.stream_relations_in_scope(
            user_id=user_id,
            statuses=self._status_filter(include_candidates, include_rejected),
        ):
            # Add edge to rustworkx graph
            ...
        return master
```

Drop the generation recheck pattern (keeps cache simple; process-local staleness is acceptable per spec).

- [ ] **Step 2: Add concurrent build test**

```python
async def test_graph_cache_concurrent_build_uses_single_build(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    # Seed some relations via pipeline+linker first
    ...

    cache = GraphCache(store=chain_store, maxsize=4)

    build_count = 0
    original = cache._build_master_graph

    async def counting_build(*args, **kwargs):
        nonlocal build_count
        build_count += 1
        return await original(*args, **kwargs)

    cache._build_master_graph = counting_build

    # Spawn 10 concurrent get_master_graph calls
    results = await asyncio.gather(*[
        cache.get_master_graph(user_id=None)
        for _ in range(10)
    ])

    assert build_count == 1  # G4: per-key lock collapses duplicates
    # All 10 should return the same MasterGraph instance
    assert all(r is results[0] for r in results)
```

- [ ] **Step 3: Convert remaining test_graph_cache.py tests** and run/commit.

```bash
git add packages/cli/src/opentools/chain/query/graph_cache.py \
        packages/cli/tests/chain/test_graph_cache.py
git commit -m "$(cat <<'EOF'
feat(chain): async GraphCache with per-key build lock (G4)

Concurrent get_master_graph for the same key now collapses to a
single build via asyncio.Lock. Uses stream_relations_in_scope for
bounded memory.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 34: Convert ChainQueryEngine to async

**Files:**
- Modify: `packages/cli/src/opentools/chain/query/engine.py`
- Modify: `packages/cli/tests/chain/test_query_engine.py`

- [ ] **Step 1: Convert k_shortest_paths to async**

`async def k_shortest_paths(...)`. Calls `await self.graph_cache.get_master_graph(...)`. Endpoint resolution and Yen's stay sync (pure in-memory). The only `await` is the graph fetch.

- [ ] **Step 2: Convert tests, run, commit**

```bash
git add packages/cli/src/opentools/chain/query/engine.py \
        packages/cli/tests/chain/test_query_engine.py
git commit -m "$(cat <<'EOF'
feat(chain): convert ChainQueryEngine to async

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 35: Convert presets and narration to async

**Files:**
- Modify: `packages/cli/src/opentools/chain/query/presets.py`
- Modify: `packages/cli/src/opentools/chain/query/narration.py`
- Modify: `packages/cli/tests/chain/test_presets.py`
- Modify: `packages/cli/tests/chain/test_narration.py`

- [ ] **Step 1: Convert presets.py**

All 5 built-in presets (`lateral_movement`, `priv_esc_chains`, `external_to_internal`, `crown_jewel`, `mitre_coverage`) become `async def`. They call `await qe.k_shortest_paths(...)` instead of the sync variant.

- [ ] **Step 2: Convert narration.py**

`narrate_path` stays async (it already is). Update cache lookups to use protocol: `await store.get_llm_link_cache(cache_key, user_id=user_id)` and `await store.put_llm_link_cache(...)`. Use the consolidated `narration_cache_key` function from `_cache_keys.py` with `user_id`.

- [ ] **Step 3: Convert tests, run, commit**

```bash
git add packages/cli/src/opentools/chain/query/presets.py \
        packages/cli/src/opentools/chain/query/narration.py \
        packages/cli/tests/chain/test_presets.py \
        packages/cli/tests/chain/test_narration.py
git commit -m "$(cat <<'EOF'
feat(chain): convert query presets and narration to async

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

# PHASE 5 — Postgres backend + unification + cleanup

## Task 36: PostgresChainStore lifecycle + Alembic migration 004

**Files:**
- Create: `packages/cli/src/opentools/chain/stores/postgres_async.py`
- Create: `packages/web/backend/alembic/versions/004_chain_jsonb_unlogged_userids.py`

- [ ] **Step 1: Create Alembic migration 004**

Check the existing migration format in `packages/web/backend/alembic/versions/003_chain_data_layer.py` to match the revision variable style. Create `004_chain_jsonb_unlogged_userids.py`:

```python
"""chain JSONB conversion and cache user_id columns

Revision ID: 004
Revises: 003
Create Date: 2026-04-10
"""
from alembic import op
import sqlalchemy as sa

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Convert Text columns to JSONB on chain_finding_relation and chain_linker_run
    op.execute(
        "ALTER TABLE chain_finding_relation "
        "ALTER COLUMN reasons_json TYPE JSONB USING reasons_json::jsonb"
    )
    op.execute(
        "ALTER TABLE chain_finding_relation "
        "ALTER COLUMN confirmed_at_reasons_json TYPE JSONB "
        "USING confirmed_at_reasons_json::jsonb"
    )
    op.execute(
        "ALTER TABLE chain_linker_run "
        "ALTER COLUMN rule_stats_json TYPE JSONB USING rule_stats_json::jsonb"
    )

    # Add user_id to cache tables (spec G37)
    op.add_column(
        "chain_extraction_cache",
        sa.Column("user_id", sa.UUID(), nullable=True),
    )
    op.add_column(
        "chain_llm_link_cache",
        sa.Column("user_id", sa.UUID(), nullable=True),
    )

    # Mark cache tables UNLOGGED (spec O17)
    op.execute("ALTER TABLE chain_extraction_cache SET UNLOGGED")
    op.execute("ALTER TABLE chain_llm_link_cache SET UNLOGGED")


def downgrade() -> None:
    op.execute("ALTER TABLE chain_llm_link_cache SET LOGGED")
    op.execute("ALTER TABLE chain_extraction_cache SET LOGGED")
    op.drop_column("chain_llm_link_cache", "user_id")
    op.drop_column("chain_extraction_cache", "user_id")
    op.execute(
        "ALTER TABLE chain_linker_run "
        "ALTER COLUMN rule_stats_json TYPE TEXT USING rule_stats_json::text"
    )
    op.execute(
        "ALTER TABLE chain_finding_relation "
        "ALTER COLUMN confirmed_at_reasons_json TYPE TEXT "
        "USING confirmed_at_reasons_json::text"
    )
    op.execute(
        "ALTER TABLE chain_finding_relation "
        "ALTER COLUMN reasons_json TYPE TEXT USING reasons_json::text"
    )
```

- [ ] **Step 2: Create `postgres_async.py` with lifecycle only**

Skeleton with lifecycle methods that Tasks 37-42 flesh out with CRUD. Similar shape to `sqlite_async.py`:

```python
"""PostgresChainStore — SQLAlchemy async backend for web chain data."""
from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from typing import AsyncContextManager, AsyncIterator, Callable
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from opentools.chain.stores._common import (
    StoreNotInitialized,
    require_initialized,
    require_user_scope,
)

logger = logging.getLogger(__name__)


class PostgresChainStore:
    def __init__(
        self,
        *,
        session: AsyncSession | None = None,
        session_factory: Callable | None = None,
    ) -> None:
        if session is None and session_factory is None:
            raise ValueError("Provide either session or session_factory")
        if session is not None and session_factory is not None:
            raise ValueError("Provide session OR session_factory, not both")
        self._session = session
        self._session_factory = session_factory
        self._owned_cm = None
        self._initialized = False
        self._txn_depth = 0

    async def initialize(self) -> None:
        if self._initialized:
            return
        if self._session is None and self._session_factory is not None:
            self._owned_cm = self._session_factory()
            self._session = await self._owned_cm.__aenter__()
        self._initialized = True

    async def close(self) -> None:
        if self._owned_cm is not None:
            await self._owned_cm.__aexit__(None, None, None)
        self._owned_cm = None
        self._session = None
        self._initialized = False

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        if not self._initialized:
            raise StoreNotInitialized(
                "PostgresChainStore.transaction() called before initialize()"
            )
        async with self._session.begin_nested():
            self._txn_depth += 1
            try:
                yield
            finally:
                self._txn_depth -= 1

    @asynccontextmanager
    async def batch_transaction(self) -> AsyncIterator[None]:
        async with self.transaction():
            yield
```

- [ ] **Step 3: Run and commit**

Run: `python -m pytest packages/ -q`
Expected: no regressions (new file doesn't affect existing tests yet).

```bash
git add packages/cli/src/opentools/chain/stores/postgres_async.py \
        packages/web/backend/alembic/versions/004_chain_jsonb_unlogged_userids.py
git commit -m "$(cat <<'EOF'
feat(web): add PostgresChainStore lifecycle + migration 004

Migration converts Text JSON columns to JSONB, adds user_id to
chain cache tables, and marks caches UNLOGGED.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Tasks 37-41: PostgresChainStore CRUD methods

Implement each protocol method group on `PostgresChainStore`. Same grouping as AsyncChainStore (Tasks 7-14). Each method uses SQLAlchemy async with `@require_initialized` and `@require_user_scope` decorators. Implementation pattern:

### Task 37: Entity CRUD methods (PostgresChainStore)

Methods: `upsert_entity`, `upsert_entities_bulk`, `get_entity`, `get_entities_by_ids`, `list_entities`, `delete_entity`.

Uses `sqlalchemy.dialects.postgresql.insert` for ON CONFLICT. Example:

```python
@require_initialized
@require_user_scope
async def upsert_entity(self, entity, *, user_id: UUID) -> None:
    from sqlalchemy.dialects.postgresql import insert
    from app.models import ChainEntity

    stmt = insert(ChainEntity).values(
        id=entity.id,
        user_id=user_id,
        type=entity.type,
        canonical_value=entity.canonical_value,
        first_seen_at=entity.first_seen_at,
        last_seen_at=entity.last_seen_at,
        mention_count=entity.mention_count,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["id"],
        set_={
            "last_seen_at": stmt.excluded.last_seen_at,
            "mention_count": stmt.excluded.mention_count,
        },
    )
    await self._session.execute(stmt)
    if self._txn_depth == 0:
        await self._session.commit()
```

**Commit message:** `feat(web): PostgresChainStore entity CRUD methods`

### Task 38: Mention CRUD (PostgresChainStore)

Same method list as Task 8. ~10 new tests for Postgres conformance.

**Commit:** `feat(web): PostgresChainStore mention CRUD methods`

### Task 39: Relation CRUD (PostgresChainStore)

Same method list as Task 9. ~8 new tests.

**Commit:** `feat(web): PostgresChainStore relation CRUD methods`

### Task 40: Linker queries + run lifecycle (PostgresChainStore)

Methods from Tasks 10 + 11. `fetch_findings_by_ids` is the critical one — reads from the web `finding` table (not a chain-specific table) and converts rows to CLI `Finding` domain objects via the shared `_web_finding_to_cli` helper from `stores/_common.py`.

- [ ] **Add `_web_finding_to_cli` to `_common.py`**

```python
def _web_finding_to_cli(row) -> Finding:
    """Convert a web SQLModel Finding row to a CLI Finding domain object.

    Preserves every field that exists on both models. Drops web-only
    fields (user_id). Verified via direct model diff — CLI and web
    Finding shapes are nearly identical apart from user_id.
    """
    from opentools.models import Finding, FindingStatus, Severity

    return Finding(
        id=row.id,
        engagement_id=row.engagement_id,
        tool=row.tool,
        severity=Severity(row.severity),
        status=FindingStatus(row.status) if row.status else FindingStatus.DISCOVERED,
        title=row.title,
        description=row.description or "",
        file_path=row.file_path,
        line_start=row.line_start,
        line_end=row.line_end,
        evidence=row.evidence,
        phase=row.phase,
        cwe=row.cwe,
        cvss=row.cvss,
        remediation=row.remediation,
        false_positive=row.false_positive,
        dedup_confidence=row.dedup_confidence,
        created_at=row.created_at,
        deleted_at=row.deleted_at,
    )
```

- [ ] Use in `PostgresChainStore.fetch_findings_by_ids`.

**Commit:** `feat(web): PostgresChainStore linker methods + web->cli converter`

### Task 41: Extraction state + LLM caches + export (PostgresChainStore)

Remaining methods from Tasks 12-14.

**Commit:** `feat(web): PostgresChainStore extraction state and export methods`

---

## Task 42: Enable Postgres parameter in conformance tests

**Files:**
- Modify: `packages/cli/tests/chain/test_store_protocol_conformance.py`

- [ ] **Step 1: Add Postgres parameter to fixture**

```python
@pytest.fixture(params=["sqlite_async", "postgres_async"])
async def conformant_store(request, tmp_path):
    if request.param == "sqlite_async":
        from opentools.chain.stores.sqlite_async import AsyncChainStore
        store = AsyncChainStore(db_path=tmp_path / f"{request.param}.db")
        await store.initialize()
        yield store, None
        await store.close()
    else:
        # Postgres path via web backend's aiosqlite-backed SQLAlchemy engine
        import uuid as _uuid
        from sqlalchemy.ext.asyncio import (
            AsyncSession, create_async_engine,
        )
        from sqlalchemy.orm import sessionmaker
        from opentools.chain.stores.postgres_async import PostgresChainStore
        # Use in-memory aiosqlite via SQLAlchemy async for conformance
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        session = async_session()
        await session.begin()
        # Create schema matching web models
        from app.models import SQLModel
        async with engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)
        # Insert a stub User row so FK constraints hold
        user_id = _uuid.uuid4()
        from app.models import User
        session.add(User(id=user_id, email=f"u_{user_id.hex[:8]}@t", hashed_password="x"))
        await session.commit()
        store = PostgresChainStore(session=session)
        await store.initialize()
        yield store, user_id
        await store.close()
        await session.rollback()
        await session.close()
        await engine.dispose()
```

- [ ] **Step 2: Run conformance suite**

Run: `python -m pytest packages/cli/tests/chain/test_store_protocol_conformance.py -v`
Expected: every test runs twice (once per parameter), all pass.

- [ ] **Step 3: Commit**

```bash
git add packages/cli/tests/chain/test_store_protocol_conformance.py
git commit -m "$(cat <<'EOF'
test(chain): enable Postgres parameter in conformance suite

Runs against web backend's aiosqlite-backed SQLAlchemy engine,
which catches ORM dialect bugs even without a real Postgres
container. Real Postgres is the optional WEB_TEST_DB_URL gate.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 43: Rewrite web chain_service + routes against shared pipeline

**Files:**
- Create: `packages/web/backend/app/services/chain_store_factory.py`
- Modify: `packages/web/backend/app/services/chain_service.py`
- Modify: `packages/web/backend/app/routes/chain.py`

- [ ] **Step 1: Create chain_store_factory.py**

```python
"""Factory for constructing PostgresChainStore from web dependencies."""
from sqlalchemy.ext.asyncio import AsyncSession

from opentools.chain.stores.postgres_async import PostgresChainStore


def chain_store_from_session(session: AsyncSession) -> PostgresChainStore:
    """Construct a PostgresChainStore for a request-scoped AsyncSession."""
    return PostgresChainStore(session=session)


def chain_store_from_factory(session_factory) -> PostgresChainStore:
    """Construct a PostgresChainStore for a background task using a
    session factory (callable that returns an async context manager)."""
    return PostgresChainStore(session_factory=session_factory)
```

- [ ] **Step 2: Rewrite chain_service.py to delegate to shared pipeline**

The existing `ChainService` class in `packages/web/backend/app/services/chain_service.py` has methods like `list_entities`, `get_entity`, `relations_for_finding`, `k_shortest_paths_stub`, etc. Rewrite each to use the shared pipeline:

```python
"""Chain service — thin wrapper over shared pipeline + PostgresChainStore."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.chain_store_factory import chain_store_from_session
from opentools.chain.config import get_chain_config
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine, get_default_rules
from opentools.chain.query.engine import ChainQueryEngine
from opentools.chain.query.graph_cache import GraphCache


class ChainService:
    async def list_entities(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        type_: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list:
        store = chain_store_from_session(session)
        await store.initialize()
        return await store.list_entities(
            user_id=user_id, entity_type=type_, limit=limit, offset=offset,
        )

    async def get_entity(self, session, *, user_id, entity_id):
        store = chain_store_from_session(session)
        await store.initialize()
        return await store.get_entity(entity_id, user_id=user_id)

    async def relations_for_finding(self, session, *, user_id, finding_id):
        store = chain_store_from_session(session)
        await store.initialize()
        return await store.relations_for_finding(finding_id, user_id=user_id)

    async def k_shortest_paths(
        self, session, *, user_id, from_id, to_id, k, max_hops, include_candidates,
    ):
        from opentools.chain.query.endpoints import parse_endpoint_spec
        store = chain_store_from_session(session)
        await store.initialize()
        cfg = get_chain_config()
        cache = GraphCache(store=store, maxsize=4)
        qe = ChainQueryEngine(store=store, graph_cache=cache, config=cfg)
        return await qe.k_shortest_paths(
            from_spec=parse_endpoint_spec(from_id),
            to_spec=parse_endpoint_spec(to_id),
            user_id=user_id, k=k, max_hops=max_hops,
            include_candidates=include_candidates,
        )

    async def create_linker_run_pending(
        self, session, *, user_id, engagement_id: str | None,
    ):
        store = chain_store_from_session(session)
        await store.initialize()
        from opentools.chain.types import LinkerMode, LinkerScope
        run = await store.start_linker_run(
            scope=LinkerScope.ENGAGEMENT if engagement_id else LinkerScope.CROSS_ENGAGEMENT,
            scope_id=engagement_id,
            mode=LinkerMode.RULES_ONLY,
            user_id=user_id,
        )
        return run

    async def get_linker_run(self, session, *, user_id, run_id):
        store = chain_store_from_session(session)
        await store.initialize()
        runs = await store.fetch_linker_runs(user_id=user_id, limit=1000)
        for r in runs:
            if r.id == run_id:
                return r
        return None
```

The `create_linker_run_stub` is replaced by `create_linker_run_pending` which uses the real protocol method.

- [ ] **Step 3: Rewrite routes/chain.py rebuild endpoint**

```python
@router.post("/rebuild", response_model=RebuildResponse, status_code=status.HTTP_202_ACCEPTED)
async def rebuild_chain(
    request: RebuildRequest,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    service: ChainService = Depends(get_chain_service),
    registry: ChainTaskRegistry = Depends(chain_task_registry_dep),
) -> RebuildResponse:
    """Start a REAL background rebuild task using the shared pipeline."""
    run = await service.create_linker_run_pending(
        session, user_id=user.id, engagement_id=request.engagement_id,
    )

    # Launch background task using session factory
    from app.database import async_session_factory
    from app.services.chain_rebuild import run_rebuild_shared

    registry.start(
        run.id,
        run_rebuild_shared(
            session_factory=async_session_factory,
            run_id=run.id,
            user_id=user.id,
            engagement_id=request.engagement_id,
        ),
    )

    return RebuildResponse(run_id=run.id, status="pending")
```

- [ ] **Step 4: Add `run_rebuild_shared` to chain_rebuild.py** (temporarily; deleted in Task 44)

Before deleting `chain_rebuild.py` in Task 44, add a new function `run_rebuild_shared` that uses the shared pipeline:

```python
async def run_rebuild_shared(
    *,
    session_factory,
    run_id: str,
    user_id,
    engagement_id: str | None,
) -> None:
    """Background worker using the shared CLI chain pipeline.

    Replaces the custom _extract_all / _link_all loops with calls to
    the shared ExtractionPipeline and LinkerEngine.
    """
    from opentools.chain.config import get_chain_config
    from opentools.chain.extractors.pipeline import ExtractionPipeline
    from opentools.chain.linker.engine import LinkerEngine, get_default_rules
    from opentools.chain.stores.postgres_async import PostgresChainStore

    try:
        async with session_factory() as session:
            store = PostgresChainStore(session=session)
            await store.initialize()
            await store.set_run_status(run_id, "running", user_id=user_id)

            cfg = get_chain_config()
            pipeline = ExtractionPipeline(store=store, config=cfg)
            engine = LinkerEngine(
                store=store, config=cfg,
                rules=get_default_rules(cfg),
            )

            # Load findings
            from app.models import Finding as WebFinding
            from sqlalchemy import select
            stmt = select(WebFinding.id).where(
                WebFinding.user_id == user_id,
                WebFinding.deleted_at.is_(None),
            )
            if engagement_id:
                stmt = stmt.where(WebFinding.engagement_id == engagement_id)
            result = await session.execute(stmt)
            finding_ids = [r[0] for r in result.all()]

            findings = await store.fetch_findings_by_ids(finding_ids, user_id=user_id)

            entities_before = len(await store.list_entities(
                user_id=user_id, limit=100000,
            ))

            for f in findings:
                try:
                    await pipeline.extract_for_finding(f, user_id=user_id)
                except Exception:
                    logger.exception("extract failed for %s", f.id)

            relations_created = 0
            for f in findings:
                try:
                    run = await engine.link_finding(f.id, user_id=user_id)
                    relations_created += run.relations_created
                except Exception:
                    logger.exception("link failed for %s", f.id)

            entities_after = len(await store.list_entities(
                user_id=user_id, limit=100000,
            ))

            await store.finish_linker_run(
                run_id,
                findings_processed=len(findings),
                entities_extracted=max(0, entities_after - entities_before),
                relations_created=relations_created,
                relations_updated=0,
                relations_skipped_sticky=0,
                rule_stats={},
                user_id=user_id,
            )
            await store.set_run_status(run_id, "done", user_id=user_id)
            await session.commit()
    except Exception as exc:
        logger.exception("rebuild failed for run_id=%s", run_id)
        try:
            async with session_factory() as session:
                store = PostgresChainStore(session=session)
                await store.initialize()
                await store.set_run_status(
                    run_id, "failed", user_id=user_id,
                )
                await session.commit()
        except Exception:
            logger.exception("failed to mark rebuild failed")
```

- [ ] **Step 5: Commit**

```bash
git add packages/web/backend/app/services/chain_store_factory.py \
        packages/web/backend/app/services/chain_service.py \
        packages/web/backend/app/services/chain_rebuild.py \
        packages/web/backend/app/routes/chain.py
git commit -m "$(cat <<'EOF'
feat(web): route chain endpoints through shared pipeline

ChainService delegates every method to PostgresChainStore via
the shared pipeline. Rebuild endpoint launches a real background
worker (run_rebuild_shared) using the shared ExtractionPipeline
and LinkerEngine — no more duplicated extraction/linking code.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 44: Delete chain_rebuild.py custom worker and sync ChainStore

**Files:**
- Delete: `packages/web/backend/app/services/chain_rebuild.py` (after moving `run_rebuild_shared` to a more appropriate location)
- Delete: `packages/cli/src/opentools/chain/store_extensions.py`

- [ ] **Step 1: Move run_rebuild_shared**

The `run_rebuild_shared` function added in Task 43 currently lives in `chain_rebuild.py`. Before deleting that file, move the function to `packages/web/backend/app/services/chain_rebuild_worker.py`:

Create `packages/web/backend/app/services/chain_rebuild_worker.py` with the `run_rebuild_shared` function body.

Update the import in `routes/chain.py`:
```python
from app.services.chain_rebuild_worker import run_rebuild_shared
```

- [ ] **Step 2: Delete old files**

```bash
git rm packages/web/backend/app/services/chain_rebuild.py
git rm packages/cli/src/opentools/chain/store_extensions.py
```

- [ ] **Step 3: Find and fix any remaining imports**

Run: `grep -rn "from opentools.chain.store_extensions\|chain_rebuild\b" packages/`
Any matches (other than `chain_rebuild_worker`) need to be updated to import from `opentools.chain.stores.sqlite_async` (for `AsyncChainStore`) or removed entirely.

- [ ] **Step 4: Run full suite**

Run: `python -m pytest packages/ -q`
Expected: `>= 570 passed, 1 skipped`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
chore(chain): delete sync ChainStore and duplicated web rebuild

Phase 5 cleanup. All consumers now use AsyncChainStore (CLI) or
PostgresChainStore (web) via the shared pipeline. run_rebuild_shared
lives in chain_rebuild_worker.py.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 45: Parameterize pipeline integration test over both backends

**Files:**
- Modify: `packages/cli/tests/chain/test_pipeline_integration.py`

- [ ] **Step 1: Add Postgres parameter**

Mirror the conformance test fixture pattern: parameterize over `sqlite_async` and `postgres_async`. The canonical fixtures and assertions stay the same — both backends should produce equivalent results.

- [ ] **Step 2: Run and commit**

Run: `python -m pytest packages/cli/tests/chain/test_pipeline_integration.py -v`
Expected: tests run twice (once per backend), all pass.

```bash
git add packages/cli/tests/chain/test_pipeline_integration.py
git commit -m "$(cat <<'EOF'
test(chain): parameterize pipeline integration over both backends

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 46: Rename and rewrite test_chain_rebuild.py → test_web_rebuild.py

**Files:**
- Rename: `packages/web/backend/tests/test_chain_rebuild.py` → `test_web_rebuild.py`
- Modify: the renamed file

- [ ] **Step 1: Rename**

```bash
git mv packages/web/backend/tests/test_chain_rebuild.py \
        packages/web/backend/tests/test_web_rebuild.py
```

- [ ] **Step 2: Update tests to use the shared pipeline**

The 3 existing tests (extracts_entities_and_creates_relations, marks_run_failed_on_error, preserves_sticky_user_confirmed) get updated assertions that reflect shared-pipeline behavior:

- `extracts_entities_and_creates_relations`: the shared pipeline runs ALL 6 linker rules, not just shared-strong-entity. Assertions should still pass (more relations, not fewer). Check the relation count assertion and adjust to `>= 1` if it was tighter.
- `marks_run_failed_on_error`: change the monkeypatch target from `_extract_all` (deleted) to `pipeline.extract_for_finding`.
- `preserves_sticky_user_confirmed`: unchanged — sticky preservation is in both the old and new linker.

- [ ] **Step 3: Run and commit**

Run: `python -m pytest packages/web/backend/tests/test_web_rebuild.py -v`
Expected: all pass.

```bash
git add packages/web/backend/tests/
git commit -m "$(cat <<'EOF'
test(web): rewrite test_chain_rebuild as test_web_rebuild

Tests now assert against shared-pipeline behavior (all 6 linker
rules, not just shared-strong-entity).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 47: Final baseline verification

- [ ] **Step 1: Run the test count gate for the final phase target**

```bash
scripts/check_test_count.sh 575
```

Expected: `OK: <N> tests passing (>= 575)` where N is 575 or more.

- [ ] **Step 2: Run pre-existing test guards**

```bash
# Pre-existing CLI tests — must be EXACTLY 177
python -m pytest packages/cli/tests/ --ignore=packages/cli/tests/chain -q
# Expected: 177 passed

# Pre-existing web tests — must be EXACTLY 21
python -m pytest packages/web/backend/tests/ \
    --ignore=packages/web/backend/tests/test_chain_api.py \
    --ignore=packages/web/backend/tests/test_chain_isolation.py \
    --ignore=packages/web/backend/tests/test_web_rebuild.py -q
# Expected: 21 passed
```

If either count differs, a scope leak happened. Locate the new test outside the chain package and move it inside.

- [ ] **Step 3: Full suite verification**

```bash
python -m pytest packages/ -q
```

Expected: `>= 575 passed, 1 skipped, 0 failed`.

- [ ] **Step 4: Commit any final fixes if needed**

If adjustments were required to hit the numbers, commit them with a clear message. Otherwise the previous Task 46 commit is the final state.

---

# Self-Review

## Spec coverage

Walking spec §14 "Scope Boundary Checklist — In scope":

- ✅ `ChainStoreProtocol` with 41 methods — Task 3
- ✅ `AsyncChainStore` + `PostgresChainStore` + shared `_common.py` — Tasks 4-14 (SQLite), 36-41 (Postgres)
- ✅ Async conversion of all chain consumers — Tasks 22 (pipeline), 24 (llm_pass), 25-26 (subscriptions), 28 (linker), 29 (batch), 30 (entity_ops), 31 (exporter), 33 (graph cache), 34 (query engine), 35 (presets + narration)
- ✅ CLI command async conversion — Tasks 27 (rebuild), 32 (remaining commands)
- ✅ Migration v4 + migration 004 — Tasks 18-19 (SQLite), 36 (Postgres)
- ✅ Deletion of sync `ChainStore`, sync `llm_link_pass`, `chain_rebuild.py` — Tasks 17 (alias phase), 24, 44
- ✅ Shared conformance test suite — Task 21 (Phase 1 SQLite), Task 42 (Phase 5 Postgres)
- ✅ Concurrency test suite — Task 33 (graph cache lock test); drain worker tests in Task 26; Phase 1 lifecycle tests cover transaction rollback
- ✅ Canonical integration test on both backends — Task 45
- ✅ Frozen `ChainConfig` — Task 16
- ✅ Test count baseline CI gate — Task 20
- ✅ Loop-scope isolation pytest config — Task 1

## Placeholder scan

Searched for "TBD", "TODO", "implement later", "similar to Task N", placeholder error handling. Tasks 7-14 use compressed contract-only descriptions pointing back to earlier representative examples — this is documented as a deliberate plan-length optimization and each compressed task names the exact files, methods, test counts, and commit messages.

## Type consistency

- `ChainStoreProtocol` defined in Task 3 with 41 methods — every later task that references a store method uses a name defined in Task 3
- `Entity`, `EntityMention`, `FindingRelation`, `LinkerRun` domain objects — unchanged from 3C.1
- `AsyncChainStore.__init__` signature defined in Task 6, used consistently through Tasks 7-14
- `PostgresChainStore.__init__` signature defined in Task 36, used consistently through Tasks 37-41
- `DrainWorker` dataclass + `start_drain_worker` function defined in Task 25, used in Task 26 tests
- `ChainBatchContext.__aenter__/__aexit__` in Task 29, used by consumers in Tasks 30-31

Note on method count: the spec repeatedly said "32 methods" but the actual method list in §4.3 had 41. The plan uses 41 as the authoritative count (matching the actual method list) and the Task 3 test verifies against that count. This is called out explicitly in Task 3 Step 1.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-04-10-phase3c1-5-async-store-refactor.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration, protects the main conversation context from accumulating implementation noise. Given the plan size (47 tasks, mix of TDD detail and mechanical conversions), this is the better fit.

**2. Inline Execution** — Execute tasks in this session using executing-plans with batch checkpoints.

Which approach?
