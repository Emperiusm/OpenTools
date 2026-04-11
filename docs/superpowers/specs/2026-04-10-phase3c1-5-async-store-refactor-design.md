# Phase 3C.1.5: Async Store Refactor — Design Specification

**Date:** 2026-04-10
**Status:** Draft
**Author:** slabl + Claude
**Depends on:** Phase 3C.1 (merged) + 3C.1 follow-ups (merged)

## 1. Overview

Refactor the chain subsystem so a single async-first codebase powers both CLI (SQLite, driven by `asyncio.run` at Typer command entry) and web (Postgres, driven by FastAPI handlers). Eliminates the duplicated `chain_rebuild.py` worker, unifies extraction and linking behind one protocol-based store abstraction, and closes the seven `store._conn.execute(...)` encapsulation leaks flagged in the Task 17 audit.

**The outcome is one codebase with two storage backends, not two codebases.** Every linker rule, every LLM provider wiring, every extractor, every query preset runs identically in CLI and web. New features are implemented once.

This refactor exists because the follow-up task that shipped `chain_rebuild.py` intentionally duplicated extraction and linker logic into a web-specific async worker. Option 1 ("expand the web worker to reach parity") creates permanent maintenance debt; option 2 ("refactor the CLI chain package to be storage-agnostic") is the architecturally correct choice. This spec implements option 2.

## 2. Decisions

| Decision | Choice |
|---|---|
| API shape | Async-first everywhere; CLI wraps entry points in `asyncio.run` (optimized C, not sync-shim approach) |
| Protocol granularity | Medium, 32 methods, no raw SQL escape hatch |
| SQLite async bridge | Native `aiosqlite` (not `asyncio.to_thread` wrapper) |
| Postgres async bridge | Existing async SQLAlchemy (unchanged from web backend pattern) |
| Migration strategy | 5 phases on one feature branch; each phase leaves the repo in a green state |
| Raw SQL in consumers | Removed entirely; closed via new protocol methods |
| Sync `ChainStore` class | Preserved as alias during phases 1-4, deleted in phase 5 |
| Linker rules / normalizers / stopwords / prompts / extractors | Zero code changes (pure functions, backend-agnostic) |
| IDF formula | Preserve Task 18's squared tech debt; fix in a separate follow-up |
| `chain_rebuild.py` web worker | Deleted in phase 5, replaced by shared pipeline + `PostgresChainStore` |
| New dependency | `aiosqlite >= 0.21` in `packages/cli/pyproject.toml`; `pytest-xdist >= 3` as dev dep |
| Test churn | ~60 CLI tests gain `async def` + `await` (mechanical) |
| CLI command churn | ~6 Typer commands gain `async def` + `await` |
| Cache tables privacy | `extraction_cache` and `llm_link_cache` become **user-scoped** (cache key includes `user_id`, tables get `user_id` column) |
| Transaction model | Per-method auto-commit preserved; `transaction()` / `batch_transaction()` open explicit nested scopes |
| Event bus | Stays synchronous; drain worker uses `call_soon_threadsafe` for thread-safe queue insertion |
| Graph cache | Process-local + request-local; no cross-request sharing in this refactor |
| Test count baseline | `scripts/check_test_count.sh` enforces `passed >= min, failed == 0` at each phase |
| Test loop isolation | `asyncio_default_fixture_loop_scope = "function"` in root pyproject.toml |

## 3. Scope

### In scope

- `ChainStoreProtocol` abstract base with 32 async methods
- `AsyncChainStore` (SQLite, via aiosqlite) implementing the protocol
- `PostgresChainStore` implementing the protocol against web chain tables
- Shared `_common.py` with `StoreNotInitialized`, `ScopingViolation`, `require_initialized` decorator, `require_user_scope` decorator, `pad_in_clause` helper, `_web_finding_to_cli` converter
- Async conversion of `ExtractionPipeline`, `LinkerEngine`, `llm_link_pass`, `ChainQueryEngine`, `GraphCache`, `entity_ops`, `exporter`, `batch`, `subscriptions`
- Closing the seven `store._conn.execute(...)` leaks
- CLI command surface converted to `async def` with `asyncio.run` at entry
- ~60 CLI test files converted to `async def` + `await`
- Migration v4 on SQLite: add `status_text` to `linker_run` (with backfill), add `user_id` to `extraction_cache` and `llm_link_cache`, wrap all DDL in transactions
- Migration 004 on Postgres: convert `reasons_json` / `confirmed_at_reasons_json` / `rule_stats_json` to JSONB; add `user_id` column to chain cache tables; mark cache tables UNLOGGED
- Deletion of sync `llm_link_pass` variant
- Deletion of sync `ChainStore` class (phase 5)
- Deletion of `packages/cli/src/opentools/chain/store_extensions.py` (phase 5)
- Deletion of `chain_rebuild.py` custom worker (phase 5)
- Removal of `extract_for_finding` sync method (phase 2)
- Shared parameterized conformance test suite
- Concurrency test suite (5 race conditions, ~10 tests)
- End-to-end integration test against both backends
- Consolidation of cache key functions into `chain/_cache_keys.py`
- `ChainConfig` marked frozen to prevent mid-run mutation

### Out of scope

- Switching SQLite for something else
- Adding new linker rules or extractors
- Changing the chain data model beyond the schema additions above
- Adding web-specific features beyond the unified rebuild
- Fixing the squared IDF formula (deferred to separate follow-up)
- Converting `EngagementStore` to async (stays sync; separate connection to the same DB)
- Merging CLI and web test infrastructure
- Performance optimization of individual queries beyond the explicit optimizations listed in §10
- Observability / metrics / tracing

## 4. Protocol Surface

Every method is `async def`. Methods return domain objects from `opentools.chain.models`, never `sqlite3.Row` or SQLAlchemy ORM instances. No raw SQL escape hatch.

### 4.1 Error taxonomy

Two runtime errors consumers can observe:

| Error | When raised |
|---|---|
| `StoreNotInitialized` | Any method called before `initialize()` or after `close()` |
| `ScopingViolation` | `PostgresChainStore` method called with `user_id=None` (web refuses None for privacy) |

Everything else propagates as backend-specific exceptions (`aiosqlite.Error`, `sqlalchemy.exc.SQLAlchemyError`) that consumers treat as fatal.

### 4.2 User scoping

Every method that touches per-user data takes `user_id: UUID | None` as a **required** keyword argument (no default). `None` means "CLI context, unscoped." `AsyncChainStore` accepts `None` freely. `PostgresChainStore` rejects `None` with `ScopingViolation`.

Cache methods (`get_extraction_cache`, `put_extraction_cache`, `get_llm_link_cache`, `put_llm_link_cache`) ARE user-scoped. Cache keys include `user_id` in the hash. Tables get a `user_id` column. This prevents a side-channel leak where user B learns that another user previously classified identical text.

### 4.3 Methods

```python
class ChainStoreProtocol(Protocol):
    # Lifecycle
    async def initialize(self) -> None: ...
    async def close(self) -> None: ...
    async def transaction(self) -> AsyncContextManager[None]: ...
    async def batch_transaction(self) -> AsyncContextManager[None]: ...

    # Entity CRUD
    async def upsert_entity(self, entity: Entity, *, user_id: UUID | None) -> None: ...
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

    # Mention CRUD
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

    # Relation CRUD
    async def upsert_relations_bulk(
        self, relations: Iterable[FindingRelation], *, user_id: UUID | None
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
    async def stream_relations_in_scope(
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

    # Linker-specific queries
    async def fetch_candidate_partners(
        self,
        *,
        finding_id: str,
        entity_ids: set[str],
        user_id: UUID | None,
        common_entity_threshold: int,
    ) -> dict[str, set[str]]: ...
    async def fetch_findings_by_ids(
        self, finding_ids: Iterable[str], *, user_id: UUID | None
    ) -> list[Finding]: ...
    async def count_findings_in_scope(
        self,
        *,
        user_id: UUID | None,
        engagement_id: str | None = None,
    ) -> int: ...
    async def compute_avg_idf(
        self, *, scope_total: int, user_id: UUID | None
    ) -> float: ...
    async def entities_for_finding(
        self, finding_id: str, *, user_id: UUID | None
    ) -> list[Entity]: ...

    # LinkerRun lifecycle
    async def start_linker_run(
        self,
        *,
        scope: LinkerScope,
        scope_id: str | None,
        mode: LinkerMode,
        user_id: UUID | None,
    ) -> LinkerRun: ...
    async def set_run_status(
        self, run_id: str, status: str, *, user_id: UUID | None
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

    # Extraction state + parser output
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

    # LLM caches (user-scoped)
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

    # Export / import
    async def fetch_findings_for_engagement(
        self, engagement_id: str, *, user_id: UUID | None
    ) -> list[str]: ...
    async def export_dump_stream(
        self,
        *,
        finding_ids: Iterable[str],
        user_id: UUID | None,
    ) -> AsyncIterator[dict]: ...
```

**32 methods total.** Every existing `store._conn.execute(...)` leak maps to a named method:

| Current leak location | New protocol method |
|---|---|
| `pipeline.py::_update_extraction_state` | `upsert_extraction_state` |
| `linker/engine.py::_persist_run` | `start_linker_run` + `finish_linker_run` |
| `linker/engine.py::_load_finding` | `fetch_findings_by_ids` |
| `linker/llm_pass.py` status update | `apply_link_classification` |
| `entity_ops.py::merge_entities` | `rewrite_mentions_entity_id` + `delete_entity` |
| `entity_ops.py::split_entity` | `rewrite_mentions_by_ids` + `upsert_entity` |
| `exporter.py::export_chain` | `export_dump_stream` |

## 5. Backend Implementations

### 5.1 File layout

```
packages/cli/src/opentools/chain/
├── store_protocol.py           # ChainStoreProtocol + error types
├── stores/
│   ├── __init__.py
│   ├── _common.py              # decorators, helpers, _web_finding_to_cli
│   ├── sqlite_async.py         # AsyncChainStore (aiosqlite)
│   └── postgres_async.py       # PostgresChainStore (SQLAlchemy)
├── _cache_keys.py              # NEW: consolidated cache key functions
└── store_extensions.py         # DELETED in Phase 5

packages/web/backend/app/services/
├── chain_service.py            # REWRITTEN: thin wrapper over shared pipeline
├── chain_store_factory.py      # NEW: constructs PostgresChainStore from session
└── chain_rebuild.py            # DELETED in Phase 5
```

### 5.2 `stores/_common.py`

Shared primitives: `StoreNotInitialized`, `ScopingViolation`, `require_initialized` decorator, `require_user_scope` decorator, `pad_in_clause` helper (pads IN-clause values to next power of 2 to hit prepared-statement cache), `_web_finding_to_cli` converter (1:1 field copy from web SQLModel Finding to CLI Pydantic Finding, dropping web-only `user_id`).

### 5.3 `AsyncChainStore` (aiosqlite)

- Construction: accepts either `db_path` (owns connection) or `aiosqlite.Connection` (borrows)
- `initialize()`: opens connection if owning, applies performance pragmas (WAL, NORMAL sync, 64MB cache, 256MB mmap, temp memory, FK on), runs async migrations via `migrate_async()`
- `close()`: passive WAL checkpoint, closes owned connection
- `transaction()`: SQLite `SAVEPOINT` + `RELEASE` / `ROLLBACK TO` via unique savepoint name per call
- `batch_transaction()`: identical to `transaction()` on SQLite; distinction is semantic (tells reader the call site expects multi-operation atomicity)
- User scoping: accepts `user_id=None` freely; does not filter (CLI is single-user)

### 5.4 `PostgresChainStore` (SQLAlchemy async)

- Construction: accepts either an `AsyncSession` (request-scoped) or a `session_factory` (background task-scoped, opens fresh session in `initialize()`)
- `initialize()`: marks store ready; opens session from factory if factory-constructed; starts top-level transaction if none active
- `close()`: closes owned session from factory path; does NOT close borrowed request-scoped session
- `transaction()`: SQLAlchemy `session.begin_nested()` (Postgres savepoint)
- `batch_transaction()`: SAME as `transaction()`; distinction is semantic
- User scoping: `@require_user_scope` decorator raises `ScopingViolation` if `user_id=None`

### 5.5 Transaction semantics

Both backends follow the same rule: **each public method commits its own writes at the end unless inside an explicit `transaction()` or `batch_transaction()` scope.** A module-local counter on each store tracks whether we're inside an explicit transaction; methods check the counter and either `commit()` or `flush()` accordingly. This matches the sync `ChainStore` behavior exactly and preserves crash resilience for long-running rebuilds.

Consumers wrap their work in explicit transactions in five places:
1. `ExtractionPipeline._persist` (delete + insert + recompute + update state)
2. `LinkerEngine.link_finding` (relation upserts + run record)
3. `llm_link_pass` (per-edge classification + status update)
4. `entity_ops.merge_entities` / `split_entity` (`batch_transaction` — full operation atomic)
5. `exporter.import_chain` (`batch_transaction` — full import atomic)

### 5.6 Schema changes

**Migration v4 (SQLite, Phase 1):**
```sql
BEGIN;
-- status_text on linker_run + backfill
ALTER TABLE linker_run ADD COLUMN status_text TEXT;
UPDATE linker_run SET status_text = CASE
    WHEN error IS NOT NULL THEN 'failed'
    WHEN finished_at IS NOT NULL THEN 'done'
    ELSE 'unknown'
END WHERE status_text IS NULL;

-- user_id on cache tables
ALTER TABLE extraction_cache ADD COLUMN user_id TEXT;
ALTER TABLE llm_link_cache ADD COLUMN user_id TEXT;

INSERT INTO schema_version (version, applied_at) VALUES (4, ?);
COMMIT;
```

**Migration 004 (Postgres, Phase 5):**
- Convert `reasons_json` / `confirmed_at_reasons_json` / `rule_stats_json` columns from `Text` to `JSONB` via `USING column::jsonb`
- Add `user_id UUID NULL` to `chain_extraction_cache` and `chain_llm_link_cache`
- Mark `chain_extraction_cache` and `chain_llm_link_cache` as `UNLOGGED` (2-3x write speedup; derivative data)

### 5.7 Connection model for CLI

`EngagementStore` (sync sqlite3) and `AsyncChainStore` (aiosqlite) hold **separate connections to the same DB file**. WAL mode lets both coexist. Chain operations NEVER join engagement transactions — events fire after the engagement store commits. `AsyncChainStore` sets `busy_timeout=5000` to wait through any lock contention from the engagement writer.

### 5.8 Generation atomicity

`start_linker_run` uses atomic SQL to increment the per-user generation counter, avoiding the read-max-plus-one race:

```sql
INSERT INTO linker_run (id, ..., generation) VALUES (
    ?, ..., (SELECT COALESCE(MAX(generation), 0) + 1 FROM linker_run WHERE user_id = ?)
)
```

Two concurrent inserts serialize at the SQL level. Same shape works on both backends.

## 6. Phased Migration Plan

Every phase leaves the repository in a working state with green tests. Phases land as separate commits on one feature branch. `scripts/check_test_count.sh` enforces `passed >= min, failed == 0` at each phase boundary via CI.

### Phase 1 — Foundation (~3 days)

**Goal:** land the protocol, `AsyncChainStore`, migration v4, sync shim. Zero existing consumer code changes. Zero existing test changes.

**Files created:**
- `store_protocol.py` (~200 lines)
- `stores/_common.py` (~150 lines including converters and decorators)
- `stores/sqlite_async.py` (`AsyncChainStore`, ~600 lines)
- `chain/_cache_keys.py` (~60 lines, consolidates existing cache key functions)
- `tests/chain/test_async_chain_store.py` (~30 unit tests)
- `tests/chain/test_store_protocol_conformance.py` (SQLite-only initially, ~40 tests)
- `tests/chain/test_migration_v4.py` (~4 tests covering forward, backfill, and rollback)

**Files modified:**
- `engagement/schema.py`: extract `MIGRATION_STATEMENTS` constant; add migration v4; add `migrate_async()` sibling; wrap all DDL in transactions (A3 fix)
- `chain/store_extensions.py`: rename internal class `ChainStore` → `SyncChainStore`; `ChainStore = SyncChainStore` alias for backwards compat
- `chain/config.py`: `ChainConfig` marked `frozen=True`
- `pyproject.toml` (root): add `asyncio_default_fixture_loop_scope = "function"`
- `packages/cli/pyproject.toml`: add `aiosqlite>=0.21`, `pytest-xdist>=3` as dev dep

**Phase 1 gate:** `pytest packages/ -q` shows `>= 530 passed, failed == 0`.

### Phase 2 — ExtractionPipeline + drain worker (~2 days)

**Goal:** ExtractionPipeline becomes async-native. Drain worker handles `finding.created` events. ~15-20 CLI tests convert to explicit extraction calls.

**Files modified:**
- `extractors/pipeline.py`: retire sync `extract_for_finding`, keep only async. Close `_update_extraction_state` leak. Wrap `_persist` in `transaction()`. Use `recompute_mention_counts` single-statement update (G5 fix).
- `linker/llm_pass.py`: delete sync `llm_link_pass`, rename `llm_link_pass_async` to `llm_link_pass`
- `chain/subscriptions.py`: add drain worker infrastructure (`start_drain_worker(store, pipeline, engine) -> DrainWorker` returning a handle; sync `on_finding_created` uses `call_soon_threadsafe` to queue finding_id; worker coroutine drains queue, extracts + links per finding)
- `chain/cli.py`: extraction-triggering commands become `async def` via Typer's native async support
- `tests/chain/conftest.py`: `engagement_store_and_chain` fixture yields `AsyncChainStore` wrapping the shared DB file via separate connection
- `tests/chain/test_pipeline.py`, `test_pipeline_integration.py`, `test_llm_pass.py`: convert to `async def` + `await`
- Tests that previously relied on implicit inline processing gain explicit `await pipeline.extract_for_finding(...)` calls

**Phase 2 gate:** `pytest packages/ -q` shows `>= 535 passed, failed == 0`.

### Phase 3 — LinkerEngine, entity_ops, exporter, batch (~2 days)

**Goal:** convert the linker and surrounding consumers. Close remaining `_conn` leaks. Implement staged parallel extraction in batch context.

**Files modified:**
- `linker/engine.py`: all methods `async def`. Replace `_load_finding` with `fetch_findings_by_ids`. Replace per-partner load loop with single batch call (G6). Replace `_persist_run` raw INSERT with `start_linker_run` + `finish_linker_run`. Pass `common_entity_threshold` to `fetch_candidate_partners` (G9). Replace `fetch_entities_with_mentions` + local IDF loop with `compute_avg_idf` (G10).
- `linker/batch.py`: `ChainBatchContext` becomes async. Staged parallel extraction: stage 1 fetches all findings in one query; stage 2 runs regex extractors in parallel via `asyncio.gather`; stage 3 bulk-inserts entities and mentions. Uses `transaction()` per-finding, NOT `batch_transaction()` wrapping the whole batch (G8).
- `chain/entity_ops.py`: `merge_entities` and `split_entity` become `async def`. All raw SQL replaced with protocol methods. Wrapped in `batch_transaction()`.
- `chain/exporter.py`: convert to async. Uses `export_dump_stream` for bounded memory. Wraps `import_chain` in `batch_transaction()`.
- `chain/cli.py`: all remaining commands become `async def`. CLI lifecycle: open stores → optional drain worker → do work → await `queue.join()` → close stores.
- Tests for linker engine, entity ops, exporter, batch, subscriptions, CLI commands: convert to `async def` + `await`

**Phase 3 gate:** `pytest packages/ -q` shows `>= 540 passed, failed == 0`.

### Phase 4 — Query engine + graph cache (~1-2 days)

**Goal:** convert the read path. Close query engine raw SQL leaks. Add graph cache concurrent build lock.

**Files modified:**
- `query/graph_cache.py`: `get_master_graph` becomes `async def`. `_build_master_graph` uses `stream_relations_in_scope` for bounded memory. Per-key `asyncio.Lock` prevents duplicate builds under concurrent access (G4). Generation recheck on cache read dropped (A2 resolution — accept per-process staleness, document, rebuild per-request on web).
- `query/engine.py`: `ChainQueryEngine.k_shortest_paths` becomes `async def`. Endpoint resolution and Yen's stay sync (pure in-memory).
- `query/bounded.py`, `neighborhood.py`, `subgraph.py`: unchanged (operate on already-built rustworkx graph)
- `query/presets.py`: all 5 presets become `async def`
- `query/narration.py`: store calls use protocol methods
- Tests for graph cache, query engine, endpoints, neighborhood, presets, narration, adapters: convert to `async def` + `await`. Add C2 concurrent build test.

**Phase 4 gate:** `pytest packages/ -q` shows `>= 545 passed, failed == 0`.

### Phase 5 — Postgres backend + unification + cleanup (~2 days)

**Goal:** land `PostgresChainStore`, rewrite web rebuild, delete duplicated code.

**Files created:**
- `stores/postgres_async.py` (`PostgresChainStore`, ~700 lines)
- `packages/web/backend/alembic/versions/004_chain_jsonb_unlogged_userids.py` (JSONB conversion + `user_id` on cache tables + UNLOGGED)
- `packages/web/backend/app/services/chain_store_factory.py` (~50 lines)
- `packages/cli/tests/chain/test_postgres_chain_store.py` (~30 tests against aiosqlite-backed SQLAlchemy)

**Files modified:**
- `tests/chain/test_store_protocol_conformance.py`: enables Postgres parameter (runs against aiosqlite-backed SQLAlchemy engine by default; real Postgres gated on `WEB_TEST_DB_URL`)
- `tests/chain/test_pipeline_integration.py`: becomes parameterized over both backends
- `packages/web/backend/app/services/chain_service.py`: rewrite to delegate all chain operations to the shared pipeline via `PostgresChainStore`. `k_shortest_paths_stub` deleted; `create_linker_run_stub` stays for the rebuild endpoint.
- `packages/web/backend/app/routes/chain.py`: `rebuild` endpoint launches background task via `ChainTaskRegistry`; `path` endpoint uses real `ChainQueryEngine`
- `packages/web/backend/tests/test_chain_rebuild.py` → renamed `test_web_rebuild.py` (A12); tests updated to assert shared-pipeline behavior with all 6 linker rules

**Files deleted:**
- `packages/web/backend/app/services/chain_rebuild.py` (−413 lines)
- `packages/cli/src/opentools/chain/store_extensions.py` (−233 lines, including `SyncChainStore` class)

**Phase 5 gate:** `pytest packages/ -q` shows `>= 575 passed, failed == 0`.

### Total refactor impact

| Phase | LOC added | LOC removed | Net |
|---|---|---|---|
| 1 | +1200 | -30 | +1170 |
| 2 | +350 | -250 | +100 |
| 3 | +800 | -600 | +200 |
| 4 | +400 | -300 | +100 |
| 5 | +1100 | -700 | +400 |
| **Total** | **+3850** | **-1880** | **+1970** |

~2000 net new lines. Extraction, linking, LLM, query engine, and rule logic now live in one place and are tested once. The web gets full feature parity with zero additional implementation work.

**Total duration: 8-10 focused working days.**

### Rollback strategy

Every phase has a clean revert via `git revert <phase-commit>`. Phases don't depend on later phases for correctness, so reverting one doesn't cascade:

- **After phase 1:** branch mergeable. `AsyncChainStore` exists unused. Sync `ChainStore` authoritative.
- **After phase 2:** branch mergeable. Extraction async; linking/query sync (hybrid but functional).
- **After phase 3:** branch mergeable. Query still sync. Awkward but functional.
- **After phase 4:** branch mergeable. CLI fully async; web still has custom worker (same state as main today).
- **After phase 5:** done.

**The highest-risk pause point is between phases 4 and 5.** If phases 1-4 land but phase 5 stalls, the refactor hasn't achieved its stated goal (unify CLI and web). Budget for phase 5 before starting phase 1.

## 7. Testing Strategy

### 7.1 Regression baseline protection

**500 pre-refactor tests stay green across every phase.** `scripts/check_test_count.sh` runs in CI with `passed >= expected_min` + `failed == 0` semantics (not exact match). Phase commits bump the expected minimum; additional tests added mid-phase don't require bumping.

Pre-existing test guards enforce EXACT count for non-chain paths (not `>=`):
- `pytest packages/cli/tests/ --ignore=packages/cli/tests/chain` must collect exactly 177 tests
- `pytest packages/web/backend/tests/ --ignore=packages/web/backend/tests/test_chain_*` must collect exactly 21 tests

Any change to pre-existing test counts is a scope leak and fails CI.

### 7.2 Backend equivalence via shared conformance tests

`test_store_protocol_conformance.py` parameterizes over both backends. The Postgres parameter runs against the web backend's existing aiosqlite-backed SQLAlchemy engine, which is ALWAYS present in CI. A separate gate on `WEB_TEST_DB_URL` enables real Postgres testing when available.

```python
@pytest.fixture(params=["sqlite_async", "postgres_async"])
async def conformant_store(request, tmp_path):
    if request.param == "sqlite_async":
        store = AsyncChainStore(db_path=tmp_path / "chain.db")
        await store.initialize()
        yield store, None
        await store.close()
    else:
        # Uses aiosqlite-backed SQLAlchemy (same engine web tests use)
        # Real Postgres path gated on WEB_TEST_DB_URL env var
        ...
```

Coverage target: every protocol method gets at least one conformance test. 32 methods × ~1.5 tests each × 2 backends = ~90 test executions.

Critical tests:
- `test_transaction_rollback_on_exception`
- `test_transaction_read_your_writes` (A10)
- `test_nested_transactions_work`
- `test_require_initialized_raises`
- `test_scoping_violation_only_on_postgres`
- `test_fetch_candidate_partners_filters_common_entities` (G9)
- `test_in_clause_padding_correctness` (O6)

### 7.3 Concurrency tests (new async surface)

5 race conditions, ~10 tests:

- **C1 drain worker:** processes queued findings in order; survives extraction failure; handles queue full
- **C2 graph cache:** concurrent build uses single build via lock (G4)
- **C3 generation atomicity:** concurrent `start_linker_run` produces unique generations
- **C4 transaction rollback:** async exception rolls back transaction; batch merge failure rolls back all mentions
- **C5 nested savepoints:** work under aiosqlite default isolation (A4 verification); inner rollback preserves outer

### 7.4 Integration test on both backends

The canonical `test_pipeline_integration.py` from Phase 3C.1 becomes the load-bearing integration test. Phase 2 converts it to async and runs against `AsyncChainStore`. Phase 5 parameterizes it over both backends. Same fixtures, same assertions, same results.

Assertions are tolerance-based (`weight >= 0.3`, `len(entities) >= N`) to accommodate minor IDF drift between backends.

### 7.5 Migration tests

- `test_migration_v4_adds_status_text_column`: verifies forward migration
- `test_migration_v4_backfills_legacy_rows`: verifies `status_text` derived from `finished_at`/`error`
- `test_migration_v4_rolls_back_on_backfill_failure`: verifies transaction atomicity (G34)
- `test_migrate_async_produces_same_schema`: verifies sync and async migration paths produce identical schemas

### 7.6 Test execution pragmatics

**Local dev:** `pytest packages/ -q` runs ~575 tests in ~60 seconds after phase 5. Optional speedup via `pytest -n auto` (pytest-xdist).

**CI:** three parallel jobs:
1. SQLite-only: `pytest packages/ -q` (no `WEB_TEST_DB_URL`)
2. Postgres-enabled: `pytest packages/ -q` with `WEB_TEST_DB_URL` pointing at a test Postgres container (if available)
3. Pre-existing regression: explicit `--ignore` guards

### 7.7 Explicit test non-goals

- Cross-process concurrency (two CLI processes on same DB)
- Postgres-specific feature testing (tsvector, GIN, UNLOGGED recovery)
- Load / performance benchmarks
- Connection pool exhaustion
- Mutation testing, property-based fuzzing
- Test matrix across aiosqlite versions (pin minimum, trust library)

## 8. What Stays Unchanged

### 8.1 Domain models (zero changes)

`Entity`, `EntityMention`, `FindingRelation`, `RelationReason`, `LinkerRun`, `ExtractionCache`, `LLMLinkCache`, `FindingExtractionState`, `FindingParserOutput`, `LLMExtractedEntity`, `LLMExtractionResponse`, `LLMLinkClassification`, `entity_id_for()`.

### 8.2 Pure-function modules (zero changes)

- `opentools.chain.types` (entity type registry, enums)
- `opentools.chain.normalizers` (per-type canonical forms)
- `opentools.chain.stopwords` (static stopword lookup)
- `opentools.chain.mitre_catalog` (technique ID validation)
- `opentools.chain.extractors.base` (protocols)
- `opentools.chain.extractors.preprocess` (text region splitter)
- `opentools.chain.extractors.ioc_finder` (ioc-finder wrapper)
- `opentools.chain.extractors.security_regex` (7 regex extractors)
- `opentools.chain.extractors.parser_aware` (5 parser extractors)
- `opentools.chain.extractors.llm.prompts` (prompt templates)
- `opentools.chain.extractors.llm._util` (chain formatters)
- `opentools.chain.linker.rules.*` (all 6 built-in rules — depend on fully-resolved `LinkerContext`)
- `opentools.chain.linker.idf` (IDF math — including the squared tech debt from Task 18, preserved intentionally)
- `opentools.chain.query.cost` (log-probability edge cost)
- `opentools.chain.query.yen` (Yen's K-shortest paths)
- `opentools.chain.query.endpoints` (endpoint parsing)
- `opentools.chain.query.adapters` (graph-json format converters)

### 8.3 Plugin API (zero changes)

`register_entity_type()`, `register_security_extractor()`, `register_parser_extractor()`, `register_query_preset()`, `list_presets()`. Existing plugins continue to work unchanged.

### 8.4 LLM provider implementations (zero changes)

`OllamaProvider`, `AnthropicAPIProvider`, `OpenAIAPIProvider`, `ClaudeCodeProvider`, `PydanticRetryWrapper`, `get_limiter()`. They were already async-first in 3C.1.

### 8.5 Other preserved surfaces

- Web frontend (HTTP contract preserved)
- `StoreEventBus` synchronous emit/subscribe API
- `EngagementStore` stays on `sqlite3.Connection`
- Existing chain table schemas beyond migration v4 and migration 004 additions
- All existing indexes, unique constraints, and foreign keys

## 9. Forward Compatibility Hooks

The refactor creates but does NOT fill these extension points:

- **H1 — New storage backend.** Implement `ChainStoreProtocol` against any DB (Neo4j, DuckDB, Cassandra). Self-contained task; no pipeline/linker changes.
- **H2 — Bayesian weight calibration (3C.3).** `FindingRelation.weight_model_version` already exists. Future `calibrate_weights` method recomputes from user-confirmed edges, writes back with `weight_model_version="bayesian_v1"`. Both versions coexist.
- **H3 — Cypher-style DSL (3C.4).** Add `query_pattern(ast: CypherAST)` to protocol. Pure-Python parser and executor plug in without touching pipeline or linker.
- **H4 — Streaming path narration.** Future `narrate_path_stream()` returns `AsyncIterator[str]`. Non-breaking addition.
- **H5 — Parallel backend fan-out.** Protocol supports multiple store instances sharded by engagement_id; no architectural changes needed to enable.
- **H6 — Path result cache across FastAPI requests.** DISTINCT from the master graph cache. In-process LRU on `(user_id, query_hash, generation)` invalidated via pub/sub from `finish_linker_run`. Additive, no protocol changes.
- **H7 — Multi-tenant drain worker rate limiting.** `start_drain_worker` grows a `rate_limiter` parameter. Additive.
- **H8 — Schema version queries.** Add `get_schema_version() -> int` when verification becomes useful.

## 10. Optimizations (tracked per phase)

| ID | Optimization | Phase |
|---|---|---|
| O3 | SQLite performance pragmas (WAL, NORMAL sync, 64MB cache, 256MB mmap, temp memory) | 1 |
| O6 | `pad_in_clause` rounds IN-clause parameter count to next power of 2 | 1 |
| O7 | Passive WAL checkpoint before `close()` | 1 |
| O13 | Batch IN-clause in groups of 500 if entity_ids exceeds that | 1 |
| O19 | Staged parallel batch extraction (fetch → CPU-parallel extract → bulk SQL) | 3 |
| O21 | `upsert_entities_bulk` single-statement protocol method | 1 (added to protocol), 2 (consumers adopt) |
| O28 | `ChainConfig` frozen prevents mid-run mutation | 1 |
| O29 | Drain worker prefetches up to 50ms or 100 IDs at a time | 3 |
| O30 | `migrate_async()` uses `executescript()` for atomic DDL | 1 |
| O8 | asyncpg `prepared_statement_cache_size=100` | 4 |
| O9 | JSONB column migration on Postgres | 5 |
| O15 | Native JSONB serialization bypasses orjson encode on writes | 5 |
| O17 | UNLOGGED cache tables on Postgres | 5 |
| O23 | pytest-xdist for local dev (optional) | 1 |

## 11. Risk Summary

| Risk | Mitigation |
|---|---|
| Phases 1-4 land but phase 5 stalls | No regression — web still uses old worker, CLI benefits from async. Budget phase 5 before starting. |
| aiosqlite version-specific bugs | Pin minimum version, conformance tests run per commit |
| SQLAlchemy `begin_nested` vs aiosqlite `SAVEPOINT` divergence | C5 conformance tests cover nested transaction behavior on both |
| Drain worker loses findings during shutdown | `await queue.join()` in CLI shutdown path before close |
| IDF formula tech debt persists | Documented explicitly; separate follow-up fix |
| Mid-refactor reviewer fatigue | Phases scoped to 200-500 LOC behavior change each; mechanical test conversion in isolated commits |
| Conformance tests miss Postgres-dialect bugs | Real-Postgres gate via `WEB_TEST_DB_URL`; acceptable gap for MVP |
| Migration v4 rollback on SQLite DDL | Explicit test (G34); verifies SQLite DDL-in-transaction behavior |

## 12. Known Limitations

- **Cross-process cache staleness:** CLI graph cache is process-local. Two CLI processes on the same DB can see different cached graphs. Acceptable for single-process CLI use.
- **Web per-request graph rebuild:** Web backend rebuilds the master graph per request. Scale concern at high web load; future H6 path result cache mitigates.
- **Multi-worker rate limiting:** `aiolimiter` is process-local. Multi-worker uvicorn deployments get N× the nominal rate.
- **Conformance tests against aiosqlite-backed SQLAlchemy miss Postgres dialect bugs:** Real-Postgres gate via `WEB_TEST_DB_URL` mitigates when available.
- **IDF squared formula:** preserved as tech debt. Fix is a separate follow-up.

## 13. Estimated Line Count

| Area | Estimate |
|---|---|
| Protocol definition + error types | 250 |
| `_common.py` (decorators, helpers, converter) | 150 |
| `AsyncChainStore` (aiosqlite) | 700 |
| `PostgresChainStore` (SQLAlchemy) | 700 |
| `chain/_cache_keys.py` consolidation | 100 |
| ExtractionPipeline async conversion | 150 changed |
| LinkerEngine async conversion + leak closes | 200 changed |
| Query engine + graph cache async | 150 changed |
| entity_ops + exporter + batch + subscriptions | 300 changed |
| CLI command async conversion | 100 changed |
| Web service rewrite | 150 changed |
| Alembic migration 004 | 100 |
| SQLite migration v4 | 50 |
| Test conversions (mechanical) | 400 changed |
| New conformance tests | 400 |
| New concurrency tests | 200 |
| New migration tests | 150 |
| `scripts/check_test_count.sh` + CI glue | 50 |
| **Total new + changed** | **~4300** |
| **Deleted** | **-2100** |
| **Net** | **+2200** |

Slightly higher than the initial Section 4 estimate because of the additional testing infrastructure.

## 14. Scope Boundary Checklist

### In scope

- `ChainStoreProtocol` with 32 async methods
- `AsyncChainStore` + `PostgresChainStore` + shared `_common.py`
- Async conversion of all chain consumers (pipeline, linker, LLM pass, query engine, graph cache, entity ops, exporter, batch, subscriptions, narration)
- CLI command async conversion
- Migration v4 (SQLite) + Migration 004 (Postgres)
- Deletion of sync `ChainStore`, `llm_link_pass` sync, `chain_rebuild.py`
- Shared conformance test suite
- Concurrency test suite
- Canonical integration test on both backends
- Frozen `ChainConfig`
- Test count baseline CI gate
- Loop-scope isolation pytest config

### Out of scope

- Switching SQLite backend
- Adding new linker rules or extractors
- Changing chain data model beyond schema additions
- IDF formula fix (separate follow-up)
- `EngagementStore` async conversion
- Web-specific features beyond unified rebuild
- Merging CLI and web test infrastructure
- Performance optimization beyond listed items
- Observability / metrics / tracing
- Path result cache across FastAPI requests (H6 hook)
- Real Postgres CI gate (optional via `WEB_TEST_DB_URL`)
