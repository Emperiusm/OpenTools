# Phase 3C.1.5 — Session 3 handoff notes (Phase 3 complete)

**Session date:** 2026-04-11 (continued from session 2)
**Branch:** `feature/phase3c1-5-phase2`
**Worktree:** `c:/Users/slabl/Documents/GitHub/OpenTools/.worktrees/phase3c1-5-phase2`
**HEAD at end of session:** `8a66666`
**Test baseline at HEAD:** 614 passed, 1 skipped

## What this session accomplished

Phase 3 is now **complete**. Every consumer downstream of the pipeline/linker chain (entity_ops, exporter, CLI status/entities/export) now uses `ChainStoreProtocol`. The sync classes still exist for Phase 4 downstream code (GraphCache, ChainQueryEngine, presets, narration, neighborhood, and the `path` + `query` CLI commands) and for `test_cli_commands.py`'s sync test seeding which uses the old sync fixture.

### Session 3 commits

| Task | Commit | Summary |
|---|---|---|
| fixes | `f7134e1` | Phase 2 gotcha fixes: `@_async_command` decorator (Typer 0.24 doesn't support `async def`); `DrainWorker.wait_idle()` replacing the `sleep(0.01)` hack; `EngagementStore.list_findings()` helper |
| 23 | `609bfd7` | `merge_entities` / `split_entity` converted to async via `ChainStoreProtocol`. test_entity_ops.py (6 tests) converted to async. `MergeResult.affected_findings` now returns `[]` (latent regression; no current consumer reads it — documented in commit message) |
| 24 | `ef127a1` | `export_chain` / `import_chain` converted to async. Exporter streams via `store.export_dump_stream` (bounded memory). Import wraps bulk upserts in `batch_transaction`. CLI `export` command converted to async via `@_async_command`. Added `fetch_all_finding_ids` protocol method (and bumped `test_store_protocol_shape` expected method count 41 → 42). test_exporter.py (5 tests) converted. `test_cli_export_runs` stayed sync — see the critical pattern note below. |
| 25 | `8a66666` | CLI `status` and `entities` commands converted to async via `@_async_command`. Use `list_entities` + `fetch_relations_in_scope` + `fetch_linker_runs` protocol methods. Tests in `test_cli_commands.py` NOT modified — the existing sync tests pass unchanged against the new async commands. |

### Phase 3 completion: what's async now

Production code using `AsyncChainStore` / `ChainStoreProtocol`:

- `extractors/pipeline.py::AsyncExtractionPipeline` (parallel to sync)
- `linker/engine.py::AsyncLinkerEngine` (parallel to sync)
- `linker/batch.py::AsyncChainBatchContext` (parallel to sync)
- `linker/llm_pass.py::llm_link_pass_async` (uses protocol, sync `llm_link_pass` still in place)
- `subscriptions.py::DrainWorker` + `start_drain_worker` (drain worker; sync `subscribe_chain_handlers` still in place)
- `entity_ops.py::merge_entities` / `split_entity` (**async-only**, sync removed in-place)
- `exporter.py::export_chain` / `import_chain` (**async-only**, sync removed in-place)
- `cli.py` commands: `rebuild`, `export`, `status`, `entities` (async via `@_async_command` decorator)

Sync code still in place:

- `extractors/pipeline.py::ExtractionPipeline` — sync class intact
- `linker/engine.py::LinkerEngine` — sync class intact
- `linker/batch.py::ChainBatchContext` — sync class intact
- `linker/llm_pass.py::llm_link_pass` — sync function intact
- `subscriptions.py::subscribe_chain_handlers` — sync factory path intact
- `query/graph_cache.py::GraphCache` — sync (Task 26)
- `query/engine.py::ChainQueryEngine` — sync (Task 27)
- `query/presets.py` — sync (Task 28)
- `query/narration.py` — sync (Task 28)
- `query/neighborhood.py` — sync (Task 27)
- `cli.py` commands: `path`, `query` — sync (Task 29)
- Sync `test_cli_commands.py` test seeding — uses sync `ExtractionPipeline` + sync `LinkerEngine` to seed data. This will flip to async in Task 29.
- Sync `engagement_store_and_chain` fixture — keeps serving sync test files.
- `store_extensions.py` — sync `ChainStore` / `SyncChainStore` alias (deleted in Task 30).

## Critical patterns documented this session

### Pattern 1: CLI commands + `@_async_command` + CliRunner tests stay sync

Task 22f first documented that Typer 0.24.1 silently ignores `async def` commands (coroutine is created but never awaited). Task 24 and 25 confirmed the downstream implication: **tests that invoke async CLI commands via `CliRunner.invoke()` must themselves stay synchronous** (NOT `@pytest.mark.asyncio` decorated). Reason:

- `@_async_command` wraps the async body in `asyncio.run(coro_fn(*args, **kwargs))`
- `asyncio.run()` raises `RuntimeError: asyncio.run() cannot be called from a running event loop` if an outer loop is active
- pytest-asyncio's per-test loop IS an outer loop when the test is decorated `@pytest.mark.asyncio`
- `CliRunner.invoke()` is synchronous — it's safe to call from a sync test function, which has no outer loop

**Cross-connection data sharing:** The sync test fixture seeds data via a sync `sqlite3.Connection` to `tmp_path / "<name>.db"` but the CLI command uses `_default_db_path()` which points to `Path.home() / ".opentools" / "engagements.db"` — these wouldn't share DB state by default. The existing test_cli_commands.py tests already monkeypatch `_default_db_path` (or set `OPENTOOLS_DB_PATH` env var) so both the sync fixture and the async CLI command hit the same file. WAL mode lets the sync writer and the async reader observe each other's commits. This is why Task 25 required zero test changes.

For Task 29 (converting `path` + `query` CLI commands), the same pattern applies — leave `test_cli_path_runs`, `test_cli_query_mitre_coverage_runs`, `test_cli_query_unknown_preset_fails` sync.

### Pattern 2: `fetch_all_finding_ids` protocol addition

Task 24 needed to enumerate findings for the "all engagements" export path. No existing protocol method covered it (`fetch_findings_for_engagement` requires a specific id). Added `fetch_all_finding_ids(*, user_id) -> list[str]` to both `store_protocol.py` and `sqlite_async.py::AsyncChainStore`. The `test_store_protocol_shape.py` EXPECTED_METHODS counter moved 41 → 42.

Future protocol additions should follow the same pattern: add to protocol → add to AsyncChainStore → bump shape test counter.

### Pattern 3: `affected_findings` latent regression in merge_entities

Task 23 dropped `MergeResult.affected_findings` to `[]` because the only protocol method that exposes mentions-with-engagement (`fetch_mentions_with_engagement`) returns `(mention_id, engagement_id)` tuples — no finding_id. No current code reads `affected_findings`, so no test fails. The deferred CLI `merge` command (marked "not implemented in 3C.1 MVP" in cli.py) will need a protocol addition to re-populate this field when wired up. Flagging here so it's not forgotten.

## Gotchas / plan-vs-reality items discovered this session

1. **Parameter names drift from plan pseudocode:**
   - Task 23 expected `rewrite_mentions_entity_id(source_entity_id, target_entity_id, ...)` but the actual signature uses `from_entity_id` / `to_entity_id`.
   - Similarly `rewrite_mentions_by_ids` uses `mention_ids` / `to_entity_id`.
   - When future tasks hit a protocol method for the first time, verify the signature in `sqlite_async.py` before writing the call.

2. **`export_dump_stream` yields dicts, not Pydantic models.** Each yielded item is `{"kind": "entity"|"mention"|"relation", "data": dict}` where the `data` dict has raw SQLite column values (including bytes for JSON columns). The exporter needs a `_normalize_row` helper to decode bytes → parsed JSON for the output file.

3. **`fetch_relations_in_scope(statuses=None)` means "all statuses".** The implementation adds a `WHERE status IN (...)` clause only if `statuses` is truthy. Passing `None` / empty collection returns everything. Useful for the CLI `status` command's relation count.

4. **`list_entities` parameter is `entity_type` (not `type_` or `type`).** Confirmed in `sqlite_async.py:376`.

5. **`_default_db_path()` monkeypatching.** The test_cli_commands.py tests already monkeypatch `_default_db_path` to point at the fixture's temp DB. This is how sync fixture + async CLI command share state. Future tasks that add new CLI commands should verify the test monkeypatching continues to work — if a new command bypasses `_get_stores_async()` and opens the DB directly, the bridge breaks.

## Remaining work

### Phase 4 — Tasks 26, 27, 28, 29, 30

- **Task 26** (GraphCache async with per-key `asyncio.Lock`): ~100 lines of surgery in `query/graph_cache.py`. `test_graph_cache.py` 10 tests → 11 tests (+1 concurrent-build test). Expected count: 615.
- **Task 27** (ChainQueryEngine + neighborhood async): `query/engine.py` + `query/neighborhood.py`. Convert `test_query_engine.py` + `test_endpoints.py` + `test_neighborhood.py` to async. The endpoints/neighborhood tests only use the pipeline/engine for seeding, so they should convert cleanly via the `async_chain_stores` fixture + `AsyncExtractionPipeline` + `AsyncLinkerEngine`. Expected count: 615.
- **Task 28** (presets + narration async): `query/presets.py` + `query/narration.py`. Convert `test_presets.py` + `test_narration.py`. Fold deferred cleanup 3 (`narration.py` imports from `_cache_keys.py`). Expected count: 615.
- **Task 29** (CLI `path` + `query` commands async): Use `@_async_command`. Tests stay sync per Pattern 1 above. Expected count: 615.
- **Task 30** (Final sync deletion): Delete sync `ExtractionPipeline`, `LinkerEngine`, `ChainBatchContext`, `llm_link_pass`, `subscribe_chain_handlers`, `_load_finding` helper, `_get_stores` sync helper. Rename `Async*` → canonical names. Delete `store_extensions.py`. Delete sync `engagement_store_and_chain` fixture and rename `async_chain_stores` → `engagement_store_and_chain`. This is mechanical but touches ~15 files; high blast radius. Recommend an additional grep-verification pass after each deletion step. Expected count: 615.

### Phase 5 — Tasks 31–42

Unchanged from the original plan's Tasks 36–47. Postgres backend + Alembic migration 004 + web backend rewrite + final baseline. Approximately 75 additional tests from the Postgres conformance suite; expected final count ≥ 690.

## Model selection for remaining tasks

- Task 26 (GraphCache): **`standard`** — asyncio.Lock lifecycle + concurrent build semantics
- Task 27 (query engine + neighborhood + 3 test files): **`standard`**
- Task 28 (presets + narration): **`haiku`** sufficient — mechanical
- Task 29 (CLI path + query): **`standard`** — two commands, Typer integration
- Task 30 (final sync deletion): **manual or `standard` with extra review** — high blast radius. Consider dispatching with `verification-before-completion` guardrails or executing inline.

## Resumption checklist for next session

1. `cd c:/Users/slabl/Documents/GitHub/OpenTools/.worktrees/phase3c1-5-phase2`
2. `git pull --ff-only`
3. `git log --oneline -10` — verify HEAD is `8a66666` or later
4. `python -m pytest packages/ -q` — verify **614 passed, 1 skipped**
5. Read this handoff for patterns and gotchas (skip session 1 + session 2 handoffs unless specific history is needed)
6. Resume with Task 26 using the `subagent-driven-development` dispatch pattern established in sessions 1–3

## Statistics

- Tasks this session: gotcha fixes + 3 (Tasks 23, 24, 25)
- Commits this session: 4 (including fixes)
- Subagent dispatches: 3 (one per task)
- Phase 2 total commits: 7 + 2 docs = 9
- Phase 3 total commits: 3 + 1 fixes + 1 doc (this file) = 5
- Combined branch history since main: 14 commits
- Zero regressions; suite held at 614/1 through every commit
