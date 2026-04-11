# Phase 3C.1.5 — Phase 2+ Plan Revision Notes

Written after Phase 1 completion (commit `e67b20b`) on branch
`feature/phase3c1-5-async-refactor`.

## Phase 1 status — DONE

21 commits landed (a3f5194 → e67b20b). Full suite: **613 passed, 1 skipped**.
Phase 1 gate (≥ 530 passing) satisfied. Zero regressions in pre-existing CLI
and web backend tests.

Completed foundation:
- `ChainStoreProtocol` with 41 async methods
- `AsyncChainStore` fully implementing all 41 methods (aiosqlite-backed)
- `migrate_async()` sibling sharing `MIGRATION_STATEMENTS` with sync `migrate()`
- Migration v4 (`status_text` column + cache `user_id` columns)
- Frozen `ChainConfig` (spec O28)
- Consolidated `_cache_keys.py` module (spec G37 user-scoping)
- Sync `ChainStore` renamed to `SyncChainStore` with compat alias
- `scripts/check_test_count.sh` CI gate
- Parameterized protocol conformance test suite (SQLite param active,
  Postgres param stubbed for Phase 5)

## Phase 2 — BLOCKED pending plan revision

The plan's Task 22 (Convert ExtractionPipeline to async) as written is
structurally infeasible in a single commit. Task 22 instructs:

> Delete the sync extract_for_finding method entirely. Rename
> extract_for_finding_async to extract_for_finding.

But the current codebase has **13 callers of the sync
`pipeline.extract_for_finding`** that would all break in that commit:

### Test files (10)
- `packages/cli/tests/chain/test_cli_commands.py` (2 calls)
- `packages/cli/tests/chain/test_endpoints.py` (1 call)
- `packages/cli/tests/chain/test_graph_cache.py` (1 call)
- `packages/cli/tests/chain/test_entity_ops.py` (2 calls)
- `packages/cli/tests/chain/test_linker_engine.py` (4 calls)
- `packages/cli/tests/chain/test_llm_pass.py` (sync `_seed_candidate_edge` helper used across 5 tests)
- `packages/cli/tests/chain/test_neighborhood.py` (1 call)
- `packages/cli/tests/chain/test_pipeline_integration.py` (1 call)
- `packages/cli/tests/chain/test_presets.py` (1 call)
- `packages/cli/tests/chain/test_query_engine.py` (1 call)

### Production modules (3)
- `packages/cli/src/opentools/chain/cli.py:127` (`rebuild` command)
- `packages/cli/src/opentools/chain/subscriptions.py:97,114` (sync handlers)
- `packages/cli/src/opentools/chain/linker/batch.py:74` (`ChainBatchContext`)

All 13 callers currently instantiate a **sync** `SyncChainStore` (the
`ChainStore` alias) and are themselves sync functions. To delete the sync
`extract_for_finding` without breaking the suite, the same commit must also
convert:

- `LinkerEngine.link_finding` (`packages/cli/src/opentools/chain/linker/engine.py:164`) to async
- All 10 test files listed above to `async def` + `await`
- All 3 production modules to async-capable (requires CLI event loop bootstrapping for `cli.py`, drain worker for `subscriptions.py`, async context for `batch.py`)
- The `engagement_store_and_chain` fixture in `conftest.py` (Task 22 already attempts this)

This is roughly the scope of Tasks 22 **through** 32 combined — not
achievable in the 3-commit Tasks 22+23+24 subagent dispatch.

## Recommended Phase 2 plan revision

### Option A — Explicit task expansion (recommended)

Split Task 22 into:

- **Task 22a**: Convert `test_pipeline.py` to async and wire `ExtractionPipeline` to accept `ChainStoreProtocol`. Keep sync `extract_for_finding` method available as an alias that delegates via `asyncio.run` when called from sync context.
- **Task 22b**: Convert `LinkerEngine` to async (also listed as Task 28, bring forward). Update `test_linker_engine.py`.
- **Task 22c**: Convert `ChainBatchContext` to async. Update `linker/batch.py` and its test.
- **Task 22d**: Convert `subscriptions.py` to drain worker design (currently Task 25, bring forward).
- **Task 22e**: Convert `test_cli_commands.py`, `test_endpoints.py`, `test_graph_cache.py`, `test_entity_ops.py`, `test_neighborhood.py`, `test_presets.py`, `test_query_engine.py` to async.
- **Task 22f**: Convert `cli.py` rebuild (and any other extraction-triggering command) to async Typer.
- **Task 22g**: Now that zero sync callers remain, delete the sync `extract_for_finding` method and the async sibling rename.

This sequences the work so every commit leaves the suite green.

### Option B — Permanent sync shim

Keep a thin sync wrapper on `ExtractionPipeline`:

```python
def extract_for_finding_sync(self, finding, **kwargs):
    """Sync adapter for callers that aren't in an event loop yet."""
    import asyncio
    return asyncio.run(self.extract_for_finding(finding, **kwargs))
```

Callers migrate incrementally across Phases 2–3. The shim is deleted in
Phase 5 once all consumers are async. This preserves the plan's 47-task
structure but contradicts the "Delete the sync extract_for_finding method
entirely" instruction in Task 22 Step 2.

## Other issues to watch

1. **`test_chain_rebuild.py` baseline count** — the user's Phase 1 gate
   command ignored `test_chain_api.py`, `test_chain_isolation.py`, and
   `test_web_rebuild.py` but NOT `test_chain_rebuild.py` (3 tests). The
   web non-chain count from the gate command is 24, not 21 as the user
   stated. This is a pre-existing baseline discrepancy, not a regression.

2. **Tasks 12/13 reference migration v4 columns** — the plan's Task 12/13
   implementations reference `status_text` (linker_run) and `user_id`
   (cache tables) before Task 18 adds them via v4. The implementer worked
   around this by using an in-memory `self._run_status` dict and by
   ignoring user_id in cache SQL until v4 lands. Once Phase 2 is unblocked
   and Task 18's migration has run, `set_run_status` and the cache methods
   should be refactored to use the schema columns directly.

3. **Task 15 consumer migration deferred** — the plan's Task 15 suggests
   modifying `pipeline.py`, `llm_pass.py`, `narration.py` to import from
   `_cache_keys.py`. That migration was deferred; those modules still
   compute cache keys inline. Phase 2 (when it touches these files anyway)
   is a natural time to complete this migration.

## Resumption checklist for next session

1. `cd .worktrees/phase3c1-5-async-refactor && git status` — verify clean
2. `python -m pytest packages/ -q` — verify **613 passed, 1 skipped** baseline
3. Revise Phase 2 plan (Tasks 22-32) to follow Option A or Option B
4. Resume with the revised Task 22 sequence

Branch can be merged into `main` as-is without touching Phase 2 — Phase 1
landings are independently useful (new protocol, new async store, the
migration v4 schema change, the CI gate script) and introduce zero
regressions. Alternatively, leave the branch open and continue Phase 2
work on it.
