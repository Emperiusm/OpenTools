# Phase 3C.1.5 Phase 2 — Session 2 handoff notes

**Session date:** 2026-04-11 (continued from session 1)
**Branch:** `feature/phase3c1-5-phase2`
**Worktree:** `c:/Users/slabl/Documents/GitHub/OpenTools/.worktrees/phase3c1-5-phase2`
**HEAD at end of session:** `d7881fe`
**Test baseline at HEAD:** 614 passed, 1 skipped

## What this session accomplished

Phase 2 is now **complete**. All pipeline/linker/batch/subscriptions/rebuild sync callers have been migrated to parallel async classes. The sync classes still exist for downstream Phase 3/4 consumers (entity_ops, exporter, query engine stack) and are deleted in Task 30.

### Session 2 commits

| Task | Commit | Summary |
|---|---|---|
| 22d | `209ea54` | `AsyncChainBatchContext` with staged parallel extraction (Semaphore(4), asyncio.gather). 5 `test_linker_batch.py` tests converted. |
| 22e | `dde1025` | Drain worker: `DrainWorker` dataclass + `start_drain_worker` + `_reset_drain_state` added to `subscriptions.py`. 2 new async drain-worker tests (7 total in test_subscriptions.py = 5 old sync + 2 new async). Used per-test `@pytest.mark.asyncio` decorators (NOT module-level) to mix sync and async tests in the same file. Suite grew 612→614. |
| 22f | `d7881fe` | CLI `rebuild` command converted to async. Uses `asyncio.run` wrapper inside a sync `def rebuild` because Typer 0.24.1 does NOT support `async def` commands natively. Added `_get_stores_async` helper. `test_cli_commands.py` had no rebuild tests to convert (verified: 7 tests cover status/entities/path/query/export but not rebuild). |

### Task 22g verification (no commit)

Ran greps to confirm Phase 2 closeout. Results:

- **Converted test files** (`test_pipeline.py`, `test_linker_engine.py`, `test_linker_batch.py`, `test_llm_pass.py`): zero sync `ExtractionPipeline(` / `LinkerEngine(` / `ChainBatchContext(` matches. Clean.
- **Unconverted test files** still use sync constructors: `test_cli_commands.py`, `test_endpoints.py`, `test_entity_ops.py`, `test_exporter.py`, `test_graph_cache.py`, `test_neighborhood.py`, `test_presets.py`, `test_query_engine.py`, `test_pipeline_integration.py`, and the 5 pre-existing sync tests in `test_subscriptions.py`. All of these migrate in Phase 3 (Tasks 23–25) or Phase 4 (Tasks 26–29).
- **Production code:** only `cli.py` rebuild uses Async classes. `batch.py:24` is a docstring example, not a real call. No stray sync constructors in production where async should be used.

## Phase 2 final state

```
Branch: feature/phase3c1-5-phase2 (tracking origin)
HEAD:   d7881fe feat(chain): convert cli rebuild command to async

History since main:
  d7881fe feat(chain): convert cli rebuild command to async
  dde1025 feat(chain): drain worker for async event-to-extraction dispatch
  209ea54 feat(chain): AsyncChainBatchContext with staged parallel extraction
  f6982d7 docs: phase 3C.1.5 Phase 2 session 1 handoff notes
  645f043 feat(chain): async llm_link_pass uses protocol + converts test_llm_pass
  d47f667 feat(chain): introduce AsyncLinkerEngine + convert test_linker_engine
  4df697e feat(chain): introduce AsyncExtractionPipeline + convert test_pipeline.py
  79ed4b6 (main) docs: revise Phase 3C.1.5 Tasks 22-32 ...

Test count at HEAD: 614 passed, 1 skipped
Phase 2 net test count delta: +1 (613 baseline → 612 after 22a consolidation → 614 after 22e added 2 drain worker tests)
```

## Gotchas / plan-vs-reality items discovered this session

1. **Typer 0.24.1 does NOT support `async def` commands.** The plan file assumed native async support (Typer 0.12+). Confirmed by a direct CliRunner smoke test. Task 22f used the `asyncio.run` wrapper pattern inside a sync `def rebuild` which calls a nested `_rebuild_async()` coroutine. Future tasks converting `status`/`entities`/`export`/`path`/`query` commands (Tasks 25 and 29) must use the same pattern. If Typer is upgraded to 0.12+/0.16+ in the future, the pattern can be simplified — but don't upgrade Typer as part of this refactor.

2. **`EngagementStore.list_findings` does not exist.** Task 22f needed to enumerate findings across all engagements for the `rebuild --engagement` unspecified case. The available APIs are `get_findings(engagement_id, ...)` (requires a specific engagement) and `list_all()` (returns engagements). Solution: iterate engagements and fan out `chain_store.fetch_findings_for_engagement(eng.id, ...)` calls. Phase 3/4 tasks that enumerate findings should mirror this pattern.

3. **`call_soon_threadsafe` from inside the running loop's thread requires an event loop yield.** Task 22e's drain worker tests had to insert `await asyncio.sleep(0.01)` before `worker.queue.join()` because `engagement_store.add_finding()` emits the sync event from inside the pytest-asyncio event loop's thread. `loop.call_soon_threadsafe(queue.put_nowait, ...)` schedules the put for the next loop cycle — without a yield, `queue.join()` observes an empty, never-incremented unfinished-task count and returns immediately. This is a **production concern** too: CLI callers using `start_drain_worker` should NOT assume `queue.join()` reflects items emitted from sync code inside the same async context without first yielding control. Document in Task 30 or the drain worker docstring.

4. **Mixed sync+async tests in one file need per-test decorators.** `test_subscriptions.py` has 5 pre-existing sync tests and 2 new async tests. A module-level `pytestmark = pytest.mark.asyncio` would try to convert the sync tests and break them. Instead, each async test uses `@pytest.mark.asyncio` individually. Any future task that keeps some sync tests and adds async tests in the same file must follow this pattern. `test_cli_commands.py` will face the same situation in Task 25 (status/entities/export) and Task 29 (path/query).

5. **Drain worker module-level state.** `_drain_queue` and `_drain_worker_task` are module globals, so only one drain worker exists per process. Calling `start_drain_worker` twice without calling `_reset_drain_state` between them leaks the first task. Acceptable for CLI (single process). Web backend (Phase 5 Task 38) will need a different approach — probably a per-request `PostgresChainStore` session with no drain worker at all.

6. **`DrainWorker.stop()` shutdown race.** The sequence is `await queue.join()` → `task.cancel()` → `await task`. Between `queue.join()` returning and `task.cancel()` executing, a new event could enqueue an item that gets cancelled before draining. Production callers doing high-throughput writes should `reset_event_bus()` or unsubscribe before calling `stop()`. Document in Task 30.

## Remaining work

**Phase 3 — Tasks 23, 24, 25:**
- Task 23: Convert `entity_ops.py` (merge/split) to async + `test_entity_ops.py` (6 tests). Straightforward mechanical port — protocol methods `rewrite_mentions_entity_id`, `delete_entity`, `fetch_mentions_with_engagement`, `rewrite_mentions_by_ids` all exist.
- Task 24: Convert `exporter.py` to async + `test_exporter.py` (5 tests). Uses `export_dump_stream` (async generator) for streaming export; `batch_transaction` for import. Check whether `export_dump_stream` actually exists as an async generator in the current sqlite_async.py; if not, that's a plan deviation.
- Task 25: Convert CLI `status`, `entities`, `export` commands to async. Use the `asyncio.run` wrapper pattern (see Task 22f). Test_cli_commands.py has tests for these — convert them per-test with `@pytest.mark.asyncio` since `path`/`query` tests stay sync until Task 29.

**Phase 4 — Tasks 26, 27, 28, 29, 30:**
- Task 26: Async `GraphCache` with per-key `asyncio.Lock` (spec G4). Add 1 concurrent-build test. `test_graph_cache.py` 10→11 tests.
- Task 27: Async `ChainQueryEngine` + `neighborhood.py`. Convert `test_query_engine.py`, `test_endpoints.py`, `test_neighborhood.py`.
- Task 28: Async `presets.py` + `narration.py`. Convert `test_presets.py`, `test_narration.py`. Fold deferred cleanup 3: `narration.py` imports from `_cache_keys.py`.
- Task 29: Convert CLI `path` + `query` commands to async (last commands).
- Task 30: **Final sync deletion.** Delete sync `ExtractionPipeline`, `LinkerEngine`, `ChainBatchContext`, `llm_link_pass`, old `subscribe_chain_handlers` path (delete `_load_finding`, `_subscribed`, sync factory types; keep `set_batch_context`, `reset_subscriptions`, drain worker stuff). Rename `AsyncExtractionPipeline` → `ExtractionPipeline`, etc. Delete `packages/cli/src/opentools/chain/store_extensions.py`. Delete sync `engagement_store_and_chain` fixture from conftest.py and rename `async_chain_stores` → `engagement_store_and_chain` (reclaim the canonical name). Rename `_get_stores_async` → `_get_stores` in `cli.py`, delete the old sync `_get_stores`. This is mechanical but high blast radius; verify each deletion individually.

**Phase 5 — Tasks 31–42:**
Substantially unchanged from the original plan's Tasks 36–47. Postgres backend + web unification + final baseline. Reference the revised plan file's "PHASE 5" section table for the mapping.

## Resumption checklist for next session

1. `cd c:/Users/slabl/Documents/GitHub/OpenTools/.worktrees/phase3c1-5-phase2`
2. `git pull --ff-only` (in case the branch advanced remotely)
3. `git log --oneline -8` — verify HEAD is `d7881fe` (or later)
4. `python -m pytest packages/ -q` — verify **614 passed, 1 skipped**
5. Read this handoff + session 1 handoff for gotchas
6. Read the revised plan file's Task 23 section: `docs/superpowers/plans/2026-04-11-phase3c1-5-phase2-revised-plan.md`
7. Dispatch Task 23 implementer following the subagent template used this session

## Test count targets for remaining phases

Original plan targets were calibrated to a wrong baseline (it assumed 613 after 22a; actual is 612 after 22a, 614 after 22e). Revised gate through remaining tasks:

| Phase | After task | Expected passing |
|---|---|---|
| Phase 3 | 23 (entity_ops) | ≥ 614 |
| Phase 3 | 24 (exporter) | ≥ 614 |
| Phase 3 | 25 (cli status/entities/export) | ≥ 614 |
| Phase 4 | 26 (graph cache + 1 concurrent test) | ≥ 615 |
| Phase 4 | 27 (query engine + endpoints + neighborhood) | ≥ 615 |
| Phase 4 | 28 (presets + narration) | ≥ 615 |
| Phase 4 | 29 (cli path + query) | ≥ 615 |
| Phase 4 | 30 (final sync deletion, rename Async* → canonical) | ≥ 615 |
| Phase 5 | 42 (final baseline) | ≥ 690 (Postgres adds ~75 conformance tests) |

The Task 30 mechanical rename should not change test count. If it does, investigate.

## Model selection guidance for remaining tasks

Based on Phase 2 execution experience:
- **Task 23 (entity_ops):** `haiku` sufficient — mechanical port, small function surface
- **Task 24 (exporter):** `standard` — check `export_dump_stream` existence first; streaming API may need adaptation
- **Task 25 (CLI status/entities/export):** `standard` — use `asyncio.run` wrapper pattern from 22f. Multiple commands in one file + mixed sync/async tests = nontrivial.
- **Task 26 (graph cache):** `standard` — `asyncio.Lock` lifecycle + concurrent build semantics
- **Task 27 (query engine + endpoints + neighborhood):** `standard` — multiple files, integration
- **Task 28 (presets + narration):** `haiku` — mechanical
- **Task 29 (cli path + query):** `standard` — second half of CLI conversion
- **Task 30 (final sync deletion):** `standard` or manual — high blast radius; recommend dispatching with strict "show me the diff before committing" guardrails, OR executing inline without a subagent so the controller sees every rename before it lands

## Session statistics

- Tasks completed this session: 22d, 22e, 22f, 22g (verification)
- Commits landed this session: 4 (including this handoff)
- Suite growth: 612 → 614 (+2 drain worker tests from 22e)
- Subagent dispatches: 3 (one per task)
- Tokens burned: ~250k across session 1+2 (plan writing + survey + 6 subagent dispatches + verifications)
- Phase 2 total: 7 tasks, 6 implementation commits + 2 doc commits, 13 production files modified, zero regressions
