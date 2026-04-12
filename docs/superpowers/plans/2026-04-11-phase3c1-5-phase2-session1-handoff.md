# Phase 3C.1.5 Phase 2 — Session 1 handoff notes

**Session date:** 2026-04-11
**Branch:** `feature/phase3c1-5-phase2`
**Worktree:** `c:/Users/slabl/Documents/GitHub/OpenTools/.worktrees/phase3c1-5-phase2`
**HEAD at end of session:** `645f043`
**Test baseline at HEAD:** 612 passed, 1 skipped

## What this session accomplished

### Stage 1 — Plan revision (merged to main at `79ed4b6`)

Wrote `docs/superpowers/plans/2026-04-11-phase3c1-5-phase2-revised-plan.md` (1829 lines) rewriting Tasks 22–32 of the original plan. Committed and pushed to main. Key revision: split Task 22 into seven sub-tasks (22a–g) that introduce parallel `Async*` classes alongside the existing sync classes so each downstream caller migrates in its own green commit. The final sync deletion moves to Task 30 (end of Phase 4) once every consumer is async.

### Stage 2 — Phase 2 execution (three tasks landed)

All three tasks kept the suite at **612 passed, 1 skipped** (one net test removed in 22a due to consolidating two transitional async-parity tests into one).

| Task | Commit | Summary |
|---|---|---|
| 22a | `4df697e` | Added `AsyncExtractionPipeline` (parallel to sync `ExtractionPipeline`). Added `async_chain_stores` conftest fixture. Converted `test_pipeline.py` (11 → 10 tests). Folded deferred Phase 1 cleanup: `AsyncChainStore.get/put_extraction_cache` and `get/put_llm_link_cache` now filter/populate `user_id` in SQL via NULL-safe `(user_id IS ? OR user_id = ?)` pattern. |
| 22b | `d47f667` | Added `AsyncLinkerEngine` (parallel to sync `LinkerEngine`). Converted `test_linker_engine.py` (6 tests). Folded deferred Phase 1 cleanups: `set_run_status` now UPDATEs `linker_run.status_text` (migration v4 column); removed the in-memory `self._run_status` scaffold dict; `_row_to_linker_run` populates `LinkerRun.status` from `status_text`; `LinkerRun` Pydantic model gained a `status: str = "pending"` field. Also fixed a collateral test (`test_async_chain_store.py::test_set_run_status_persists_status_text`) whose assertion targeted the removed in-memory dict. |
| 22c | `645f043` | Rewrote `llm_link_pass_async` to use `ChainStoreProtocol` (`fetch_relations_in_scope`, `apply_link_classification`, `get/put_llm_link_cache`). Added explicit sticky-status guard before `apply_link_classification` since the protocol method unconditionally updates (sync SQL had a `WHERE status NOT IN (user_confirmed, user_rejected)` guard). Uses `link_classification_cache_key` from `_cache_keys`. Converted `test_llm_pass.py` (5 tests) + `_seed_candidate_edge` helper to async. Added `_demote_all_to_candidate` test helper using `upsert_relations_bulk` (no protocol method for "force status downgrade"). |

## What remains — Phase 2 Tasks 22d–22g

The revised plan file lives at `docs/superpowers/plans/2026-04-11-phase3c1-5-phase2-revised-plan.md` on main (also reachable from this worktree). Resume at Task 22d.

**Task 22d — AsyncChainBatchContext.** Add an `AsyncChainBatchContext` class to `packages/cli/src/opentools/chain/linker/batch.py` next to the existing sync `ChainBatchContext`. Convert `test_linker_batch.py` (5 tests) to async. The new class uses staged parallel extraction: stage 1 single `fetch_findings_by_ids`, stage 2 `asyncio.gather` with `Semaphore(4)`, stage 3 sequential linking. See plan file lines ~700-800 for the full task spec.

**Task 22e — Drain worker.** Rewrite `packages/cli/src/opentools/chain/subscriptions.py` to add a drain worker (`start_drain_worker`, `DrainWorker` dataclass) alongside the existing sync `subscribe_chain_handlers`. Add 2 new drain-worker tests to `test_subscriptions.py` on top of the 5 existing sync tests (total 7). Expected test count gain: +2. See plan file lines ~850-1000.

**Task 22f — CLI rebuild async.** Convert the `rebuild` command in `packages/cli/src/opentools/chain/cli.py` to `async def`, add `_get_stores_async` helper, use `AsyncExtractionPipeline` + `AsyncLinkerEngine`. Convert the rebuild test(s) in `test_cli_commands.py`. Leave `status`, `entities`, `path`, `export`, `query` sync — those move in Task 25 / 29. See plan file lines ~1020-1120.

**Task 22g — Phase 2 closeout verification.** Grep for remaining sync `ExtractionPipeline(` / `LinkerEngine(` / `ChainBatchContext(` constructors in converted test files. No new commit if everything passes. See plan file lines ~1160-1200.

## Remaining work after Phase 2

Phase 3 (Tasks 23–25): entity_ops, exporter, cli.py status/entities/export.
Phase 4 (Tasks 26–30): GraphCache, ChainQueryEngine, presets, narration, cli.py path/query, and final sync deletion (Task 30).
Phase 5 (Tasks 31–42): unchanged from the original plan's Tasks 36–47 (Postgres backend, web rewrite, test_web_rebuild, final baseline).

## Gotchas / plan-vs-reality items discovered this session

1. **`LinkerRun` is a Pydantic BaseModel, not a dataclass.** The plan described it as a dataclass. Adding fields works the same way but the `model_copy(update={...})` mechanism is needed for immutable updates in tests.

2. **`fetch_relations_in_scope` does not support weight filters.** `llm_link_pass_async` filters weight in Python after fetching. Fine for the test scale; note if Phase 5 performance work ever pushes relation counts into the thousands.

3. **`apply_link_classification` protocol method unconditionally updates.** Unlike the sync SQL that had a `WHERE status NOT IN (user_confirmed, user_rejected)` guard, the protocol method will overwrite sticky statuses. The 22c implementation added an explicit Python-level guard before calling. If Task 30 or Phase 5 tightens the protocol method itself to guard internally, the explicit guards become redundant and can be removed.

4. **CLI single-user store ignores `user_id` in `set_run_status` WHERE clause.** `AsyncChainStore.set_run_status` (post-22b) accepts a `user_id` kwarg for protocol conformance but ignores it in SQL. This matches existing update/delete patterns in `sqlite_async.py`. Web `PostgresChainStore` (Phase 5 Task 35) will need to honor user_id.

5. **`LinkerScope.FINDING_SINGLE` is the right scope for single-finding link runs.** Not `LinkerScope.ENGAGEMENT`. The plan file at line ~580 shows `ENGAGEMENT` in the pseudocode; the implementer correctly mirrored the sync `_record_run` usage which uses `FINDING_SINGLE`. If the plan snippet in future tasks says `ENGAGEMENT` for a single-finding call, override to `FINDING_SINGLE`.

6. **`pytest-asyncio` mode = `auto` is configured in the ROOT `pyproject.toml`, but pytest picks up `packages/cli/pyproject.toml` as the configfile** (it's closer to the tests). The CLI pyproject has no asyncio config, so async tests need explicit `pytestmark = pytest.mark.asyncio` at module level. Every converted test file this session uses this pattern. Tasks 22d–22g test conversions must follow the same pattern.

7. **`_persist_async` in the sync pipeline resets `mention_count` to 0 before bulk insert, then calls `recompute_mention_counts`.** The async port preserves this ground-truth reconciliation behavior through protocol methods. If the `recompute_mention_counts` protocol method is ever removed, the ports need to recompute manually before the bulk insert.

8. **Test count accounting from Phase 1 baseline:** Original main was 613 passed, 1 skipped. Task 22a dropped to 612 (consolidated two tests into one). Tasks 22b and 22c maintained 612. The revised plan's gate table targeted ≥ 613 for 22a — that target was off by one. Use **≥ 612** as the gate through the rest of Phase 2.

## Resumption instructions for next session

### Checklist to re-establish context

1. `cd c:/Users/slabl/Documents/GitHub/OpenTools/.worktrees/phase3c1-5-phase2`
2. `git log --oneline -6` — verify HEAD is `645f043` (or a follow-up if Task 22d already ran)
3. `python -m pytest packages/ -q` — verify **612 passed, 1 skipped**
4. Read this handoff file (the short version is: "Tasks 22a/b/c done, resume at 22d")
5. Read the revised plan's Task 22d section: `docs/superpowers/plans/2026-04-11-phase3c1-5-phase2-revised-plan.md` — find `## Task 22d`

### Execution approach that worked this session

- Invoked `superpowers:subagent-driven-development` then dispatched one implementer per task via `Agent(subagent_type=general-purpose)`
- Pasted the full task text into the implementer prompt (no plan file reading — saves context)
- Included parent HEAD SHA and expected baseline test count
- Told implementer "DO NOT read the plan file or spec file"
- Included escalation guidance (NEEDS_CONTEXT / DONE_WITH_CONCERNS / BLOCKED patterns)
- Verified commit + test count via Bash after each task before moving on
- Did NOT run a separate spec-reviewer or code-quality-reviewer subagent per task — the implementer's self-review + my post-hoc grep verification was sufficient given these are mechanical parallel-class introductions. **For riskier tasks (e.g. Task 22e drain worker, Task 30 final deletion) a formal spec review is recommended.**

### Task 22d prompt skeleton

```
You are implementing Task 22d of Phase 3C.1.5 Phase 2.

Working directory: c:/Users/slabl/Documents/GitHub/OpenTools/.worktrees/phase3c1-5-phase2
Parent HEAD: 645f043 (Tasks 22a/b/c landed)
Test baseline: 612 passed, 1 skipped. Your commit must keep ≥ 612.

DO NOT read the plan or spec files.

Context: Phase 2 introduces parallel Async* classes next to sync ones.
22a added AsyncExtractionPipeline. 22b added AsyncLinkerEngine. 22c
rewrote llm_link_pass_async. Now 22d adds AsyncChainBatchContext next
to the existing sync ChainBatchContext.

[Paste Task 22d body from the revised plan file, lines for "## Task 22d"]

[Include the same escalation paths and report format as previous dispatches]
```

The subagent-dispatch template follows the same pattern as the three prompts from this session — copy the structure and just swap in Task 22d's task body.

### Model selection

- Tasks 22d and 22f: small enough for `standard` model (AsyncChainBatchContext is ~100 lines of port; rebuild command is ~50 lines)
- Task 22e (drain worker): **`standard` minimum, possibly `opus`**. The drain worker involves `asyncio.Queue`, `call_soon_threadsafe`, and event-loop lifetime management. Easier to get wrong than the mechanical ports.
- Task 22g: pure verification, no code changes — inline check via grep, no subagent needed
- Tasks 23, 24, 25 (Phase 3): mechanical `haiku` should suffice
- Tasks 26–29 (Phase 4): `standard` (query engine conversion has integration judgment)
- Task 30 (final deletion): `standard` — it's mechanical but high blast radius; verify each deletion individually

### Estimated context budget per remaining task

Based on this session's usage (3 tasks × ~100k tokens per full dispatch+verify cycle):
- Task 22d: ~60k tokens
- Task 22e: ~80k tokens (drain worker complexity)
- Task 22f: ~50k tokens
- Task 22g: ~10k tokens (verify-only)

A follow-up session should be able to finish Phase 2 cleanly and possibly start Phase 3. Phase 4/5 is probably another 2–3 sessions.

## Files added/modified this session (worktree summary)

```
docs/superpowers/plans/2026-04-11-phase3c1-5-phase2-revised-plan.md    (new, 1829 lines, already on main)
docs/superpowers/plans/2026-04-11-phase3c1-5-phase2-session1-handoff.md (this file, new)
packages/cli/src/opentools/chain/extractors/pipeline.py                 (+253 lines: AsyncExtractionPipeline)
packages/cli/src/opentools/chain/linker/engine.py                       (+~200 lines: AsyncLinkerEngine)
packages/cli/src/opentools/chain/linker/llm_pass.py                     (llm_link_pass_async rewritten)
packages/cli/src/opentools/chain/models.py                              (LinkerRun.status field)
packages/cli/src/opentools/chain/stores/sqlite_async.py                 (cache user_id filters, set_run_status, __init__ cleanup)
packages/cli/tests/chain/conftest.py                                    (+async_chain_stores fixture)
packages/cli/tests/chain/test_pipeline.py                               (11 sync → 10 async tests)
packages/cli/tests/chain/test_linker_engine.py                          (6 tests → async)
packages/cli/tests/chain/test_llm_pass.py                               (5 tests + helper → async)
packages/cli/tests/chain/test_async_chain_store.py                      (1 test assertion updated for set_run_status behavior change)
```

Branch `feature/phase3c1-5-phase2` should be pushed to `origin` at end-of-session so the next session can pick up from a remote-synced state.
