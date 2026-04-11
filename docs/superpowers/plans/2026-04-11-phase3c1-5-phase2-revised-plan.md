# Phase 3C.1.5 Phase 2+ — Revised Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the async-store refactor by converting every chain consumer (pipeline, linker, batch, subscriptions, entity_ops, exporter, query stack, CLI) to `ChainStoreProtocol`-backed async, then delete the sync store and sync classes. Picks up where Phase 1 (tasks 1–21, merged on main at commit `58d7d77`) left off.

**Architecture:** Phase 2 adds **parallel async classes** (`AsyncExtractionPipeline`, `AsyncLinkerEngine`, `AsyncChainBatchContext`) alongside the existing sync classes, plus a new `async_chain_stores` conftest fixture. Each downstream consumer migrates from sync → async in its own commit so every commit leaves the test suite green. The final task (30) renames `Async*` → canonical names and deletes the sync implementations once zero sync callers remain.

**Tech Stack:** aiosqlite, Python asyncio, pytest-asyncio, SQLAlchemy async (Phase 5 only), Typer (native async command support).

---

## How this plan differs from the original

**Original plan file:** `docs/superpowers/plans/2026-04-10-phase3c1-5-async-store-refactor.md` — Tasks 1–21 (Phase 1) executed as written and are merged. Tasks 22–47 are SUPERSEDED by this file.

**Why it was revised:** Original Task 22 instructed deleting sync `extract_for_finding` in a single commit, but 13 downstream sync callers (10 test files + `cli.py` + `subscriptions.py` + `linker/batch.py`) would all break in that commit. Root cause analysis is in `docs/superpowers/plans/2026-04-11-phase3c1-5-phase2-revision-notes.md`.

**What this plan preserves from the original:**
- Locked decisions: async-first final API, 41 protocol methods, aiosqlite + SQLAlchemy backends, user-scoped caches, per-method commits outside explicit transaction scope, sync EngagementStore holding its own connection, drain worker design for subscriptions
- Task numbering 1–21 (untouched, merged)
- Phase 5 substance (tasks 31–42 below map onto original tasks 36–47 with renumbering)

**Deferred Phase 1 cleanups folded into this plan:**
1. `AsyncChainStore.set_run_status` currently writes to an in-memory dict because migration v4's `status_text` column was added after the linker-run methods were written. Now that v4 is merged, update `set_run_status` to UPDATE the column and `_row_to_linker_run` to populate `LinkerRun.status` from it. `LinkerRun` model needs a `status` field added. → folded into Task 22b.
2. `AsyncChainStore` cache methods accept `user_id` but don't filter by it in SQL. Now that v4 added the columns, add `user_id` to WHERE/INSERT clauses. → folded into Task 22a.
3. Task 15 consumer migration (import from `_cache_keys.py` instead of inline computation) is deferred: `extractors/pipeline.py`, `linker/llm_pass.py`, `query/narration.py` still compute cache keys inline. → folded into Task 22a (pipeline), Task 22c (llm_pass), Task 28 (narration).

**Locked decisions (do NOT re-litigate during execution):**
- Async-first API. No sync shims in the final state. The parallel `Sync*` classes that exist temporarily during Phase 2–4 are all deleted in Task 30.
- 41 protocol methods (original spec said "32" but the authoritative count is 41, matching the merged `AsyncChainStore`).
- `EngagementStore` stays sync. `EngagementStore` and `AsyncChainStore` hold *separate* connections to the same SQLite file (WAL mode).
- Drain worker uses `asyncio.get_event_loop_policy().get_event_loop().call_soon_threadsafe` so the sync engagement-store event handler is safe from any thread.
- Per-method commits unless inside an explicit `transaction()` or `batch_transaction()` scope (uses `AsyncChainStore._txn_depth` counter already implemented).
- IDF squared formula preserved as tech debt. Do NOT fix during this refactor.
- `ChainConfig` is frozen (Task 16, merged).

---

## Test count gates

Baseline on main at start of Phase 2: **613 passed, 1 skipped**.

| Phase | After task | Expected passing | Notes |
|---|---|---|---|
| Phase 2 | 22a | ≥ 613 | test_pipeline.py converted in-place (no count change) |
| Phase 2 | 22b | ≥ 613 | test_linker_engine.py converted in-place |
| Phase 2 | 22c | ≥ 613 | test_llm_pass.py converted in-place |
| Phase 2 | 22d | ≥ 613 | test_linker_batch.py converted in-place |
| Phase 2 | 22e | ≥ 615 | test_subscriptions.py now has 2 extra drain-worker tests |
| Phase 2 | 22f | ≥ 615 | test_cli_commands.py rebuild test async |
| Phase 3 | 23 | ≥ 615 | test_entity_ops.py converted in-place |
| Phase 3 | 24 | ≥ 615 | test_exporter.py converted in-place |
| Phase 3 | 25 | ≥ 615 | test_cli_commands.py status/entities/export async |
| Phase 4 | 26 | ≥ 616 | test_graph_cache.py +1 concurrent-build test |
| Phase 4 | 27 | ≥ 616 | test_query_engine.py + test_endpoints.py + test_neighborhood.py converted |
| Phase 4 | 28 | ≥ 616 | test_presets.py + test_narration.py converted |
| Phase 4 | 29 | ≥ 616 | test_cli_commands.py path/query async |
| Phase 4 | 30 | ≥ 616 | Sync classes deleted; zero count change expected |
| Phase 5 | 31–42 | ≥ 690 | Postgres backend + web rewrite adds substantial tests |

Gate script: `scripts/check_test_count.sh <min>`.

Pre-existing guard counts (re-check at phase boundaries; the Phase 1 baseline command ignored `test_chain_rebuild.py` for the web count, so web non-chain = 24 not 21 as originally stated):
- Pre-existing CLI tests (`packages/cli/tests/` minus `packages/cli/tests/chain/`): **177**
- Pre-existing web tests (`packages/web/backend/tests/` minus `test_chain_api.py`, `test_chain_isolation.py`, `test_chain_rebuild.py`, `test_web_rebuild.py`): **24**

---

# PHASE 2 — Pipeline + linker + batch + subscriptions (async-first)

## Task 22a: Introduce AsyncExtractionPipeline + async conftest fixture + convert test_pipeline.py

**Files:**
- Modify: `packages/cli/src/opentools/chain/extractors/pipeline.py`
- Modify: `packages/cli/tests/chain/conftest.py`
- Modify: `packages/cli/tests/chain/test_pipeline.py`
- Modify: `packages/cli/src/opentools/chain/stores/sqlite_async.py` (fold in deferred cleanup 2: user_id SQL filter in cache methods)

- [ ] **Step 1: Fold deferred cleanup 2 into AsyncChainStore cache methods**

In `sqlite_async.py`, update `get_extraction_cache`, `put_extraction_cache`, `get_llm_link_cache`, `put_llm_link_cache` to filter/include `user_id` in SQL. Current methods store `user_id` in the method signature but ignore it in SQL. Change:

```python
async def get_extraction_cache(
    self, cache_key: str, *, user_id: UUID | None,
) -> dict | None:
    self._require_initialized()
    row = await self._fetchone(
        "SELECT response_json FROM chain_extraction_cache "
        "WHERE cache_key = ? AND "
        "(user_id IS ? OR user_id = ?)",
        (cache_key, user_id, str(user_id) if user_id else None),
    )
    if row is None:
        return None
    return orjson.loads(row[0])

async def put_extraction_cache(
    self, cache_key: str, response: dict, *, user_id: UUID | None,
) -> None:
    self._require_initialized()
    await self._execute(
        "INSERT OR REPLACE INTO chain_extraction_cache "
        "(cache_key, user_id, response_json, created_at) "
        "VALUES (?, ?, ?, ?)",
        (
            cache_key,
            str(user_id) if user_id else None,
            orjson.dumps(response).decode("utf-8"),
            _utcnow().isoformat(),
        ),
    )
    if self._txn_depth == 0:
        await self._conn.commit()
```

Apply the same pattern to `get_llm_link_cache` / `put_llm_link_cache`. Verify against the actual current implementation — the SQL table names and column order may differ slightly from the snippet above.

- [ ] **Step 2: Add AsyncExtractionPipeline class to pipeline.py**

Leave the existing sync `ExtractionPipeline` class untouched. ADD a new class below it:

```python
class AsyncExtractionPipeline:
    """Async three-stage extraction pipeline using ChainStoreProtocol.

    Replaces the sync ExtractionPipeline incrementally. Sync callers
    continue to use ExtractionPipeline (which takes SyncChainStore);
    async callers use AsyncExtractionPipeline (which takes any
    ChainStoreProtocol implementation — today AsyncChainStore, in
    Phase 5 also PostgresChainStore).
    """

    def __init__(
        self,
        *,
        store,  # ChainStoreProtocol
        config: ChainConfig,
        security_extractors: list | None = None,
        parser_extractors: list | None = None,
    ) -> None:
        self.store = store
        self.config = config
        self.security_extractors = security_extractors or list(BUILTIN_SECURITY_EXTRACTORS)
        self.security_extractors.insert(0, IocFinderExtractor())
        self.parser_extractors = parser_extractors or list(BUILTIN_PARSER_EXTRACTORS)

    async def extract_for_finding(
        self,
        finding: Finding,
        *,
        user_id: UUID | None = None,
        llm_provider: LLMExtractionProvider | None = None,
        force: bool = False,
    ) -> ExtractionResult:
        new_hash = _extraction_input_hash(finding)
        if not force:
            cur = await self.store.get_extraction_hash(finding.id, user_id=user_id)
            if cur == new_hash:
                return ExtractionResult(
                    entities_created=0, mentions_created=0,
                    stage1_count=0, stage2_count=0, stage3_count=0,
                    cache_hit=True, was_force=False,
                )

        await self.store.delete_mentions_for_finding(finding.id, user_id=user_id)

        ctx = ExtractionContext(finding=finding)

        stage1 = await self._run_stage1_async(finding, ctx, user_id=user_id)
        ctx.already_extracted.extend(stage1)

        stage2 = self._run_stage2(finding, ctx)
        ctx.already_extracted.extend(stage2)

        stage3: list[ExtractedEntity] = []
        if llm_provider is not None:
            stage3 = await self._run_stage3(finding, ctx, llm_provider, user_id=user_id)
            ctx.already_extracted.extend(stage3)

        all_raw = stage1 + stage2 + stage3

        async with self.store.transaction():
            entities_created, mentions_created = await self._persist_async(
                finding, all_raw, user_id=user_id,
            )
            await self.store.upsert_extraction_state(
                finding.id, new_hash, user_id=user_id,
            )

        return ExtractionResult(
            entities_created=entities_created,
            mentions_created=mentions_created,
            stage1_count=len(stage1),
            stage2_count=len(stage2),
            stage3_count=len(stage3),
            cache_hit=False,
            was_force=force,
        )

    async def _run_stage1_async(
        self, finding: Finding, ctx: ExtractionContext, *, user_id: UUID | None,
    ) -> list[ExtractedEntity]:
        rows = await self.store.get_parser_output(finding.id, user_id=user_id)
        out: list[ExtractedEntity] = []
        for row in rows:
            parser_name = row["parser_name"]
            data = row["data"]  # already parsed by protocol method
            for ex in self.parser_extractors:
                if ex.tool_name != parser_name:
                    continue
                try:
                    out.extend(ex.extract(finding, data, ctx))
                except Exception as exc:
                    logger.warning(
                        "parser-aware extractor %s failed for finding %s: %s",
                        ex.tool_name, finding.id, exc,
                    )
                    continue
        return out

    def _run_stage2(self, finding: Finding, ctx: ExtractionContext):
        # Identical to sync ExtractionPipeline._run_stage2 — pure Python, no store access
        return ExtractionPipeline._run_stage2(self, finding, ctx)

    async def _run_stage3(
        self,
        finding: Finding,
        ctx: ExtractionContext,
        provider: LLMExtractionProvider,
        *,
        user_id: UUID | None,
    ) -> list[ExtractedEntity]:
        # Fold deferred cleanup 3 (cache key consolidation) here:
        # Use _cache_keys.extraction_cache_key instead of any inline computation.
        from opentools.chain._cache_keys import extraction_cache_key

        prose_fields = [finding.title or "", finding.description or "", finding.evidence or ""]
        combined = "\n".join(p for p in prose_fields if p)
        if not combined:
            return []

        cache_key = extraction_cache_key(
            content=combined,
            provider_name=provider.name,
            provider_model=provider.model,
            user_id=user_id,
        )
        cached = await self.store.get_extraction_cache(cache_key, user_id=user_id)
        if cached is not None:
            return [ExtractedEntity(**e) for e in cached["entities"]]

        try:
            results = list(await provider.extract_entities(combined, ctx))
        except Exception as exc:
            logger.warning(
                "LLM stage3 extraction failed for finding %s: %s",
                finding.id, exc, exc_info=True,
            )
            return []

        await self.store.put_extraction_cache(
            cache_key,
            {"entities": [r.__dict__ for r in results]},
            user_id=user_id,
        )
        return results

    async def _persist_async(
        self, finding: Finding, raw: list, *, user_id: UUID | None,
    ) -> tuple[int, int]:
        # Normalization + dedupe logic identical to sync _persist.
        # Difference: uses await store.upsert_entities_bulk / add_mentions_bulk / recompute_mention_counts.
        # Copy the entity/mention building logic verbatim from sync _persist.
        # Replace the three store writes with:
        #   await self.store.upsert_entities_bulk(entity_list, user_id=user_id)
        #   await self.store.add_mentions_bulk(mention_list, user_id=user_id)
        #   await self.store.recompute_mention_counts(
        #       [e.id for e in entity_list], user_id=user_id,
        #   )
        ...
```

**Implementation note for the subagent:** the `_persist_async` body is a line-by-line port of the existing sync `_persist` — copy the Python logic (normalization, dedup key construction, mention building) verbatim and only swap the three store-write calls for awaited protocol methods. Do NOT reinvent the normalization logic.

- [ ] **Step 3: Add async_chain_stores fixture to conftest.py**

Leave existing `engagement_store_and_chain` fixture untouched (sync tests still need it during Phase 2–4). ADD a new fixture:

```python
import pytest_asyncio

@pytest_asyncio.fixture
async def async_chain_stores(tmp_path):
    """Yield (EngagementStore, AsyncChainStore, now) sharing the same DB file.

    EngagementStore owns a sync sqlite3 connection; AsyncChainStore owns
    an aiosqlite connection to the same file. WAL mode permits both.
    """
    from opentools.chain.stores.sqlite_async import AsyncChainStore
    from opentools.engagement.store import EngagementStore
    from opentools.models import Engagement, EngagementStatus, EngagementType

    db_path = tmp_path / "combined.db"
    engagement_store = EngagementStore(db_path=db_path)
    now = datetime.now(timezone.utc)
    engagement_store.create(Engagement(
        id="eng_test", name="test", target="example.com",
        type=EngagementType.PENTEST, status=EngagementStatus.ACTIVE,
        created_at=now, updated_at=now,
    ))

    chain_store = AsyncChainStore(db_path=db_path)
    await chain_store.initialize()

    yield engagement_store, chain_store, now

    await chain_store.close()
    engagement_store._conn.close()
```

If `pytest_asyncio` is not yet in `pyproject.toml` dependencies, add it (check root `pyproject.toml` first — Task 1 may have already pulled it in). Configure `asyncio_mode = "auto"` in `pyproject.toml`'s `[tool.pytest.ini_options]` section.

Run `pip install -e 'packages/cli[dev]'` to verify the dev extra installs cleanly.

- [ ] **Step 4: Convert test_pipeline.py to async + AsyncExtractionPipeline**

For each of the 11 tests, change:
- `def test_*(engagement_store_and_chain)` → `async def test_*(async_chain_stores)`
- `ExtractionPipeline(store=chain_store, config=...)` → `AsyncExtractionPipeline(store=chain_store, config=...)`
- `pipeline.extract_for_finding(f)` → `await pipeline.extract_for_finding(f)`
- `chain_store.mentions_for_finding(f.id)` → `await chain_store.mentions_for_finding(f.id, user_id=None)`

Delete the two existing tests `test_extract_for_finding_async_matches_sync` and `test_extract_for_finding_async_llm_stage_awaited` — they test the transitional bridge that no longer exists in the new async pipeline. Replace them with one consolidated test `test_pipeline_llm_stage_awaits_provider` that exercises the async LLM stage via `AsyncExtractionPipeline`.

`_insert_finding` helper stays sync (`engagement_store.add_finding` is sync).

- [ ] **Step 5: Run tests**

```bash
python -m pytest packages/cli/tests/chain/test_pipeline.py -v
```
Expected: 10 passed (11 - 2 + 1 = 10, or verify exact count).

```bash
python -m pytest packages/ -q
```
Expected: ≥ 613 passed, 1 skipped. Adjust the gate below if test count dropped by one due to the two-for-one test consolidation.

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/chain/extractors/pipeline.py \
        packages/cli/src/opentools/chain/stores/sqlite_async.py \
        packages/cli/tests/chain/conftest.py \
        packages/cli/tests/chain/test_pipeline.py
git commit -m "$(cat <<'EOF'
feat(chain): introduce AsyncExtractionPipeline + convert test_pipeline.py

Adds AsyncExtractionPipeline class using ChainStoreProtocol. Sync
ExtractionPipeline is left in place for sync callers in
subscriptions/batch/cli.py/entity_ops/exporter — those migrate in
later tasks. test_pipeline.py now uses the new async pipeline +
async_chain_stores fixture.

Also folds deferred Phase 1 cleanups: AsyncChainStore cache methods
now filter by user_id in SQL (migration v4 columns merged), and
stage 3 LLM cache uses the consolidated _cache_keys.extraction_cache_key
helper.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 22b: Introduce AsyncLinkerEngine + fold deferred set_run_status cleanup + convert test_linker_engine.py

**Files:**
- Modify: `packages/cli/src/opentools/chain/linker/engine.py`
- Modify: `packages/cli/src/opentools/chain/models.py` (add `status` field to `LinkerRun`)
- Modify: `packages/cli/src/opentools/chain/stores/sqlite_async.py` (fold deferred cleanup 1)
- Modify: `packages/cli/tests/chain/test_linker_engine.py`

- [ ] **Step 1: Add `status` field to LinkerRun model**

In `models.py`, locate `LinkerRun` dataclass. Add:

```python
@dataclass
class LinkerRun:
    id: str
    scope: LinkerScope
    scope_id: str | None
    mode: LinkerMode
    generation: int
    started_at: datetime
    finished_at: datetime | None = None
    findings_processed: int = 0
    entities_extracted: int = 0
    relations_created: int = 0
    relations_updated: int = 0
    relations_skipped_sticky: int = 0
    rule_stats: dict = field(default_factory=dict)
    error: str | None = None
    status: str = "pending"  # NEW: pending | running | done | failed
    user_id: UUID | None = None
```

- [ ] **Step 2: Fold deferred cleanup 1 — set_run_status writes to status_text column**

In `sqlite_async.py`, update `set_run_status`:

```python
async def set_run_status(
    self, run_id: str, status: str, *, user_id: UUID | None,
) -> None:
    self._require_initialized()
    await self._execute(
        "UPDATE linker_run SET status_text = ? WHERE id = ? AND "
        "(user_id IS ? OR user_id = ?)",
        (status, run_id, user_id, str(user_id) if user_id else None),
    )
    if self._txn_depth == 0:
        await self._conn.commit()
    # Remove the self._run_status dict scaffolding — no longer needed.
```

Delete the `self._run_status: dict = {}` attribute from `AsyncChainStore.__init__`.

Update `_row_to_linker_run` (or equivalent row-to-dataclass helper) to populate `LinkerRun.status = row["status_text"] or "pending"`.

- [ ] **Step 3: Add AsyncLinkerEngine class to engine.py**

Leave existing sync `LinkerEngine` untouched. ADD a new class below it. Structure:

```python
class AsyncLinkerEngine:
    """Async rule-based linker using ChainStoreProtocol."""

    def __init__(
        self,
        *,
        store,  # ChainStoreProtocol
        config: ChainConfig,
        rules: list[Rule] | None = None,
    ) -> None:
        self.store = store
        self.config = config
        self.rules = rules if rules is not None else get_default_rules(config)

    async def make_context(self, *, user_id: UUID | None) -> LinkerContext:
        generation = await self.store.current_linker_generation(user_id=user_id)
        n_findings = await self.store.count_findings_in_scope(user_id=user_id)
        avg_idf = await self.store.compute_avg_idf(user_id=user_id)
        common_entity_threshold = derive_common_entity_threshold(
            n_findings, self.config.linker,
        )
        return LinkerContext(
            generation=generation,
            n_findings_in_scope=n_findings,
            avg_idf=avg_idf,
            common_entity_threshold=common_entity_threshold,
            rule_stats={},
        )

    async def link_finding(
        self,
        finding_id: str,
        *,
        user_id: UUID | None,
        context: LinkerContext | None = None,
    ) -> LinkerRun:
        start = time.monotonic()
        ctx = context or await self.make_context(user_id=user_id)

        run_id = f"run_{uuid.uuid4().hex[:12]}"
        now = _utcnow()

        # 1. Load the source finding via protocol
        source_findings = await self.store.fetch_findings_by_ids(
            [finding_id], user_id=user_id,
        )
        if not source_findings:
            return await self._record_run(
                run_id, now, 0, 0, 0, 0, 0,
                error=f"finding {finding_id} not found",
                generation=ctx.generation,
                user_id=user_id,
            )
        source_finding = source_findings[0]

        # 2. Load the source finding's entities via protocol
        source_entities = await self.store.entities_for_finding(
            finding_id, user_id=user_id,
        )
        if not source_entities:
            return await self._record_run(
                run_id, now, 1, 0, 0, 0, 0,
                generation=ctx.generation, user_id=user_id,
            )

        # 3. Inverted-index partner lookup (spec G6: single batch fetch)
        source_entity_ids = {e.id for e in source_entities}
        partner_map = await self.store.fetch_candidate_partners(
            finding_id=finding_id,
            entity_ids=source_entity_ids,
            common_entity_threshold=ctx.common_entity_threshold,
            user_id=user_id,
        )

        # Single batch fetch for ALL partner findings (replaces per-partner loop)
        partner_findings = await self.store.fetch_findings_by_ids(
            list(partner_map.keys()), user_id=user_id,
        )
        partner_by_id = {p.id: p for p in partner_findings}

        # 4. Apply rules per partner
        relations_to_upsert: list[FindingRelation] = []
        relations_updated = 0
        relations_skipped_sticky = 0
        rule_stats: dict[str, dict] = {}

        for partner_id, shared_entity_ids in partner_map.items():
            partner_finding = partner_by_id.get(partner_id)
            if partner_finding is None:
                continue
            shared_entities = [e for e in source_entities if e.id in shared_entity_ids]

            # Rule application loop is IDENTICAL to sync LinkerEngine.link_finding
            # body — copy verbatim, only the store access surrounding it changes.
            ...

        async with self.store.transaction():
            if relations_to_upsert:
                await self.store.upsert_relations_bulk(
                    relations_to_upsert, user_id=user_id,
                )

        duration_ms = int((time.monotonic() - start) * 1000)

        return await self._record_run(
            run_id, now,
            findings_processed=1,
            entities_extracted=len(source_entities),
            relations_created=len(relations_to_upsert),
            relations_updated=relations_updated,
            relations_skipped_sticky=relations_skipped_sticky,
            duration_ms=duration_ms,
            rule_stats=rule_stats,
            generation=ctx.generation,
            user_id=user_id,
        )

    async def _record_run(self, run_id, now, findings_processed, entities_extracted,
                          relations_created, relations_updated, relations_skipped_sticky,
                          *, generation, user_id, error=None, rule_stats=None,
                          duration_ms=0) -> LinkerRun:
        run = await self.store.start_linker_run(
            scope=LinkerScope.ENGAGEMENT,
            scope_id=None,
            mode=LinkerMode.RULES_ONLY,
            user_id=user_id,
        )
        await self.store.finish_linker_run(
            run.id,
            findings_processed=findings_processed,
            entities_extracted=entities_extracted,
            relations_created=relations_created,
            relations_updated=relations_updated,
            relations_skipped_sticky=relations_skipped_sticky,
            rule_stats=rule_stats or {},
            user_id=user_id,
        )
        await self.store.set_run_status(run.id, "done" if not error else "failed", user_id=user_id)
        run.status = "done" if not error else "failed"
        run.error = error
        return run
```

**Implementation note:** The rule-application loop body (rule.apply, contribution collection, direction resolution, FindingRelation construction) is identical to the sync engine's `link_finding`. Copy verbatim — do not reinvent it.

- [ ] **Step 4: Convert test_linker_engine.py to async**

For each of 6 tests:
- `def test_*(engagement_store_and_chain)` → `async def test_*(async_chain_stores)`
- `ExtractionPipeline(store=chain_store, ...)` → `AsyncExtractionPipeline(store=chain_store, ...)` + `await pipeline.extract_for_finding(...)`
- `LinkerEngine(store=chain_store, ...)` → `AsyncLinkerEngine(store=chain_store, ...)`
- `engine.make_context(user_id=None)` → `await engine.make_context(user_id=None)`
- `engine.link_finding(fid, user_id=None, context=ctx)` → `await engine.link_finding(fid, user_id=None, context=ctx)`

- [ ] **Step 5: Run and commit**

```bash
python -m pytest packages/cli/tests/chain/test_linker_engine.py -v
```
Expected: 6 passed.

```bash
python -m pytest packages/ -q
```
Expected: ≥ 613 passed.

```bash
git add packages/cli/src/opentools/chain/linker/engine.py \
        packages/cli/src/opentools/chain/models.py \
        packages/cli/src/opentools/chain/stores/sqlite_async.py \
        packages/cli/tests/chain/test_linker_engine.py
git commit -m "$(cat <<'EOF'
feat(chain): introduce AsyncLinkerEngine + convert test_linker_engine.py

Adds AsyncLinkerEngine class using ChainStoreProtocol. Replaces
per-partner load loop with single batch fetch_findings_by_ids call
(spec G6). Wraps relation upserts in store.transaction() for atomicity.

Also folds deferred Phase 1 cleanup: set_run_status now writes to
the linker_run.status_text column (migration v4) instead of the
temporary in-memory _run_status dict. LinkerRun model gains a
status field populated from status_text.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 22c: Async llm_link_pass using protocol + convert test_llm_pass.py

**Files:**
- Modify: `packages/cli/src/opentools/chain/linker/llm_pass.py`
- Modify: `packages/cli/tests/chain/test_llm_pass.py`

- [ ] **Step 1: Rewrite llm_link_pass_async against protocol**

The current `llm_link_pass_async` still uses raw SQL via sync store. Rewrite it:
- Change the `store` parameter type hint to accept `ChainStoreProtocol`
- Replace relation fetch with `await store.fetch_relations_in_scope(statuses=[RelationStatus.CANDIDATE], user_id=user_id, min_weight=..., max_weight=...)`
- Replace per-edge UPDATE with `await store.apply_link_classification(relation_id, classification, user_id=user_id)`
- Replace cache lookups with `await store.get_llm_link_cache(cache_key, user_id=user_id)` / `put_llm_link_cache(...)`
- Import `link_classification_cache_key` from `opentools.chain._cache_keys` (folds deferred cleanup 3 for llm_pass)
- Wrap per-edge (classification + cache write) in `async with store.transaction():`

Leave the sync `llm_link_pass` function untouched — it still depends on sync store for callers that haven't migrated.

- [ ] **Step 2: Convert test_llm_pass.py to async**

5 tests. Convert `_seed_candidate_edge(engagement_store, chain_store)` helper to:

```python
async def _seed_candidate_edge(engagement_store, chain_store):
    now = datetime.now(timezone.utc)
    a = Finding(
        id="fl_a", engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title="A", description="SSH on 10.0.0.5", created_at=now,
    )
    b = Finding(
        id="fl_b", engagement_id="eng_test", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title="B", description="HTTP on 10.0.0.5", created_at=now,
    )
    engagement_store.add_finding(a)
    engagement_store.add_finding(b)

    cfg = ChainConfig()
    pipeline = AsyncExtractionPipeline(store=chain_store, config=cfg)
    await pipeline.extract_for_finding(a)
    await pipeline.extract_for_finding(b)

    engine = AsyncLinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))
    ctx = await engine.make_context(user_id=None)
    await engine.link_finding(a.id, user_id=None, context=ctx)
    return a, b
```

Update each test:
- `def test_*(engagement_store_and_chain)` → `async def test_*(async_chain_stores)`
- `_seed_candidate_edge(engagement_store, chain_store)` → `await _seed_candidate_edge(engagement_store, chain_store)`
- `llm_link_pass(provider=..., store=chain_store, ...)` → `await llm_link_pass_async(provider=..., store=chain_store, ...)`
- Imports: `from opentools.chain.linker.llm_pass import llm_link_pass_async` (replaces sync import)

Any raw SQL in tests that demotes relations to CANDIDATE must use an `await store.apply_link_classification(...)` call or an equivalent protocol method.

- [ ] **Step 3: Run and commit**

```bash
python -m pytest packages/cli/tests/chain/test_llm_pass.py -v
python -m pytest packages/ -q
```
Expected: ≥ 613 passed.

```bash
git add packages/cli/src/opentools/chain/linker/llm_pass.py \
        packages/cli/tests/chain/test_llm_pass.py
git commit -m "$(cat <<'EOF'
feat(chain): async llm_link_pass uses protocol + converts test_llm_pass

llm_link_pass_async now uses ChainStoreProtocol methods
(fetch_relations_in_scope, apply_link_classification, LLM cache
get/put). Wraps per-edge classification + cache write in
store.transaction() for atomicity. Folds deferred cleanup 3:
imports link_classification_cache_key from _cache_keys module.

Sync llm_link_pass is left in place until Task 30 (final sync
deletion) for consumers not yet migrated.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 22d: AsyncChainBatchContext with staged parallel extraction + convert test_linker_batch.py

**Files:**
- Modify: `packages/cli/src/opentools/chain/linker/batch.py`
- Modify: `packages/cli/tests/chain/test_linker_batch.py`

- [ ] **Step 1: Add AsyncChainBatchContext class**

Leave sync `ChainBatchContext` untouched. ADD below it:

```python
_async_nesting = 0
_EXTRACTION_CONCURRENCY = 4


class AsyncChainBatchContext:
    """Async batch context with staged parallel extraction (spec O19).

    Stage 1: fetch all findings via a single fetch_findings_by_ids call.
    Stage 2: run extraction in parallel via asyncio.gather + Semaphore(4).
    Stage 3: link each finding sequentially (SQL serializes anyway).

    Each finding's extraction runs in its own per-finding transaction
    so partial progress is visible and a crash mid-batch is recoverable.
    """

    def __init__(
        self,
        *,
        pipeline: "AsyncExtractionPipeline",
        engine: "AsyncLinkerEngine",
    ) -> None:
        self.pipeline = pipeline
        self.engine = engine
        self._deferred: list[str] = []
        self._entered = False

    async def __aenter__(self) -> "AsyncChainBatchContext":
        global _async_nesting
        if _async_nesting > 0:
            raise RuntimeError("AsyncChainBatchContext does not support nesting")
        _async_nesting += 1
        set_batch_context(True)
        self._entered = True
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        global _async_nesting
        try:
            await self._flush()
        finally:
            _async_nesting -= 1
            set_batch_context(False)

    def defer_linking(self, finding_id: str) -> None:
        if not self._entered:
            raise RuntimeError("defer_linking called outside of 'async with' block")
        self._deferred.append(finding_id)

    async def _flush(self) -> None:
        if not self._deferred:
            return

        store = self.pipeline.store
        findings = await store.fetch_findings_by_ids(self._deferred, user_id=None)

        semaphore = asyncio.Semaphore(_EXTRACTION_CONCURRENCY)

        async def _extract_one(finding):
            async with semaphore:
                try:
                    await self.pipeline.extract_for_finding(finding)
                except Exception:
                    logger.exception("batch extract failed for %s", finding.id)

        await asyncio.gather(*(_extract_one(f) for f in findings))

        ctx = await self.engine.make_context(user_id=None)
        for fid in self._deferred:
            try:
                await self.engine.link_finding(fid, user_id=None, context=ctx)
            except Exception:
                logger.exception("batch link failed for %s", fid)
```

Add `import asyncio` at the top of the file if not already present.

- [ ] **Step 2: Convert test_linker_batch.py to async (5 tests)**

Each `with ChainBatchContext(pipeline=sync_pipeline, engine=sync_engine) as batch:` becomes `async with AsyncChainBatchContext(pipeline=async_pipeline, engine=async_engine) as batch:`. Fixture switches to `async_chain_stores`.

- [ ] **Step 3: Run and commit**

```bash
python -m pytest packages/cli/tests/chain/test_linker_batch.py -v
python -m pytest packages/ -q
```

```bash
git add packages/cli/src/opentools/chain/linker/batch.py \
        packages/cli/tests/chain/test_linker_batch.py
git commit -m "$(cat <<'EOF'
feat(chain): AsyncChainBatchContext with staged parallel extraction

Stage 1 fetches all deferred findings in one query; stage 2 runs
extraction in parallel via asyncio.gather + Semaphore(4); stage 3
links sequentially. Per-finding transactions (not whole-batch) so
partial progress is visible and crash-resilient.

Sync ChainBatchContext remains until Task 30 for sync consumers
not yet migrated.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 22e: Drain worker replaces sync subscribe_chain_handlers + convert test_subscriptions.py

**Files:**
- Modify: `packages/cli/src/opentools/chain/subscriptions.py`
- Modify: `packages/cli/tests/chain/test_subscriptions.py`

- [ ] **Step 1: Add drain worker to subscriptions.py**

Keep existing `subscribe_chain_handlers`, `set_batch_context`, and `reset_subscriptions` — they still support sync test fixtures until Task 30. ADD alongside them:

```python
import asyncio
from dataclasses import dataclass

_drain_queue: asyncio.Queue | None = None
_drain_worker_task: asyncio.Task | None = None


def _reset_drain_state() -> None:
    """Test helper: clear drain worker module state."""
    global _drain_queue, _drain_worker_task
    if _drain_worker_task is not None and not _drain_worker_task.done():
        _drain_worker_task.cancel()
    _drain_queue = None
    _drain_worker_task = None


@dataclass
class DrainWorker:
    """Handle for a running drain worker.

    Returned by start_drain_worker. Call `await worker.stop()` during
    CLI shutdown to drain pending work and cancel the background task.
    """
    task: asyncio.Task
    queue: asyncio.Queue

    async def stop(self) -> None:
        await self.queue.join()
        self.task.cancel()
        try:
            await self.task
        except asyncio.CancelledError:
            pass


async def start_drain_worker(store, pipeline, engine) -> DrainWorker:
    """Start a background drain worker and subscribe to finding.* events.

    Call from CLI command lifecycle AFTER constructing the store, pipeline,
    and engine. Returns a DrainWorker handle for orderly shutdown.

    The sync event-bus handler uses call_soon_threadsafe so it's safe
    to queue from any thread context (CLI main, engagement store thread).
    """
    global _drain_queue, _drain_worker_task

    if _drain_queue is None:
        _drain_queue = asyncio.Queue(maxsize=10000)

    async def _drain():
        while True:
            finding_id = await _drain_queue.get()
            try:
                if _in_batch_context:
                    continue
                findings = await store.fetch_findings_by_ids(
                    [finding_id], user_id=None,
                )
                if not findings:
                    continue
                await pipeline.extract_for_finding(findings[0])
                await engine.link_finding(finding_id, user_id=None)
            except Exception:
                logger.exception(
                    "drain worker extract+link failed for %s", finding_id,
                )
            finally:
                _drain_queue.task_done()

    _drain_worker_task = asyncio.create_task(_drain())

    bus = get_event_bus()
    loop = asyncio.get_running_loop()

    def _on_created(finding_id, **_kwargs):
        if _drain_queue is None:
            return
        try:
            loop.call_soon_threadsafe(_drain_queue.put_nowait, finding_id)
        except (asyncio.QueueFull, RuntimeError) as exc:
            logger.warning("drain queue dispatch failed: %s", exc)

    def _on_updated(finding_id, **_kwargs):
        _on_created(finding_id)

    def _on_deleted(finding_id, **_kwargs):
        pass  # FK cascade handles cleanup

    bus.subscribe("finding.created", _on_created)
    bus.subscribe("finding.updated", _on_updated)
    bus.subscribe("finding.deleted", _on_deleted)

    return DrainWorker(task=_drain_worker_task, queue=_drain_queue)
```

- [ ] **Step 2: Add drain worker tests to test_subscriptions.py**

Leave the 5 existing sync tests intact — they still pass because the sync `subscribe_chain_handlers` path is unchanged. ADD 2 new async tests:

```python
import asyncio

async def test_drain_worker_processes_finding_created(async_chain_stores):
    engagement_store, chain_store, _ = async_chain_stores
    reset_subscriptions()
    reset_event_bus()
    _reset_drain_state()

    cfg = ChainConfig()
    pipeline = AsyncExtractionPipeline(store=chain_store, config=cfg)
    engine = AsyncLinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    worker = await start_drain_worker(chain_store, pipeline, engine)

    engagement_store.add_finding(_finding("drain_a"))
    await worker.queue.join()

    mentions = await chain_store.mentions_for_finding("drain_a", user_id=None)
    assert len(mentions) >= 1

    await worker.stop()
    reset_subscriptions()
    reset_event_bus()
    _reset_drain_state()


async def test_drain_worker_respects_batch_context(async_chain_stores):
    engagement_store, chain_store, _ = async_chain_stores
    reset_subscriptions()
    reset_event_bus()
    _reset_drain_state()

    cfg = ChainConfig()
    pipeline = AsyncExtractionPipeline(store=chain_store, config=cfg)
    engine = AsyncLinkerEngine(store=chain_store, config=cfg, rules=get_default_rules(cfg))

    worker = await start_drain_worker(chain_store, pipeline, engine)

    set_batch_context(True)
    try:
        engagement_store.add_finding(_finding("drain_b"))
        await asyncio.sleep(0.1)  # let the worker drain what it can
        mentions = await chain_store.mentions_for_finding("drain_b", user_id=None)
        # Drain worker short-circuits inside batch context
        assert mentions == []
    finally:
        set_batch_context(False)

    await worker.stop()
    reset_subscriptions()
    reset_event_bus()
    _reset_drain_state()
```

Update imports at the top:
```python
from opentools.chain.subscriptions import (
    DrainWorker,
    _reset_drain_state,
    reset_subscriptions,
    set_batch_context,
    start_drain_worker,
    subscribe_chain_handlers,
)
from opentools.chain.extractors.pipeline import (
    AsyncExtractionPipeline,
    ExtractionPipeline,
)
from opentools.chain.linker.engine import AsyncLinkerEngine, LinkerEngine, get_default_rules
```

- [ ] **Step 3: Run and commit**

```bash
python -m pytest packages/cli/tests/chain/test_subscriptions.py -v
python -m pytest packages/ -q
```
Expected: ≥ 615 passed (5 old + 2 new drain tests).

```bash
git add packages/cli/src/opentools/chain/subscriptions.py \
        packages/cli/tests/chain/test_subscriptions.py
git commit -m "$(cat <<'EOF'
feat(chain): drain worker for async event-to-extraction dispatch

start_drain_worker returns a DrainWorker handle that CLI lifecycle
awaits on shutdown. Sync event handler uses call_soon_threadsafe
to queue from any thread. Sync subscribe_chain_handlers stays in
place for tests not yet migrated.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 22f: Convert cli.py rebuild command to async + async test_cli_commands.py rebuild tests

**Files:**
- Modify: `packages/cli/src/opentools/chain/cli.py`
- Modify: `packages/cli/tests/chain/test_cli_commands.py`

- [ ] **Step 1: Add async store helper + convert rebuild command**

In `cli.py`, ADD (don't remove the sync `_get_stores`):

```python
async def _get_stores_async() -> tuple[EngagementStore, "AsyncChainStore"]:
    from opentools.chain.stores.sqlite_async import AsyncChainStore
    db = _default_db_path()
    db.parent.mkdir(parents=True, exist_ok=True)
    engagement_store = EngagementStore(db_path=db)
    chain_store = AsyncChainStore(db_path=db)
    await chain_store.initialize()
    return engagement_store, chain_store
```

Convert the `rebuild` command to async:

```python
@app.command()
async def rebuild(
    engagement: str | None = typer.Option(None, "--engagement"),
    force: bool = typer.Option(False, "--force"),
) -> None:
    """Re-run extraction + linking for findings in scope."""
    from opentools.chain.extractors.pipeline import AsyncExtractionPipeline
    from opentools.chain.linker.engine import AsyncLinkerEngine

    engagement_store, chain_store = await _get_stores_async()
    try:
        cfg = get_chain_config()

        if engagement:
            finding_ids = await chain_store.fetch_findings_for_engagement(
                engagement, user_id=None,
            )
        else:
            # Use engagement_store for the "all engagements" path
            finding_ids = [
                f.id for f in engagement_store.list_findings(engagement_id=None)
            ]

        if not finding_ids:
            rprint("[yellow]no findings to process[/yellow]")
            return

        findings = await chain_store.fetch_findings_by_ids(finding_ids, user_id=None)

        pipeline = AsyncExtractionPipeline(store=chain_store, config=cfg)
        engine = AsyncLinkerEngine(
            store=chain_store, config=cfg, rules=get_default_rules(cfg),
        )

        processed = 0
        for f in findings:
            try:
                await pipeline.extract_for_finding(f, force=force)
            except Exception as exc:
                rprint(f"[red]extract failed for {f.id}: {exc}[/red]")
                continue
            processed += 1

        ctx = await engine.make_context(user_id=None)
        for f in findings:
            try:
                await engine.link_finding(f.id, user_id=None, context=ctx)
            except Exception as exc:
                rprint(f"[red]link failed for {f.id}: {exc}[/red]")

        rprint(f"[green]rebuild complete: {processed} findings processed[/green]")
    finally:
        await chain_store.close()
```

Typer supports `async def` commands natively as of 0.12+. Verify the installed version; if older, wrap with `asyncio.run` inside the command body instead.

Leave `status`, `entities`, `path`, `export`, `query` commands sync — they are converted in Task 25 / 29.

- [ ] **Step 2: Convert rebuild-test in test_cli_commands.py to async**

Identify the test(s) that exercise the rebuild command (likely `test_rebuild_command_reextracts_on_force` or similar). Typer's `CliRunner` handles async commands natively. If the test was structured as:

```python
def test_rebuild(engagement_store_and_chain):
    engagement_store, chain_store, _ = engagement_store_and_chain
    pipeline = ExtractionPipeline(store=chain_store, config=ChainConfig())
    pipeline.extract_for_finding(f1)
    pipeline.extract_for_finding(f2)
    ...
    runner.invoke(app, ["rebuild", "--engagement", "eng_test"])
```

Rewrite as:

```python
async def test_rebuild(async_chain_stores):
    engagement_store, chain_store, _ = async_chain_stores
    pipeline = AsyncExtractionPipeline(store=chain_store, config=ChainConfig())
    await pipeline.extract_for_finding(f1)
    await pipeline.extract_for_finding(f2)
    ...
    runner.invoke(app, ["rebuild", "--engagement", "eng_test"])
```

The `runner.invoke` call stays synchronous — Typer handles the async bridging internally. The seeding of fixture data is what needs to be awaited.

Any test that still uses the sync fixture + sync pipeline for non-rebuild commands (status, entities, path, export, query) stays unchanged until Task 25 / 29.

- [ ] **Step 3: Run and commit**

```bash
python -m pytest packages/cli/tests/chain/test_cli_commands.py -v
python -m pytest packages/ -q
```

```bash
git add packages/cli/src/opentools/chain/cli.py \
        packages/cli/tests/chain/test_cli_commands.py
git commit -m "$(cat <<'EOF'
feat(chain): convert cli rebuild command to async

_get_stores_async opens an AsyncChainStore against the default CLI
database. rebuild uses AsyncExtractionPipeline + AsyncLinkerEngine
and closes the store in a finally block. Other CLI commands remain
sync until their dependencies (entity_ops, exporter, query engine)
are converted in tasks 23-29.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 22g: Phase 2 closeout — verify zero sync callers of pipeline/engine/batch/llm_pass for converted test files

**Files:**
- None modified; this is a verification task

- [ ] **Step 1: Grep for remaining sync callers in converted test files**

```bash
grep -rn "ExtractionPipeline(" packages/cli/tests/chain/test_pipeline.py \
    packages/cli/tests/chain/test_linker_engine.py \
    packages/cli/tests/chain/test_linker_batch.py \
    packages/cli/tests/chain/test_llm_pass.py \
    packages/cli/tests/chain/test_subscriptions.py
```
Expected: only `AsyncExtractionPipeline(` matches (or zero if the file doesn't construct one). Any bare `ExtractionPipeline(` in these files is a conversion miss — fix in a follow-up commit before proceeding.

```bash
grep -rn "LinkerEngine(" packages/cli/tests/chain/test_linker_engine.py \
    packages/cli/tests/chain/test_linker_batch.py \
    packages/cli/tests/chain/test_llm_pass.py \
    packages/cli/tests/chain/test_subscriptions.py
```
Expected: only `AsyncLinkerEngine(` matches.

- [ ] **Step 2: Verify Phase 2 gate**

```bash
scripts/check_test_count.sh 615
```
Expected: `OK: <N> tests passing (>= 615)`.

- [ ] **Step 3: No commit — Phase 2 already landed in tasks 22a–22f**

This task is a checkpoint. If the greps reveal misses, create a small follow-up commit with message `fix(chain): phase2 conversion miss in <file>`.

---

# PHASE 3 — Entity ops + exporter + remaining sync-caller-free CLI commands

## Task 23: Convert entity_ops to async + test_entity_ops.py

**Files:**
- Modify: `packages/cli/src/opentools/chain/entity_ops.py`
- Modify: `packages/cli/tests/chain/test_entity_ops.py`

- [ ] **Step 1: Rewrite entity_ops.py to be async**

Convert `merge_entities` and `split_entity` to `async def`. Change `store: ChainStore` type hint to accept `ChainStoreProtocol`. Replace internal raw SQL with protocol methods:

- `store.get_entity(id, user_id=user_id)` (already a protocol method)
- `store.rewrite_mentions_entity_id(source_entity_id, target_entity_id, user_id=user_id)`
- `store.delete_entity(id, user_id=user_id)`
- For split: `store.fetch_mentions_with_engagement(entity_id, user_id=user_id)` returns `(mention_id, engagement_id)` pairs; partition then `store.rewrite_mentions_by_ids(mention_ids, target_entity_id, user_id=user_id)`
- Wrap each operation in `async with store.batch_transaction():`

Delete the file's `from opentools.chain.store_extensions import ChainStore` import (no longer needed).

- [ ] **Step 2: Convert test_entity_ops.py to async (6 tests)**

For each test:
- Switch fixture: `async_chain_stores`
- Seeding: `AsyncExtractionPipeline(...)` + `await pipeline.extract_for_finding(f)`
- Entity ops calls: `await merge_entities(store=chain_store, ...)`, `await split_entity(...)`

- [ ] **Step 3: Run and commit**

```bash
python -m pytest packages/cli/tests/chain/test_entity_ops.py -v
python -m pytest packages/ -q
```
Expected: ≥ 615 passed.

```bash
git add packages/cli/src/opentools/chain/entity_ops.py \
        packages/cli/tests/chain/test_entity_ops.py
git commit -m "$(cat <<'EOF'
feat(chain): convert entity_ops merge/split to async via protocol

Each operation wrapped in store.batch_transaction() for atomicity.
Uses rewrite_mentions_entity_id and rewrite_mentions_by_ids protocol
methods; no more direct SQL.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 24: Convert exporter to async + test_exporter.py

**Files:**
- Modify: `packages/cli/src/opentools/chain/exporter.py`
- Modify: `packages/cli/tests/chain/test_exporter.py`

- [ ] **Step 1: Rewrite exporter.py to be async**

Convert `export_chain` and `import_chain` to `async def`. Change store type hint to `ChainStoreProtocol`. Replace internals:

- Export: `store.fetch_findings_for_engagement(engagement_id, user_id=user_id)` to get IDs, then `async for item in store.export_dump_stream(finding_ids, user_id=user_id)` yielding entity/mention/relation dicts. Write each item to the output file as it arrives (bounded memory per spec O12).
- Import: `async with store.batch_transaction():` wrapping the entire import loop. Use `upsert_entities_bulk`, `add_mentions_bulk`, `upsert_relations_bulk`.

- [ ] **Step 2: Convert test_exporter.py to async (5 tests)**

Standard mechanical conversion. Seed with `AsyncExtractionPipeline`.

- [ ] **Step 3: Run and commit**

```bash
python -m pytest packages/cli/tests/chain/test_exporter.py -v
python -m pytest packages/ -q
```

```bash
git add packages/cli/src/opentools/chain/exporter.py \
        packages/cli/tests/chain/test_exporter.py
git commit -m "$(cat <<'EOF'
feat(chain): async exporter with streaming export_dump_stream

Uses export_dump_stream for bounded memory; wraps import loop in
batch_transaction for atomicity.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 25: Convert cli.py status, entities, export commands to async

**Files:**
- Modify: `packages/cli/src/opentools/chain/cli.py`
- Modify: `packages/cli/tests/chain/test_cli_commands.py` (non-path, non-query tests only)

- [ ] **Step 1: Convert three commands**

`status`, `entities`, `export` don't depend on the query engine / graph cache / presets (those wait for Phase 4). Each command becomes:

```python
@app.command()
async def status() -> None:
    _engagement_store, chain_store = await _get_stores_async()
    try:
        # Use protocol methods instead of raw SQL COUNT queries
        entities = await chain_store.list_entities(user_id=None, limit=1000000)
        relations = await chain_store.fetch_relations_in_scope(
            statuses=None, user_id=None,
        )
        runs = await chain_store.fetch_linker_runs(user_id=None, limit=1)
        ...
    finally:
        await chain_store.close()
```

`entities`: use `await chain_store.list_entities(entity_type=type_, limit=limit, user_id=None)`.

`export`: `from opentools.chain.exporter import export_chain` (now async) — `await export_chain(store=chain_store, engagement_id=engagement, output_path=output)`.

- [ ] **Step 2: Convert relevant tests in test_cli_commands.py**

Only the tests that exercise status/entities/export. Seeding uses `AsyncExtractionPipeline`.

- [ ] **Step 3: Run and commit**

```bash
python -m pytest packages/cli/tests/chain/test_cli_commands.py -v
python -m pytest packages/ -q
```

```bash
git add packages/cli/src/opentools/chain/cli.py \
        packages/cli/tests/chain/test_cli_commands.py
git commit -m "$(cat <<'EOF'
feat(chain): convert cli status/entities/export commands to async

path and query commands remain sync pending Phase 4 query engine
conversion.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

# PHASE 4 — Query engine + graph cache + presets + narration + final sync deletion

## Task 26: Async GraphCache with concurrent build lock (spec G4)

**Files:**
- Modify: `packages/cli/src/opentools/chain/query/graph_cache.py`
- Modify: `packages/cli/tests/chain/test_graph_cache.py`

- [ ] **Step 1: Rewrite GraphCache**

`get_master_graph` becomes `async def`. Uses `asyncio.Lock` per cache key:

```python
class GraphCache:
    def __init__(self, *, store, maxsize: int = 8) -> None:
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
        generation = await self.store.current_linker_generation(user_id=user_id)
        key = (
            str(user_id) if user_id else None,
            generation, include_candidates, include_rejected,
        )
        if key in self._cache:
            self._access_order.remove(key)
            self._access_order.append(key)
            return self._cache[key]

        # Per-key lock collapses duplicate concurrent builds (spec G4)
        lock = self._build_locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key in self._cache:  # re-check after waiting
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

    async def _build_master_graph(self, user_id, generation, include_candidates, include_rejected):
        master = MasterGraph(...)  # build empty
        async for rel in self.store.stream_relations_in_scope(
            user_id=user_id,
            statuses=self._status_filter(include_candidates, include_rejected),
        ):
            ...  # add edge to rustworkx graph
        return master
```

- [ ] **Step 2: Add concurrent-build test**

```python
async def test_graph_cache_concurrent_build_collapses_to_one(async_chain_stores):
    engagement_store, chain_store, _ = async_chain_stores
    # Seed via AsyncExtractionPipeline + AsyncLinkerEngine ...

    cache = GraphCache(store=chain_store, maxsize=4)

    build_count = 0
    original = cache._build_master_graph

    async def counting_build(*args, **kwargs):
        nonlocal build_count
        build_count += 1
        return await original(*args, **kwargs)

    cache._build_master_graph = counting_build

    results = await asyncio.gather(*[
        cache.get_master_graph(user_id=None) for _ in range(10)
    ])

    assert build_count == 1  # G4: per-key lock collapses duplicates
    assert all(r is results[0] for r in results)
```

- [ ] **Step 3: Convert remaining test_graph_cache.py tests (10 total, +1 new = 11)**

- [ ] **Step 4: Run and commit**

```bash
python -m pytest packages/cli/tests/chain/test_graph_cache.py -v
python -m pytest packages/ -q
```
Expected: ≥ 616 passed.

```bash
git add packages/cli/src/opentools/chain/query/graph_cache.py \
        packages/cli/tests/chain/test_graph_cache.py
git commit -m "$(cat <<'EOF'
feat(chain): async GraphCache with per-key build lock (G4)

Concurrent get_master_graph for the same key collapses to a single
build via asyncio.Lock. Uses stream_relations_in_scope for bounded
memory. Drops the generation-recheck pattern (process-local staleness
is acceptable per spec).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 27: Async ChainQueryEngine + test_endpoints.py + test_neighborhood.py conversions

**Files:**
- Modify: `packages/cli/src/opentools/chain/query/engine.py`
- Modify: `packages/cli/src/opentools/chain/query/neighborhood.py`
- Modify: `packages/cli/tests/chain/test_query_engine.py`
- Modify: `packages/cli/tests/chain/test_endpoints.py`
- Modify: `packages/cli/tests/chain/test_neighborhood.py`

- [ ] **Step 1: Convert query/engine.py**

`k_shortest_paths` becomes `async def`. Its only `await` is `await self.graph_cache.get_master_graph(...)`. Endpoint resolution and Yen's algorithm stay sync (pure in-memory). Change `store: ChainStore` → `store: ChainStoreProtocol` or delete the explicit hint.

- [ ] **Step 2: Convert query/neighborhood.py**

Neighborhood functions that touch the store become async. Functions operating purely on in-memory graphs stay sync.

- [ ] **Step 3: Convert test_query_engine.py, test_endpoints.py, test_neighborhood.py**

All three switch to `async_chain_stores` fixture, seed via `AsyncExtractionPipeline` + `AsyncLinkerEngine`, await query calls.

- [ ] **Step 4: Run and commit**

```bash
python -m pytest packages/cli/tests/chain/test_query_engine.py \
                 packages/cli/tests/chain/test_endpoints.py \
                 packages/cli/tests/chain/test_neighborhood.py -v
python -m pytest packages/ -q
```

```bash
git add packages/cli/src/opentools/chain/query/engine.py \
        packages/cli/src/opentools/chain/query/neighborhood.py \
        packages/cli/tests/chain/test_query_engine.py \
        packages/cli/tests/chain/test_endpoints.py \
        packages/cli/tests/chain/test_neighborhood.py
git commit -m "$(cat <<'EOF'
feat(chain): async ChainQueryEngine + neighborhood + test conversions

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 28: Async presets + narration + test conversions

**Files:**
- Modify: `packages/cli/src/opentools/chain/query/presets.py`
- Modify: `packages/cli/src/opentools/chain/query/narration.py`
- Modify: `packages/cli/tests/chain/test_presets.py`
- Modify: `packages/cli/tests/chain/test_narration.py`

- [ ] **Step 1: Convert presets.py**

All 5 built-in presets (`lateral_movement`, `priv_esc_chains`, `external_to_internal`, `crown_jewel`, `mitre_coverage`) become `async def`. They call `await qe.k_shortest_paths(...)`.

- [ ] **Step 2: Convert narration.py**

`narrate_path` stays async (it already is). Update cache lookups to use protocol: `await store.get_llm_link_cache(cache_key, user_id=user_id)` + `put_llm_link_cache(...)`. Fold deferred cleanup 3: use `narration_cache_key` from `_cache_keys.py` with `user_id`.

- [ ] **Step 3: Convert test_presets.py (8 tests) + test_narration.py (4 tests)**

- [ ] **Step 4: Run and commit**

```bash
python -m pytest packages/cli/tests/chain/test_presets.py \
                 packages/cli/tests/chain/test_narration.py -v
python -m pytest packages/ -q
```

```bash
git add packages/cli/src/opentools/chain/query/presets.py \
        packages/cli/src/opentools/chain/query/narration.py \
        packages/cli/tests/chain/test_presets.py \
        packages/cli/tests/chain/test_narration.py
git commit -m "$(cat <<'EOF'
feat(chain): async presets + narration + test conversions

narration uses consolidated _cache_keys.narration_cache_key
(deferred cleanup 3 closed).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 29: Convert cli.py path + query commands to async

**Files:**
- Modify: `packages/cli/src/opentools/chain/cli.py`
- Modify: `packages/cli/tests/chain/test_cli_commands.py` (path + query tests)

- [ ] **Step 1: Convert path command**

```python
@app.command()
async def path(
    from_: str = typer.Argument(..., metavar="FROM"),
    to: str = typer.Argument(...),
    k: int = typer.Option(5, "-k"),
    max_hops: int = typer.Option(6, "--max-hops"),
    include_candidates: bool = typer.Option(False, "--include-candidates"),
) -> None:
    _engagement_store, chain_store = await _get_stores_async()
    try:
        cfg = get_chain_config()
        cache = GraphCache(store=chain_store, maxsize=4)
        qe = ChainQueryEngine(store=chain_store, graph_cache=cache, config=cfg)

        try:
            from_spec = parse_endpoint_spec(from_)
            to_spec = parse_endpoint_spec(to)
        except ValueError as exc:
            rprint(f"[red]invalid endpoint: {exc}[/red]")
            raise typer.Exit(code=1)

        results = await qe.k_shortest_paths(
            from_spec=from_spec, to_spec=to_spec,
            user_id=None, k=k, max_hops=max_hops,
            include_candidates=include_candidates,
        )
        # ... rendering unchanged
    finally:
        await chain_store.close()
```

- [ ] **Step 2: Convert query command**

Similar treatment. Each preset branch `await`s its call.

- [ ] **Step 3: Convert test_cli_commands.py path + query tests**

- [ ] **Step 4: Run and commit**

```bash
python -m pytest packages/cli/tests/chain/test_cli_commands.py -v
python -m pytest packages/ -q
```

```bash
git add packages/cli/src/opentools/chain/cli.py \
        packages/cli/tests/chain/test_cli_commands.py
git commit -m "$(cat <<'EOF'
feat(chain): convert cli path + query commands to async

All chain CLI commands now use AsyncChainStore. The sync
_get_stores helper still exists for the sync ChainStore alias but
no CLI command references it.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 30: Final sync deletion — rename Async* → canonical, delete sync classes

**Files:**
- Modify: `packages/cli/src/opentools/chain/extractors/pipeline.py`
- Modify: `packages/cli/src/opentools/chain/linker/engine.py`
- Modify: `packages/cli/src/opentools/chain/linker/batch.py`
- Modify: `packages/cli/src/opentools/chain/linker/llm_pass.py`
- Modify: `packages/cli/src/opentools/chain/subscriptions.py`
- Modify: `packages/cli/src/opentools/chain/cli.py`
- Modify: `packages/cli/tests/chain/conftest.py`
- Delete: `packages/cli/src/opentools/chain/store_extensions.py` (sync ChainStore shim)
- Delete: `packages/cli/tests/chain/test_pipeline.py`-embedded sync comparison tests (any that survived)

- [ ] **Step 1: Verify zero remaining sync callers**

```bash
grep -rn "from opentools.chain.store_extensions\|SyncChainStore\|ChainStore(" packages/cli/
```

Expected: matches only in `store_extensions.py` itself (about to be deleted). Any production match is a conversion miss.

```bash
grep -rn "ExtractionPipeline(" packages/cli/
grep -rn "LinkerEngine(" packages/cli/
grep -rn "ChainBatchContext(" packages/cli/
```

Should now only match `AsyncExtractionPipeline`, `AsyncLinkerEngine`, `AsyncChainBatchContext` — i.e., no bare sync constructors remain.

- [ ] **Step 2: Delete sync ExtractionPipeline class from pipeline.py**

Delete the `class ExtractionPipeline:` block entirely. Rename `AsyncExtractionPipeline` → `ExtractionPipeline`. Remove any sync-specific helpers (`_run_stage1` sync variant, `_persist` sync variant, `_update_extraction_state`). Remove the `from opentools.chain.store_extensions import ChainStore` import.

- [ ] **Step 3: Same surgery in engine.py, batch.py, llm_pass.py**

- `linker/engine.py`: delete `class LinkerEngine:` block, rename `AsyncLinkerEngine` → `LinkerEngine`
- `linker/batch.py`: delete `class ChainBatchContext:` and `_nesting` global, rename `AsyncChainBatchContext` → `ChainBatchContext`, rename `_async_nesting` → `_nesting`
- `linker/llm_pass.py`: delete sync `llm_link_pass` function, rename `llm_link_pass_async` → `llm_link_pass`

- [ ] **Step 4: Delete sync subscribe_chain_handlers path from subscriptions.py**

Delete `subscribe_chain_handlers`, `_on_created`/`_on_updated`/`_on_deleted` sync inner functions, `_load_finding` helper, `StoreFactory`/`PipelineFactory`/`EngineFactory` type aliases, `_subscribed` global. Keep: `set_batch_context`, `reset_subscriptions` (now only resets drain state), `DrainWorker`, `start_drain_worker`, `_reset_drain_state`.

- [ ] **Step 5: Delete _get_stores sync helper from cli.py**

Remove `_get_stores()` and its call sites. Rename `_get_stores_async` → `_get_stores`. Remove `from opentools.chain.store_extensions import ChainStore` import.

- [ ] **Step 6: Delete store_extensions.py**

```bash
git rm packages/cli/src/opentools/chain/store_extensions.py
```

- [ ] **Step 7: Delete sync engagement_store_and_chain fixture from conftest.py**

Rename `async_chain_stores` → `engagement_store_and_chain` (reclaim the canonical name now that the sync version is gone). Update EVERY test file to use the new name (this is a mechanical `sed`-style rename; no test logic changes).

```bash
grep -rln "async_chain_stores" packages/cli/tests/chain/ | \
    xargs -I{} sed -i 's/async_chain_stores/engagement_store_and_chain/g' {}
```

(Use a Python script if the Windows shell's `sed` / `xargs` is unavailable.)

- [ ] **Step 8: Delete sync `chain_store` fixture**

The old `chain_store(tmp_path)` fixture in conftest.py (line 20–30) yields a sync ChainStore directly. If any test still uses it, migrate to the async fixture. Then delete the sync fixture.

- [ ] **Step 9: Update any remaining imports + type hints**

```bash
grep -rn "store_extensions" packages/cli/
grep -rn "ChainStore\b" packages/cli/src/opentools/chain/
```

The only `ChainStore` references should now be in `store_protocol.py` (protocol class is `ChainStoreProtocol`, not named `ChainStore`). Any dangling imports get fixed.

- [ ] **Step 10: Run full suite**

```bash
python -m pytest packages/ -q
```
Expected: ≥ 616 passed, 1 skipped. The count should be identical to after Task 29 — this task only renames.

```bash
scripts/check_test_count.sh 616
```

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
chore(chain): delete sync chain classes; Async* → canonical names

Phase 2-4 retirement pass. ExtractionPipeline, LinkerEngine,
ChainBatchContext, llm_link_pass, subscribe_chain_handlers now
refer exclusively to the async implementations using
ChainStoreProtocol. Sync store_extensions module deleted. CLI
_get_stores_async renamed to _get_stores. Conftest
async_chain_stores renamed to engagement_store_and_chain.

No behavior change — all consumers migrated in tasks 22-29.

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

# PHASE 5 — Postgres backend + web unification + cleanup

Phase 5 tasks are substantially UNCHANGED from the original plan's Tasks 36–47. This plan renumbers them but the content carries over. Subagent implementers should consult the original plan file (`docs/superpowers/plans/2026-04-10-phase3c1-5-async-store-refactor.md`) for the task bodies — ONLY the task numbers and test count gates need translation.

| Revised task | Original task | Summary |
|---|---|---|
| 31 | 36 | `PostgresChainStore` lifecycle + Alembic migration 004 (JSONB + user_id + UNLOGGED) |
| 32 | 37 | `PostgresChainStore` entity CRUD methods |
| 33 | 38 | `PostgresChainStore` mention CRUD |
| 34 | 39 | `PostgresChainStore` relation CRUD |
| 35 | 40 | `PostgresChainStore` linker queries + run lifecycle + `_web_finding_to_cli` helper |
| 36 | 41 | `PostgresChainStore` extraction state + LLM caches + export |
| 37 | 42 | Enable Postgres parameter in `test_store_protocol_conformance.py` |
| 38 | 43 | Rewrite web `chain_service.py` + `routes/chain.py` against shared pipeline + `chain_store_factory.py` |
| 39 | 44 | Delete `chain_rebuild.py` custom worker; move `run_rebuild_shared` to `chain_rebuild_worker.py` |
| 40 | 45 | Parameterize `test_pipeline_integration.py` over both backends |
| 41 | 46 | Rename `test_chain_rebuild.py` → `test_web_rebuild.py` and rewrite assertions against shared pipeline |
| 42 | 47 | Final baseline verification (scripts/check_test_count.sh 690) |

**Cross-task reminder applying to all of Phase 5:** the shared pipeline is now `ExtractionPipeline` (after Task 30's rename), not `AsyncExtractionPipeline`. Any Phase 5 original-plan snippet that references `AsyncExtractionPipeline` should use `ExtractionPipeline`.

---

# Self-Review

## Spec coverage

This plan covers every Phase 2+ requirement listed in the original spec's §14 scope checklist. Parallel async classes are a refinement of the original "convert in place" approach that preserves green commits while reaching the same final state (zero sync chain code, everything via `ChainStoreProtocol`).

Per-section verification:
- ✅ All chain consumers (pipeline, linker, batch, subscriptions, entity_ops, exporter, graph cache, query engine, presets, narration) converted to async → Tasks 22a–28
- ✅ CLI commands converted → Tasks 22f (rebuild), 25 (status/entities/export), 29 (path/query)
- ✅ Drain worker replaces sync event subscribers → Task 22e
- ✅ Sync `ChainStore` and all `Sync*` classes deleted → Task 30
- ✅ Deferred Phase 1 cleanups (status_text column, cache user_id SQL filter, _cache_keys consumer migration) → folded into 22a, 22b, 22c, 28
- ✅ Phase 5 Postgres backend + web unification → Tasks 31–42 (reference original plan)
- ✅ Canonical integration test on both backends → Task 40 (maps to original 45)

## Placeholder scan

This plan avoids placeholders by following the parallel-class convention: when a task adds `AsyncClassName` alongside existing `ClassName`, the implementer can copy the sync class's body verbatim for any Python-pure logic (normalization, rule application loops, dedup), changing only the store-interaction calls to `await protocol_method(...)`. The plan explicitly notes "copy verbatim — do not reinvent" wherever this applies.

The only implementation details left to the subagent are:
1. Exact function arguments of AsyncChainStore methods — these are already in `sqlite_async.py` and the subagent can read the file's public API.
2. SQL column names in `status_text` / cache tables — implementer reads migration v4 (`migrations/` dir) to confirm.
3. Whether Typer's current pinned version supports `async def` commands natively — implementer checks `pyproject.toml` and the installed `typer.__version__`; fallback is `asyncio.run` wrapping.

## Type consistency

- `AsyncExtractionPipeline` signature defined in Task 22a, referenced identically in 22b, 22c, 22d, 22e, 22f, 23–29.
- `AsyncLinkerEngine` signature defined in Task 22b, referenced identically in 22c, 22d, 22e, 22f, 23, 26–29.
- `AsyncChainBatchContext` signature defined in Task 22d.
- `DrainWorker.stop()` defined in Task 22e.
- `GraphCache.get_master_graph(*, user_id, include_candidates, include_rejected)` — Task 26.
- `ChainQueryEngine.k_shortest_paths(*, from_spec, to_spec, user_id, k, max_hops, include_candidates)` — Task 27.
- Protocol method names match the 41 methods listed in `store_protocol.py` as merged in Phase 1.

`LinkerRun.status` field is added in Task 22b and referenced in subsequent tasks that pass runs across the service boundary (mainly Phase 5 Task 38's web chain_service).

## Execution notes for subagent-driven-development

1. Baseline: **613 passed, 1 skipped** on main at commit `58d7d77`. Verify before starting 22a.
2. Each task 22a–30 is small enough for a single haiku dispatch in most cases. Tasks 22a, 22b, 22e (new code introductions) may need `standard` model. Task 30 is mechanical enough for haiku but the grep-verification steps require careful attention.
3. Between each task, run `python -m pytest packages/ -q` and verify against the gate table above.
4. If a task's test count dropped unexpectedly, the most likely cause is a test file conversion that lost a test — check the converted file against its pre-conversion version in git before proceeding.
5. Subagent-dispatch template: pass the exact task number, the worktree path, the parent HEAD SHA at dispatch, and the expected post-task test count. Tell the subagent "DO NOT read the original plan file or spec — all context is in this prompt."

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-04-11-phase3c1-5-phase2-revised-plan.md`.**

Recommended execution path: **Subagent-Driven Development** — fresh subagent per task, review between tasks. Phase 2+ has 17 discrete tasks (22a–g + 23–30 + 31–42); dispatching each to a focused subagent keeps the main conversation context clean and makes plan-vs-reality drift visible immediately at each review checkpoint.
