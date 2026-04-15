# Phase 3C.4: Cypher-Style Query DSL — Design Specification

**Date:** 2026-04-13
**Status:** Draft
**Author:** slabl + Claude
**Depends on:** Phase 3C.1 (data layer), 3C.2 (per-engagement viz), 3C.3 (global view + Bayesian calibration)

## 1. Overview

Phase 3C.4 adds a Cypher-style query DSL for custom graph queries over the attack chain knowledge graph. Users can write pattern-matching queries to explore findings, entities, and their relationships — from the CLI, an interactive REPL, or a web query editor.

The DSL is read-only (no mutations), operates on a virtual heterogeneous graph (findings + entities as first-class nodes), and supports plugin-extensible functions.

## 2. Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Parser library | `lark` (LALR mode) | Pure Python, EBNF, fast LALR parsing, actively maintained, ~500KB |
| Graph model | Virtual heterogeneous graph | Entities promoted to first-class nodes with MENTIONED_IN edges; enables pattern matching through entities |
| Variable-length paths | Edge-type-filtered traversal | Explicit relationship type labels control what edge types are followed; standard Cypher semantics |
| Architecture | Layered pipeline (Parser → Planner → VirtualGraphBuilder → Executor) | Each layer testable independently; virtual graph cached for REPL reuse; planner extensible for future optimization |
| Web query editor | Standalone page first, inline overlay last | Standalone page is independent and testable; inline overlay on graph pages is the final 3C.4 task |
| Plugin functions | Scalar + aggregation functions | `collect()` pulled into v1 grammar to support plugin aggregations |
| Result format | Dual: table + subgraph projection | Power users want both raw data and visual; subgraph projection is cheap |
| REPL interaction | Stateful sessions with named result sets | Documented as OpenTools extension; enables iterative exploration |
| Resource limits | Configurable with defaults (30s timeout, 1000 rows, 10,000 intermediate bindings) | Intermediate binding cap important because heterogeneous graph increases branching factor |
| Engagement scoping | Context-dependent | Pre-scoped from engagement pages, cross-engagement from standalone/global; engagement filter always available |
| Variable-length max hops | Hard cap of 10, enforced at parse time | Prevents combinatorial explosion even if other limits are raised |
| Plugin sandboxing | No sandbox in v1 | Plugins receive read-only property dicts; timeout kills hung plugins; true sandboxing deferred |

## 3. Grammar & Parser

**Grammar file:** `packages/cli/src/opentools/chain/cypher/grammar.lark`

**Parser:** `lark` with LALR mode. Parse output is a typed AST using Python dataclasses.

### 3.1 Supported Grammar (v1)

```
MATCH <pattern> [, <pattern>]*
[WHERE <expression>]
RETURN <return_item> [, <return_item>]*
```

**Patterns:**

```
(var:Label)                    — node pattern
-[var:Label]->                 — directed edge (outgoing)
<-[var:Label]-                 — directed edge (incoming)
-[var:Label*min..max]->        — variable-length path (outgoing)
<-[var:Label*min..max]-        — variable-length path (incoming)
```

**Node labels:** `Finding`, `Host`, `IP`, `CVE`, `Domain`, `Port`, `MitreAttack`, `Entity` (wildcard for any entity type).

**Edge labels:** `LINKED`, `MENTIONED_IN`.

**WHERE expressions:**

| Category | Syntax |
|---|---|
| Property access | `a.severity`, `r.weight`, `a.title` |
| Comparisons | `=`, `<>`, `<`, `>`, `<=`, `>=` |
| Boolean | `AND`, `OR`, `NOT` |
| String | `CONTAINS`, `STARTS WITH`, `ENDS WITH` |
| Membership | `IN [list]` |
| Null check | `IS NULL`, `IS NOT NULL` |
| Built-in functions | `length(path)`, `nodes(path)`, `relationships(path)`, `has_entity(node, type, value)`, `has_mitre(node, technique_id)` |
| Plugin functions | `plugin_name.function_name(args...)` |

**RETURN items:**

| Category | Syntax |
|---|---|
| Variables | `a`, `r`, `path` |
| Property access | `a.title`, `r.weight` |
| Aggregation | `collect(a)` |
| Plugin aggregations | `plugin_name.agg_function(collect(a))` |

### 3.2 Session Extension (OpenTools-specific)

```
result_name = MATCH ... RETURN ...
```

Stores the result set in a session variable, referenceable in later queries within the same REPL session. This is an OpenTools extension, not standard Cypher.

### 3.3 Read-Only Enforcement

The grammar does not define tokens for `CREATE`, `DELETE`, `SET`, `MERGE`, `REMOVE`, `DETACH`, `DROP`. These are caught as parse errors — mutation verbs never produce a valid AST.

### 3.4 AST Dataclasses

Defined in `ast_nodes.py`: `MatchClause`, `NodePattern`, `EdgePattern`, `VarLengthSpec`, `WhereExpr`, `ComparisonExpr`, `BooleanExpr`, `FunctionCallExpr`, `PropertyAccessExpr`, `ReturnClause`, `ReturnItem`, `SessionAssignment`.

## 4. Virtual Heterogeneous Graph

The virtual graph augments the existing `MasterGraph` (finding-only) with entity nodes and `MENTIONED_IN` edges.

### 4.1 Node Types

| Label | Source | Properties |
|---|---|---|
| `Finding` | `FindingNode` from `MasterGraph` | `id`, `severity`, `tool`, `title`, `created_at`, `engagement_id` |
| `Host` | `Entity` where `type="host"` | `id`, `canonical_value`, `mention_count` |
| `IP` | `Entity` where `type="ip"` | `id`, `canonical_value`, `mention_count` |
| `CVE` | `Entity` where `type="cve"` | `id`, `canonical_value`, `mention_count` |
| `Domain` | `Entity` where `type="domain"` | `id`, `canonical_value`, `mention_count` |
| `Port` | `Entity` where `type="port"` | `id`, `canonical_value`, `mention_count` |
| `MitreAttack` | `Entity` where `type="mitre_technique"` | `id`, `canonical_value`, `mention_count` |

Any entity type not in this list is accessible via the generic `Entity` label.

### 4.2 Edge Types

| Label | Direction | Meaning | Properties |
|---|---|---|---|
| `LINKED` | Finding → Finding | Existing `FindingRelation` edges | `weight`, `status`, `reasons`, `llm_rationale`, `llm_relation_type` |
| `MENTIONED_IN` | Entity → Finding | Derived from `EntityMention` rows | `field`, `confidence`, `extractor` |

### 4.3 VirtualGraphBuilder

**Location:** `packages/cli/src/opentools/chain/cypher/virtual_graph.py`

Takes a `MasterGraph` + entity/mention data from `ChainStoreProtocol` and produces a `VirtualGraph`:

```python
@dataclass
class VirtualGraph:
    graph: rx.PyDiGraph
    finding_map: dict[str, int]    # finding_id → node index
    entity_map: dict[str, int]     # entity_id → node index
    reverse_map: dict[int, str]    # node index → id (finding or entity)
    node_labels: dict[int, str]    # node index → label ("Finding", "Host", etc.)
    generation: int
```

### 4.4 Caching

`VirtualGraphCache` wraps `GraphCache`. Keyed by `(user_id, generation, include_candidates, engagement_ids_frozenset)`. Same async LRU pattern as `GraphCache` with per-key build lock. `maxsize=4`.

REPL sessions reuse the cache across queries — the virtual graph is only rebuilt when the linker generation advances or engagement scope changes.

### 4.5 Build Cost

For an engagement with 500 findings and 2,000 entities, the virtual graph adds ~2,000 nodes and ~5,000 MENTIONED_IN edges on top of the existing master graph. Build time dominated by entity/mention DB queries, not graph construction. Expected <500ms for typical engagement sizes.

## 5. Planner

The planner translates the AST into an ordered sequence of execution steps. In v1 it follows query order (no cost-based optimization), but the layer exists for future cardinality estimation and reordering.

### 5.1 Data Structures

```python
@dataclass
class QueryPlan:
    steps: list[PlanStep]
    return_spec: ReturnSpec
    limits: QueryLimits

@dataclass
class PlanStep:
    kind: Literal["scan", "expand", "filter", "var_length_expand"]
    target_var: str              # which query variable this step binds
    label: str | None            # node/edge label constraint
    direction: Literal["out", "in", "both"] | None
    min_hops: int | None         # for var_length_expand
    max_hops: int | None
    predicates: list[WhereExpr]  # pushed-down WHERE clauses for this step
```

**Step kinds:**

- **scan** — find all nodes matching a label, create one binding per match
- **expand** — follow edges from bound nodes to next pattern element
- **filter** — apply WHERE predicates to current bindings
- **var_length_expand** — bounded DFS for variable-length paths

### 5.2 Predicate Pushdown

The planner analyzes WHERE clauses and attaches each predicate to the earliest step whose bound variables satisfy it. `WHERE a.severity = "critical"` gets pushed down to the scan step that binds `a`, not deferred to a post-match filter pass. This is the one optimization v1 performs.

### 5.3 Variable-Length Path Planning

`(a:Finding)-[r:LINKED*1..5]->(b:Finding)` becomes three steps:

1. Scan for `a` (with any pushed-down predicates on `a`)
2. `var_length_expand` following LINKED edges 1-5 hops, binding `r` as a path variable
3. Bind `b` as the terminal node

The expand uses bounded DFS with the intermediate binding cap (default 10,000) as the kill switch.

### 5.4 Session Result References

Session variables can be used as the source in a MATCH pattern via `FROM` syntax:

```
critical = MATCH (a:Finding) WHERE a.severity = "critical" RETURN a
MATCH (a) FROM critical -[r:LINKED]->(b:Finding) RETURN a, b
```

The `FROM <variable>` clause tells the planner to insert a `scan` step that reads bindings from the session store instead of scanning the graph. The stored result set's column `a` seeds the binding table, and execution continues from there with the remaining pattern.

Only RETURN-ed variables from the stored result are available — internal bindings that were not returned are discarded.

## 6. Executor

The executor walks the `QueryPlan` against the `VirtualGraph`, managing bindings and enforcing resource limits.

### 6.1 Core Class

```python
class CypherExecutor:
    def __init__(
        self,
        *,
        virtual_graph: VirtualGraph,
        plan: QueryPlan,
        session: QuerySession,
        plugin_registry: PluginFunctionRegistry,
        limits: QueryLimits,
    ) -> None: ...

    async def execute(self) -> QueryResult: ...
```

### 6.2 Binding Table

The executor maintains a list of `Binding` dicts — each dict maps query variable names to graph node/edge indices. Every plan step transforms the binding table:

- **scan** — iterates all nodes with matching label, creates one binding per match
- **expand** — for each existing binding, follows edges of the specified type/direction, extends the binding with the new variable
- **filter** — evaluates predicates against each binding, drops non-matching rows
- **var_length_expand** — bounded DFS from each binding's current position, produces one binding per discovered path (the path variable binds to a `PathBinding` containing the full node/edge sequence)

### 6.3 Resource Enforcement

Checked at every step boundary:

- `len(bindings) <= intermediate_binding_cap` (default 10,000). Exceeding aborts with `QueryResourceError`.
- Monotonic timer checks against timeout (default 30s).
- Final result rows capped at `max_rows` (default 1,000) — applied after RETURN projection.

### 6.4 RETURN Projection

After all match steps complete, the executor projects the binding table:

- Variable references → serialize the bound node/edge data
- Property access (`a.severity`) → extract from node/edge payload
- `collect(a)` → group and aggregate
- Plugin functions → invoke registered callables with bound values

### 6.5 Output

```python
@dataclass
class QueryResult:
    columns: list[str]           # RETURN column names
    rows: list[dict[str, Any]]   # tabular data
    subgraph: SubgraphProjection | None  # union of all matched nodes/edges
    stats: QueryStats            # timing, bindings explored, rows returned
    truncated: bool
    truncation_reason: str | None

@dataclass
class SubgraphProjection:
    node_indices: set[int]
    edge_indices: set[tuple[int, int]]
```

### 6.6 Plugin Function Invocation

Plugin scalar functions receive property values and return scalars. Plugin aggregation functions receive `list[Any]` (collected values) and return scalars. Both called synchronously — async plugin functions not supported in v1. The query timeout kills hung plugins.

## 7. Plugin Function Registry

### 7.1 Registration API

```python
# packages/cli/src/opentools/chain/cypher/plugins.py

def register_query_function(
    name: str,              # "my_plugin.risk_score"
    fn: Callable,           # (value: Any) -> scalar
    *,
    help: str = "",
    arg_types: list[str],   # ["node"], ["node", "str"], etc.
    return_type: str,       # "float", "bool", "str"
) -> None: ...

def register_query_aggregation(
    name: str,              # "my_plugin.combined_risk"
    fn: Callable,           # (values: list[Any]) -> scalar
    *,
    help: str = "",
    input_type: str,
    return_type: str,
) -> None: ...
```

### 7.2 Namespacing

Plugin functions must use dotted names (`plugin_name.function_name`). Built-in functions (`length`, `nodes`, `relationships`, `has_entity`, `has_mitre`, `collect`) are un-namespaced. Prevents collisions and clarifies built-in vs. plugin in queries.

### 7.3 Validation

- Registration time: name collision check
- Plan time: all function references resolve to registered functions, argument counts match
- Unresolved functions produce `QueryValidationError` before execution

### 7.4 Discovery

`list_query_functions()` returns all registered functions with help text and signatures — used by REPL tab completion and web editor autocomplete.

## 8. CLI Surface

### 8.1 `opentools chain query run '<cypher>'`

Single-shot query execution.

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--timeout` | 30 | Query timeout in seconds |
| `--max-rows` | 1000 | Maximum result rows |
| `--engagement` | None | Scope to engagement (omit for cross-engagement) |
| `--include-candidates` | false | Include candidate-status edges |
| `--format` | table | Output format: `table`, `json`, `csv` |
| `--no-subgraph` | false | Skip subgraph projection |

### 8.2 `opentools chain query repl`

Interactive REPL session.

**Multi-line detection:** Open parens, trailing `-`, or trailing `|` prompt continuation lines. Prompt changes from `cypher>` to `   ...>`.

**Session variables:** `results = MATCH ... RETURN ...` stores the result set. Typing `results` alone re-displays it. Tab completion shows available session variables.

**Special commands (`:` prefix):**

| Command | Description |
|---|---|
| `:help` | Grammar reference and available functions |
| `:functions` | List all built-in and plugin functions |
| `:presets` | List available presets (for reference) |
| `:limits` | Show/set timeout, max-rows, intermediate cap |
| `:clear` | Clear session variables |
| `:quit` / `:exit` | Exit REPL |

Accepts `--engagement`, `--include-candidates` flags at launch, also settable via `:limits`.

Uses `prompt_toolkit` for line editing, history, and tab completion.

### 8.3 `opentools chain query explain '<cypher>'`

Dry-run that shows the query plan without executing. Outputs plan steps, pushed-down predicates, and estimated scan sizes.

## 9. Web Surface

### 9.1 Phase 1: Standalone Query Page

**Route:** `/chain/query`

**Backend endpoint:** `POST /api/chain/query`

Request:
```json
{
  "query": "MATCH (a:Finding)-[:LINKED]->(b:Finding) WHERE a.severity = 'critical' RETURN a, b",
  "engagement_id": "eng-123",
  "include_candidates": false,
  "timeout": 30,
  "max_rows": 1000
}
```

Response:
```json
{
  "columns": ["a", "b"],
  "rows": [{"a": {...}, "b": {...}}],
  "subgraph": {
    "nodes": [{"id": "...", "label": "Finding", "properties": {...}}],
    "edges": [{"source": "...", "target": "...", "label": "LINKED", "properties": {...}}]
  },
  "stats": {"duration_ms": 45, "bindings_explored": 312, "rows_returned": 8},
  "truncated": false
}
```

**Security:** Requires authentication. `user_id` from JWT propagated to executor. Queries cannot cross user boundaries.

**Metadata endpoint:** `GET /api/chain/query/functions` — returns all available functions with names, help text, arg types. Powers editor autocomplete.

**Frontend component:** `ChainQueryPage.vue`

Layout — split pane:
- **Top:** CodeMirror 6 editor with Cypher syntax highlighting. Autocomplete for labels, property names, functions (fetched from metadata endpoint). Run via button or Ctrl+Enter.
- **Bottom left:** Sortable data grid showing result rows. Columns from RETURN clause.
- **Bottom right:** Mini force-graph preview rendering the subgraph projection. Uses `ForceGraphCanvas` from 3C.2. Clicking a node in the table highlights it in the graph and vice versa.
- **Engagement filter:** Dropdown at top. Pre-populated from context if navigated from an engagement page.

### 9.2 Phase 2: Inline Overlay (Final 3C.4 Task)

Collapsible query panel added to `ChainGraphView.vue` and `GlobalChainView.vue`. Query results highlight matching nodes/edges in the main graph (yellow glow). Reuses CodeMirror editor and tabular results from standalone page, embedded as overlay. Engagement scope auto-set from current page context.

## 10. Safety & Security

### 10.1 Read-Only Enforcement

Two layers:
1. **Lexer-level:** Grammar does not define mutation verb tokens. Parse errors before AST.
2. **Executor-level:** Only rustworkx read methods called. No `ChainStoreProtocol` write methods invoked during execution.

### 10.2 User Scoping

`user_id` set once by `VirtualGraphBuilder` and propagated to every `ChainStoreProtocol` call. Web: `PostgresChainStore` enforces `@require_user_scope`. CLI: `user_id=None` (single-user).

### 10.3 Input Sanitization

Query string parsed by lark — rejects anything not matching grammar. No string interpolation, no SQL generation, no eval. Entity lookups go through `normalize()` + `entity_id_for()` content-addressing — no injection surface.

### 10.4 Resource Limits

| Limit | Default | Configurable via |
|---|---|---|
| Query timeout | 30s | `ChainConfig`, CLI `--timeout`, web request body |
| Max result rows | 1,000 | `ChainConfig`, CLI `--max-rows`, web request body |
| Intermediate binding cap | 10,000 | `ChainConfig`, CLI `:limits` in REPL |
| Variable-length max hops | 10 (hard cap) | Grammar-enforced, `*1..N` where N <= 10 |

### 10.5 Plugin Function Sandboxing

No sandbox in v1. Plugins receive read-only property dicts, not graph references. Timeout kills hung plugins. Documented as known limitation; true sandboxing deferred.

## 11. Testing Strategy

### 11.1 Unit Tests

| Layer | Focus | Est. Cases |
|---|---|---|
| Parser | Grammar edge cases, valid/invalid queries, mutation rejection, var-length bounds | ~40-50 |
| Planner | Predicate pushdown, session references, var-length step generation | ~20 |
| VirtualGraphBuilder | Node/edge counts, labels, property access, MENTIONED_IN direction, cache LRU | ~15 |
| Executor | End-to-end per step kind, resource limit enforcement, collect() aggregation | ~30 |
| Plugin registry | Registration, collision rejection, resolution, invocation | ~10 |

### 11.2 Integration Tests

| Area | Focus | Est. Cases |
|---|---|---|
| CLI `query run` | Typer test runner, output formats, engagement scoping | ~10 |
| CLI REPL | Session variables, multi-line, special commands, prompt_toolkit mocking | ~10 |
| Web endpoint | POST /api/chain/query, auth, user scoping, response shape, 403 on unauthorized | ~10 |

### 11.3 Conformance Tests

Same query test suite runs against both `AsyncChainStore` (aiosqlite) and `PostgresChainStore` (SQLAlchemy async), following the backend parameterization pattern from 3C.1.5. Verifies virtual graph builds identically from both backends.

**Total:** ~145-175 tests. All async, following existing `pytest-asyncio` patterns.

## 12. File Layout

### 12.1 Core Module

```
packages/cli/src/opentools/chain/cypher/
├── __init__.py              # public API: parse_and_execute(), CypherSession
├── grammar.lark             # lark EBNF grammar
├── parser.py                # lark parser → typed AST
├── ast_nodes.py             # AST dataclass definitions
├── planner.py               # AST → QueryPlan with predicate pushdown
├── virtual_graph.py         # VirtualGraphBuilder + VirtualGraphCache
├── executor.py              # CypherExecutor
├── plugins.py               # PluginFunctionRegistry + registration API
├── session.py               # QuerySession — named result sets, REPL state
├── result.py                # QueryResult, SubgraphProjection, QueryStats
├── limits.py                # QueryLimits + QueryResourceError
├── builtins.py              # length, nodes, relationships, has_entity, has_mitre, collect
└── errors.py                # QueryParseError, QueryValidationError, QueryResourceError
```

### 12.2 CLI Additions

- `packages/cli/src/opentools/chain/cli.py` — new `query` command group (`run`, `repl`, `explain`)

### 12.3 Web Additions

- `packages/web/backend/app/routes/chain_query.py` — `POST /api/chain/query`, `GET /api/chain/query/functions`
- `packages/web/frontend/src/pages/ChainQueryPage.vue` — standalone query page
- `packages/web/frontend/src/components/chain/CypherEditor.vue` — CodeMirror wrapper with Cypher mode
- `packages/web/frontend/src/components/chain/QueryResultsPane.vue` — tabular results + mini graph

### 12.4 Inline Overlay (Final Task)

- `packages/web/frontend/src/components/chain/InlineQueryPanel.vue` — collapsible overlay for `ChainGraphView.vue` and `GlobalChainView.vue`

### 12.5 Tests

- `packages/cli/tests/chain/cypher/` — `test_parser.py`, `test_planner.py`, `test_virtual_graph.py`, `test_executor.py`, `test_plugins.py`, `test_session.py`, `test_cli_query.py`
- `packages/web/backend/tests/chain/test_query_routes.py`
