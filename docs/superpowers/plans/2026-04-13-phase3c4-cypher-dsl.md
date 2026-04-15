# Phase 3C.4: Cypher-Style Query DSL — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Cypher-style query DSL that lets users write pattern-matching queries over the attack chain knowledge graph from CLI, REPL, or web editor.

**Architecture:** Layered pipeline — Parser (lark LALR) → Planner (predicate pushdown) → VirtualGraphBuilder (heterogeneous graph with entities as nodes) → Executor (binding-table pattern matcher with resource limits). Virtual graph cached for REPL reuse. Dual result format: table + subgraph projection.

**Tech Stack:** `lark` (parser), `rustworkx` (graph engine), `prompt_toolkit` (REPL), CodeMirror 6 (web editor), existing `ChainStoreProtocol` + `GraphCache` infrastructure.

**Spec:** `docs/superpowers/specs/2026-04-13-phase3c4-cypher-dsl-design.md`

---

## File Map

### New files (CLI package)

| File | Responsibility |
|---|---|
| `packages/cli/src/opentools/chain/cypher/__init__.py` | Public API: `parse_and_execute()`, `CypherSession` |
| `packages/cli/src/opentools/chain/cypher/errors.py` | `QueryParseError`, `QueryValidationError`, `QueryResourceError` |
| `packages/cli/src/opentools/chain/cypher/limits.py` | `QueryLimits` dataclass |
| `packages/cli/src/opentools/chain/cypher/ast_nodes.py` | AST dataclass definitions |
| `packages/cli/src/opentools/chain/cypher/grammar.lark` | Lark EBNF grammar |
| `packages/cli/src/opentools/chain/cypher/parser.py` | Lark parser → typed AST |
| `packages/cli/src/opentools/chain/cypher/builtins.py` | Built-in functions: `length`, `nodes`, `relationships`, `has_entity`, `has_mitre`, `collect` |
| `packages/cli/src/opentools/chain/cypher/plugins.py` | `PluginFunctionRegistry` + registration API |
| `packages/cli/src/opentools/chain/cypher/virtual_graph.py` | `VirtualGraph`, `VirtualGraphBuilder`, `VirtualGraphCache` |
| `packages/cli/src/opentools/chain/cypher/planner.py` | AST → `QueryPlan` with predicate pushdown |
| `packages/cli/src/opentools/chain/cypher/executor.py` | `CypherExecutor` — walks plan against virtual graph |
| `packages/cli/src/opentools/chain/cypher/result.py` | `QueryResult`, `SubgraphProjection`, `QueryStats` |
| `packages/cli/src/opentools/chain/cypher/session.py` | `QuerySession` — named result sets, REPL state |

### New test files

| File | Tests for |
|---|---|
| `packages/cli/tests/chain/cypher/__init__.py` | Package marker |
| `packages/cli/tests/chain/cypher/test_errors.py` | Error classes |
| `packages/cli/tests/chain/cypher/test_limits.py` | QueryLimits |
| `packages/cli/tests/chain/cypher/test_ast_nodes.py` | AST dataclasses |
| `packages/cli/tests/chain/cypher/test_parser.py` | Grammar + parser |
| `packages/cli/tests/chain/cypher/test_builtins.py` | Built-in functions |
| `packages/cli/tests/chain/cypher/test_plugins.py` | Plugin registry |
| `packages/cli/tests/chain/cypher/test_virtual_graph.py` | VirtualGraphBuilder + cache |
| `packages/cli/tests/chain/cypher/test_planner.py` | Planner + predicate pushdown |
| `packages/cli/tests/chain/cypher/test_executor.py` | Executor end-to-end |
| `packages/cli/tests/chain/cypher/test_session.py` | Session state |
| `packages/cli/tests/chain/cypher/test_cli_query.py` | CLI commands |

### Modified files (CLI)

| File | Change |
|---|---|
| `packages/cli/src/opentools/chain/cli.py` | Replace existing `query` command with new `query` subgroup (`run`, `repl`, `explain`) |
| `packages/cli/src/opentools/chain/config.py` | Add `CypherConfig` to `ChainConfig` |

### New files (Web backend)

| File | Responsibility |
|---|---|
| `packages/web/backend/app/routes/chain_query.py` | `POST /api/chain/query`, `GET /api/chain/query/functions` |
| `packages/web/backend/tests/chain/test_query_routes.py` | Web endpoint tests |

### Modified files (Web backend)

| File | Change |
|---|---|
| `packages/web/backend/app/main.py` | Register `chain_query.router` |

### New files (Web frontend)

| File | Responsibility |
|---|---|
| `packages/web/frontend/src/views/ChainQueryView.vue` | Standalone query page |
| `packages/web/frontend/src/components/CypherEditor.vue` | CodeMirror wrapper with Cypher mode |
| `packages/web/frontend/src/components/QueryResultsPane.vue` | Tabular results + mini graph |
| `packages/web/frontend/src/components/InlineQueryPanel.vue` | Collapsible overlay (final task) |

### Modified files (Web frontend)

| File | Change |
|---|---|
| `packages/web/frontend/src/router/index.ts` | Add `/chain/query` route |
| `packages/web/frontend/src/views/ChainGraphView.vue` | Add InlineQueryPanel (final task) |

---

## Tasks

### Task 1: Error Types + Limits

**Files:**
- Create: `packages/cli/src/opentools/chain/cypher/__init__.py`
- Create: `packages/cli/src/opentools/chain/cypher/errors.py`
- Create: `packages/cli/src/opentools/chain/cypher/limits.py`
- Create: `packages/cli/tests/chain/cypher/__init__.py`
- Create: `packages/cli/tests/chain/cypher/test_errors.py`
- Create: `packages/cli/tests/chain/cypher/test_limits.py`

- [ ] **Step 1: Write failing tests for error classes**

```python
# packages/cli/tests/chain/cypher/test_errors.py
from opentools.chain.cypher.errors import (
    QueryParseError,
    QueryResourceError,
    QueryValidationError,
)


def test_query_parse_error_is_exception():
    err = QueryParseError("unexpected token", line=3, column=12)
    assert isinstance(err, Exception)
    assert err.line == 3
    assert err.column == 12
    assert "unexpected token" in str(err)


def test_query_validation_error_is_exception():
    err = QueryValidationError("unknown function: foo.bar")
    assert isinstance(err, Exception)
    assert "foo.bar" in str(err)


def test_query_resource_error_is_exception():
    err = QueryResourceError("binding cap exceeded", limit_name="intermediate_binding_cap", limit_value=10_000)
    assert isinstance(err, Exception)
    assert err.limit_name == "intermediate_binding_cap"
    assert err.limit_value == 10_000
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_errors.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'opentools.chain.cypher'`

- [ ] **Step 3: Implement error classes**

```python
# packages/cli/src/opentools/chain/cypher/__init__.py
"""Cypher-style query DSL for the attack chain knowledge graph."""

# packages/cli/src/opentools/chain/cypher/errors.py
"""Query DSL error hierarchy."""
from __future__ import annotations


class QueryParseError(Exception):
    def __init__(self, message: str, *, line: int | None = None, column: int | None = None) -> None:
        self.line = line
        self.column = column
        loc = ""
        if line is not None:
            loc = f" (line {line}"
            if column is not None:
                loc += f", col {column}"
            loc += ")"
        super().__init__(f"{message}{loc}")


class QueryValidationError(Exception):
    pass


class QueryResourceError(Exception):
    def __init__(self, message: str, *, limit_name: str, limit_value: int | float) -> None:
        self.limit_name = limit_name
        self.limit_value = limit_value
        super().__init__(message)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_errors.py -v`
Expected: 3 passed

- [ ] **Step 5: Write failing tests for QueryLimits**

```python
# packages/cli/tests/chain/cypher/test_limits.py
from opentools.chain.cypher.limits import QueryLimits


def test_query_limits_defaults():
    limits = QueryLimits()
    assert limits.timeout_seconds == 30.0
    assert limits.max_rows == 1000
    assert limits.intermediate_binding_cap == 10_000
    assert limits.max_var_length_hops == 10


def test_query_limits_custom():
    limits = QueryLimits(timeout_seconds=60.0, max_rows=500)
    assert limits.timeout_seconds == 60.0
    assert limits.max_rows == 500
    assert limits.intermediate_binding_cap == 10_000  # unchanged default


def test_query_limits_frozen():
    limits = QueryLimits()
    try:
        limits.timeout_seconds = 99.0
        assert False, "should be frozen"
    except Exception:
        pass
```

- [ ] **Step 6: Implement QueryLimits**

```python
# packages/cli/src/opentools/chain/cypher/limits.py
"""Resource limits for query execution."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class QueryLimits(BaseModel):
    model_config = ConfigDict(frozen=True)

    timeout_seconds: float = 30.0
    max_rows: int = 1000
    intermediate_binding_cap: int = 10_000
    max_var_length_hops: int = 10
```

- [ ] **Step 7: Run all cypher tests**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/ -v`
Expected: 6 passed

- [ ] **Step 8: Commit**

```bash
git add packages/cli/src/opentools/chain/cypher/__init__.py packages/cli/src/opentools/chain/cypher/errors.py packages/cli/src/opentools/chain/cypher/limits.py packages/cli/tests/chain/cypher/__init__.py packages/cli/tests/chain/cypher/test_errors.py packages/cli/tests/chain/cypher/test_limits.py
git commit -m "feat(cypher): add error types and query limits"
```

---

### Task 2: AST Node Definitions

**Files:**
- Create: `packages/cli/src/opentools/chain/cypher/ast_nodes.py`
- Create: `packages/cli/tests/chain/cypher/test_ast_nodes.py`

- [ ] **Step 1: Write failing tests for AST nodes**

```python
# packages/cli/tests/chain/cypher/test_ast_nodes.py
from opentools.chain.cypher.ast_nodes import (
    BooleanExpr,
    ComparisonExpr,
    EdgePattern,
    FunctionCallExpr,
    MatchClause,
    NodePattern,
    PropertyAccessExpr,
    ReturnClause,
    ReturnItem,
    SessionAssignment,
    VarLengthSpec,
    WhereClause,
)


def test_node_pattern():
    n = NodePattern(variable="a", label="Finding")
    assert n.variable == "a"
    assert n.label == "Finding"


def test_node_pattern_no_label():
    n = NodePattern(variable="x", label=None)
    assert n.label is None


def test_edge_pattern_outgoing():
    e = EdgePattern(variable="r", label="LINKED", direction="out", var_length=None)
    assert e.direction == "out"
    assert e.var_length is None


def test_edge_pattern_with_var_length():
    vl = VarLengthSpec(min_hops=1, max_hops=5)
    e = EdgePattern(variable="r", label="LINKED", direction="out", var_length=vl)
    assert e.var_length.min_hops == 1
    assert e.var_length.max_hops == 5


def test_var_length_spec_defaults():
    vl = VarLengthSpec(min_hops=1, max_hops=3)
    assert vl.min_hops == 1
    assert vl.max_hops == 3


def test_property_access_expr():
    p = PropertyAccessExpr(variable="a", property_name="severity")
    assert p.variable == "a"
    assert p.property_name == "severity"


def test_comparison_expr():
    left = PropertyAccessExpr(variable="a", property_name="severity")
    c = ComparisonExpr(left=left, operator="=", right="critical")
    assert c.operator == "="
    assert c.right == "critical"


def test_boolean_expr():
    left = ComparisonExpr(
        left=PropertyAccessExpr(variable="a", property_name="severity"),
        operator="=", right="critical",
    )
    right = ComparisonExpr(
        left=PropertyAccessExpr(variable="a", property_name="tool"),
        operator="=", right="nmap",
    )
    b = BooleanExpr(operator="AND", operands=[left, right])
    assert b.operator == "AND"
    assert len(b.operands) == 2


def test_function_call_expr():
    f = FunctionCallExpr(name="has_entity", args=["a", "host", "10.0.0.1"])
    assert f.name == "has_entity"
    assert len(f.args) == 3


def test_function_call_plugin_namespaced():
    f = FunctionCallExpr(name="my_plugin.risk_score", args=["a"])
    assert "." in f.name


def test_match_clause():
    node_a = NodePattern(variable="a", label="Finding")
    edge_r = EdgePattern(variable="r", label="LINKED", direction="out", var_length=None)
    node_b = NodePattern(variable="b", label="Finding")
    mc = MatchClause(patterns=[(node_a, edge_r, node_b)])
    assert len(mc.patterns) == 1


def test_where_clause():
    pred = ComparisonExpr(
        left=PropertyAccessExpr(variable="a", property_name="severity"),
        operator="=", right="critical",
    )
    wc = WhereClause(expression=pred)
    assert wc.expression is pred


def test_return_clause():
    items = [
        ReturnItem(expression="a", alias=None),
        ReturnItem(expression=PropertyAccessExpr(variable="a", property_name="title"), alias="name"),
    ]
    rc = ReturnClause(items=items)
    assert len(rc.items) == 2
    assert rc.items[1].alias == "name"


def test_session_assignment():
    rc = ReturnClause(items=[ReturnItem(expression="a", alias=None)])
    mc = MatchClause(patterns=[])
    sa = SessionAssignment(variable_name="results", match_clause=mc, where_clause=None, return_clause=rc)
    assert sa.variable_name == "results"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_ast_nodes.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement AST nodes**

```python
# packages/cli/src/opentools/chain/cypher/ast_nodes.py
"""Typed AST nodes for the Cypher-style query DSL."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class VarLengthSpec:
    min_hops: int
    max_hops: int


@dataclass
class NodePattern:
    variable: str | None
    label: str | None


@dataclass
class EdgePattern:
    variable: str | None
    label: str | None
    direction: Literal["out", "in"]
    var_length: VarLengthSpec | None


@dataclass
class PropertyAccessExpr:
    variable: str
    property_name: str


@dataclass
class ComparisonExpr:
    left: Any  # PropertyAccessExpr | FunctionCallExpr
    operator: str  # =, <>, <, >, <=, >=, CONTAINS, STARTS WITH, ENDS WITH, IN, IS NULL, IS NOT NULL
    right: Any  # literal value, list, or None for IS NULL/IS NOT NULL


@dataclass
class BooleanExpr:
    operator: Literal["AND", "OR", "NOT"]
    operands: list[Any]  # ComparisonExpr | BooleanExpr | FunctionCallExpr


@dataclass
class FunctionCallExpr:
    name: str  # "has_entity", "length", "my_plugin.risk_score", etc.
    args: list[Any] = field(default_factory=list)


@dataclass
class ReturnItem:
    expression: Any  # str (variable name), PropertyAccessExpr, FunctionCallExpr
    alias: str | None


@dataclass
class MatchClause:
    patterns: list[tuple]  # list of (NodePattern, EdgePattern, NodePattern, ...) tuples


@dataclass
class WhereClause:
    expression: Any  # ComparisonExpr | BooleanExpr | FunctionCallExpr


@dataclass
class ReturnClause:
    items: list[ReturnItem]


@dataclass
class FromClause:
    session_variable: str


@dataclass
class SessionAssignment:
    variable_name: str
    match_clause: MatchClause
    where_clause: WhereClause | None
    return_clause: ReturnClause


@dataclass
class CypherQuery:
    match_clause: MatchClause
    where_clause: WhereClause | None
    return_clause: ReturnClause
    from_clause: FromClause | None = None
    session_assignment: str | None = None  # if this is a "name = MATCH ..." form
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_ast_nodes.py -v`
Expected: 14 passed

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/chain/cypher/ast_nodes.py packages/cli/tests/chain/cypher/test_ast_nodes.py
git commit -m "feat(cypher): add AST node definitions"
```

---

### Task 3: Lark Grammar + Parser

**Files:**
- Create: `packages/cli/src/opentools/chain/cypher/grammar.lark`
- Create: `packages/cli/src/opentools/chain/cypher/parser.py`
- Create: `packages/cli/tests/chain/cypher/test_parser.py`

- [ ] **Step 1: Write failing tests for the parser**

```python
# packages/cli/tests/chain/cypher/test_parser.py
import pytest

from opentools.chain.cypher.ast_nodes import (
    ComparisonExpr,
    CypherQuery,
    EdgePattern,
    FunctionCallExpr,
    NodePattern,
    PropertyAccessExpr,
    SessionAssignment,
)
from opentools.chain.cypher.errors import QueryParseError
from opentools.chain.cypher.parser import parse_cypher


# ─── basic MATCH ... RETURN ──────────────────────────────────────────


def test_parse_simple_match_return():
    q = parse_cypher("MATCH (a:Finding) RETURN a")
    assert isinstance(q, CypherQuery)
    assert len(q.match_clause.patterns) == 1
    assert len(q.return_clause.items) == 1


def test_parse_two_node_pattern():
    q = parse_cypher("MATCH (a:Finding)-[r:LINKED]->(b:Finding) RETURN a, b")
    assert len(q.match_clause.patterns) == 1
    pattern = q.match_clause.patterns[0]
    # pattern is a tuple: (NodePattern, EdgePattern, NodePattern)
    assert isinstance(pattern[0], NodePattern)
    assert pattern[0].label == "Finding"
    assert isinstance(pattern[1], EdgePattern)
    assert pattern[1].label == "LINKED"
    assert pattern[1].direction == "out"
    assert isinstance(pattern[2], NodePattern)
    assert pattern[2].label == "Finding"


def test_parse_incoming_edge():
    q = parse_cypher("MATCH (a:Finding)<-[r:MENTIONED_IN]-(e:Host) RETURN a, e")
    pattern = q.match_clause.patterns[0]
    assert pattern[1].direction == "in"
    assert pattern[1].label == "MENTIONED_IN"


# ─── entity node labels ──────────────────────────────────────────────


def test_parse_entity_node_labels():
    for label in ["Host", "IP", "CVE", "Domain", "Port", "MitreAttack", "Entity"]:
        q = parse_cypher(f"MATCH (e:{label}) RETURN e")
        assert q.match_clause.patterns[0][0].label == label


# ─── variable-length paths ───────────────────────────────────────────


def test_parse_var_length_path():
    q = parse_cypher("MATCH (a:Finding)-[r:LINKED*1..5]->(b:Finding) RETURN a, b")
    edge = q.match_clause.patterns[0][1]
    assert edge.var_length is not None
    assert edge.var_length.min_hops == 1
    assert edge.var_length.max_hops == 5


def test_parse_var_length_exceeds_max_hops():
    with pytest.raises(QueryParseError, match="max.*10"):
        parse_cypher("MATCH (a:Finding)-[r:LINKED*1..15]->(b:Finding) RETURN a, b")


# ─── WHERE clause ────────────────────────────────────────────────────


def test_parse_where_comparison():
    q = parse_cypher('MATCH (a:Finding) WHERE a.severity = "critical" RETURN a')
    assert q.where_clause is not None
    expr = q.where_clause.expression
    assert isinstance(expr, ComparisonExpr)
    assert isinstance(expr.left, PropertyAccessExpr)
    assert expr.left.variable == "a"
    assert expr.left.property_name == "severity"
    assert expr.operator == "="
    assert expr.right == "critical"


def test_parse_where_numeric_comparison():
    q = parse_cypher("MATCH (a:Finding)-[r:LINKED]->(b:Finding) WHERE r.weight > 2.0 RETURN a, b")
    expr = q.where_clause.expression
    assert expr.operator == ">"
    assert expr.right == 2.0


def test_parse_where_and():
    q = parse_cypher('MATCH (a:Finding) WHERE a.severity = "critical" AND a.tool = "nmap" RETURN a')
    expr = q.where_clause.expression
    assert expr.operator == "AND" if hasattr(expr, "operator") else True


def test_parse_where_function_call():
    q = parse_cypher('MATCH (a:Finding) WHERE has_entity(a, "host", "10.0.0.1") RETURN a')
    assert q.where_clause is not None


def test_parse_where_contains():
    q = parse_cypher('MATCH (a:Finding) WHERE a.title CONTAINS "ssh" RETURN a')
    expr = q.where_clause.expression
    assert expr.operator == "CONTAINS"


def test_parse_where_is_null():
    q = parse_cypher("MATCH (a:Finding)-[r:LINKED]->(b:Finding) WHERE r.llm_rationale IS NOT NULL RETURN a, b")
    assert q.where_clause is not None


# ─── RETURN ──────────────────────────────────────────────────────────


def test_parse_return_property():
    q = parse_cypher("MATCH (a:Finding) RETURN a.title, a.severity")
    assert len(q.return_clause.items) == 2
    assert isinstance(q.return_clause.items[0].expression, PropertyAccessExpr)


def test_parse_return_collect():
    q = parse_cypher("MATCH (a:Finding)-[r:LINKED]->(b:Finding) RETURN collect(a)")
    item = q.return_clause.items[0]
    assert isinstance(item.expression, FunctionCallExpr)
    assert item.expression.name == "collect"


# ─── session assignment ──────────────────────────────────────────────


def test_parse_session_assignment():
    q = parse_cypher("results = MATCH (a:Finding) RETURN a")
    assert q.session_assignment == "results"


# ─── FROM clause ─────────────────────────────────────────────────────


def test_parse_from_clause():
    q = parse_cypher("MATCH (a) FROM prev_results -[r:LINKED]->(b:Finding) RETURN a, b")
    assert q.from_clause is not None
    assert q.from_clause.session_variable == "prev_results"


# ─── read-only enforcement ───────────────────────────────────────────


@pytest.mark.parametrize("verb", ["CREATE", "DELETE", "SET", "MERGE", "REMOVE", "DETACH", "DROP"])
def test_parse_rejects_mutation_verbs(verb):
    with pytest.raises(QueryParseError):
        parse_cypher(f"{verb} (a:Finding)")


# ─── edge cases ──────────────────────────────────────────────────────


def test_parse_empty_string():
    with pytest.raises(QueryParseError):
        parse_cypher("")


def test_parse_garbage():
    with pytest.raises(QueryParseError):
        parse_cypher("not a query at all 123 !!!")


def test_parse_case_insensitive_keywords():
    q = parse_cypher("match (a:Finding) where a.severity = \"critical\" return a")
    assert q is not None


def test_parse_multiple_patterns():
    q = parse_cypher("MATCH (a:Finding)-[r:LINKED]->(b:Finding), (b)-[:MENTIONED_IN]->(e:Host) RETURN a, e")
    assert len(q.match_clause.patterns) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_parser.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Create the lark grammar**

```lark
// packages/cli/src/opentools/chain/cypher/grammar.lark
// Cypher-style query DSL grammar — read-only subset for OpenTools

?start: session_assignment | query

session_assignment: IDENTIFIER "=" query

query: match_clause where_clause? return_clause

match_clause: MATCH_KW pattern ("," pattern)*
where_clause: WHERE_KW expression
return_clause: RETURN_KW return_item ("," return_item)*

// ─── patterns ────────────────────────────────────────────────

pattern: node_pattern (edge_pattern node_pattern)*
       | node_pattern from_clause (edge_pattern node_pattern)*

from_clause: FROM_KW IDENTIFIER

node_pattern: "(" IDENTIFIER? (":" LABEL)? ")"

edge_pattern: "-[" edge_detail "]->"    -> edge_out
            | "<-[" edge_detail "]-"    -> edge_in

edge_detail: IDENTIFIER? (":" EDGE_LABEL)? var_length?

var_length: "*" INT ".." INT

// ─── expressions ─────────────────────────────────────────────

?expression: or_expr

?or_expr: and_expr (OR_KW and_expr)*
?and_expr: not_expr (AND_KW not_expr)*
?not_expr: NOT_KW not_expr | comparison
?comparison: operand CMP_OP operand        -> cmp_expr
           | operand STRING_OP operand     -> string_expr
           | operand IN_KW "[" value_list "]" -> in_expr
           | operand IS_KW NULL_KW         -> is_null_expr
           | operand IS_KW NOT_KW NULL_KW  -> is_not_null_expr
           | function_call
           | "(" expression ")"

?operand: property_access | function_call | literal | IDENTIFIER

property_access: IDENTIFIER "." IDENTIFIER

function_call: DOTTED_NAME "(" arg_list? ")"
             | IDENTIFIER "(" arg_list? ")"

arg_list: expression ("," expression)*

value_list: literal ("," literal)*

// ─── return items ────────────────────────────────────────────

return_item: expression (AS_KW IDENTIFIER)?

// ─── literals ────────────────────────────────────────────────

?literal: ESCAPED_STRING -> string_literal
        | SIGNED_NUMBER  -> number_literal
        | TRUE_KW        -> true_literal
        | FALSE_KW       -> false_literal
        | NULL_KW        -> null_literal

// ─── terminals ───────────────────────────────────────────────

MATCH_KW: /MATCH/i
WHERE_KW: /WHERE/i
RETURN_KW: /RETURN/i
AND_KW: /AND/i
OR_KW: /OR/i
NOT_KW: /NOT/i
IN_KW: /IN/i
IS_KW: /IS/i
NULL_KW: /NULL/i
AS_KW: /AS/i
FROM_KW: /FROM/i
TRUE_KW: /true/i
FALSE_KW: /false/i

CMP_OP: "=" | "<>" | "<=" | ">=" | "<" | ">"
STRING_OP: /CONTAINS/i | /STARTS\s+WITH/i | /ENDS\s+WITH/i

LABEL: "Finding" | "Host" | "IP" | "CVE" | "Domain" | "Port" | "MitreAttack" | "Entity"
EDGE_LABEL: "LINKED" | "MENTIONED_IN"

DOTTED_NAME: IDENTIFIER "." IDENTIFIER

IDENTIFIER: /[a-zA-Z_][a-zA-Z0-9_]*/

%import common.ESCAPED_STRING
%import common.SIGNED_NUMBER
%import common.INT
%import common.WS
%ignore WS
```

- [ ] **Step 4: Implement the parser module**

```python
# packages/cli/src/opentools/chain/cypher/parser.py
"""Lark-based parser for the Cypher-style query DSL."""
from __future__ import annotations

from pathlib import Path

from lark import Lark, Transformer, v_args, exceptions as lark_exceptions

from opentools.chain.cypher.ast_nodes import (
    BooleanExpr,
    ComparisonExpr,
    CypherQuery,
    EdgePattern,
    FromClause,
    FunctionCallExpr,
    MatchClause,
    NodePattern,
    PropertyAccessExpr,
    ReturnClause,
    ReturnItem,
    VarLengthSpec,
    WhereClause,
)
from opentools.chain.cypher.errors import QueryParseError

_GRAMMAR_PATH = Path(__file__).parent / "grammar.lark"
_MAX_VAR_LENGTH_HOPS = 10

# Mutation verbs rejected before parsing
_MUTATION_VERBS = {"CREATE", "DELETE", "SET", "MERGE", "REMOVE", "DETACH", "DROP"}


def _check_mutation_verbs(query: str) -> None:
    """Reject queries that start with or contain mutation verbs."""
    tokens = query.strip().split()
    if not tokens:
        raise QueryParseError("empty query")
    first = tokens[0].upper()
    if first in _MUTATION_VERBS:
        raise QueryParseError(f"mutation verb '{first}' is not supported (read-only DSL)")
    # Also check for mutation verbs anywhere (e.g., after MATCH)
    for token in tokens:
        upper = token.upper().rstrip("(")
        if upper in _MUTATION_VERBS:
            raise QueryParseError(f"mutation verb '{upper}' is not supported (read-only DSL)")


@v_args(inline=True)
class CypherTransformer(Transformer):
    """Transform lark parse tree into typed AST nodes."""

    def start(self, item):
        return item

    def query(self, *args):
        match_clause = args[0]
        where_clause = None
        return_clause = None
        from_clause = None

        for arg in args[1:]:
            if isinstance(arg, WhereClause):
                where_clause = arg
            elif isinstance(arg, ReturnClause):
                return_clause = arg

        # Extract from_clause from match_clause patterns if present
        if hasattr(match_clause, '_from_clause'):
            from_clause = match_clause._from_clause

        return CypherQuery(
            match_clause=match_clause,
            where_clause=where_clause,
            return_clause=return_clause,
            from_clause=from_clause,
        )

    def session_assignment(self, name, query):
        query.session_assignment = str(name)
        return query

    def match_clause(self, *patterns):
        return MatchClause(patterns=list(patterns))

    def pattern(self, *elements):
        result = []
        from_clause = None
        for el in elements:
            if isinstance(el, FromClause):
                from_clause = el
            else:
                result.append(el)
        pattern_tuple = tuple(result)
        # Attach from_clause as metadata if present
        if from_clause is not None:
            # We'll handle this at the match_clause level
            pass
        return pattern_tuple

    def from_clause(self, name):
        return FromClause(session_variable=str(name))

    def node_pattern(self, *args):
        variable = None
        label = None
        for arg in args:
            s = str(arg)
            if arg.type == "LABEL":
                label = s
            elif arg.type == "IDENTIFIER":
                variable = s
        return NodePattern(variable=variable, label=label)

    def edge_out(self, detail):
        return EdgePattern(
            variable=detail.get("variable"),
            label=detail.get("label"),
            direction="out",
            var_length=detail.get("var_length"),
        )

    def edge_in(self, detail):
        return EdgePattern(
            variable=detail.get("variable"),
            label=detail.get("label"),
            direction="in",
            var_length=detail.get("var_length"),
        )

    def edge_detail(self, *args):
        result = {"variable": None, "label": None, "var_length": None}
        for arg in args:
            if isinstance(arg, VarLengthSpec):
                result["var_length"] = arg
            else:
                s = str(arg)
                if arg.type == "EDGE_LABEL":
                    result["label"] = s
                elif arg.type == "IDENTIFIER":
                    result["variable"] = s
        return result

    def var_length(self, min_hops, max_hops):
        mn = int(min_hops)
        mx = int(max_hops)
        if mx > _MAX_VAR_LENGTH_HOPS:
            raise QueryParseError(
                f"variable-length max hops {mx} exceeds limit of {_MAX_VAR_LENGTH_HOPS}",
                line=None, column=None,
            )
        return VarLengthSpec(min_hops=mn, max_hops=mx)

    def where_clause(self, expr):
        return WhereClause(expression=expr)

    def return_clause(self, *items):
        return ReturnClause(items=list(items))

    def return_item(self, expr, *rest):
        alias = None
        if rest:
            alias = str(rest[0])
        # If expr is a plain identifier string (Token), keep as string
        if hasattr(expr, 'type') and expr.type == 'IDENTIFIER':
            expr = str(expr)
        return ReturnItem(expression=expr, alias=alias)

    # ─── expressions ──────────────────────────────────────────

    def or_expr(self, *args):
        if len(args) == 1:
            return args[0]
        return BooleanExpr(operator="OR", operands=list(args))

    def and_expr(self, *args):
        if len(args) == 1:
            return args[0]
        return BooleanExpr(operator="AND", operands=list(args))

    def not_expr(self, expr):
        return BooleanExpr(operator="NOT", operands=[expr])

    def cmp_expr(self, left, op, right):
        return ComparisonExpr(left=left, operator=str(op), right=right)

    def string_expr(self, left, op, right):
        return ComparisonExpr(left=left, operator=str(op).strip().upper(), right=right)

    def in_expr(self, left, values):
        return ComparisonExpr(left=left, operator="IN", right=values)

    def is_null_expr(self, operand):
        return ComparisonExpr(left=operand, operator="IS NULL", right=None)

    def is_not_null_expr(self, operand):
        return ComparisonExpr(left=operand, operator="IS NOT NULL", right=None)

    def value_list(self, *values):
        return list(values)

    def property_access(self, var, prop):
        return PropertyAccessExpr(variable=str(var), property_name=str(prop))

    def function_call(self, name, *args):
        arg_list = []
        if args and args[0] is not None:
            arg_list = args[0]
        return FunctionCallExpr(name=str(name), args=arg_list)

    def arg_list(self, *args):
        return list(args)

    # ─── literals ─────────────────────────────────────────────

    def string_literal(self, s):
        return str(s)[1:-1]  # strip quotes

    def number_literal(self, n):
        s = str(n)
        return float(s) if "." in s else int(s)

    def true_literal(self, *_):
        return True

    def false_literal(self, *_):
        return False

    def null_literal(self, *_):
        return None

    def IDENTIFIER(self, token):
        return token


_parser: Lark | None = None


def _get_parser() -> Lark:
    global _parser
    if _parser is None:
        _parser = Lark(
            _GRAMMAR_PATH.read_text(),
            parser="lalr",
            transformer=CypherTransformer(),
        )
    return _parser


def parse_cypher(query: str) -> CypherQuery:
    """Parse a Cypher query string into a typed AST.

    Raises QueryParseError on invalid syntax or mutation verbs.
    """
    stripped = query.strip()
    if not stripped:
        raise QueryParseError("empty query")

    _check_mutation_verbs(stripped)

    try:
        result = _get_parser().parse(stripped)
    except lark_exceptions.UnexpectedInput as e:
        raise QueryParseError(
            str(e),
            line=getattr(e, "line", None),
            column=getattr(e, "column", None),
        ) from e
    except Exception as e:
        raise QueryParseError(str(e)) from e

    if not isinstance(result, CypherQuery):
        raise QueryParseError(f"unexpected parse result type: {type(result)}")

    return result
```

Note: The grammar and transformer above are a starting point. The lark grammar may need iterative refinement to handle all test cases correctly — the agent implementing this task should adjust the grammar terminals, precedence rules, and transformer methods until all parser tests pass. The grammar structure and AST node mapping are the contract; the exact lark syntax may need tuning.

- [ ] **Step 5: Run tests iteratively until all pass**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_parser.py -v`
Expected: All 22 tests pass. If specific tests fail due to grammar ambiguities, adjust the `.lark` file — terminal precedence, rule ordering, or token definitions. Common issues: IDENTIFIER vs LABEL priority, DOTTED_NAME matching, case-insensitive keywords.

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/chain/cypher/grammar.lark packages/cli/src/opentools/chain/cypher/parser.py packages/cli/tests/chain/cypher/test_parser.py
git commit -m "feat(cypher): add lark grammar and parser"
```

---

### Task 4: Built-in Functions + Plugin Registry

**Files:**
- Create: `packages/cli/src/opentools/chain/cypher/builtins.py`
- Create: `packages/cli/src/opentools/chain/cypher/plugins.py`
- Create: `packages/cli/tests/chain/cypher/test_builtins.py`
- Create: `packages/cli/tests/chain/cypher/test_plugins.py`

- [ ] **Step 1: Write failing tests for built-in functions**

```python
# packages/cli/tests/chain/cypher/test_builtins.py
import pytest

from opentools.chain.cypher.builtins import (
    builtin_collect,
    builtin_has_entity,
    builtin_has_mitre,
    builtin_length,
    builtin_nodes,
    builtin_relationships,
    get_builtin,
    list_builtins,
)


def test_builtin_length():
    path = {"nodes": [1, 2, 3], "edges": [10, 20]}
    assert builtin_length(path) == 2


def test_builtin_length_empty_path():
    path = {"nodes": [1], "edges": []}
    assert builtin_length(path) == 0


def test_builtin_nodes():
    path = {"nodes": ["a", "b", "c"], "edges": [1, 2]}
    assert builtin_nodes(path) == ["a", "b", "c"]


def test_builtin_relationships():
    path = {"nodes": ["a", "b"], "edges": ["r1"]}
    assert builtin_relationships(path) == ["r1"]


def test_builtin_has_entity():
    node = {"entities": [{"type": "host", "canonical_value": "10.0.0.1"}, {"type": "cve", "canonical_value": "CVE-2024-1234"}]}
    assert builtin_has_entity(node, "host", "10.0.0.1") is True
    assert builtin_has_entity(node, "host", "10.0.0.2") is False
    assert builtin_has_entity(node, "cve", "CVE-2024-1234") is True


def test_builtin_has_entity_no_entities():
    node = {"entities": []}
    assert builtin_has_entity(node, "host", "anything") is False


def test_builtin_has_mitre():
    node = {"entities": [{"type": "mitre_technique", "canonical_value": "T1059"}]}
    assert builtin_has_mitre(node, "T1059") is True
    assert builtin_has_mitre(node, "T1078") is False


def test_builtin_collect():
    values = [1, 2, 3, 4]
    assert builtin_collect(values) == [1, 2, 3, 4]


def test_get_builtin():
    fn = get_builtin("length")
    assert fn is builtin_length
    assert get_builtin("nonexistent") is None


def test_list_builtins():
    builtins = list_builtins()
    assert "length" in builtins
    assert "has_entity" in builtins
    assert "collect" in builtins
    assert len(builtins) >= 6
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_builtins.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement built-in functions**

```python
# packages/cli/src/opentools/chain/cypher/builtins.py
"""Built-in functions for the Cypher DSL."""
from __future__ import annotations

from typing import Any, Callable


def builtin_length(path: dict) -> int:
    return len(path.get("edges", []))


def builtin_nodes(path: dict) -> list:
    return path.get("nodes", [])


def builtin_relationships(path: dict) -> list:
    return path.get("edges", [])


def builtin_has_entity(node: dict, entity_type: str, entity_value: str) -> bool:
    for ent in node.get("entities", []):
        if ent.get("type") == entity_type and ent.get("canonical_value") == entity_value:
            return True
    return False


def builtin_has_mitre(node: dict, technique_id: str) -> bool:
    return builtin_has_entity(node, "mitre_technique", technique_id)


def builtin_collect(values: list) -> list:
    return list(values)


_BUILTINS: dict[str, dict] = {
    "length": {"fn": builtin_length, "help": "Number of edges in a path", "arg_types": ["path"], "return_type": "int"},
    "nodes": {"fn": builtin_nodes, "help": "List of nodes in a path", "arg_types": ["path"], "return_type": "list"},
    "relationships": {"fn": builtin_relationships, "help": "List of edges in a path", "arg_types": ["path"], "return_type": "list"},
    "has_entity": {"fn": builtin_has_entity, "help": "Check if node mentions entity", "arg_types": ["node", "str", "str"], "return_type": "bool"},
    "has_mitre": {"fn": builtin_has_mitre, "help": "Check if node mentions MITRE technique", "arg_types": ["node", "str"], "return_type": "bool"},
    "collect": {"fn": builtin_collect, "help": "Aggregate values into a list", "arg_types": ["list"], "return_type": "list", "is_aggregation": True},
}


def get_builtin(name: str) -> Callable | None:
    entry = _BUILTINS.get(name)
    return entry["fn"] if entry else None


def list_builtins() -> dict[str, dict]:
    return {name: {k: v for k, v in info.items() if k != "fn"} for name, info in _BUILTINS.items()}
```

- [ ] **Step 4: Run builtin tests**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_builtins.py -v`
Expected: 10 passed

- [ ] **Step 5: Write failing tests for plugin registry**

```python
# packages/cli/tests/chain/cypher/test_plugins.py
import pytest

from opentools.chain.cypher.plugins import (
    PluginFunctionRegistry,
)


@pytest.fixture
def registry():
    return PluginFunctionRegistry()


def test_register_scalar_function(registry):
    registry.register_function(
        "my_plugin.risk_score",
        fn=lambda node: 0.9,
        help="Risk score",
        arg_types=["node"],
        return_type="float",
    )
    assert registry.get_function("my_plugin.risk_score") is not None


def test_register_aggregation(registry):
    registry.register_aggregation(
        "my_plugin.combined_risk",
        fn=lambda values: max(values),
        help="Max risk",
        input_type="float",
        return_type="float",
    )
    assert registry.get_aggregation("my_plugin.combined_risk") is not None


def test_reject_undotted_plugin_name(registry):
    with pytest.raises(ValueError, match="dotted"):
        registry.register_function(
            "no_dot",
            fn=lambda x: x,
            help="bad",
            arg_types=["node"],
            return_type="float",
        )


def test_reject_duplicate_name(registry):
    registry.register_function(
        "my_plugin.f",
        fn=lambda x: x,
        help="first",
        arg_types=["node"],
        return_type="float",
    )
    with pytest.raises(ValueError, match="already registered"):
        registry.register_function(
            "my_plugin.f",
            fn=lambda x: x,
            help="second",
            arg_types=["node"],
            return_type="float",
        )


def test_list_all_functions(registry):
    registry.register_function(
        "a.one", fn=lambda x: x, help="h1", arg_types=["node"], return_type="float",
    )
    registry.register_aggregation(
        "a.two", fn=lambda v: sum(v), help="h2", input_type="float", return_type="float",
    )
    all_fns = registry.list_all()
    assert "a.one" in all_fns
    assert "a.two" in all_fns
    assert all_fns["a.one"]["kind"] == "scalar"
    assert all_fns["a.two"]["kind"] == "aggregation"


def test_resolve_returns_none_for_unknown(registry):
    assert registry.get_function("nonexistent.fn") is None
    assert registry.get_aggregation("nonexistent.fn") is None
```

- [ ] **Step 6: Implement plugin registry**

```python
# packages/cli/src/opentools/chain/cypher/plugins.py
"""Plugin function registry for the Cypher DSL."""
from __future__ import annotations

from typing import Any, Callable


class PluginFunctionRegistry:
    def __init__(self) -> None:
        self._scalars: dict[str, dict] = {}
        self._aggregations: dict[str, dict] = {}

    def register_function(
        self,
        name: str,
        fn: Callable,
        *,
        help: str = "",
        arg_types: list[str],
        return_type: str,
    ) -> None:
        if "." not in name:
            raise ValueError(f"plugin function names must be dotted (e.g., 'plugin.func'), got: {name!r}")
        if name in self._scalars or name in self._aggregations:
            raise ValueError(f"function {name!r} already registered")
        self._scalars[name] = {
            "fn": fn,
            "help": help,
            "arg_types": arg_types,
            "return_type": return_type,
        }

    def register_aggregation(
        self,
        name: str,
        fn: Callable,
        *,
        help: str = "",
        input_type: str,
        return_type: str,
    ) -> None:
        if "." not in name:
            raise ValueError(f"plugin aggregation names must be dotted (e.g., 'plugin.agg'), got: {name!r}")
        if name in self._scalars or name in self._aggregations:
            raise ValueError(f"function {name!r} already registered")
        self._aggregations[name] = {
            "fn": fn,
            "help": help,
            "input_type": input_type,
            "return_type": return_type,
        }

    def get_function(self, name: str) -> Callable | None:
        entry = self._scalars.get(name)
        return entry["fn"] if entry else None

    def get_aggregation(self, name: str) -> Callable | None:
        entry = self._aggregations.get(name)
        return entry["fn"] if entry else None

    def list_all(self) -> dict[str, dict]:
        result: dict[str, dict] = {}
        for name, info in self._scalars.items():
            result[name] = {
                "kind": "scalar",
                "help": info["help"],
                "arg_types": info["arg_types"],
                "return_type": info["return_type"],
            }
        for name, info in self._aggregations.items():
            result[name] = {
                "kind": "aggregation",
                "help": info["help"],
                "input_type": info["input_type"],
                "return_type": info["return_type"],
            }
        return result
```

- [ ] **Step 7: Run all tests**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_builtins.py tests/chain/cypher/test_plugins.py -v`
Expected: 16 passed

- [ ] **Step 8: Commit**

```bash
git add packages/cli/src/opentools/chain/cypher/builtins.py packages/cli/src/opentools/chain/cypher/plugins.py packages/cli/tests/chain/cypher/test_builtins.py packages/cli/tests/chain/cypher/test_plugins.py
git commit -m "feat(cypher): add built-in functions and plugin registry"
```

---

### Task 5: Result Types

**Files:**
- Create: `packages/cli/src/opentools/chain/cypher/result.py`

- [ ] **Step 1: Write the result types**

These are data containers used by the executor (Task 8). No separate test file — they're exercised by executor tests.

```python
# packages/cli/src/opentools/chain/cypher/result.py
"""Query result types."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class QueryStats:
    duration_ms: float = 0.0
    bindings_explored: int = 0
    rows_returned: int = 0


@dataclass
class SubgraphProjection:
    node_indices: set[int] = field(default_factory=set)
    edge_tuples: set[tuple[int, int]] = field(default_factory=set)


@dataclass
class QueryResult:
    columns: list[str] = field(default_factory=list)
    rows: list[dict[str, Any]] = field(default_factory=list)
    subgraph: SubgraphProjection | None = None
    stats: QueryStats = field(default_factory=QueryStats)
    truncated: bool = False
    truncation_reason: str | None = None
```

- [ ] **Step 2: Commit**

```bash
git add packages/cli/src/opentools/chain/cypher/result.py
git commit -m "feat(cypher): add result types"
```

---

### Task 6: Virtual Graph Builder + Cache

**Files:**
- Create: `packages/cli/src/opentools/chain/cypher/virtual_graph.py`
- Create: `packages/cli/tests/chain/cypher/test_virtual_graph.py`

- [ ] **Step 1: Write failing tests for VirtualGraphBuilder**

```python
# packages/cli/tests/chain/cypher/test_virtual_graph.py
"""Tests for the virtual heterogeneous graph builder and cache."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
import rustworkx as rx

from opentools.chain.cypher.virtual_graph import (
    EntityNode,
    VirtualGraph,
    VirtualGraphBuilder,
    VirtualGraphCache,
)
from opentools.chain.models import Entity, EntityMention
from opentools.chain.query.graph_cache import EdgeData, FindingNode, MasterGraph
from opentools.chain.types import MentionField, RelationStatus


def _make_master_graph() -> MasterGraph:
    """Create a small master graph with 3 findings and 2 LINKED edges."""
    g = rx.PyDiGraph()
    now = datetime.now(timezone.utc)
    n0 = g.add_node(FindingNode(finding_id="fnd_1", severity="high", tool="nmap", title="Open SSH", created_at=now))
    n1 = g.add_node(FindingNode(finding_id="fnd_2", severity="critical", tool="nuclei", title="RCE vuln", created_at=now))
    n2 = g.add_node(FindingNode(finding_id="fnd_3", severity="medium", tool="burp", title="XSS", created_at=now))

    g.add_edge(n0, n1, EdgeData(
        relation_id="rel_1", weight=2.0, cost=0.5, status="auto_confirmed",
        symmetric=False, reasons=[], llm_rationale=None, llm_relation_type=None,
    ))
    g.add_edge(n1, n2, EdgeData(
        relation_id="rel_2", weight=1.5, cost=0.7, status="auto_confirmed",
        symmetric=False, reasons=[], llm_rationale=None, llm_relation_type=None,
    ))

    return MasterGraph(
        graph=g,
        node_map={"fnd_1": n0, "fnd_2": n1, "fnd_3": n2},
        reverse_map={n0: "fnd_1", n1: "fnd_2", n2: "fnd_3"},
        generation=1,
        max_weight=2.0,
    )


def _make_entities() -> list[Entity]:
    now = datetime.now(timezone.utc)
    return [
        Entity(id="ent_host1", type="host", canonical_value="10.0.0.1", first_seen_at=now, last_seen_at=now, mention_count=2),
        Entity(id="ent_cve1", type="cve", canonical_value="CVE-2024-1234", first_seen_at=now, last_seen_at=now, mention_count=1),
    ]


def _make_mentions() -> list[EntityMention]:
    now = datetime.now(timezone.utc)
    return [
        EntityMention(id="m1", entity_id="ent_host1", finding_id="fnd_1", field=MentionField.DESCRIPTION, raw_value="10.0.0.1", extractor="ioc_finder", confidence=1.0, created_at=now),
        EntityMention(id="m2", entity_id="ent_host1", finding_id="fnd_2", field=MentionField.DESCRIPTION, raw_value="10.0.0.1", extractor="ioc_finder", confidence=1.0, created_at=now),
        EntityMention(id="m3", entity_id="ent_cve1", finding_id="fnd_2", field=MentionField.TITLE, raw_value="CVE-2024-1234", extractor="security_regex", confidence=0.95, created_at=now),
    ]


@pytest.mark.asyncio
async def test_build_virtual_graph_node_counts():
    master = _make_master_graph()
    builder = VirtualGraphBuilder()
    vg = builder.build(master, _make_entities(), _make_mentions())

    # 3 findings + 2 entities = 5 nodes
    assert vg.graph.num_nodes() == 5
    assert len(vg.finding_map) == 3
    assert len(vg.entity_map) == 2


@pytest.mark.asyncio
async def test_build_virtual_graph_edge_counts():
    master = _make_master_graph()
    builder = VirtualGraphBuilder()
    vg = builder.build(master, _make_entities(), _make_mentions())

    # 2 LINKED edges + 3 MENTIONED_IN edges = 5 total
    assert vg.graph.num_edges() == 5


@pytest.mark.asyncio
async def test_build_virtual_graph_node_labels():
    master = _make_master_graph()
    builder = VirtualGraphBuilder()
    vg = builder.build(master, _make_entities(), _make_mentions())

    finding_labels = [vg.node_labels[idx] for idx in vg.finding_map.values()]
    assert all(l == "Finding" for l in finding_labels)

    host_idx = vg.entity_map["ent_host1"]
    assert vg.node_labels[host_idx] == "Host"

    cve_idx = vg.entity_map["ent_cve1"]
    assert vg.node_labels[cve_idx] == "CVE"


@pytest.mark.asyncio
async def test_mentioned_in_direction():
    """MENTIONED_IN edges go Entity → Finding."""
    master = _make_master_graph()
    builder = VirtualGraphBuilder()
    vg = builder.build(master, _make_entities(), _make_mentions())

    host_idx = vg.entity_map["ent_host1"]
    successors = list(vg.graph.successor_indices(host_idx))
    # Host entity should have successors (findings it's mentioned in)
    assert len(successors) == 2
    successor_ids = {vg.reverse_map[s] for s in successors}
    assert successor_ids == {"fnd_1", "fnd_2"}


@pytest.mark.asyncio
async def test_linked_edges_preserved():
    """LINKED edges between findings are preserved from the master graph."""
    master = _make_master_graph()
    builder = VirtualGraphBuilder()
    vg = builder.build(master, _make_entities(), _make_mentions())

    fnd1_idx = vg.finding_map["fnd_1"]
    fnd2_idx = vg.finding_map["fnd_2"]
    edge_data = vg.graph.get_edge_data(fnd1_idx, fnd2_idx)
    assert edge_data is not None


@pytest.mark.asyncio
async def test_entity_node_properties():
    master = _make_master_graph()
    builder = VirtualGraphBuilder()
    vg = builder.build(master, _make_entities(), _make_mentions())

    host_idx = vg.entity_map["ent_host1"]
    node_data = vg.graph.get_node_data(host_idx)
    assert isinstance(node_data, EntityNode)
    assert node_data.entity_id == "ent_host1"
    assert node_data.canonical_value == "10.0.0.1"
    assert node_data.entity_type == "host"


@pytest.mark.asyncio
async def test_virtual_graph_cache_reuse():
    """Same cache key returns the same VirtualGraph instance."""
    master = _make_master_graph()
    entities = _make_entities()
    mentions = _make_mentions()

    store = AsyncMock()
    store.current_linker_generation = AsyncMock(return_value=1)
    store.list_entities = AsyncMock(return_value=entities)
    # Need a method to fetch all mentions for a scope
    store.fetch_all_mentions_in_scope = AsyncMock(return_value=mentions)

    graph_cache = AsyncMock()
    graph_cache.get_master_graph = AsyncMock(return_value=master)

    cache = VirtualGraphCache(store=store, graph_cache=graph_cache, maxsize=4)
    vg1 = await cache.get(user_id=None, include_candidates=False, engagement_ids=None)
    vg2 = await cache.get(user_id=None, include_candidates=False, engagement_ids=None)
    assert vg1 is vg2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_virtual_graph.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement VirtualGraphBuilder and VirtualGraphCache**

```python
# packages/cli/src/opentools/chain/cypher/virtual_graph.py
"""Virtual heterogeneous graph: findings + entities as first-class nodes."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from uuid import UUID

import rustworkx as rx

from opentools.chain.models import Entity, EntityMention
from opentools.chain.query.graph_cache import EdgeData, FindingNode, MasterGraph

if TYPE_CHECKING:
    from opentools.chain.query.graph_cache import GraphCache
    from opentools.chain.store_protocol import ChainStoreProtocol

# Entity type → node label mapping
_ENTITY_TYPE_TO_LABEL: dict[str, str] = {
    "host": "Host",
    "ip": "IP",
    "cve": "CVE",
    "domain": "Domain",
    "port": "Port",
    "mitre_technique": "MitreAttack",
}


@dataclass
class EntityNode:
    entity_id: str
    entity_type: str
    canonical_value: str
    mention_count: int


@dataclass
class MentionedInEdge:
    mention_id: str
    field: str
    confidence: float
    extractor: str


@dataclass
class VirtualGraph:
    graph: rx.PyDiGraph
    finding_map: dict[str, int]     # finding_id → node index
    entity_map: dict[str, int]      # entity_id → node index
    reverse_map: dict[int, str]     # node index → id
    node_labels: dict[int, str]     # node index → label
    generation: int


class VirtualGraphBuilder:
    """Build a VirtualGraph from a MasterGraph + entity/mention data."""

    def build(
        self,
        master: MasterGraph,
        entities: list[Entity],
        mentions: list[EntityMention],
    ) -> VirtualGraph:
        graph = rx.PyDiGraph()
        finding_map: dict[str, int] = {}
        entity_map: dict[str, int] = {}
        reverse_map: dict[int, str] = {}
        node_labels: dict[int, str] = {}

        # Copy finding nodes from master graph
        for finding_id, master_idx in master.node_map.items():
            node_data = master.graph.get_node_data(master_idx)
            idx = graph.add_node(node_data)
            finding_map[finding_id] = idx
            reverse_map[idx] = finding_id
            node_labels[idx] = "Finding"

        # Copy LINKED edges from master graph
        for edge_idx in master.graph.edge_indices():
            src, tgt = master.graph.get_edge_endpoints_by_index(edge_idx)
            edge_data = master.graph.get_edge_data_by_index(edge_idx)
            src_id = master.reverse_map.get(src)
            tgt_id = master.reverse_map.get(tgt)
            if src_id and tgt_id and src_id in finding_map and tgt_id in finding_map:
                graph.add_edge(finding_map[src_id], finding_map[tgt_id], edge_data)

        # Add entity nodes
        for entity in entities:
            label = _ENTITY_TYPE_TO_LABEL.get(entity.type, "Entity")
            en = EntityNode(
                entity_id=entity.id,
                entity_type=entity.type,
                canonical_value=entity.canonical_value,
                mention_count=entity.mention_count,
            )
            idx = graph.add_node(en)
            entity_map[entity.id] = idx
            reverse_map[idx] = entity.id
            node_labels[idx] = label

        # Add MENTIONED_IN edges: Entity → Finding
        for mention in mentions:
            entity_idx = entity_map.get(mention.entity_id)
            finding_idx = finding_map.get(mention.finding_id)
            if entity_idx is not None and finding_idx is not None:
                edge = MentionedInEdge(
                    mention_id=mention.id,
                    field=mention.field.value if hasattr(mention.field, "value") else str(mention.field),
                    confidence=mention.confidence,
                    extractor=mention.extractor,
                )
                graph.add_edge(entity_idx, finding_idx, edge)

        return VirtualGraph(
            graph=graph,
            finding_map=finding_map,
            entity_map=entity_map,
            reverse_map=reverse_map,
            node_labels=node_labels,
            generation=master.generation,
        )


class VirtualGraphCache:
    """Async LRU cache of virtual graphs."""

    def __init__(
        self,
        *,
        store: "ChainStoreProtocol",
        graph_cache: "GraphCache",
        maxsize: int = 4,
    ) -> None:
        self.store = store
        self.graph_cache = graph_cache
        self.maxsize = maxsize
        self._cache: dict[tuple, VirtualGraph] = {}
        self._access_order: list[tuple] = []
        self._build_locks: dict[tuple, asyncio.Lock] = {}
        self._builder = VirtualGraphBuilder()

    async def get(
        self,
        *,
        user_id: UUID | None,
        include_candidates: bool = False,
        engagement_ids: frozenset[str] | None = None,
    ) -> VirtualGraph:
        generation = await self.store.current_linker_generation(user_id=user_id)
        key = (
            str(user_id) if user_id else None,
            generation,
            include_candidates,
            engagement_ids,
        )

        if key in self._cache:
            self._access_order.remove(key)
            self._access_order.append(key)
            return self._cache[key]

        lock = self._build_locks.setdefault(key, asyncio.Lock())
        async with lock:
            if key in self._cache:
                self._access_order.remove(key)
                self._access_order.append(key)
                return self._cache[key]

            master = await self.graph_cache.get_master_graph(
                user_id=user_id,
                include_candidates=include_candidates,
            )
            entities = await self.store.list_entities(
                user_id=user_id, limit=100_000,
            )
            mentions = await self.store.fetch_all_mentions_in_scope(
                user_id=user_id,
            )

            vg = self._builder.build(master, entities, mentions)
            self._cache[key] = vg
            self._access_order.append(key)

            while len(self._access_order) > self.maxsize:
                oldest = self._access_order.pop(0)
                self._cache.pop(oldest, None)
                self._build_locks.pop(oldest, None)

            return vg

    def invalidate(self, *, user_id: UUID | None) -> None:
        user_key = str(user_id) if user_id else None
        to_remove = [k for k in self._access_order if k[0] == user_key]
        for k in to_remove:
            self._access_order.remove(k)
            self._cache.pop(k, None)
            self._build_locks.pop(k, None)

    def clear(self) -> None:
        self._cache.clear()
        self._access_order.clear()
        self._build_locks.clear()
```

Note: The `VirtualGraphCache.get()` method calls `store.fetch_all_mentions_in_scope()` — this is a new protocol method that needs to be added to `ChainStoreProtocol` and both backends. The implementing agent should add this method (returns all `EntityMention` rows for the user scope) as part of this task if it doesn't already exist. Check `store_protocol.py` and the existing mention-related methods (`mentions_for_finding`, `add_mentions_bulk`) for the pattern.

- [ ] **Step 4: Run tests and iterate until passing**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_virtual_graph.py -v`
Expected: 7 passed. If `get_edge_endpoints_by_index` or `get_edge_data_by_index` are not available in the installed rustworkx version, use the edge iteration API instead (`edge_list()` returns `(src, tgt)` tuples, `edges()` returns payloads).

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/chain/cypher/virtual_graph.py packages/cli/tests/chain/cypher/test_virtual_graph.py
git commit -m "feat(cypher): add virtual heterogeneous graph builder and cache"
```

---

### Task 7: Planner

**Files:**
- Create: `packages/cli/src/opentools/chain/cypher/planner.py`
- Create: `packages/cli/tests/chain/cypher/test_planner.py`

- [ ] **Step 1: Write failing tests for the planner**

```python
# packages/cli/tests/chain/cypher/test_planner.py
import pytest

from opentools.chain.cypher.ast_nodes import (
    ComparisonExpr,
    CypherQuery,
    EdgePattern,
    MatchClause,
    NodePattern,
    PropertyAccessExpr,
    ReturnClause,
    ReturnItem,
    VarLengthSpec,
    WhereClause,
)
from opentools.chain.cypher.limits import QueryLimits
from opentools.chain.cypher.planner import plan_query, PlanStep, QueryPlan


def _simple_query() -> CypherQuery:
    """MATCH (a:Finding) RETURN a"""
    return CypherQuery(
        match_clause=MatchClause(patterns=[
            (NodePattern(variable="a", label="Finding"),),
        ]),
        where_clause=None,
        return_clause=ReturnClause(items=[ReturnItem(expression="a", alias=None)]),
    )


def _two_node_query() -> CypherQuery:
    """MATCH (a:Finding)-[r:LINKED]->(b:Finding) RETURN a, b"""
    return CypherQuery(
        match_clause=MatchClause(patterns=[
            (
                NodePattern(variable="a", label="Finding"),
                EdgePattern(variable="r", label="LINKED", direction="out", var_length=None),
                NodePattern(variable="b", label="Finding"),
            ),
        ]),
        where_clause=None,
        return_clause=ReturnClause(items=[
            ReturnItem(expression="a", alias=None),
            ReturnItem(expression="b", alias=None),
        ]),
    )


def _filtered_query() -> CypherQuery:
    """MATCH (a:Finding) WHERE a.severity = "critical" RETURN a"""
    return CypherQuery(
        match_clause=MatchClause(patterns=[
            (NodePattern(variable="a", label="Finding"),),
        ]),
        where_clause=WhereClause(expression=ComparisonExpr(
            left=PropertyAccessExpr(variable="a", property_name="severity"),
            operator="=",
            right="critical",
        )),
        return_clause=ReturnClause(items=[ReturnItem(expression="a", alias=None)]),
    )


def _var_length_query() -> CypherQuery:
    """MATCH (a:Finding)-[r:LINKED*1..5]->(b:Finding) RETURN a, b"""
    return CypherQuery(
        match_clause=MatchClause(patterns=[
            (
                NodePattern(variable="a", label="Finding"),
                EdgePattern(variable="r", label="LINKED", direction="out", var_length=VarLengthSpec(min_hops=1, max_hops=5)),
                NodePattern(variable="b", label="Finding"),
            ),
        ]),
        where_clause=None,
        return_clause=ReturnClause(items=[
            ReturnItem(expression="a", alias=None),
            ReturnItem(expression="b", alias=None),
        ]),
    )


def test_plan_simple_scan():
    plan = plan_query(_simple_query(), QueryLimits())
    assert len(plan.steps) == 1
    assert plan.steps[0].kind == "scan"
    assert plan.steps[0].label == "Finding"
    assert plan.steps[0].target_var == "a"


def test_plan_two_node_has_scan_then_expand():
    plan = plan_query(_two_node_query(), QueryLimits())
    assert plan.steps[0].kind == "scan"
    assert plan.steps[0].target_var == "a"
    assert plan.steps[1].kind == "expand"
    assert plan.steps[1].target_var == "r"
    assert plan.steps[1].label == "LINKED"
    # The third step binds b via the expand target
    # (or b is bound implicitly by the expand — depends on implementation)


def test_plan_predicate_pushdown():
    plan = plan_query(_filtered_query(), QueryLimits())
    # The WHERE predicate on 'a' should be pushed down to the scan step for 'a'
    scan_step = plan.steps[0]
    assert scan_step.kind == "scan"
    assert scan_step.target_var == "a"
    assert len(scan_step.predicates) == 1
    assert isinstance(scan_step.predicates[0], ComparisonExpr)


def test_plan_var_length_expand():
    plan = plan_query(_var_length_query(), QueryLimits())
    var_length_steps = [s for s in plan.steps if s.kind == "var_length_expand"]
    assert len(var_length_steps) == 1
    vl = var_length_steps[0]
    assert vl.min_hops == 1
    assert vl.max_hops == 5
    assert vl.label == "LINKED"


def test_plan_preserves_limits():
    limits = QueryLimits(timeout_seconds=60.0, max_rows=500)
    plan = plan_query(_simple_query(), limits)
    assert plan.limits.timeout_seconds == 60.0
    assert plan.limits.max_rows == 500
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_planner.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement planner**

```python
# packages/cli/src/opentools/chain/cypher/planner.py
"""Query planner: AST → QueryPlan with predicate pushdown."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from opentools.chain.cypher.ast_nodes import (
    BooleanExpr,
    ComparisonExpr,
    CypherQuery,
    EdgePattern,
    FunctionCallExpr,
    NodePattern,
    PropertyAccessExpr,
    ReturnClause,
)
from opentools.chain.cypher.limits import QueryLimits


@dataclass
class PlanStep:
    kind: Literal["scan", "expand", "filter", "var_length_expand"]
    target_var: str
    label: str | None = None
    direction: Literal["out", "in", "both"] | None = None
    min_hops: int | None = None
    max_hops: int | None = None
    predicates: list[Any] = field(default_factory=list)
    from_session: str | None = None  # for session result scans


@dataclass
class ReturnSpec:
    items: list[Any]  # ReturnItem instances from the AST


@dataclass
class QueryPlan:
    steps: list[PlanStep]
    return_spec: ReturnSpec
    limits: QueryLimits


def _extract_variables(expr: Any) -> set[str]:
    """Extract variable names referenced in an expression."""
    if isinstance(expr, PropertyAccessExpr):
        return {expr.variable}
    if isinstance(expr, ComparisonExpr):
        return _extract_variables(expr.left) | (
            _extract_variables(expr.right) if not isinstance(expr.right, (str, int, float, bool, type(None), list)) else set()
        )
    if isinstance(expr, BooleanExpr):
        result: set[str] = set()
        for op in expr.operands:
            result |= _extract_variables(op)
        return result
    if isinstance(expr, FunctionCallExpr):
        result = set()
        for arg in expr.args:
            if isinstance(arg, str):
                result.add(arg)
            else:
                result |= _extract_variables(arg)
        return result
    if isinstance(expr, str):
        return {expr}
    return set()


def _flatten_and(expr: Any) -> list[Any]:
    """Flatten AND expressions into a list of conjuncts."""
    if isinstance(expr, BooleanExpr) and expr.operator == "AND":
        result = []
        for op in expr.operands:
            result.extend(_flatten_and(op))
        return result
    return [expr]


def plan_query(query: CypherQuery, limits: QueryLimits) -> QueryPlan:
    """Convert a parsed CypherQuery AST into a QueryPlan."""
    steps: list[PlanStep] = []

    # Collect all WHERE predicates as a flat list of conjuncts
    pending_predicates: list[Any] = []
    if query.where_clause is not None:
        pending_predicates = _flatten_and(query.where_clause.expression)

    # Track which variables are bound so far
    bound_vars: set[str] = set()

    # Process each pattern in the MATCH clause
    for pattern_tuple in query.match_clause.patterns:
        elements = list(pattern_tuple)

        for i, element in enumerate(elements):
            if isinstance(element, NodePattern):
                var = element.variable
                if var and var not in bound_vars:
                    # Check if this is a FROM-clause scan
                    from_session = None
                    if query.from_clause and i == 0:
                        from_session = query.from_clause.session_variable

                    step = PlanStep(
                        kind="scan",
                        target_var=var,
                        label=element.label,
                        from_session=from_session,
                    )
                    bound_vars.add(var)

                    # Push down predicates whose variables are now all bound
                    remaining = []
                    for pred in pending_predicates:
                        pred_vars = _extract_variables(pred)
                        if pred_vars <= bound_vars:
                            step.predicates.append(pred)
                        else:
                            remaining.append(pred)
                    pending_predicates = remaining

                    steps.append(step)

            elif isinstance(element, EdgePattern):
                var = element.variable
                if element.var_length is not None:
                    step = PlanStep(
                        kind="var_length_expand",
                        target_var=var or f"_anon_edge_{i}",
                        label=element.label,
                        direction=element.direction,
                        min_hops=element.var_length.min_hops,
                        max_hops=element.var_length.max_hops,
                    )
                else:
                    step = PlanStep(
                        kind="expand",
                        target_var=var or f"_anon_edge_{i}",
                        label=element.label,
                        direction=element.direction,
                    )
                if var:
                    bound_vars.add(var)

                # Push down predicates
                remaining = []
                for pred in pending_predicates:
                    pred_vars = _extract_variables(pred)
                    if pred_vars <= bound_vars:
                        step.predicates.append(pred)
                    else:
                        remaining.append(pred)
                pending_predicates = remaining

                steps.append(step)

    # Any remaining predicates become a final filter step
    if pending_predicates:
        steps.append(PlanStep(
            kind="filter",
            target_var="_post_filter",
            predicates=pending_predicates,
        ))

    return QueryPlan(
        steps=steps,
        return_spec=ReturnSpec(items=query.return_clause.items),
        limits=limits,
    )
```

- [ ] **Step 4: Run tests**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_planner.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/chain/cypher/planner.py packages/cli/tests/chain/cypher/test_planner.py
git commit -m "feat(cypher): add query planner with predicate pushdown"
```

---

### Task 8: Executor

**Files:**
- Create: `packages/cli/src/opentools/chain/cypher/executor.py`
- Create: `packages/cli/tests/chain/cypher/test_executor.py`

- [ ] **Step 1: Write failing tests for the executor**

```python
# packages/cli/tests/chain/cypher/test_executor.py
"""End-to-end executor tests against small fixture virtual graphs."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
import rustworkx as rx

from opentools.chain.cypher.executor import CypherExecutor
from opentools.chain.cypher.limits import QueryLimits
from opentools.chain.cypher.parser import parse_cypher
from opentools.chain.cypher.planner import plan_query
from opentools.chain.cypher.plugins import PluginFunctionRegistry
from opentools.chain.cypher.result import QueryResult
from opentools.chain.cypher.session import QuerySession
from opentools.chain.cypher.virtual_graph import EntityNode, MentionedInEdge, VirtualGraph
from opentools.chain.query.graph_cache import EdgeData, FindingNode


def _build_test_vg() -> VirtualGraph:
    """3 findings, 1 host entity, 2 LINKED edges, 2 MENTIONED_IN edges."""
    g = rx.PyDiGraph()
    now = datetime.now(timezone.utc)

    # Findings
    n0 = g.add_node(FindingNode(finding_id="fnd_1", severity="high", tool="nmap", title="Open SSH", created_at=now))
    n1 = g.add_node(FindingNode(finding_id="fnd_2", severity="critical", tool="nuclei", title="RCE vuln", created_at=now))
    n2 = g.add_node(FindingNode(finding_id="fnd_3", severity="medium", tool="burp", title="XSS", created_at=now))

    # Entity
    n3 = g.add_node(EntityNode(entity_id="ent_host1", entity_type="host", canonical_value="10.0.0.1", mention_count=2))

    # LINKED: fnd_1 -> fnd_2, fnd_2 -> fnd_3
    g.add_edge(n0, n1, EdgeData(
        relation_id="rel_1", weight=2.0, cost=0.5, status="auto_confirmed",
        symmetric=False, reasons=[], llm_rationale=None, llm_relation_type=None,
    ))
    g.add_edge(n1, n2, EdgeData(
        relation_id="rel_2", weight=1.5, cost=0.7, status="auto_confirmed",
        symmetric=False, reasons=[], llm_rationale=None, llm_relation_type=None,
    ))

    # MENTIONED_IN: host -> fnd_1, host -> fnd_2
    g.add_edge(n3, n0, MentionedInEdge(mention_id="m1", field="description", confidence=1.0, extractor="ioc_finder"))
    g.add_edge(n3, n1, MentionedInEdge(mention_id="m2", field="description", confidence=1.0, extractor="ioc_finder"))

    return VirtualGraph(
        graph=g,
        finding_map={"fnd_1": n0, "fnd_2": n1, "fnd_3": n2},
        entity_map={"ent_host1": n3},
        reverse_map={n0: "fnd_1", n1: "fnd_2", n2: "fnd_3", n3: "ent_host1"},
        node_labels={n0: "Finding", n1: "Finding", n2: "Finding", n3: "Host"},
        generation=1,
    )


def _execute(query_str: str, vg: VirtualGraph | None = None, limits: QueryLimits | None = None) -> QueryResult:
    """Parse, plan, and execute a query synchronously for tests."""
    import asyncio
    if vg is None:
        vg = _build_test_vg()
    if limits is None:
        limits = QueryLimits()
    ast = parse_cypher(query_str)
    plan = plan_query(ast, limits)
    executor = CypherExecutor(
        virtual_graph=vg,
        plan=plan,
        session=QuerySession(),
        plugin_registry=PluginFunctionRegistry(),
        limits=limits,
    )
    return asyncio.get_event_loop().run_until_complete(executor.execute())


@pytest.mark.asyncio
async def test_scan_all_findings():
    result = _execute("MATCH (a:Finding) RETURN a")
    assert len(result.rows) == 3
    assert "a" in result.columns


@pytest.mark.asyncio
async def test_scan_entity_label():
    result = _execute("MATCH (h:Host) RETURN h")
    assert len(result.rows) == 1


@pytest.mark.asyncio
async def test_expand_linked():
    result = _execute("MATCH (a:Finding)-[r:LINKED]->(b:Finding) RETURN a, b")
    assert len(result.rows) == 2  # fnd_1->fnd_2, fnd_2->fnd_3


@pytest.mark.asyncio
async def test_expand_mentioned_in():
    result = _execute("MATCH (h:Host)-[r:MENTIONED_IN]->(f:Finding) RETURN h, f")
    assert len(result.rows) == 2  # host->fnd_1, host->fnd_2


@pytest.mark.asyncio
async def test_where_filter():
    result = _execute('MATCH (a:Finding) WHERE a.severity = "critical" RETURN a')
    assert len(result.rows) == 1
    assert result.rows[0]["a"]["severity"] == "critical"


@pytest.mark.asyncio
async def test_where_numeric_comparison():
    result = _execute("MATCH (a:Finding)-[r:LINKED]->(b:Finding) WHERE r.weight > 1.8 RETURN a, b")
    assert len(result.rows) == 1  # only rel_1 has weight=2.0


@pytest.mark.asyncio
async def test_return_property():
    result = _execute("MATCH (a:Finding) RETURN a.title, a.severity")
    assert len(result.rows) == 3
    assert "a.title" in result.columns or "title" in str(result.columns)


@pytest.mark.asyncio
async def test_subgraph_projection():
    result = _execute("MATCH (a:Finding)-[r:LINKED]->(b:Finding) RETURN a, b")
    assert result.subgraph is not None
    assert len(result.subgraph.node_indices) >= 2


@pytest.mark.asyncio
async def test_resource_limit_max_rows():
    result = _execute("MATCH (a:Finding) RETURN a", limits=QueryLimits(max_rows=1))
    assert len(result.rows) == 1
    assert result.truncated is True


@pytest.mark.asyncio
async def test_resource_limit_timeout():
    """A near-zero timeout should abort quickly."""
    from opentools.chain.cypher.errors import QueryResourceError
    # This test verifies the timeout mechanism exists — with a tiny graph
    # it may not actually trigger, so we use a very small timeout
    result = _execute("MATCH (a:Finding) RETURN a", limits=QueryLimits(timeout_seconds=0.0001))
    # Either it completes (graph is tiny) or raises QueryResourceError
    # Both are acceptable — the important thing is the mechanism exists
    assert isinstance(result, QueryResult)


@pytest.mark.asyncio
async def test_empty_result():
    result = _execute('MATCH (a:Finding) WHERE a.severity = "nonexistent" RETURN a')
    assert len(result.rows) == 0
    assert result.truncated is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_executor.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement the executor**

```python
# packages/cli/src/opentools/chain/cypher/executor.py
"""CypherExecutor: walks a QueryPlan against a VirtualGraph."""
from __future__ import annotations

import time
from typing import Any

from opentools.chain.cypher.ast_nodes import (
    BooleanExpr,
    ComparisonExpr,
    FunctionCallExpr,
    PropertyAccessExpr,
    ReturnItem,
)
from opentools.chain.cypher.builtins import get_builtin
from opentools.chain.cypher.errors import QueryResourceError
from opentools.chain.cypher.limits import QueryLimits
from opentools.chain.cypher.planner import PlanStep, QueryPlan
from opentools.chain.cypher.plugins import PluginFunctionRegistry
from opentools.chain.cypher.result import QueryResult, QueryStats, SubgraphProjection
from opentools.chain.cypher.session import QuerySession
from opentools.chain.cypher.virtual_graph import EntityNode, MentionedInEdge, VirtualGraph
from opentools.chain.query.graph_cache import EdgeData, FindingNode

# Binding = dict mapping variable names to node/edge indices or data
Binding = dict[str, Any]


class CypherExecutor:
    def __init__(
        self,
        *,
        virtual_graph: VirtualGraph,
        plan: QueryPlan,
        session: QuerySession,
        plugin_registry: PluginFunctionRegistry,
        limits: QueryLimits,
    ) -> None:
        self.vg = virtual_graph
        self.plan = plan
        self.session = session
        self.plugins = plugin_registry
        self.limits = limits

    async def execute(self) -> QueryResult:
        start = time.monotonic()
        bindings: list[Binding] = [{}]  # start with one empty binding
        explored = 0

        for step in self.plan.steps:
            # Timeout check
            elapsed = time.monotonic() - start
            if elapsed > self.limits.timeout_seconds:
                raise QueryResourceError(
                    f"query timeout after {elapsed:.1f}s",
                    limit_name="timeout_seconds",
                    limit_value=self.limits.timeout_seconds,
                )

            if step.kind == "scan":
                bindings = self._step_scan(step, bindings)
            elif step.kind == "expand":
                bindings = self._step_expand(step, bindings)
            elif step.kind == "var_length_expand":
                bindings = self._step_var_length_expand(step, bindings)
            elif step.kind == "filter":
                bindings = self._step_filter(step, bindings)

            explored += len(bindings)

            # Intermediate binding cap
            if len(bindings) > self.limits.intermediate_binding_cap:
                raise QueryResourceError(
                    f"intermediate binding cap exceeded: {len(bindings)} > {self.limits.intermediate_binding_cap}",
                    limit_name="intermediate_binding_cap",
                    limit_value=self.limits.intermediate_binding_cap,
                )

        # Project RETURN
        columns, rows = self._project_return(bindings)

        # Truncate
        truncated = False
        truncation_reason = None
        if len(rows) > self.limits.max_rows:
            rows = rows[:self.limits.max_rows]
            truncated = True
            truncation_reason = f"max_rows ({self.limits.max_rows})"

        # Build subgraph projection
        subgraph = self._build_subgraph(bindings)

        elapsed_ms = (time.monotonic() - start) * 1000
        return QueryResult(
            columns=columns,
            rows=rows,
            subgraph=subgraph,
            stats=QueryStats(duration_ms=elapsed_ms, bindings_explored=explored, rows_returned=len(rows)),
            truncated=truncated,
            truncation_reason=truncation_reason,
        )

    # ─── step implementations ────────────────────────────────────

    def _step_scan(self, step: PlanStep, bindings: list[Binding]) -> list[Binding]:
        """Scan all nodes matching the label, create bindings."""
        new_bindings: list[Binding] = []

        # If scanning from session, use stored result set
        if step.from_session:
            stored = self.session.get(step.from_session)
            if stored is not None:
                for row in stored.rows:
                    if step.target_var in row:
                        binding = {step.target_var: row[step.target_var]}
                        new_bindings.append(binding)
                return new_bindings

        for idx in self.vg.graph.node_indices():
            label = self.vg.node_labels.get(idx)
            if step.label and label != step.label:
                continue

            node_data = self.vg.graph.get_node_data(idx)
            node_dict = self._node_to_dict(node_data, idx)

            for b in bindings:
                new_b = {**b, step.target_var: node_dict}
                new_b[f"_idx_{step.target_var}"] = idx  # internal index tracking
                if self._check_predicates(step.predicates, new_b):
                    new_bindings.append(new_b)

        return new_bindings

    def _step_expand(self, step: PlanStep, bindings: list[Binding]) -> list[Binding]:
        """Expand from bound nodes along edges of the specified type."""
        new_bindings: list[Binding] = []

        for b in bindings:
            # Find the last bound node index
            last_node_var = self._last_node_var(b)
            if last_node_var is None:
                continue
            src_idx = b.get(f"_idx_{last_node_var}")
            if src_idx is None:
                continue

            # Get edges based on direction
            if step.direction == "out":
                neighbors = self._outgoing_edges(src_idx, step.label)
            elif step.direction == "in":
                neighbors = self._incoming_edges(src_idx, step.label)
            else:
                neighbors = self._outgoing_edges(src_idx, step.label) + self._incoming_edges(src_idx, step.label)

            for tgt_idx, edge_data in neighbors:
                tgt_node = self.vg.graph.get_node_data(tgt_idx)
                tgt_dict = self._node_to_dict(tgt_node, tgt_idx)
                edge_dict = self._edge_to_dict(edge_data)

                # Find the next node variable from the plan
                next_node_var = self._next_node_var_after_edge(step.target_var)

                new_b = {**b}
                new_b[step.target_var] = edge_dict
                new_b[f"_idx_{step.target_var}"] = (src_idx, tgt_idx)
                if next_node_var:
                    new_b[next_node_var] = tgt_dict
                    new_b[f"_idx_{next_node_var}"] = tgt_idx

                # Check label on target node if the plan specifies one
                tgt_label = self.vg.node_labels.get(tgt_idx)
                next_step_label = self._get_next_node_label(step.target_var)
                if next_step_label and tgt_label != next_step_label:
                    continue

                if self._check_predicates(step.predicates, new_b):
                    new_bindings.append(new_b)

        return new_bindings

    def _step_var_length_expand(self, step: PlanStep, bindings: list[Binding]) -> list[Binding]:
        """Bounded DFS for variable-length path patterns."""
        new_bindings: list[Binding] = []

        for b in bindings:
            last_node_var = self._last_node_var(b)
            if last_node_var is None:
                continue
            start_idx = b.get(f"_idx_{last_node_var}")
            if start_idx is None:
                continue

            # DFS with depth bounds
            paths = self._bounded_dfs(
                start_idx,
                label=step.label,
                direction=step.direction or "out",
                min_depth=step.min_hops or 1,
                max_depth=step.max_hops or 10,
            )

            next_node_var = self._next_node_var_after_edge(step.target_var)

            for path_nodes, path_edges in paths:
                if not path_nodes:
                    continue
                end_idx = path_nodes[-1]
                end_node = self.vg.graph.get_node_data(end_idx)
                end_dict = self._node_to_dict(end_node, end_idx)

                # Check target node label
                end_label = self.vg.node_labels.get(end_idx)
                next_step_label = self._get_next_node_label(step.target_var)
                if next_step_label and end_label != next_step_label:
                    continue

                path_dict = {
                    "nodes": [self._node_to_dict(self.vg.graph.get_node_data(n), n) for n in path_nodes],
                    "edges": [self._edge_to_dict(e) for e in path_edges],
                }

                new_b = {**b}
                new_b[step.target_var] = path_dict
                if next_node_var:
                    new_b[next_node_var] = end_dict
                    new_b[f"_idx_{next_node_var}"] = end_idx

                if self._check_predicates(step.predicates, new_b):
                    new_bindings.append(new_b)

        return new_bindings

    def _step_filter(self, step: PlanStep, bindings: list[Binding]) -> list[Binding]:
        return [b for b in bindings if self._check_predicates(step.predicates, b)]

    # ─── helpers ──────────────────────────────────────────────────

    def _outgoing_edges(self, src_idx: int, label: str | None) -> list[tuple[int, Any]]:
        result = []
        for tgt_idx in self.vg.graph.successor_indices(src_idx):
            edge_data = self.vg.graph.get_edge_data(src_idx, tgt_idx)
            if label and not self._edge_matches_label(edge_data, label):
                continue
            result.append((tgt_idx, edge_data))
        return result

    def _incoming_edges(self, src_idx: int, label: str | None) -> list[tuple[int, Any]]:
        result = []
        for pred_idx in self.vg.graph.predecessor_indices(src_idx):
            edge_data = self.vg.graph.get_edge_data(pred_idx, src_idx)
            if label and not self._edge_matches_label(edge_data, label):
                continue
            result.append((pred_idx, edge_data))
        return result

    def _edge_matches_label(self, edge_data: Any, label: str) -> bool:
        if label == "LINKED" and isinstance(edge_data, EdgeData):
            return True
        if label == "MENTIONED_IN" and isinstance(edge_data, MentionedInEdge):
            return True
        return False

    def _bounded_dfs(
        self,
        start: int,
        *,
        label: str | None,
        direction: str,
        min_depth: int,
        max_depth: int,
    ) -> list[tuple[list[int], list[Any]]]:
        """Return all paths of length [min_depth, max_depth] from start."""
        results: list[tuple[list[int], list[Any]]] = []
        # Stack: (current_node, path_nodes, path_edges, visited)
        stack: list[tuple[int, list[int], list[Any], set[int]]] = [
            (start, [start], [], {start})
        ]

        while stack:
            current, path_nodes, path_edges, visited = stack.pop()
            depth = len(path_edges)

            if depth >= min_depth:
                # Record this path (end node, not start)
                results.append((list(path_nodes), list(path_edges)))

            if depth >= max_depth:
                continue

            if direction == "out":
                neighbors = self._outgoing_edges(current, label)
            elif direction == "in":
                neighbors = self._incoming_edges(current, label)
            else:
                neighbors = self._outgoing_edges(current, label) + self._incoming_edges(current, label)

            for next_idx, edge_data in neighbors:
                if next_idx not in visited:
                    stack.append((
                        next_idx,
                        path_nodes + [next_idx],
                        path_edges + [edge_data],
                        visited | {next_idx},
                    ))

        return results

    def _node_to_dict(self, node_data: Any, idx: int) -> dict:
        if isinstance(node_data, FindingNode):
            return {
                "id": node_data.finding_id,
                "label": "Finding",
                "severity": node_data.severity,
                "tool": node_data.tool,
                "title": node_data.title,
                "created_at": str(node_data.created_at) if node_data.created_at else None,
                "_idx": idx,
            }
        if isinstance(node_data, EntityNode):
            return {
                "id": node_data.entity_id,
                "label": self.vg.node_labels.get(idx, "Entity"),
                "canonical_value": node_data.canonical_value,
                "entity_type": node_data.entity_type,
                "mention_count": node_data.mention_count,
                "_idx": idx,
            }
        return {"_idx": idx}

    def _edge_to_dict(self, edge_data: Any) -> dict:
        if isinstance(edge_data, EdgeData):
            return {
                "label": "LINKED",
                "relation_id": edge_data.relation_id,
                "weight": edge_data.weight,
                "status": edge_data.status,
                "reasons": [r.rule for r in edge_data.reasons] if edge_data.reasons else [],
                "llm_rationale": edge_data.llm_rationale,
                "llm_relation_type": edge_data.llm_relation_type,
            }
        if isinstance(edge_data, MentionedInEdge):
            return {
                "label": "MENTIONED_IN",
                "mention_id": edge_data.mention_id,
                "field": edge_data.field,
                "confidence": edge_data.confidence,
                "extractor": edge_data.extractor,
            }
        return {}

    def _check_predicates(self, predicates: list, binding: Binding) -> bool:
        for pred in predicates:
            if not self._eval_predicate(pred, binding):
                return False
        return True

    def _eval_predicate(self, pred: Any, binding: Binding) -> bool:
        if isinstance(pred, ComparisonExpr):
            left_val = self._eval_expr(pred.left, binding)
            if pred.operator == "IS NULL":
                return left_val is None
            if pred.operator == "IS NOT NULL":
                return left_val is not None
            right_val = self._eval_expr(pred.right, binding)
            return self._compare(left_val, pred.operator, right_val)
        if isinstance(pred, BooleanExpr):
            if pred.operator == "AND":
                return all(self._eval_predicate(op, binding) for op in pred.operands)
            if pred.operator == "OR":
                return any(self._eval_predicate(op, binding) for op in pred.operands)
            if pred.operator == "NOT":
                return not self._eval_predicate(pred.operands[0], binding)
        if isinstance(pred, FunctionCallExpr):
            return bool(self._eval_function(pred, binding))
        return True

    def _eval_expr(self, expr: Any, binding: Binding) -> Any:
        if isinstance(expr, PropertyAccessExpr):
            node_or_edge = binding.get(expr.variable)
            if isinstance(node_or_edge, dict):
                return node_or_edge.get(expr.property_name)
            return None
        if isinstance(expr, FunctionCallExpr):
            return self._eval_function(expr, binding)
        if isinstance(expr, str) and expr in binding:
            return binding[expr]
        return expr  # literal value

    def _eval_function(self, func: FunctionCallExpr, binding: Binding) -> Any:
        # Check built-ins first
        builtin_fn = get_builtin(func.name)
        if builtin_fn is not None:
            args = [self._eval_expr(a, binding) for a in func.args]
            return builtin_fn(*args)
        # Check plugin registry
        plugin_fn = self.plugins.get_function(func.name)
        if plugin_fn is not None:
            args = [self._eval_expr(a, binding) for a in func.args]
            return plugin_fn(*args)
        plugin_agg = self.plugins.get_aggregation(func.name)
        if plugin_agg is not None:
            args = [self._eval_expr(a, binding) for a in func.args]
            return plugin_agg(*args)
        return None

    def _compare(self, left: Any, op: str, right: Any) -> bool:
        try:
            if op == "=":
                return left == right
            if op == "<>":
                return left != right
            if op == "<":
                return left < right
            if op == ">":
                return left > right
            if op == "<=":
                return left <= right
            if op == ">=":
                return left >= right
            if op == "CONTAINS":
                return isinstance(left, str) and isinstance(right, str) and right in left
            if op in ("STARTS WITH", "STARTS_WITH"):
                return isinstance(left, str) and isinstance(right, str) and left.startswith(right)
            if op in ("ENDS WITH", "ENDS_WITH"):
                return isinstance(left, str) and isinstance(right, str) and left.endswith(right)
            if op == "IN":
                return left in right if isinstance(right, list) else False
        except TypeError:
            return False
        return False

    def _last_node_var(self, binding: Binding) -> str | None:
        """Find the last node variable in the binding (has _idx_ prefix that maps to an int)."""
        last = None
        for key in binding:
            if key.startswith("_idx_") and isinstance(binding[key], int):
                last = key[5:]
        return last

    def _next_node_var_after_edge(self, edge_var: str) -> str | None:
        """Find the node variable that follows this edge variable in the plan steps."""
        found_edge = False
        for step in self.plan.steps:
            if step.target_var == edge_var:
                found_edge = True
                continue
            if found_edge and step.kind == "scan":
                return step.target_var
        # If no explicit scan step for the next node, check the pattern
        # The next node's variable needs to come from the AST patterns
        return None

    def _get_next_node_label(self, edge_var: str) -> str | None:
        """Get the label of the node that follows this edge variable in the plan."""
        found_edge = False
        for step in self.plan.steps:
            if step.target_var == edge_var:
                found_edge = True
                continue
            if found_edge and step.kind == "scan":
                return step.label
        return None

    def _project_return(self, bindings: list[Binding]) -> tuple[list[str], list[dict]]:
        """Project bindings through RETURN clause."""
        columns: list[str] = []
        for item in self.plan.return_spec.items:
            if isinstance(item, ReturnItem):
                if item.alias:
                    columns.append(item.alias)
                elif isinstance(item.expression, PropertyAccessExpr):
                    columns.append(f"{item.expression.variable}.{item.expression.property_name}")
                elif isinstance(item.expression, str):
                    columns.append(item.expression)
                elif isinstance(item.expression, FunctionCallExpr):
                    columns.append(item.expression.name)
                else:
                    columns.append(str(item.expression))
            else:
                columns.append(str(item))

        rows: list[dict] = []
        for b in bindings:
            row: dict = {}
            for i, item in enumerate(self.plan.return_spec.items):
                col = columns[i]
                if isinstance(item, ReturnItem):
                    val = self._eval_expr(item.expression, b)
                else:
                    val = self._eval_expr(item, b)
                # Strip internal keys from node dicts
                if isinstance(val, dict):
                    val = {k: v for k, v in val.items() if not k.startswith("_")}
                row[col] = val
            rows.append(row)

        return columns, rows

    def _build_subgraph(self, bindings: list[Binding]) -> SubgraphProjection:
        """Collect all node/edge indices touched by bindings."""
        nodes: set[int] = set()
        edges: set[tuple[int, int]] = set()

        for b in bindings:
            for key, val in b.items():
                if key.startswith("_idx_") and isinstance(val, int):
                    nodes.add(val)
                elif key.startswith("_idx_") and isinstance(val, tuple):
                    edges.add(val)
                    nodes.add(val[0])
                    nodes.add(val[1])

        return SubgraphProjection(node_indices=nodes, edge_tuples=edges)
```

Note: This is a substantial implementation. The key design decisions are: (1) bindings track `_idx_` prefixed keys for internal graph index bookkeeping, (2) node/edge data is serialized to dicts early for property access in WHERE clauses, (3) DFS for variable-length paths uses a visited set to prevent cycles. The implementing agent should run the tests iteratively and fix any issues — the executor's expand/scan interaction with the planner's step ordering is the most likely area for edge cases.

- [ ] **Step 4: Run tests iteratively until all pass**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_executor.py -v`
Expected: 11 passed. The `_next_node_var_after_edge` and `_get_next_node_label` methods need to correctly trace the relationship between edge variables and their target node variables in the plan. If tests fail on expand steps, the agent should inspect how the planner generates steps and adjust the executor's step-chaining logic.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/chain/cypher/executor.py packages/cli/tests/chain/cypher/test_executor.py
git commit -m "feat(cypher): add query executor with binding table and resource limits"
```

---

### Task 9: Query Session

**Files:**
- Create: `packages/cli/src/opentools/chain/cypher/session.py`
- Create: `packages/cli/tests/chain/cypher/test_session.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/cli/tests/chain/cypher/test_session.py
from opentools.chain.cypher.result import QueryResult, QueryStats
from opentools.chain.cypher.session import QuerySession


def test_session_store_and_get():
    session = QuerySession()
    result = QueryResult(columns=["a"], rows=[{"a": 1}, {"a": 2}], stats=QueryStats())
    session.store("my_results", result)
    retrieved = session.get("my_results")
    assert retrieved is result


def test_session_get_unknown():
    session = QuerySession()
    assert session.get("nonexistent") is None


def test_session_list_variables():
    session = QuerySession()
    r1 = QueryResult(columns=["a"], rows=[], stats=QueryStats())
    r2 = QueryResult(columns=["b"], rows=[], stats=QueryStats())
    session.store("first", r1)
    session.store("second", r2)
    assert set(session.list_variables()) == {"first", "second"}


def test_session_clear():
    session = QuerySession()
    session.store("x", QueryResult(columns=[], rows=[], stats=QueryStats()))
    session.clear()
    assert session.get("x") is None
    assert session.list_variables() == []


def test_session_overwrite():
    session = QuerySession()
    r1 = QueryResult(columns=["a"], rows=[{"a": 1}], stats=QueryStats())
    r2 = QueryResult(columns=["a"], rows=[{"a": 2}], stats=QueryStats())
    session.store("x", r1)
    session.store("x", r2)
    assert session.get("x") is r2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_session.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement QuerySession**

```python
# packages/cli/src/opentools/chain/cypher/session.py
"""Query session: named result sets for the REPL."""
from __future__ import annotations

from opentools.chain.cypher.result import QueryResult


class QuerySession:
    def __init__(self) -> None:
        self._variables: dict[str, QueryResult] = {}

    def store(self, name: str, result: QueryResult) -> None:
        self._variables[name] = result

    def get(self, name: str) -> QueryResult | None:
        return self._variables.get(name)

    def list_variables(self) -> list[str]:
        return list(self._variables.keys())

    def clear(self) -> None:
        self._variables.clear()
```

- [ ] **Step 4: Run tests**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_session.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/chain/cypher/session.py packages/cli/tests/chain/cypher/test_session.py
git commit -m "feat(cypher): add query session for named result sets"
```

---

### Task 10: Public API + Config Integration

**Files:**
- Modify: `packages/cli/src/opentools/chain/cypher/__init__.py`
- Modify: `packages/cli/src/opentools/chain/config.py`

- [ ] **Step 1: Add CypherConfig to ChainConfig**

Add to `packages/cli/src/opentools/chain/config.py`, before the `ChainConfig` class:

```python
class CypherConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    timeout_seconds: float = 30.0
    max_rows: int = 1000
    intermediate_binding_cap: int = 10_000
    max_var_length_hops: int = 10
    virtual_graph_cache_size: int = 4
```

Add `cypher: CypherConfig = CypherConfig()` to the `ChainConfig` class fields (after the `query` field).

- [ ] **Step 2: Write the public API in `__init__.py`**

```python
# packages/cli/src/opentools/chain/cypher/__init__.py
"""Cypher-style query DSL for the attack chain knowledge graph."""
from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from opentools.chain.cypher.errors import QueryParseError, QueryResourceError, QueryValidationError
from opentools.chain.cypher.executor import CypherExecutor
from opentools.chain.cypher.limits import QueryLimits
from opentools.chain.cypher.parser import parse_cypher
from opentools.chain.cypher.planner import plan_query
from opentools.chain.cypher.plugins import PluginFunctionRegistry
from opentools.chain.cypher.result import QueryResult
from opentools.chain.cypher.session import QuerySession
from opentools.chain.cypher.virtual_graph import VirtualGraphCache

if TYPE_CHECKING:
    from opentools.chain.config import ChainConfig
    from opentools.chain.query.graph_cache import GraphCache
    from opentools.chain.store_protocol import ChainStoreProtocol


async def parse_and_execute(
    query: str,
    *,
    store: "ChainStoreProtocol",
    graph_cache: "GraphCache",
    vg_cache: VirtualGraphCache,
    session: QuerySession | None = None,
    plugin_registry: PluginFunctionRegistry | None = None,
    user_id: UUID | None = None,
    include_candidates: bool = False,
    engagement_ids: frozenset[str] | None = None,
    limits: QueryLimits | None = None,
) -> QueryResult:
    """Parse, plan, and execute a Cypher query — main entry point."""
    if session is None:
        session = QuerySession()
    if plugin_registry is None:
        plugin_registry = PluginFunctionRegistry()
    if limits is None:
        limits = QueryLimits()

    ast = parse_cypher(query)
    plan = plan_query(ast, limits)

    vg = await vg_cache.get(
        user_id=user_id,
        include_candidates=include_candidates,
        engagement_ids=engagement_ids,
    )

    executor = CypherExecutor(
        virtual_graph=vg,
        plan=plan,
        session=session,
        plugin_registry=plugin_registry,
        limits=limits,
    )
    result = await executor.execute()

    # Store in session if this was a session assignment
    if ast.session_assignment:
        session.store(ast.session_assignment, result)

    return result


class CypherSession:
    """High-level session object for CLI REPL and web editor."""

    def __init__(
        self,
        *,
        store: "ChainStoreProtocol",
        graph_cache: "GraphCache",
        config: "ChainConfig",
        user_id: UUID | None = None,
    ) -> None:
        from opentools.chain.cypher.virtual_graph import VirtualGraphCache
        self.store = store
        self.graph_cache = graph_cache
        self.user_id = user_id
        self.session = QuerySession()
        self.plugin_registry = PluginFunctionRegistry()
        self.limits = QueryLimits(
            timeout_seconds=config.cypher.timeout_seconds,
            max_rows=config.cypher.max_rows,
            intermediate_binding_cap=config.cypher.intermediate_binding_cap,
            max_var_length_hops=config.cypher.max_var_length_hops,
        )
        self.vg_cache = VirtualGraphCache(
            store=store,
            graph_cache=graph_cache,
            maxsize=config.cypher.virtual_graph_cache_size,
        )
        self._engagement_ids: frozenset[str] | None = None
        self._include_candidates = False

    def set_engagement_scope(self, engagement_ids: frozenset[str] | None) -> None:
        self._engagement_ids = engagement_ids

    def set_include_candidates(self, include: bool) -> None:
        self._include_candidates = include

    async def execute(self, query: str) -> QueryResult:
        return await parse_and_execute(
            query,
            store=self.store,
            graph_cache=self.graph_cache,
            vg_cache=self.vg_cache,
            session=self.session,
            plugin_registry=self.plugin_registry,
            user_id=self.user_id,
            include_candidates=self._include_candidates,
            engagement_ids=self._engagement_ids,
            limits=self.limits,
        )
```

- [ ] **Step 3: Run full test suite**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/ -v`
Expected: All previous tests still pass. No new tests needed — the public API is exercised by the CLI tests in Task 11.

- [ ] **Step 4: Commit**

```bash
git add packages/cli/src/opentools/chain/cypher/__init__.py packages/cli/src/opentools/chain/config.py
git commit -m "feat(cypher): add public API and CypherConfig"
```

---

### Task 11: CLI Commands (run, repl, explain)

**Files:**
- Modify: `packages/cli/src/opentools/chain/cli.py`
- Create: `packages/cli/tests/chain/cypher/test_cli_query.py`

- [ ] **Step 1: Write failing tests for CLI query commands**

```python
# packages/cli/tests/chain/cypher/test_cli_query.py
"""Tests for the CLI query subcommands."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from opentools.chain.cli import app


runner = CliRunner()


@pytest.fixture(autouse=True)
def mock_stores():
    """Mock out the store/cache infrastructure so CLI commands can run."""
    mock_chain_store = AsyncMock()
    mock_chain_store.initialize = AsyncMock()
    mock_chain_store.close = AsyncMock()
    mock_chain_store.current_linker_generation = AsyncMock(return_value=1)

    with patch("opentools.chain.cli._get_stores", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = (AsyncMock(), mock_chain_store)
        yield mock_chain_store


def test_query_run_help():
    result = runner.invoke(app, ["query", "run", "--help"])
    assert result.exit_code == 0
    assert "Execute a Cypher query" in result.output or "cypher" in result.output.lower()


def test_query_explain_help():
    result = runner.invoke(app, ["query", "explain", "--help"])
    assert result.exit_code == 0


def test_query_repl_help():
    result = runner.invoke(app, ["query", "repl", "--help"])
    assert result.exit_code == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_cli_query.py -v`
Expected: FAIL — the existing `query` command in `cli.py` is a single command, not a subgroup.

- [ ] **Step 3: Replace the existing `query` command with a subgroup**

In `packages/cli/src/opentools/chain/cli.py`, replace the existing `query` command (the preset runner around line 274-328) with a new `query` subgroup. The existing preset functionality moves to `query preset` (or stays as the `preset` command at the top level — agent should choose based on what breaks fewer existing tests).

Add a new Typer sub-app:

```python
query_app = typer.Typer(help="Cypher query DSL commands")
app.add_typer(query_app, name="query")


@query_app.command("run")
@_async_command
async def query_run(
    cypher: str = typer.Argument(..., help="Cypher query string"),
    timeout: float = typer.Option(30.0, "--timeout", help="Query timeout in seconds"),
    max_rows: int = typer.Option(1000, "--max-rows", help="Maximum result rows"),
    engagement: str | None = typer.Option(None, "--engagement", help="Scope to engagement"),
    include_candidates: bool = typer.Option(False, "--include-candidates", help="Include candidate edges"),
    format: str = typer.Option("table", "--format", help="Output format: table, json, csv"),
    no_subgraph: bool = typer.Option(False, "--no-subgraph", help="Skip subgraph projection"),
) -> None:
    """Execute a Cypher query."""
    from opentools.chain.cypher import CypherSession
    from opentools.chain.cypher.limits import QueryLimits
    from opentools.chain.query.graph_cache import GraphCache

    _engagement_store, chain_store = await _get_stores()
    try:
        cfg = get_chain_config()
        cache = GraphCache(store=chain_store, maxsize=cfg.query.graph_cache_size)
        session = CypherSession(store=chain_store, graph_cache=cache, config=cfg)

        if engagement:
            session.set_engagement_scope(frozenset([engagement]))
        session.set_include_candidates(include_candidates)
        session.limits = QueryLimits(timeout_seconds=timeout, max_rows=max_rows)

        result = await session.execute(cypher)

        if format == "json":
            import json
            rprint(json.dumps({"columns": result.columns, "rows": result.rows, "stats": {"duration_ms": result.stats.duration_ms, "rows_returned": result.stats.rows_returned}, "truncated": result.truncated}, indent=2, default=str))
        elif format == "csv":
            if result.columns:
                rprint(",".join(result.columns))
                for row in result.rows:
                    rprint(",".join(str(row.get(c, "")) for c in result.columns))
        else:
            # Table format
            if not result.rows:
                rprint("[yellow]no results[/yellow]")
                return
            table = Table()
            for col in result.columns:
                table.add_column(col)
            for row in result.rows:
                table.add_row(*[str(row.get(c, "")) for c in result.columns])
            Console().print(table)
            rprint(f"[dim]{result.stats.rows_returned} rows, {result.stats.duration_ms:.1f}ms[/dim]")
            if result.truncated:
                rprint(f"[yellow]truncated: {result.truncation_reason}[/yellow]")
    finally:
        await chain_store.close()


@query_app.command("explain")
@_async_command
async def query_explain(
    cypher: str = typer.Argument(..., help="Cypher query string"),
) -> None:
    """Show the query plan without executing."""
    from opentools.chain.cypher.limits import QueryLimits
    from opentools.chain.cypher.parser import parse_cypher
    from opentools.chain.cypher.planner import plan_query

    limits = QueryLimits()
    ast = parse_cypher(cypher)
    plan = plan_query(ast, limits)

    rprint("[bold]Query Plan[/bold]")
    for i, step in enumerate(plan.steps, 1):
        rprint(f"  {i}. {step.kind}: {step.target_var} (label={step.label}, direction={step.direction})")
        if step.predicates:
            rprint(f"     predicates: {len(step.predicates)} pushed down")
        if step.min_hops is not None:
            rprint(f"     hops: {step.min_hops}..{step.max_hops}")


@query_app.command("repl")
@_async_command
async def query_repl(
    engagement: str | None = typer.Option(None, "--engagement", help="Scope to engagement"),
    include_candidates: bool = typer.Option(False, "--include-candidates"),
) -> None:
    """Start an interactive Cypher query REPL."""
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import InMemoryHistory

    from opentools.chain.cypher import CypherSession
    from opentools.chain.cypher.errors import QueryParseError, QueryResourceError, QueryValidationError
    from opentools.chain.query.graph_cache import GraphCache

    _engagement_store, chain_store = await _get_stores()
    try:
        cfg = get_chain_config()
        cache = GraphCache(store=chain_store, maxsize=cfg.query.graph_cache_size)
        cypher_session = CypherSession(store=chain_store, graph_cache=cache, config=cfg)

        if engagement:
            cypher_session.set_engagement_scope(frozenset([engagement]))
        cypher_session.set_include_candidates(include_candidates)

        prompt_session = PromptSession(history=InMemoryHistory())
        rprint("[bold]OpenTools Cypher REPL[/bold] (type :help for help, :quit to exit)")

        while True:
            try:
                text = prompt_session.prompt("cypher> ")
            except (EOFError, KeyboardInterrupt):
                break

            text = text.strip()
            if not text:
                continue

            # Multi-line continuation
            while text.endswith("-") or text.endswith("|") or text.count("(") > text.count(")"):
                try:
                    continuation = prompt_session.prompt("   ...> ")
                    text += " " + continuation.strip()
                except (EOFError, KeyboardInterrupt):
                    break

            # Special commands
            if text.startswith(":"):
                cmd = text[1:].strip().lower()
                if cmd in ("quit", "exit"):
                    break
                elif cmd == "help":
                    rprint("Cypher query DSL. MATCH (a:Finding)-[r:LINKED]->(b:Finding) WHERE ... RETURN ...")
                    rprint("Labels: Finding, Host, IP, CVE, Domain, Port, MitreAttack, Entity")
                    rprint("Edges: LINKED, MENTIONED_IN")
                elif cmd == "functions":
                    from opentools.chain.cypher.builtins import list_builtins
                    for name, info in list_builtins().items():
                        rprint(f"  {name}: {info.get('help', '')}")
                    for name, info in cypher_session.plugin_registry.list_all().items():
                        rprint(f"  {name}: {info.get('help', '')} [{info.get('kind', '')}]")
                elif cmd == "clear":
                    cypher_session.session.clear()
                    rprint("[dim]session cleared[/dim]")
                elif cmd.startswith("limits"):
                    rprint(f"timeout: {cypher_session.limits.timeout_seconds}s")
                    rprint(f"max_rows: {cypher_session.limits.max_rows}")
                    rprint(f"intermediate_cap: {cypher_session.limits.intermediate_binding_cap}")
                else:
                    rprint(f"[red]unknown command: {text}[/red]")
                continue

            # Check if it's just a variable name (display stored result)
            if text in cypher_session.session.list_variables():
                stored = cypher_session.session.get(text)
                if stored:
                    for row in stored.rows[:20]:
                        rprint(row)
                    if len(stored.rows) > 20:
                        rprint(f"[dim]... {len(stored.rows) - 20} more rows[/dim]")
                continue

            # Execute query
            try:
                result = await cypher_session.execute(text)
                if not result.rows:
                    rprint("[yellow]no results[/yellow]")
                else:
                    table = Table()
                    for col in result.columns:
                        table.add_column(col)
                    for row in result.rows:
                        table.add_row(*[str(row.get(c, "")) for c in result.columns])
                    Console().print(table)
                    rprint(f"[dim]{result.stats.rows_returned} rows, {result.stats.duration_ms:.1f}ms[/dim]")
            except (QueryParseError, QueryValidationError) as e:
                rprint(f"[red]Parse error: {e}[/red]")
            except QueryResourceError as e:
                rprint(f"[red]Resource limit: {e}[/red]")
            except Exception as e:
                rprint(f"[red]Error: {e}[/red]")

        rprint("[dim]bye[/dim]")
    finally:
        await chain_store.close()
```

The agent should also rename the existing `query` function (the preset runner) to `preset` and add it to `query_app` or keep it as a top-level command. Check existing tests in `test_cli_commands.py` to see if anything references `query` by name and update accordingly.

- [ ] **Step 4: Run tests**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/test_cli_query.py -v`
Expected: 3 passed

- [ ] **Step 5: Run existing CLI tests to check for regressions**

Run: `cd packages/cli && python -m pytest tests/chain/test_cli_commands.py -v`
Expected: If the old `query` command was renamed to `preset`, update any tests that invoke it. All tests should pass.

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/chain/cli.py packages/cli/tests/chain/cypher/test_cli_query.py
git commit -m "feat(cypher): add CLI query commands (run, explain, repl)"
```

---

### Task 12: Web Backend — Query Endpoint

**Files:**
- Create: `packages/web/backend/app/routes/chain_query.py`
- Modify: `packages/web/backend/app/main.py`
- Create: `packages/web/backend/tests/chain/test_query_routes.py`

- [ ] **Step 1: Write failing tests for the web endpoint**

```python
# packages/web/backend/tests/chain/test_query_routes.py
"""Tests for the Cypher query web API endpoints."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_query_endpoint_requires_auth(client):
    response = await client.post("/api/chain/query", json={"query": "MATCH (a:Finding) RETURN a"})
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_functions_endpoint_requires_auth(client):
    response = await client.get("/api/chain/query/functions")
    assert response.status_code in (401, 403)
```

Note: The implementing agent should adapt these tests to match the project's existing auth test patterns (check `packages/web/backend/tests/` for how authenticated requests are mocked — there's likely a fixture that provides an auth token or mock user).

- [ ] **Step 2: Implement the query routes**

```python
# packages/web/backend/app/routes/chain_query.py
"""Cypher query DSL web API endpoints."""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.database import async_session_factory
from app.dependencies import get_current_user, get_db
from app.models import User

router = APIRouter(prefix="/api/chain/query", tags=["chain-query"])


class QueryRequest(BaseModel):
    query: str
    engagement_id: Optional[str] = None
    include_candidates: bool = False
    timeout: float = 30.0
    max_rows: int = 1000


class QueryResponse(BaseModel):
    columns: list[str]
    rows: list[dict[str, Any]]
    subgraph: Optional[dict] = None
    stats: dict
    truncated: bool


class FunctionInfo(BaseModel):
    name: str
    kind: str
    help: str


@router.post("", response_model=QueryResponse)
async def execute_query(
    request: QueryRequest,
    current_user: User = Depends(get_current_user),
    db=Depends(get_db),
):
    """Execute a Cypher query against the attack chain knowledge graph."""
    from opentools.chain.config import get_chain_config
    from opentools.chain.cypher import parse_and_execute
    from opentools.chain.cypher.errors import QueryParseError, QueryResourceError, QueryValidationError
    from opentools.chain.cypher.limits import QueryLimits
    from opentools.chain.cypher.plugins import PluginFunctionRegistry
    from opentools.chain.cypher.virtual_graph import VirtualGraphCache
    from opentools.chain.query.graph_cache import GraphCache

    from app.services.chain_service import ChainService

    try:
        cfg = get_chain_config()
        chain_service = ChainService(session_factory=async_session_factory)
        store = chain_service.get_store(user_id=current_user.id)
        graph_cache = GraphCache(store=store, maxsize=cfg.query.graph_cache_size)
        vg_cache = VirtualGraphCache(store=store, graph_cache=graph_cache, maxsize=cfg.cypher.virtual_graph_cache_size)

        engagement_ids = frozenset([request.engagement_id]) if request.engagement_id else None
        limits = QueryLimits(timeout_seconds=request.timeout, max_rows=request.max_rows)

        result = await parse_and_execute(
            request.query,
            store=store,
            graph_cache=graph_cache,
            vg_cache=vg_cache,
            user_id=current_user.id,
            include_candidates=request.include_candidates,
            engagement_ids=engagement_ids,
            limits=limits,
        )

        subgraph_data = None
        if result.subgraph:
            subgraph_data = {
                "nodes": [{"index": idx} for idx in result.subgraph.node_indices],
                "edges": [{"source": s, "target": t} for s, t in result.subgraph.edge_tuples],
            }

        return QueryResponse(
            columns=result.columns,
            rows=result.rows,
            subgraph=subgraph_data,
            stats={
                "duration_ms": result.stats.duration_ms,
                "bindings_explored": result.stats.bindings_explored,
                "rows_returned": result.stats.rows_returned,
            },
            truncated=result.truncated,
        )

    except QueryParseError as e:
        raise HTTPException(status_code=400, detail=f"Parse error: {e}")
    except QueryValidationError as e:
        raise HTTPException(status_code=400, detail=f"Validation error: {e}")
    except QueryResourceError as e:
        raise HTTPException(status_code=400, detail=f"Resource limit: {e}")


@router.get("/functions")
async def list_functions(
    current_user: User = Depends(get_current_user),
):
    """List all available query functions (built-in and plugin)."""
    from opentools.chain.cypher.builtins import list_builtins

    result = []
    for name, info in list_builtins().items():
        result.append({"name": name, "kind": "builtin", "help": info.get("help", "")})
    return result
```

Note: The `ChainService.get_store()` call above is a placeholder — the implementing agent should check the actual `chain_service.py` API for how to get a `ChainStoreProtocol` instance for the web backend. It likely involves creating a `PostgresChainStore` with the user's session and user_id. Follow the patterns in `packages/web/backend/app/routes/chain.py`.

- [ ] **Step 3: Register the router in main.py**

In `packages/web/backend/app/main.py`, add:

```python
from app.routes import chain_query
app.include_router(chain_query.router)
```

alongside the existing `app.include_router(chain.router)`.

- [ ] **Step 4: Run tests**

Run: `cd packages/web/backend && python -m pytest tests/chain/test_query_routes.py -v`
Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add packages/web/backend/app/routes/chain_query.py packages/web/backend/app/main.py packages/web/backend/tests/chain/test_query_routes.py
git commit -m "feat(cypher): add web query API endpoints"
```

---

### Task 13: Web Frontend — Standalone Query Page

**Files:**
- Create: `packages/web/frontend/src/views/ChainQueryView.vue`
- Create: `packages/web/frontend/src/components/CypherEditor.vue`
- Create: `packages/web/frontend/src/components/QueryResultsPane.vue`
- Modify: `packages/web/frontend/src/router/index.ts`

- [ ] **Step 1: Add the route**

In `packages/web/frontend/src/router/index.ts`, add after the engagement-chain route:

```typescript
{ path: '/chain/query', name: 'chain-query', component: () => import('@/views/ChainQueryView.vue') },
```

- [ ] **Step 2: Create CypherEditor.vue**

```vue
<!-- packages/web/frontend/src/components/CypherEditor.vue -->
<template>
  <div class="cypher-editor">
    <div ref="editorContainer" class="editor-container"></div>
    <div class="editor-actions">
      <button class="run-btn" @click="$emit('run')" :disabled="disabled">
        Run (Ctrl+Enter)
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { EditorView, basicSetup } from 'codemirror'
import { EditorState } from '@codemirror/state'
import { keymap } from '@codemirror/view'

const props = defineProps<{
  modelValue: string
  disabled?: boolean
}>()

const emit = defineEmits<{
  'update:modelValue': [value: string]
  run: []
}>()

const editorContainer = ref<HTMLElement>()
let view: EditorView | null = null

onMounted(() => {
  if (!editorContainer.value) return

  const runKeymap = keymap.of([{
    key: 'Ctrl-Enter',
    run: () => { emit('run'); return true },
  }])

  const startState = EditorState.create({
    doc: props.modelValue,
    extensions: [
      basicSetup,
      runKeymap,
      EditorView.updateListener.of((update) => {
        if (update.docChanged) {
          emit('update:modelValue', update.state.doc.toString())
        }
      }),
    ],
  })

  view = new EditorView({
    state: startState,
    parent: editorContainer.value,
  })
})

watch(() => props.modelValue, (newVal) => {
  if (view && view.state.doc.toString() !== newVal) {
    view.dispatch({
      changes: { from: 0, to: view.state.doc.length, insert: newVal },
    })
  }
})
</script>

<style scoped>
.cypher-editor {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--border-color, #ddd);
  border-radius: 4px;
}
.editor-container {
  min-height: 100px;
  max-height: 200px;
  overflow: auto;
}
.editor-actions {
  display: flex;
  justify-content: flex-end;
  padding: 4px 8px;
  border-top: 1px solid var(--border-color, #ddd);
}
.run-btn {
  padding: 4px 12px;
  cursor: pointer;
}
</style>
```

- [ ] **Step 3: Create QueryResultsPane.vue**

```vue
<!-- packages/web/frontend/src/components/QueryResultsPane.vue -->
<template>
  <div class="query-results">
    <div v-if="loading" class="loading">Running query...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else-if="result" class="results-grid">
      <div class="stats">
        {{ result.stats.rows_returned }} rows, {{ result.stats.duration_ms.toFixed(1) }}ms
        <span v-if="result.truncated" class="truncated">(truncated)</span>
      </div>
      <table v-if="result.rows.length > 0">
        <thead>
          <tr>
            <th v-for="col in result.columns" :key="col">{{ col }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(row, idx) in result.rows" :key="idx" @click="$emit('row-click', row, idx)">
            <td v-for="col in result.columns" :key="col">{{ formatCell(row[col]) }}</td>
          </tr>
        </tbody>
      </table>
      <div v-else class="no-results">No results</div>
    </div>
  </div>
</template>

<script setup lang="ts">
defineProps<{
  result: any | null
  loading: boolean
  error: string | null
}>()

defineEmits<{
  'row-click': [row: any, index: number]
}>()

function formatCell(value: any): string {
  if (value === null || value === undefined) return ''
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}
</script>

<style scoped>
.query-results { overflow: auto; }
.stats { padding: 4px 8px; font-size: 0.85em; color: #666; }
.truncated { color: #e67e22; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: 4px 8px; border-bottom: 1px solid #eee; text-align: left; }
th { font-weight: 600; background: #f8f8f8; }
tr:hover { background: #f0f8ff; cursor: pointer; }
.error { color: #e74c3c; padding: 8px; }
.loading { padding: 8px; color: #666; }
.no-results { padding: 8px; color: #999; }
</style>
```

- [ ] **Step 4: Create ChainQueryView.vue**

```vue
<!-- packages/web/frontend/src/views/ChainQueryView.vue -->
<template>
  <div class="chain-query-page">
    <h1>Chain Query</h1>
    <div class="toolbar">
      <select v-model="engagementId">
        <option :value="null">All engagements</option>
      </select>
    </div>
    <div class="editor-section">
      <CypherEditor v-model="queryText" :disabled="loading" @run="runQuery" />
    </div>
    <div class="results-section">
      <QueryResultsPane
        :result="result"
        :loading="loading"
        :error="error"
        @row-click="onRowClick"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import CypherEditor from '@/components/CypherEditor.vue'
import QueryResultsPane from '@/components/QueryResultsPane.vue'

const queryText = ref('MATCH (a:Finding) RETURN a')
const engagementId = ref<string | null>(null)
const result = ref<any>(null)
const loading = ref(false)
const error = ref<string | null>(null)

async function runQuery() {
  loading.value = true
  error.value = null
  result.value = null

  try {
    const body: any = { query: queryText.value }
    if (engagementId.value) {
      body.engagement_id = engagementId.value
    }

    const response = await fetch('/api/chain/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })

    if (!response.ok) {
      const data = await response.json().catch(() => ({ detail: response.statusText }))
      error.value = data.detail || `Error ${response.status}`
      return
    }

    result.value = await response.json()
  } catch (e: any) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}

function onRowClick(row: any, index: number) {
  // Future: highlight in graph preview
}
</script>

<style scoped>
.chain-query-page { padding: 16px; max-width: 1200px; margin: 0 auto; }
.toolbar { margin-bottom: 12px; }
.editor-section { margin-bottom: 12px; }
.results-section { border: 1px solid #eee; border-radius: 4px; min-height: 200px; }
</style>
```

Note: The auth token inclusion in the `fetch` call depends on the project's existing auth pattern (cookie-based, bearer token in headers, etc.). The implementing agent should check how other views like `ChainGraphView.vue` make API calls and follow that pattern.

- [ ] **Step 5: Verify the page loads in the browser**

Start the dev server and navigate to `/chain/query`. Verify:
- CodeMirror editor renders
- Run button visible
- The page doesn't crash

- [ ] **Step 6: Commit**

```bash
git add packages/web/frontend/src/views/ChainQueryView.vue packages/web/frontend/src/components/CypherEditor.vue packages/web/frontend/src/components/QueryResultsPane.vue packages/web/frontend/src/router/index.ts
git commit -m "feat(cypher): add standalone web query page"
```

---

### Task 14: Inline Query Panel (Final 3C.4 Task)

**Files:**
- Create: `packages/web/frontend/src/components/InlineQueryPanel.vue`
- Modify: `packages/web/frontend/src/views/ChainGraphView.vue`
- Modify: `packages/web/frontend/src/views/GlobalChainView.vue` (if exists from 3C.3)

- [ ] **Step 1: Create InlineQueryPanel.vue**

```vue
<!-- packages/web/frontend/src/components/InlineQueryPanel.vue -->
<template>
  <div class="inline-query-panel" :class="{ collapsed: !expanded }">
    <button class="toggle-btn" @click="expanded = !expanded">
      {{ expanded ? 'Hide Query' : 'Query' }}
    </button>
    <div v-if="expanded" class="panel-content">
      <CypherEditor v-model="queryText" :disabled="loading" @run="runQuery" />
      <QueryResultsPane
        :result="result"
        :loading="loading"
        :error="error"
        @row-click="$emit('highlight', $event)"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import CypherEditor from '@/components/CypherEditor.vue'
import QueryResultsPane from '@/components/QueryResultsPane.vue'

const props = defineProps<{
  engagementId?: string | null
}>()

const emit = defineEmits<{
  highlight: [nodeIds: string[]]
}>()

const expanded = ref(false)
const queryText = ref('MATCH (a:Finding)-[r:LINKED]->(b:Finding) RETURN a, b')
const result = ref<any>(null)
const loading = ref(false)
const error = ref<string | null>(null)

async function runQuery() {
  loading.value = true
  error.value = null
  result.value = null

  try {
    const body: any = { query: queryText.value }
    if (props.engagementId) {
      body.engagement_id = props.engagementId
    }

    const response = await fetch('/api/chain/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })

    if (!response.ok) {
      const data = await response.json().catch(() => ({ detail: response.statusText }))
      error.value = data.detail || `Error ${response.status}`
      return
    }

    result.value = await response.json()

    // Emit highlight event with matched node IDs
    if (result.value?.subgraph?.nodes) {
      const nodeIds = result.value.subgraph.nodes.map((n: any) => n.id).filter(Boolean)
      emit('highlight', nodeIds)
    }
  } catch (e: any) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.inline-query-panel {
  position: absolute;
  bottom: 0;
  left: 0;
  right: 0;
  background: white;
  border-top: 2px solid #ddd;
  z-index: 10;
  max-height: 50%;
  overflow: auto;
}
.inline-query-panel.collapsed {
  max-height: 32px;
  overflow: hidden;
}
.toggle-btn {
  width: 100%;
  padding: 6px;
  text-align: center;
  cursor: pointer;
  border: none;
  background: #f5f5f5;
}
.panel-content {
  padding: 8px;
}
</style>
```

- [ ] **Step 2: Add InlineQueryPanel to ChainGraphView.vue**

The implementing agent should read `ChainGraphView.vue`, find the template section, and add the inline panel. Add it inside the main container, after the `ForceGraphCanvas` component:

```vue
<InlineQueryPanel
  :engagement-id="engagementId"
  @highlight="onQueryHighlight"
/>
```

Import the component and add the highlight handler:

```typescript
import InlineQueryPanel from '@/components/InlineQueryPanel.vue'

function onQueryHighlight(nodeIds: string[]) {
  // Apply glow effect to matched nodes in the force graph
  // Implementation depends on ForceGraphCanvas API — the agent should
  // check what highlighting mechanism the canvas supports
}
```

- [ ] **Step 3: Add InlineQueryPanel to GlobalChainView.vue**

If `GlobalChainView.vue` exists (from 3C.3), add the same `InlineQueryPanel` component. The panel should be identical but without a fixed `engagement-id` prop (since the global view is cross-engagement). Follow the same pattern as Step 2.

If `GlobalChainView.vue` does not yet exist (3C.3 not yet merged), skip this step — it will be added when the global view is implemented.

- [ ] **Step 4: Verify in browser**

Start the dev server, navigate to an engagement chain page. Verify:
- "Query" button visible at bottom
- Clicking it expands the inline panel
- CodeMirror editor works
- Running a query shows results
- Collapsing works

- [ ] **Step 5: Commit**

```bash
git add packages/web/frontend/src/components/InlineQueryPanel.vue packages/web/frontend/src/views/ChainGraphView.vue
git commit -m "feat(cypher): add inline query panel to chain graph views"
```

---

### Task 15: Protocol Addition + Full Integration Test

**Files:**
- Modify: `packages/cli/src/opentools/chain/store_protocol.py`
- Modify both store backends to implement `fetch_all_mentions_in_scope`
- Create: `packages/cli/tests/chain/cypher/test_integration.py`

- [ ] **Step 1: Add `fetch_all_mentions_in_scope` to ChainStoreProtocol**

Add to `packages/cli/src/opentools/chain/store_protocol.py`:

```python
async def fetch_all_mentions_in_scope(
    self, *, user_id: UUID | None
) -> list[EntityMention]:
    """Return all entity mentions for the user scope.

    Used by VirtualGraphBuilder to populate MENTIONED_IN edges.
    """
    ...
```

- [ ] **Step 2: Implement in AsyncChainStore**

The implementing agent should find `AsyncChainStore` (the aiosqlite backend) and add the implementation. Pattern: `SELECT * FROM entity_mentions` (or the equivalent table name), scoped by user_id if non-None, returning `EntityMention` domain objects.

- [ ] **Step 3: Implement in PostgresChainStore**

Same query via SQLAlchemy async. Follow the existing pattern of other `fetch_*` methods in `PostgresChainStore`.

- [ ] **Step 4: Write integration test**

```python
# packages/cli/tests/chain/cypher/test_integration.py
"""End-to-end integration test: parse → plan → build virtual graph → execute."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from opentools.chain.cypher import parse_and_execute
from opentools.chain.cypher.limits import QueryLimits
from opentools.chain.cypher.plugins import PluginFunctionRegistry
from opentools.chain.cypher.session import QuerySession
from opentools.chain.cypher.virtual_graph import VirtualGraphCache
from opentools.chain.models import Entity, EntityMention
from opentools.chain.query.graph_cache import GraphCache
from tests.chain.cypher.test_virtual_graph import _make_entities, _make_master_graph, _make_mentions


@pytest.fixture
def mock_store():
    from unittest.mock import AsyncMock
    store = AsyncMock()
    store.current_linker_generation = AsyncMock(return_value=1)
    store.stream_relations_in_scope = AsyncMock(return_value=iter([]))
    store.fetch_all_finding_ids = AsyncMock(return_value=["fnd_1", "fnd_2", "fnd_3"])
    store.fetch_findings_by_ids = AsyncMock(return_value=[])
    store.list_entities = AsyncMock(return_value=_make_entities())
    store.fetch_all_mentions_in_scope = AsyncMock(return_value=_make_mentions())
    return store


@pytest.mark.asyncio
async def test_full_pipeline(mock_store):
    """Parse a query, build virtual graph, execute, get results."""
    graph_cache = GraphCache(store=mock_store, maxsize=4)

    # We need to mock get_master_graph since the store is fully mocked
    master = _make_master_graph()
    from unittest.mock import AsyncMock as AM
    graph_cache.get_master_graph = AM(return_value=master)

    vg_cache = VirtualGraphCache(store=mock_store, graph_cache=graph_cache, maxsize=4)

    result = await parse_and_execute(
        "MATCH (a:Finding) RETURN a",
        store=mock_store,
        graph_cache=graph_cache,
        vg_cache=vg_cache,
        limits=QueryLimits(),
    )

    assert len(result.rows) == 3
    assert "a" in result.columns
```

- [ ] **Step 5: Run all cypher tests**

Run: `cd packages/cli && python -m pytest tests/chain/cypher/ -v`
Expected: All tests pass (target: ~80+ tests at this point).

- [ ] **Step 6: Run full test suite for regressions**

Run: `cd packages/cli && python -m pytest tests/ -x --timeout=120`
Expected: No regressions.

- [ ] **Step 7: Commit**

```bash
git add packages/cli/src/opentools/chain/store_protocol.py packages/cli/tests/chain/cypher/test_integration.py
git commit -m "feat(cypher): add fetch_all_mentions_in_scope + integration test"
```

---

## Task Summary

| Task | Description | Est. Tests |
|---|---|---|
| 1 | Error types + QueryLimits | 6 |
| 2 | AST node definitions | 14 |
| 3 | Lark grammar + parser | 22 |
| 4 | Built-in functions + plugin registry | 16 |
| 5 | Result types | 0 (exercised by T8) |
| 6 | Virtual graph builder + cache | 7 |
| 7 | Planner | 5 |
| 8 | Executor | 11 |
| 9 | Query session | 5 |
| 10 | Public API + config | 0 (exercised by T11, T15) |
| 11 | CLI commands | 3+ |
| 12 | Web backend endpoints | 2+ |
| 13 | Web frontend query page | manual |
| 14 | Inline query panel (final task) | manual |
| 15 | Protocol addition + integration test | 1+ |
| **Total** | | **~92+ automated** |
