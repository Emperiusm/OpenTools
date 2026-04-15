"""Cypher query executor: walks a QueryPlan against a VirtualGraph.

Uses a binding-table approach where each step produces/filters a list of
bindings (dict[str, Any]).  Resource limits (timeout, binding cap, row cap)
are checked at step boundaries.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from opentools.chain.cypher.ast_nodes import (
    BooleanExpr,
    ComparisonExpr,
    FunctionCallExpr,
    PropertyAccessExpr,
    ReturnItem,
)
from opentools.chain.cypher.builtins import get_builtin
from opentools.chain.cypher.errors import QueryResourceError, QueryValidationError
from opentools.chain.cypher.limits import QueryLimits
from opentools.chain.cypher.planner import PlanStep, QueryPlan
from opentools.chain.cypher.plugins import PluginFunctionRegistry
from opentools.chain.cypher.result import QueryResult, QueryStats, SubgraphProjection
from opentools.chain.cypher.session import QuerySession
from opentools.chain.cypher.virtual_graph import EntityNode, MentionedInEdge, VirtualGraph
from opentools.chain.query.graph_cache import EdgeData, FindingNode


# ─── serialization helpers ───────────────────────────────────────────────────


def _serialize_finding(node: FindingNode, idx: int) -> dict[str, Any]:
    created = node.created_at
    if isinstance(created, datetime):
        created = created.isoformat()
    return {
        "id": node.finding_id,
        "label": "Finding",
        "severity": node.severity,
        "tool": node.tool,
        "title": node.title,
        "created_at": created,
        "_idx": idx,
    }


def _serialize_entity(node: EntityNode, idx: int) -> dict[str, Any]:
    return {
        "id": node.entity_id,
        "label": node.entity_type.capitalize() if node.entity_type else "Entity",
        "canonical_value": node.canonical_value,
        "entity_type": node.entity_type,
        "mention_count": node.mention_count,
        "_idx": idx,
    }


def _serialize_node(node_data: Any, idx: int) -> dict[str, Any]:
    if isinstance(node_data, FindingNode):
        return _serialize_finding(node_data, idx)
    if isinstance(node_data, EntityNode):
        return _serialize_entity(node_data, idx)
    return {"_idx": idx, "label": "Unknown"}


def _serialize_edge_data(edge: EdgeData) -> dict[str, Any]:
    return {
        "label": "LINKED",
        "relation_id": edge.relation_id,
        "weight": edge.weight,
        "cost": edge.cost,
        "status": edge.status,
        "reasons": edge.reasons,
        "llm_rationale": edge.llm_rationale,
        "llm_relation_type": edge.llm_relation_type,
    }


def _serialize_mentioned_in(edge: MentionedInEdge) -> dict[str, Any]:
    return {
        "label": "MENTIONED_IN",
        "mention_id": edge.mention_id,
        "field": edge.field,
        "confidence": edge.confidence,
        "extractor": edge.extractor,
    }


def _serialize_edge(edge_data: Any) -> dict[str, Any]:
    if isinstance(edge_data, EdgeData):
        return _serialize_edge_data(edge_data)
    if isinstance(edge_data, MentionedInEdge):
        return _serialize_mentioned_in(edge_data)
    return {"label": "UNKNOWN"}


def _edge_matches_label(edge_data: Any, label: str | None) -> bool:
    """Check whether an edge payload matches the requested type label."""
    if label is None:
        return True
    if label == "LINKED":
        return isinstance(edge_data, EdgeData)
    if label == "MENTIONED_IN":
        return isinstance(edge_data, MentionedInEdge)
    return False


def _strip_internal_keys(d: dict[str, Any]) -> dict[str, Any]:
    """Remove internal bookkeeping keys (e.g. _idx) from an output dict."""
    return {k: v for k, v in d.items() if not k.startswith("_idx")}


# ─── predicate evaluation ───────────────────────────────────────────────────


def _resolve_expr(expr: Any, binding: dict[str, Any], plugin_registry: PluginFunctionRegistry) -> Any:
    """Resolve an expression against a binding row."""
    if isinstance(expr, PropertyAccessExpr):
        node_or_edge = binding.get(expr.variable)
        if node_or_edge is None:
            return None
        if isinstance(node_or_edge, dict):
            return node_or_edge.get(expr.property_name)
        return getattr(node_or_edge, expr.property_name, None)

    if isinstance(expr, FunctionCallExpr):
        resolved_args = [_resolve_expr(a, binding, plugin_registry) for a in expr.args]
        fn = get_builtin(expr.name)
        if fn is None:
            fn = plugin_registry.get_function(expr.name)
        if fn is None:
            raise QueryValidationError(f"Unknown function: {expr.name}")
        return fn(*resolved_args)

    if isinstance(expr, ComparisonExpr):
        return _eval_comparison(expr, binding, plugin_registry)

    if isinstance(expr, BooleanExpr):
        return _eval_boolean(expr, binding, plugin_registry)

    # Bare string: could be a variable reference or a literal.
    # The parser emits var_ref as a plain str, and string_val as a plain str.
    # We disambiguate by checking the binding table first.
    if isinstance(expr, str):
        if expr in binding:
            return binding[expr]
        return expr

    # Other literal values (int, float, bool, None, list)
    if isinstance(expr, (int, float, bool, type(None), list)):
        return expr

    return expr


def _eval_comparison(expr: ComparisonExpr, binding: dict[str, Any], plugin_registry: PluginFunctionRegistry) -> bool:
    left = _resolve_expr(expr.left, binding, plugin_registry)
    right = _resolve_expr(expr.right, binding, plugin_registry)
    op = expr.operator

    if op == "=":
        return left == right
    if op == "!=":
        return left != right
    if op == "<>":
        return left != right
    if op == "<":
        return left is not None and right is not None and left < right
    if op == ">":
        return left is not None and right is not None and left > right
    if op == "<=":
        return left is not None and right is not None and left <= right
    if op == ">=":
        return left is not None and right is not None and left >= right
    if op == "CONTAINS":
        return left is not None and right is not None and right in left
    if op == "STARTS WITH":
        return left is not None and right is not None and str(left).startswith(str(right))
    if op == "ENDS WITH":
        return left is not None and right is not None and str(left).endswith(str(right))
    if op == "IN":
        return left is not None and right is not None and left in right
    if op == "IS NULL":
        return left is None
    if op == "IS NOT NULL":
        return left is not None

    raise QueryValidationError(f"Unknown operator: {op}")


def _eval_boolean(expr: BooleanExpr, binding: dict[str, Any], plugin_registry: PluginFunctionRegistry) -> bool:
    if expr.operator == "AND":
        return all(_resolve_expr(op, binding, plugin_registry) for op in expr.operands)
    if expr.operator == "OR":
        return any(_resolve_expr(op, binding, plugin_registry) for op in expr.operands)
    if expr.operator == "NOT":
        return not _resolve_expr(expr.operands[0], binding, plugin_registry)
    raise QueryValidationError(f"Unknown boolean operator: {expr.operator}")


def _eval_predicates(predicates: list[Any], binding: dict[str, Any], plugin_registry: PluginFunctionRegistry) -> bool:
    """Evaluate a list of predicate expressions (conjuncts) against a binding."""
    for pred in predicates:
        result = _resolve_expr(pred, binding, plugin_registry)
        if not result:
            return False
    return True


# ─── executor ────────────────────────────────────────────────────────────────

Binding = dict[str, Any]


class CypherExecutor:
    """Execute a QueryPlan against a VirtualGraph, producing a QueryResult.

    Args:
        virtual_graph:   The heterogeneous graph to query.
        plan:            The query plan from the planner.
        session:         Query session for named result sets.
        plugin_registry: Registry for plugin scalar/aggregation functions.
        limits:          Resource limits for the query.
    """

    def __init__(
        self,
        *,
        virtual_graph: VirtualGraph,
        plan: QueryPlan,
        session: QuerySession,
        plugin_registry: PluginFunctionRegistry,
        limits: QueryLimits,
    ) -> None:
        self._vg = virtual_graph
        self._plan = plan
        self._session = session
        self._plugins = plugin_registry
        self._limits = limits

    async def execute(self) -> QueryResult:
        """Execute the plan and return a QueryResult."""
        start_time = time.monotonic()
        bindings: list[Binding] = [{}]  # start with one empty binding

        for step in self._plan.steps:
            # Timeout check
            elapsed = time.monotonic() - start_time
            if elapsed > self._limits.timeout_seconds:
                raise QueryResourceError(
                    f"Query timed out after {elapsed:.1f}s (limit: {self._limits.timeout_seconds}s)",
                    limit_name="timeout_seconds",
                    limit_value=self._limits.timeout_seconds,
                )

            if step.kind == "scan":
                bindings = self._exec_scan(step, bindings)
            elif step.kind == "expand":
                bindings = self._exec_expand(step, bindings)
            elif step.kind == "var_length_expand":
                bindings = self._exec_var_length_expand(step, bindings)
            elif step.kind == "filter":
                bindings = self._exec_filter(step, bindings)

            # Intermediate binding cap
            if len(bindings) > self._limits.intermediate_binding_cap:
                raise QueryResourceError(
                    f"Intermediate bindings ({len(bindings)}) exceed cap ({self._limits.intermediate_binding_cap})",
                    limit_name="intermediate_binding_cap",
                    limit_value=self._limits.intermediate_binding_cap,
                )

        # Project RETURN
        elapsed_ms = (time.monotonic() - start_time) * 1000
        return self._project_return(bindings, elapsed_ms)

    # ── step executors ────────────────────────────────────────────────────

    def _exec_scan(self, step: PlanStep, bindings: list[Binding]) -> list[Binding]:
        """Scan: iterate all nodes matching a label, create or validate bindings."""
        var = step.target_var

        # If the variable is already bound in all existing bindings, this is a
        # no-op (the expand step already bound it).
        if bindings and all(var in b for b in bindings):
            # Still apply predicates if any
            if step.predicates:
                return [b for b in bindings if _eval_predicates(step.predicates, b, self._plugins)]
            return bindings

        new_bindings: list[Binding] = []
        g = self._vg.graph
        node_indices = g.node_indices()

        for b in bindings:
            for idx in node_indices:
                # Label filter
                if step.label is not None:
                    node_label = self._vg.node_labels.get(idx)
                    if node_label != step.label:
                        continue

                node_data = g.get_node_data(idx)
                serialized = _serialize_node(node_data, idx)
                new_b = {**b, var: serialized, f"_idx_{var}": idx}

                # Apply pushed-down predicates
                if step.predicates and not _eval_predicates(step.predicates, new_b, self._plugins):
                    continue

                new_bindings.append(new_b)

        return new_bindings

    def _exec_expand(self, step: PlanStep, bindings: list[Binding]) -> list[Binding]:
        """Expand: follow edges from the last bound node.

        The expand step binds BOTH the edge variable AND the target node variable.
        The planner produces: scan(a) -> expand(r) -> scan(b).
        We look ahead to find which node variable should be bound by this expand.
        """
        edge_var = step.target_var
        g = self._vg.graph

        # Determine the source node variable (most recently bound node var)
        # and the target node variable (next scan step's target_var).
        source_var = self._find_source_var(bindings)
        target_var = self._find_expand_target_var(step)

        new_bindings: list[Binding] = []

        for b in bindings:
            src_idx = b.get(f"_idx_{source_var}")
            if src_idx is None:
                continue

            edges = self._get_directed_edges(src_idx, step.direction)

            for (edge_src, edge_tgt, edge_data) in edges:
                if not _edge_matches_label(edge_data, step.label):
                    continue

                # Determine the "other" node index (the target of the traversal)
                other_idx = edge_tgt if edge_src == src_idx else edge_src

                # If target_var is already bound, check it matches
                if target_var and target_var in b:
                    existing_idx = b.get(f"_idx_{target_var}")
                    if existing_idx != other_idx:
                        continue

                # Check label of target node if the next scan step has a label
                target_label = self._get_next_scan_label(target_var)
                if target_label is not None:
                    actual_label = self._vg.node_labels.get(other_idx)
                    if actual_label != target_label:
                        continue

                serialized_edge = _serialize_edge(edge_data)
                other_node_data = g.get_node_data(other_idx)
                serialized_target = _serialize_node(other_node_data, other_idx)

                new_b = {**b, edge_var: serialized_edge}
                if target_var:
                    new_b[target_var] = serialized_target
                    new_b[f"_idx_{target_var}"] = other_idx

                # Apply pushed-down predicates
                if step.predicates and not _eval_predicates(step.predicates, new_b, self._plugins):
                    continue

                new_bindings.append(new_b)

        return new_bindings

    def _exec_var_length_expand(self, step: PlanStep, bindings: list[Binding]) -> list[Binding]:
        """Variable-length expand: bounded DFS producing path bindings."""
        edge_var = step.target_var
        g = self._vg.graph
        source_var = self._find_source_var(bindings)
        target_var = self._find_expand_target_var(step)

        min_hops = step.min_hops or 1
        max_hops = min(step.max_hops or self._limits.max_var_length_hops, self._limits.max_var_length_hops)

        new_bindings: list[Binding] = []

        for b in bindings:
            src_idx = b.get(f"_idx_{source_var}")
            if src_idx is None:
                continue

            # BFS/DFS to find all paths of length [min_hops, max_hops]
            paths = self._bounded_dfs(src_idx, step.label, step.direction, min_hops, max_hops)

            for path_nodes, path_edges in paths:
                end_idx = path_nodes[-1]

                # Check target label
                target_label = self._get_next_scan_label(target_var)
                if target_label is not None:
                    actual_label = self._vg.node_labels.get(end_idx)
                    if actual_label != target_label:
                        continue

                serialized_path = {
                    "nodes": [_serialize_node(g.get_node_data(ni), ni) for ni in path_nodes],
                    "edges": [_serialize_edge(e) for e in path_edges],
                }

                new_b = {**b, edge_var: serialized_path}
                if target_var:
                    end_node_data = g.get_node_data(end_idx)
                    new_b[target_var] = _serialize_node(end_node_data, end_idx)
                    new_b[f"_idx_{target_var}"] = end_idx

                if step.predicates and not _eval_predicates(step.predicates, new_b, self._plugins):
                    continue

                new_bindings.append(new_b)

        return new_bindings

    def _exec_filter(self, step: PlanStep, bindings: list[Binding]) -> list[Binding]:
        """Filter: apply remaining predicates."""
        return [b for b in bindings if _eval_predicates(step.predicates, b, self._plugins)]

    # ── helpers ───────────────────────────────────────────────────────────

    def _find_source_var(self, bindings: list[Binding]) -> str:
        """Find the most recently bound node variable (has _idx_ prefix)."""
        if not bindings or not bindings[0]:
            return ""
        # Get the last node variable that was bound (has _idx_ key)
        b = bindings[0]
        node_vars = [k[5:] for k in b if k.startswith("_idx_")]
        return node_vars[-1] if node_vars else ""

    def _find_expand_target_var(self, step: PlanStep) -> str | None:
        """Find the target node variable for an expand step.

        Look at the plan steps: the step after this expand should be a scan
        for the target node. Return that scan's target_var.
        """
        steps = self._plan.steps
        step_idx = None
        for i, s in enumerate(steps):
            if s is step:
                step_idx = i
                break
        if step_idx is None:
            return None

        # Look for the next scan step after this expand
        for i in range(step_idx + 1, len(steps)):
            if steps[i].kind == "scan":
                return steps[i].target_var
            if steps[i].kind in ("expand", "var_length_expand"):
                # Another expand before a scan — the intermediate node
                break
        return None

    def _get_next_scan_label(self, target_var: str | None) -> str | None:
        """Get the label from the next scan step for a given variable."""
        if target_var is None:
            return None
        for s in self._plan.steps:
            if s.kind == "scan" and s.target_var == target_var:
                return s.label
        return None

    def _get_directed_edges(self, src_idx: int, direction: str | None) -> list[tuple[int, int, Any]]:
        """Get edges from/to a node based on direction."""
        g = self._vg.graph
        results: list[tuple[int, int, Any]] = []

        if direction in ("out", None, "both"):
            # Outgoing edges
            try:
                out_edges = g.out_edges(src_idx)
                for src, tgt, data in out_edges:
                    results.append((src, tgt, data))
            except Exception:
                pass

        if direction in ("in", "both"):
            # Incoming edges
            try:
                in_edges = g.in_edges(src_idx)
                for src, tgt, data in in_edges:
                    results.append((src, tgt, data))
            except Exception:
                pass

        return results

    def _bounded_dfs(
        self,
        start_idx: int,
        label: str | None,
        direction: str | None,
        min_hops: int,
        max_hops: int,
    ) -> list[tuple[list[int], list[Any]]]:
        """Bounded DFS returning all paths of length [min_hops, max_hops].

        Returns list of (node_indices, edge_payloads) tuples.
        """
        results: list[tuple[list[int], list[Any]]] = []
        stack: list[tuple[list[int], list[Any]]] = [([start_idx], [])]

        while stack:
            path_nodes, path_edges = stack.pop()
            current = path_nodes[-1]
            depth = len(path_edges)

            if depth >= min_hops:
                results.append((path_nodes, path_edges))

            if depth >= max_hops:
                continue

            edges = self._get_directed_edges(current, direction)
            for (edge_src, edge_tgt, edge_data) in edges:
                if not _edge_matches_label(edge_data, label):
                    continue
                next_idx = edge_tgt if edge_src == current else edge_src
                if next_idx in path_nodes:
                    continue  # avoid cycles
                stack.append((path_nodes + [next_idx], path_edges + [edge_data]))

        return results

    # ── RETURN projection ─────────────────────────────────────────────────

    def _project_return(self, bindings: list[Binding], elapsed_ms: float) -> QueryResult:
        """Project bindings through the RETURN clause to produce final output."""
        return_items = self._plan.return_spec.items
        columns = self._compute_columns(return_items)
        subgraph = SubgraphProjection()

        rows: list[dict[str, Any]] = []
        truncated = False
        truncation_reason: str | None = None

        for b in bindings:
            if len(rows) >= self._limits.max_rows:
                truncated = True
                truncation_reason = f"Row limit ({self._limits.max_rows}) reached"
                break

            row: dict[str, Any] = {}
            for item, col_name in zip(return_items, columns):
                value = self._resolve_return_item(item, b)
                # Strip internal keys from dict values
                if isinstance(value, dict):
                    # Track subgraph nodes/edges
                    idx = value.get("_idx")
                    if idx is not None:
                        subgraph.node_indices.add(idx)
                    value = _strip_internal_keys(value)
                row[col_name] = value

            # Track subgraph edges from bindings
            self._track_subgraph_edges(b, subgraph)
            rows.append(row)

        # Only return subgraph if there are edges tracked
        result_subgraph = subgraph if subgraph.node_indices else None

        return QueryResult(
            columns=columns,
            rows=rows,
            subgraph=result_subgraph,
            stats=QueryStats(
                duration_ms=elapsed_ms,
                bindings_explored=len(bindings),
                rows_returned=len(rows),
            ),
            truncated=truncated,
            truncation_reason=truncation_reason,
        )

    def _compute_columns(self, return_items: list[ReturnItem]) -> list[str]:
        """Compute column names from ReturnItems."""
        columns: list[str] = []
        for item in return_items:
            if item.alias:
                columns.append(item.alias)
            elif isinstance(item.expression, PropertyAccessExpr):
                columns.append(f"{item.expression.variable}.{item.expression.property_name}")
            elif isinstance(item.expression, FunctionCallExpr):
                columns.append(item.expression.name)
            elif isinstance(item.expression, str):
                columns.append(item.expression)
            else:
                columns.append(str(item.expression))
        return columns

    def _resolve_return_item(self, item: ReturnItem, binding: Binding) -> Any:
        """Resolve a single ReturnItem against a binding."""
        return _resolve_expr(item.expression, binding, self._plugins)

    def _track_subgraph_edges(self, binding: Binding, subgraph: SubgraphProjection) -> None:
        """Track edge tuples in the subgraph projection from binding _idx_ keys."""
        idx_keys = sorted([k for k in binding if k.startswith("_idx_")])
        node_indices = [binding[k] for k in idx_keys]
        for idx in node_indices:
            subgraph.node_indices.add(idx)
        # If there are at least 2 node indices, track the edge between consecutive pairs
        if len(node_indices) >= 2:
            for i in range(len(node_indices) - 1):
                subgraph.edge_tuples.add((node_indices[i], node_indices[i + 1]))
