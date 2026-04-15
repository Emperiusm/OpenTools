"""Query planner: AST → QueryPlan with predicate pushdown."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Literal
from opentools.chain.cypher.ast_nodes import (
    BooleanExpr, ComparisonExpr, CypherQuery, EdgePattern,
    FunctionCallExpr, NodePattern, PropertyAccessExpr,
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
    from_session: str | None = None

@dataclass
class ReturnSpec:
    items: list[Any]

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
    steps: list[PlanStep] = []
    pending_predicates: list[Any] = []
    if query.where_clause is not None:
        pending_predicates = _flatten_and(query.where_clause.expression)
    bound_vars: set[str] = set()

    for pattern_tuple in query.match_clause.patterns:
        elements = list(pattern_tuple)
        for i, element in enumerate(elements):
            if isinstance(element, NodePattern):
                var = element.variable
                if var and var not in bound_vars:
                    from_session = None
                    if query.from_clause and i == 0:
                        from_session = query.from_clause.session_variable
                    step = PlanStep(kind="scan", target_var=var, label=element.label, from_session=from_session)
                    bound_vars.add(var)
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
                        kind="var_length_expand", target_var=var or f"_anon_edge_{i}",
                        label=element.label, direction=element.direction,
                        min_hops=element.var_length.min_hops, max_hops=element.var_length.max_hops,
                    )
                else:
                    step = PlanStep(
                        kind="expand", target_var=var or f"_anon_edge_{i}",
                        label=element.label, direction=element.direction,
                    )
                if var:
                    bound_vars.add(var)
                remaining = []
                for pred in pending_predicates:
                    pred_vars = _extract_variables(pred)
                    if pred_vars <= bound_vars:
                        step.predicates.append(pred)
                    else:
                        remaining.append(pred)
                pending_predicates = remaining
                steps.append(step)

    if pending_predicates:
        steps.append(PlanStep(kind="filter", target_var="_post_filter", predicates=pending_predicates))

    return QueryPlan(steps=steps, return_spec=ReturnSpec(items=query.return_clause.items), limits=limits)
