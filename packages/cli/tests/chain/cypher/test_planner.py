# packages/cli/tests/chain/cypher/test_planner.py
import pytest
from opentools.chain.cypher.ast_nodes import (
    ComparisonExpr, CypherQuery, EdgePattern, MatchClause,
    NodePattern, PropertyAccessExpr, ReturnClause, ReturnItem,
    VarLengthSpec, WhereClause,
)
from opentools.chain.cypher.limits import QueryLimits
from opentools.chain.cypher.planner import plan_query, PlanStep, QueryPlan

def _simple_query() -> CypherQuery:
    """MATCH (a:Finding) RETURN a"""
    return CypherQuery(
        match_clause=MatchClause(patterns=[(NodePattern(variable="a", label="Finding"),)]),
        where_clause=None,
        return_clause=ReturnClause(items=[ReturnItem(expression="a", alias=None)]),
    )

def _two_node_query() -> CypherQuery:
    """MATCH (a:Finding)-[r:LINKED]->(b:Finding) RETURN a, b"""
    return CypherQuery(
        match_clause=MatchClause(patterns=[
            (NodePattern(variable="a", label="Finding"),
             EdgePattern(variable="r", label="LINKED", direction="out", var_length=None),
             NodePattern(variable="b", label="Finding")),
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
        match_clause=MatchClause(patterns=[(NodePattern(variable="a", label="Finding"),)]),
        where_clause=WhereClause(expression=ComparisonExpr(
            left=PropertyAccessExpr(variable="a", property_name="severity"),
            operator="=", right="critical",
        )),
        return_clause=ReturnClause(items=[ReturnItem(expression="a", alias=None)]),
    )

def _var_length_query() -> CypherQuery:
    """MATCH (a:Finding)-[r:LINKED*1..5]->(b:Finding) RETURN a, b"""
    return CypherQuery(
        match_clause=MatchClause(patterns=[
            (NodePattern(variable="a", label="Finding"),
             EdgePattern(variable="r", label="LINKED", direction="out", var_length=VarLengthSpec(min_hops=1, max_hops=5)),
             NodePattern(variable="b", label="Finding")),
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

def test_plan_predicate_pushdown():
    plan = plan_query(_filtered_query(), QueryLimits())
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
