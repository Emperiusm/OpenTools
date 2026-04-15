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
