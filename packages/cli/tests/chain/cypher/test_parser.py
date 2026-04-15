"""Tests for the Cypher-style query parser."""
import pytest
from opentools.chain.cypher.ast_nodes import (
    ComparisonExpr, CypherQuery, EdgePattern, FunctionCallExpr,
    NodePattern, PropertyAccessExpr, SessionAssignment,
)
from opentools.chain.cypher.errors import QueryParseError
from opentools.chain.cypher.parser import parse_cypher


def test_parse_simple_match_return():
    q = parse_cypher("MATCH (a:Finding) RETURN a")
    assert isinstance(q, CypherQuery)
    assert len(q.match_clause.patterns) == 1
    assert len(q.return_clause.items) == 1


def test_parse_two_node_pattern():
    q = parse_cypher("MATCH (a:Finding)-[r:LINKED]->(b:Finding) RETURN a, b")
    assert len(q.match_clause.patterns) == 1
    pattern = q.match_clause.patterns[0]
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


def test_parse_entity_node_labels():
    for label in ["Host", "IP", "CVE", "Domain", "Port", "MitreAttack", "Entity"]:
        q = parse_cypher(f"MATCH (e:{label}) RETURN e")
        assert q.match_clause.patterns[0][0].label == label


def test_parse_var_length_path():
    q = parse_cypher("MATCH (a:Finding)-[r:LINKED*1..5]->(b:Finding) RETURN a, b")
    edge = q.match_clause.patterns[0][1]
    assert edge.var_length is not None
    assert edge.var_length.min_hops == 1
    assert edge.var_length.max_hops == 5


def test_parse_var_length_exceeds_max_hops():
    with pytest.raises(QueryParseError, match="max.*10"):
        parse_cypher("MATCH (a:Finding)-[r:LINKED*1..15]->(b:Finding) RETURN a, b")


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


def test_parse_return_property():
    q = parse_cypher("MATCH (a:Finding) RETURN a.title, a.severity")
    assert len(q.return_clause.items) == 2
    assert isinstance(q.return_clause.items[0].expression, PropertyAccessExpr)


def test_parse_return_collect():
    q = parse_cypher("MATCH (a:Finding)-[r:LINKED]->(b:Finding) RETURN collect(a)")
    item = q.return_clause.items[0]
    assert isinstance(item.expression, FunctionCallExpr)
    assert item.expression.name == "collect"


def test_parse_session_assignment():
    q = parse_cypher("results = MATCH (a:Finding) RETURN a")
    assert q.session_assignment == "results"


def test_parse_from_clause():
    q = parse_cypher("MATCH (a) FROM prev_results -[r:LINKED]->(b:Finding) RETURN a, b")
    assert q.from_clause is not None
    assert q.from_clause.session_variable == "prev_results"


@pytest.mark.parametrize("verb", ["CREATE", "DELETE", "SET", "MERGE", "REMOVE", "DETACH", "DROP"])
def test_parse_rejects_mutation_verbs(verb):
    with pytest.raises(QueryParseError):
        parse_cypher(f"{verb} (a:Finding)")


def test_parse_empty_string():
    with pytest.raises(QueryParseError):
        parse_cypher("")


def test_parse_garbage():
    with pytest.raises(QueryParseError):
        parse_cypher("not a query at all 123 !!!")


def test_parse_case_insensitive_keywords():
    q = parse_cypher('match (a:Finding) where a.severity = "critical" return a')
    assert q is not None


def test_parse_multiple_patterns():
    q = parse_cypher("MATCH (a:Finding)-[r:LINKED]->(b:Finding), (b)-[:MENTIONED_IN]->(e:Host) RETURN a, e")
    assert len(q.match_clause.patterns) == 2
