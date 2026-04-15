"""Lark-based parser and transformer for the Cypher-style query DSL."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from lark import Lark, Token, Transformer, Tree
from lark.exceptions import LarkError

from .ast_nodes import (
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
from .errors import QueryParseError

_MUTATION_VERBS = re.compile(
    r"\b(CREATE|DELETE|SET|MERGE|REMOVE|DETACH|DROP)\b", re.IGNORECASE
)

_MAX_VAR_LENGTH_HOPS = 10

_GRAMMAR_PATH = Path(__file__).parent / "grammar.lark"

_parser: Lark | None = None


def _get_parser() -> Lark:
    """Lazily load and cache the Lark parser."""
    global _parser
    if _parser is None:
        _parser = Lark(
            _GRAMMAR_PATH.read_text(encoding="utf-8"),
            parser="lalr",
            start="start",
        )
    return _parser


# Helper sets for disambiguation
_NODE_LABELS = frozenset({"Finding", "Host", "IP", "CVE", "Domain", "Port", "MitreAttack", "Entity"})
_EDGE_LABELS = frozenset({"LINKED", "MENTIONED_IN"})

# Terminal types that are keyword tokens (should be filtered)
_KW_TYPES = frozenset({
    "KW_MATCH", "KW_WHERE", "KW_RETURN", "KW_AND", "KW_OR", "KW_NOT",
    "KW_AS", "KW_FROM", "KW_CONTAINS", "KW_STARTS_WITH", "KW_ENDS_WITH",
    "KW_IS_NOT_NULL", "KW_IS_NULL", "KW_IN",
})


def _filter_kw(items: list) -> list:
    """Filter out keyword tokens from transformer items."""
    return [i for i in items if not (isinstance(i, Token) and i.type in _KW_TYPES)]


class CypherTransformer(Transformer):
    """Transform Lark parse tree into typed AST nodes."""

    # -- Literals --

    def string_val(self, items: list) -> str:
        return str(items[0])[1:-1]

    def float_val(self, items: list) -> float:
        return float(items[0])

    def int_val(self, items: list) -> int:
        return int(items[0])

    def var_ref(self, items: list) -> str:
        return str(items[0])

    # -- Property access --

    def prop_access(self, items: list) -> PropertyAccessExpr:
        idents = [i for i in items if isinstance(i, Token) and i.type == "IDENT"]
        return PropertyAccessExpr(variable=str(idents[0]), property_name=str(idents[1]))

    # -- Function calls --

    def function_call(self, items: list) -> FunctionCallExpr:
        name = str(items[0])
        args_list: list = []
        for item in items[1:]:
            if isinstance(item, list):
                args_list = item
        return FunctionCallExpr(name=name, args=args_list)

    def arg_list(self, items: list) -> list:
        return list(items)

    # -- Comparison / boolean expressions --

    def comp_op(self, items: list) -> str:
        return str(items[0])

    def comparison_expr(self, items: list) -> ComparisonExpr:
        # items: [left_expr, comp_op_str, right_expr]
        left, op, right = items
        return ComparisonExpr(left=left, operator=op, right=right)

    def contains_expr(self, items: list) -> ComparisonExpr:
        filtered = _filter_kw(items)
        return ComparisonExpr(left=filtered[0], operator="CONTAINS", right=filtered[1])

    def starts_with_expr(self, items: list) -> ComparisonExpr:
        filtered = _filter_kw(items)
        return ComparisonExpr(left=filtered[0], operator="STARTS WITH", right=filtered[1])

    def ends_with_expr(self, items: list) -> ComparisonExpr:
        filtered = _filter_kw(items)
        return ComparisonExpr(left=filtered[0], operator="ENDS WITH", right=filtered[1])

    def in_expr(self, items: list) -> ComparisonExpr:
        filtered = _filter_kw(items)
        return ComparisonExpr(left=filtered[0], operator="IN", right=filtered[1])

    def is_null_expr(self, items: list) -> ComparisonExpr:
        filtered = _filter_kw(items)
        return ComparisonExpr(left=filtered[0], operator="IS NULL", right=None)

    def is_not_null_expr(self, items: list) -> ComparisonExpr:
        filtered = _filter_kw(items)
        return ComparisonExpr(left=filtered[0], operator="IS NOT NULL", right=None)

    def where_func(self, items: list) -> Any:
        return items[0]

    def not_expr(self, items: list) -> BooleanExpr:
        filtered = _filter_kw(items)
        return BooleanExpr(operator="NOT", operands=[filtered[0]])

    def or_expr(self, items: list) -> BooleanExpr | Any:
        filtered = _filter_kw(items)
        if len(filtered) == 1:
            return filtered[0]
        return BooleanExpr(operator="OR", operands=filtered)

    def and_expr(self, items: list) -> BooleanExpr | Any:
        filtered = _filter_kw(items)
        if len(filtered) == 1:
            return filtered[0]
        return BooleanExpr(operator="AND", operands=filtered)

    # -- Pattern elements --

    def variable_def(self, items: list) -> str:
        return str(items[0])

    def label_def(self, items: list) -> str:
        return str(items[0])

    def edge_var(self, items: list) -> str:
        return str(items[0])

    def edge_label(self, items: list) -> str:
        return str(items[0])

    def var_length(self, items: list) -> VarLengthSpec:
        ints = [i for i in items if isinstance(i, Token) and i.type == "INT"]
        min_hops = int(ints[0])
        max_hops = int(ints[1])
        if max_hops > _MAX_VAR_LENGTH_HOPS:
            raise QueryParseError(
                f"Variable-length max hops {max_hops} exceeds max of {_MAX_VAR_LENGTH_HOPS}"
            )
        return VarLengthSpec(min_hops=min_hops, max_hops=max_hops)

    def edge_detail(self, items: list) -> dict:
        variable = None
        label = None
        vl = None
        for item in items:
            if isinstance(item, VarLengthSpec):
                vl = item
            elif isinstance(item, str):
                if item in _EDGE_LABELS:
                    label = item
                else:
                    variable = item
        return {"variable": variable, "label": label, "var_length": vl}

    def outgoing_edge(self, items: list) -> EdgePattern:
        detail = items[0]
        return EdgePattern(
            variable=detail["variable"],
            label=detail["label"],
            direction="out",
            var_length=detail["var_length"],
        )

    def incoming_edge(self, items: list) -> EdgePattern:
        detail = items[0]
        return EdgePattern(
            variable=detail["variable"],
            label=detail["label"],
            direction="in",
            var_length=detail["var_length"],
        )

    def edge_pattern(self, items: list) -> EdgePattern:
        return items[0]

    def from_clause(self, items: list) -> FromClause:
        filtered = _filter_kw(items)
        return FromClause(session_variable=str(filtered[0]))

    def node_pattern(self, items: list) -> tuple:
        """Return (NodePattern, optional FromClause)."""
        variable = None
        label = None
        fc = None
        for item in items:
            if isinstance(item, FromClause):
                fc = item
            elif isinstance(item, str):
                if item in _NODE_LABELS:
                    label = item
                else:
                    variable = item
        return (NodePattern(variable=variable, label=label), fc)

    def pattern(self, items: list) -> tuple:
        """Build a pattern tuple from alternating nodes and edges.

        Returns (pattern_elements_tuple, optional_from_clause).
        """
        elements = []
        from_clause = None
        for item in items:
            if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], NodePattern):
                node, fc = item
                elements.append(node)
                if fc is not None:
                    from_clause = fc
            elif isinstance(item, EdgePattern):
                elements.append(item)
        return (tuple(elements), from_clause)

    def pattern_list(self, items: list) -> list:
        return list(items)

    def match_clause(self, items: list) -> tuple:
        """Return (MatchClause, optional FromClause)."""
        filtered = _filter_kw(items)
        pattern_items = filtered[0]  # list of (pattern_tuple, from_clause) tuples
        patterns = []
        from_clause = None
        for pattern_tuple, fc in pattern_items:
            patterns.append(pattern_tuple)
            if fc is not None:
                from_clause = fc
        return (MatchClause(patterns=patterns), from_clause)

    def where_clause(self, items: list) -> WhereClause:
        filtered = _filter_kw(items)
        return WhereClause(expression=filtered[0])

    # -- Return clause --

    def return_item(self, items: list) -> ReturnItem:
        expression = items[0]
        alias = items[1] if len(items) > 1 else None
        return ReturnItem(expression=expression, alias=alias)

    def alias(self, items: list) -> str:
        filtered = _filter_kw(items)
        return str(filtered[0])

    def return_list(self, items: list) -> list:
        return list(items)

    def return_clause(self, items: list) -> ReturnClause:
        filtered = _filter_kw(items)
        return ReturnClause(items=filtered[0])

    # -- Top-level --

    def query(self, items: list) -> CypherQuery:
        match_result = items[0]
        match_clause, from_clause = match_result

        where_clause = None
        return_clause = None
        for item in items[1:]:
            if isinstance(item, WhereClause):
                where_clause = item
            elif isinstance(item, ReturnClause):
                return_clause = item

        return CypherQuery(
            match_clause=match_clause,
            where_clause=where_clause,
            return_clause=return_clause,
            from_clause=from_clause,
        )

    def session_assignment(self, items: list) -> CypherQuery:
        var_name = str(items[0])
        query = items[1]
        query.session_assignment = var_name
        return query

    def start(self, items: list) -> CypherQuery:
        return items[0]


def parse_cypher(query: str) -> CypherQuery:
    """Parse a Cypher-style query string into a CypherQuery AST.

    Args:
        query: The query string to parse.

    Returns:
        A CypherQuery AST node.

    Raises:
        QueryParseError: If the query is empty, contains mutation verbs,
            or has syntax errors.
    """
    if not query or not query.strip():
        raise QueryParseError("Empty query")

    # Reject mutation verbs before parsing
    if _MUTATION_VERBS.search(query):
        raise QueryParseError(
            f"Mutation operations are not allowed: {_MUTATION_VERBS.search(query).group(1)}"
        )

    try:
        parser = _get_parser()
        tree = parser.parse(query)
        transformer = CypherTransformer()
        result = transformer.transform(tree)
        return result
    except QueryParseError:
        raise
    except LarkError as exc:
        raise QueryParseError(f"Syntax error: {exc}") from exc
    except Exception as exc:
        raise QueryParseError(f"Parse error: {exc}") from exc
