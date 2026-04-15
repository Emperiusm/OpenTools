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
    left: Any
    operator: str
    right: Any


@dataclass
class BooleanExpr:
    operator: Literal["AND", "OR", "NOT"]
    operands: list[Any]


@dataclass
class FunctionCallExpr:
    name: str
    args: list[Any] = field(default_factory=list)


@dataclass
class ReturnItem:
    expression: Any
    alias: str | None


@dataclass
class MatchClause:
    patterns: list[tuple]


@dataclass
class WhereClause:
    expression: Any


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
    session_assignment: str | None = None
