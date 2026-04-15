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
