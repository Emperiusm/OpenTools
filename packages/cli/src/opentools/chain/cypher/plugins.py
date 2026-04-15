"""Plugin function registry for the Cypher DSL."""
from __future__ import annotations
from typing import Any, Callable

class PluginFunctionRegistry:
    def __init__(self) -> None:
        self._scalars: dict[str, dict] = {}
        self._aggregations: dict[str, dict] = {}

    def register_function(self, name: str, fn: Callable, *, help: str = "", arg_types: list[str], return_type: str) -> None:
        if "." not in name:
            raise ValueError(f"plugin function names must be dotted (e.g., 'plugin.func'), got: {name!r}")
        if name in self._scalars or name in self._aggregations:
            raise ValueError(f"function {name!r} already registered")
        self._scalars[name] = {"fn": fn, "help": help, "arg_types": arg_types, "return_type": return_type}

    def register_aggregation(self, name: str, fn: Callable, *, help: str = "", input_type: str, return_type: str) -> None:
        if "." not in name:
            raise ValueError(f"plugin aggregation names must be dotted (e.g., 'plugin.agg'), got: {name!r}")
        if name in self._scalars or name in self._aggregations:
            raise ValueError(f"function {name!r} already registered")
        self._aggregations[name] = {"fn": fn, "help": help, "input_type": input_type, "return_type": return_type}

    def get_function(self, name: str) -> Callable | None:
        entry = self._scalars.get(name)
        return entry["fn"] if entry else None

    def get_aggregation(self, name: str) -> Callable | None:
        entry = self._aggregations.get(name)
        return entry["fn"] if entry else None

    def list_all(self) -> dict[str, dict]:
        result: dict[str, dict] = {}
        for name, info in self._scalars.items():
            result[name] = {"kind": "scalar", "help": info["help"], "arg_types": info["arg_types"], "return_type": info["return_type"]}
        for name, info in self._aggregations.items():
            result[name] = {"kind": "aggregation", "help": info["help"], "input_type": info["input_type"], "return_type": info["return_type"]}
        return result
