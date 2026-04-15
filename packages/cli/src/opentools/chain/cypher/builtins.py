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
