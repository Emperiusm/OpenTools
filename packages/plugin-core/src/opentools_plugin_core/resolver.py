"""Dependency tree resolution with conflict and cycle detection."""

from __future__ import annotations
from opentools_plugin_core.errors import DependencyResolveError


def resolve(target: str, catalog: dict[str, dict], installed: set[str]) -> list[str]:
    order: list[str] = []
    visited: set[str] = set()
    in_stack: set[str] = set()

    def _visit(name: str) -> None:
        if name in installed:
            return
        if name in in_stack:
            raise DependencyResolveError(
                f"Circular dependency detected involving '{name}'",
                hint="Check the plugin's requires.plugins for cycles",
            )
        if name in visited:
            return
        if name not in catalog:
            raise DependencyResolveError(
                f"Plugin '{name}' not found in any registry",
                hint=f"opentools plugin search {name}",
            )
        in_stack.add(name)
        entry = catalog[name]
        for dep in entry.get("requires_plugins", []):
            dep_name = dep["name"] if isinstance(dep, dict) else dep
            _visit(dep_name)
        in_stack.discard(name)
        visited.add(name)
        order.append(name)

    _visit(target)
    return order


def detect_conflicts(
    new_plugin: str,
    new_provides: dict[str, list[str]],
    installed_provides: dict[str, dict[str, str]],
) -> list[str]:
    conflicts: list[str] = []
    for category in ("containers", "skills", "recipes"):
        existing = installed_provides.get(category, {})
        for item in new_provides.get(category, []):
            if item in existing:
                owner = existing[item]
                conflicts.append(f"{category[:-1]} '{item}' already provided by '{owner}'")
    return conflicts
