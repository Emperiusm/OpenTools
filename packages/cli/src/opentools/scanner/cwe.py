"""CWE hierarchy — parent/child relationships, alias resolution, and OWASP mapping."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=None)
def _load_json(filename: str) -> dict:
    """Load JSON from data/ directory, strip _comment keys."""
    path = Path(__file__).parent / "data" / filename
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return {k: v for k, v in data.items() if k != "_comment"}


class CWEHierarchy:
    """Loads and queries CWE parent/child relationships, resolves aliases, and maps to OWASP."""

    def __init__(self) -> None:
        self._hierarchy = _load_json("cwe_hierarchy.json")
        self._aliases = _load_json("cwe_aliases.json")
        self._owasp = _load_json("cwe_owasp_map.json")

    def get_name(self, cwe_id: str) -> str | None:
        """Get human-readable name for a CWE ID."""
        entry = self._hierarchy.get(cwe_id)
        if entry is None:
            return None
        return entry.get("name")

    def get_parent(self, cwe_id: str) -> str | None:
        """Get parent CWE ID, or None if root."""
        entry = self._hierarchy.get(cwe_id)
        if entry is None:
            return None
        # parent may be null in JSON, which becomes None in Python
        return entry.get("parent")

    def get_children(self, cwe_id: str) -> list[str]:
        """Get child CWE IDs."""
        entry = self._hierarchy.get(cwe_id)
        if entry is None:
            return []
        return list(entry.get("children", []))

    def is_related(self, cwe_a: str, cwe_b: str) -> bool:
        """True if CWEs share a parent or one is ancestor of the other.

        Checks:
        - Direct parent/child relationship (either direction).
        - Siblings: both share a common parent.
        - Grandparent relationships: either CWE's grandparent equals the other's parent or itself.
        """
        if cwe_a == cwe_b:
            return True

        parent_a = self.get_parent(cwe_a)
        parent_b = self.get_parent(cwe_b)

        # Direct parent/child — a is parent of b, or b is parent of a
        if parent_b == cwe_a or parent_a == cwe_b:
            return True

        # Siblings — share the same non-None parent
        if parent_a is not None and parent_a == parent_b:
            return True

        # Grandparent relationships (2 levels up)
        grandparent_a = self.get_parent(parent_a) if parent_a is not None else None
        grandparent_b = self.get_parent(parent_b) if parent_b is not None else None

        # a's grandparent is b, or b's grandparent is a
        if grandparent_a == cwe_b or grandparent_b == cwe_a:
            return True

        # a's grandparent is b's parent, or b's grandparent is a's parent (cousins via 2-level)
        if grandparent_a is not None and grandparent_a == parent_b:
            return True
        if grandparent_b is not None and grandparent_b == parent_a:
            return True

        # Shared grandparent
        if grandparent_a is not None and grandparent_a == grandparent_b:
            return True

        return False

    def resolve_alias(self, alias: str) -> str | None:
        """Resolve alias/shorthand to canonical CWE ID.

        If already a canonical CWE ID, returns it directly.
        Case-insensitive lookup.
        """
        # Pass-through for canonical IDs that exist in the hierarchy
        if alias in self._hierarchy:
            return alias

        # Case-insensitive lookup in aliases
        lower = alias.lower()
        # Check aliases dict (keys are already lowercase per the JSON)
        result = self._aliases.get(lower)
        if result is not None:
            return result

        # Try case-insensitive scan as a fallback
        for key, value in self._aliases.items():
            if key.lower() == lower:
                return value

        return None

    def get_owasp_category(self, cwe_id: str) -> str | None:
        """Map CWE to OWASP Top 10 2021 category.

        Walks up the parent hierarchy if a direct mapping is not found.
        """
        current = cwe_id
        visited: set[str] = set()

        while current is not None and current not in visited:
            visited.add(current)

            category = self._owasp.get(current)
            if category is not None:
                return category

            current = self.get_parent(current)

        return None
