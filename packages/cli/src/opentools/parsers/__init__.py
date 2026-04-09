"""Tool output parser registry.

Each parser module exports a `parse(raw_output: str) -> list[Finding]` function.
The registry auto-discovers parser modules in this directory.
"""

import importlib
import pkgutil
from typing import Callable
from opentools.models import Finding

_PARSERS: dict[str, Callable[[str], list[Finding]]] = {}


def _discover_parsers() -> None:
    """Auto-discover parser modules in this package."""
    import opentools.parsers as pkg
    for importer, modname, ispkg in pkgutil.iter_modules(pkg.__path__):
        if modname.startswith("_"):
            continue
        module = importlib.import_module(f"opentools.parsers.{modname}")
        if hasattr(module, "parse"):
            _PARSERS[modname] = module.parse


def get_parser(tool_name: str) -> Callable[[str], list[Finding]] | None:
    """Get parser function for a tool, or None if no parser exists."""
    if not _PARSERS:
        _discover_parsers()
    return _PARSERS.get(tool_name)


def list_parsers() -> list[str]:
    """Return names of all available parsers."""
    if not _PARSERS:
        _discover_parsers()
    return list(_PARSERS.keys())
