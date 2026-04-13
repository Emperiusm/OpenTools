"""ParserPlugin protocol and ParserRouter with builtin + plugin discovery."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Iterator, Protocol, runtime_checkable

from opentools.scanner.models import RawFinding


@runtime_checkable
class ParserPlugin(Protocol):
    """Protocol that all parsers (builtin and plugin) must implement."""

    name: str
    version: str
    confidence_tier: float

    def validate(self, data: bytes) -> bool:
        """Return True if *data* looks like valid output for this parser."""
        ...

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        """Parse raw tool output and yield RawFinding objects."""
        ...


class ParserRouter:
    """Routes tool output to the correct parser.

    Maintains a registry of builtin and plugin parsers.  Plugin parsers
    override builtins of the same name.  Supports dynamic discovery from
    configurable directories.
    """

    def __init__(self) -> None:
        self._builtins: dict[str, ParserPlugin] = {}
        self._plugins: dict[str, ParserPlugin] = {}

    def register(self, parser: ParserPlugin, *, plugin: bool = False) -> None:
        """Register a parser.  If *plugin* is True, it overrides builtins."""
        target = self._plugins if plugin else self._builtins
        target[parser.name] = parser

    def get(self, name: str) -> ParserPlugin | None:
        """Return the parser for *name*.  Plugins take precedence."""
        return self._plugins.get(name) or self._builtins.get(name)

    def list_parsers(self) -> list[str]:
        """Return sorted list of all registered parser names."""
        names = set(self._builtins.keys()) | set(self._plugins.keys())
        return sorted(names)

    def discover_plugins(self, directory: str) -> None:
        """Load all ``*.py`` files from *directory* that expose a ``PARSER`` attribute.

        Each module must define a module-level ``PARSER`` object that satisfies
        the ``ParserPlugin`` protocol.
        """
        dir_path = Path(directory)
        if not dir_path.is_dir():
            return

        for py_file in sorted(dir_path.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            module_name = f"opentools_parser_plugin_{py_file.stem}"
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            try:
                spec.loader.exec_module(module)
            except Exception:
                continue
            parser_obj = getattr(module, "PARSER", None)
            if parser_obj is not None and hasattr(parser_obj, "name"):
                self.register(parser_obj, plugin=True)
