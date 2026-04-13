"""NormalizationEngine — standardizes paths, CWEs, severities, and titles.

Uses static data files from ``scanner/data/`` (severity_maps.json,
title_normalization.json) and the CWEHierarchy for alias resolution.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Sequence

from opentools.scanner.cwe import CWEHierarchy
from opentools.scanner.models import RawFinding


_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@lru_cache(maxsize=1)
def _load_severity_maps() -> dict[str, dict[str, str]]:
    path = _DATA_DIR / "severity_maps.json"
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return {k: v for k, v in data.items() if k != "_comment"}


@lru_cache(maxsize=1)
def _load_title_patterns() -> list[tuple[re.Pattern, str]]:
    path = _DATA_DIR / "title_normalization.json"
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    patterns = data.get("patterns", [])
    compiled = []
    for entry in patterns:
        try:
            compiled.append((re.compile(entry["regex"], re.IGNORECASE), entry["title"]))
        except re.error:
            continue
    return compiled


class NormalizationEngine:
    """Standardizes findings across tools for comparable dedup.

    - **Paths**: resolve to relative, normalize separators
    - **CWEs**: alias resolution via CWEHierarchy
    - **Severities**: per-tool mapping to canonical scale
    - **Titles**: regex-based canonical title mapping
    - **Location fingerprints**: rebuilt from normalized path + line
    """

    def __init__(self) -> None:
        self._severity_maps = _load_severity_maps()
        self._title_patterns = _load_title_patterns()
        self._cwe = CWEHierarchy()

    def normalize(self, findings: Sequence[RawFinding]) -> list[RawFinding]:
        """Return a new list of findings with normalized fields.

        Original finding objects are not mutated; new copies are created.
        """
        result = []
        for f in findings:
            updates: dict = {}

            # 1. Path normalization
            norm_path = self._normalize_path(f.file_path)
            if norm_path != f.file_path:
                updates["file_path"] = norm_path

            # 2. Severity normalization
            norm_sev = self._normalize_severity(f.tool, f.raw_severity)
            if norm_sev != f.raw_severity:
                updates["raw_severity"] = norm_sev

            # 3. CWE normalization
            norm_cwe = self._normalize_cwe(f.cwe)
            if norm_cwe != f.cwe:
                updates["cwe"] = norm_cwe

            # 4. Title normalization
            canon_title = self._normalize_title(f.title)
            updates["canonical_title"] = canon_title

            # 5. Location fingerprint update
            norm_fp = self._normalize_location_fingerprint(
                f.location_fingerprint, f.file_path, norm_path
            )
            if norm_fp != f.location_fingerprint:
                updates["location_fingerprint"] = norm_fp

            if updates:
                result.append(f.model_copy(update=updates))
            else:
                result.append(f)

        return result

    def _normalize_path(self, path: str | None) -> str | None:
        """Normalize file path: forward slashes, strip leading ./ and drive prefixes."""
        if path is None:
            return None

        # Backslash to forward slash
        normalized = path.replace("\\", "/")

        # Strip leading ./
        if normalized.startswith("./"):
            normalized = normalized[2:]

        # Strip Windows drive letter + path prefix (e.g., C:/Users/.../project/)
        # Heuristic: if path starts with X:/ where X is a letter, strip up to
        # the first occurrence of src/, lib/, app/, etc., or just remove the drive letter
        drive_match = re.match(r"^[A-Za-z]:/", normalized)
        if drive_match:
            # Try to find a common project root indicator
            for marker in ("src/", "lib/", "app/", "pkg/", "packages/", "test/", "tests/"):
                idx = normalized.find(marker)
                if idx != -1:
                    normalized = normalized[idx:]
                    break
            else:
                # No marker found — just strip the drive letter
                normalized = normalized[drive_match.end():]

        # Strip leading /
        normalized = normalized.lstrip("/")

        return normalized

    def _normalize_severity(self, tool: str, raw_severity: str) -> str:
        """Map tool-specific severity to canonical severity."""
        tool_map = self._severity_maps.get(tool)
        if tool_map is None:
            return raw_severity
        return tool_map.get(raw_severity, raw_severity)

    def _normalize_cwe(self, cwe: str | None) -> str | None:
        """Resolve CWE aliases to canonical CWE IDs."""
        if cwe is None:
            return None
        resolved = self._cwe.resolve_alias(cwe)
        return resolved if resolved is not None else cwe

    def _normalize_title(self, title: str) -> str:
        """Match title against regex patterns and return canonical title."""
        for pattern, canonical in self._title_patterns:
            if pattern.search(title):
                return canonical
        return title

    def _normalize_location_fingerprint(
        self,
        fingerprint: str,
        original_path: str | None,
        normalized_path: str | None,
    ) -> str:
        """Update location fingerprint with normalized path."""
        if original_path is None or normalized_path is None:
            return fingerprint
        if original_path == normalized_path:
            return fingerprint
        return fingerprint.replace(original_path, normalized_path)
