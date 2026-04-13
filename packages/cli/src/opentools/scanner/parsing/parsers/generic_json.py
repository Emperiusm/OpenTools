"""Generic JSON parser — fallback for tools without a dedicated parser.

Handles two common formats:
- Object with a "findings", "results", or "vulnerabilities" key containing a list
- Top-level array of finding-like objects

Each object should have at minimum a ``title`` or ``name`` field.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Iterator

from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)

_LIST_KEYS = ("findings", "results", "vulnerabilities", "issues", "alerts")


class GenericJsonParser:
    """Best-effort parser for arbitrary JSON tool output."""

    name = "generic_json"
    version = "1.0.0"
    confidence_tier = 0.3

    def validate(self, data: bytes) -> bool:
        """Accept any valid JSON (dict or list)."""
        try:
            parsed = json.loads(data)
            return isinstance(parsed, (dict, list))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        parsed = json.loads(data)
        items = self._extract_items(parsed)

        for item in items:
            if not isinstance(item, dict):
                continue

            title = (
                item.get("title")
                or item.get("name")
                or item.get("rule_id")
                or item.get("check_id")
                or "Unknown finding"
            )
            severity = str(
                item.get("severity")
                or item.get("level")
                or item.get("risk")
                or "info"
            )
            file_path = item.get("file") or item.get("path") or item.get("location")
            line = item.get("line") or item.get("line_start") or item.get("lineno")
            description = item.get("description") or item.get("message") or ""
            cwe = item.get("cwe")

            evidence_str = f"generic:{title}:{file_path}:{line}"
            evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()
            location_fp = f"{file_path or 'unknown'}:{line or 0}"

            if line is not None:
                precision = LocationPrecision.EXACT_LINE
            elif file_path:
                precision = LocationPrecision.FILE
            else:
                precision = LocationPrecision.HOST

            yield RawFinding(
                id=str(uuid.uuid4()),
                scan_task_id=scan_task_id,
                scan_id=scan_id,
                tool="generic",
                raw_severity=severity,
                title=title,
                description=description,
                file_path=file_path,
                line_start=int(line) if line is not None else None,
                line_end=None,
                evidence=description,
                evidence_quality=EvidenceQuality.HEURISTIC,
                evidence_hash=evidence_hash,
                cwe=cwe,
                location_fingerprint=location_fp,
                location_precision=precision,
                parser_version=self.version,
                parser_confidence=self.confidence_tier,
                discovered_at=datetime.now(timezone.utc),
            )

    def _extract_items(self, parsed: dict | list) -> list:
        """Extract the list of finding-like items from parsed JSON."""
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            for key in _LIST_KEYS:
                if key in parsed and isinstance(parsed[key], list):
                    return parsed[key]
            # Fallback: try any key whose value is a list of dicts
            for value in parsed.values():
                if isinstance(value, list) and value and isinstance(value[0], dict):
                    return value
        return []
