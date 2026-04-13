"""Semgrep JSON output parser."""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Iterator

import orjson

from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)


_CWE_RE = re.compile(r"CWE-(\d+)")


class SemgrepParser:
    """Parses Semgrep JSON output into RawFinding objects."""

    name = "semgrep"
    version = "1.0.0"
    confidence_tier = 0.9

    def validate(self, data: bytes) -> bool:
        """Check that data is valid Semgrep JSON (has a ``results`` key)."""
        try:
            parsed = orjson.loads(data)
            return isinstance(parsed, dict) and "results" in parsed
        except (orjson.JSONDecodeError, UnicodeDecodeError):
            return False

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        """Parse Semgrep JSON output and yield RawFinding objects."""
        parsed = orjson.loads(data)
        results = parsed.get("results", [])

        for result in results:
            check_id = result.get("check_id", "unknown")
            path = result.get("path", "")
            start = result.get("start", {})
            end = result.get("end", {})
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})

            line_start = start.get("line")
            line_end = end.get("line")

            # Determine location precision
            if line_start is not None and line_end is not None and line_start != line_end:
                precision = LocationPrecision.LINE_RANGE
            elif line_start is not None:
                precision = LocationPrecision.EXACT_LINE
            elif path:
                precision = LocationPrecision.FILE
            else:
                precision = LocationPrecision.FILE

            # Extract CWE — semgrep stores as list of strings like "CWE-78: ..."
            cwe_raw = metadata.get("cwe", [])
            cwe = None
            if isinstance(cwe_raw, list):
                for entry in cwe_raw:
                    m = _CWE_RE.search(str(entry))
                    if m:
                        cwe = f"CWE-{m.group(1)}"
                        break
            elif isinstance(cwe_raw, str):
                m = _CWE_RE.search(cwe_raw)
                if m:
                    cwe = f"CWE-{m.group(1)}"

            # Build evidence hash from check_id + path + line
            evidence_str = f"{check_id}:{path}:{line_start}:{line_end}"
            evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()

            # Build location fingerprint
            location_fp = f"{path}:{line_start or 0}"

            # Map semgrep confidence to evidence quality
            confidence_str = metadata.get("confidence", "").upper()
            if confidence_str == "HIGH":
                evidence_quality = EvidenceQuality.STRUCTURED
            elif confidence_str == "MEDIUM":
                evidence_quality = EvidenceQuality.STRUCTURED
            else:
                evidence_quality = EvidenceQuality.PATTERN

            raw_severity = extra.get("severity", "INFO")
            description = extra.get("message", "")

            yield RawFinding(
                id=str(uuid.uuid4()),
                scan_task_id=scan_task_id,
                scan_id=scan_id,
                tool="semgrep",
                raw_severity=raw_severity,
                title=check_id,
                description=description,
                file_path=path or None,
                line_start=line_start,
                line_end=line_end,
                evidence=description,
                evidence_quality=evidence_quality,
                evidence_hash=evidence_hash,
                cwe=cwe,
                location_fingerprint=location_fp,
                location_precision=precision,
                parser_version=self.version,
                parser_confidence=self.confidence_tier,
                discovered_at=datetime.now(timezone.utc),
            )
