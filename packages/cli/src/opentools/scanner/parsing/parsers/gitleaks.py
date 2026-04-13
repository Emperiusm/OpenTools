"""Gitleaks JSON output parser."""

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


class GitleaksParser:
    """Parses Gitleaks JSON output (array of leak objects)."""

    name = "gitleaks"
    version = "1.0.0"
    confidence_tier = 0.9

    def validate(self, data: bytes) -> bool:
        """Gitleaks outputs a JSON array of objects."""
        try:
            parsed = json.loads(data)
            return isinstance(parsed, list)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        parsed = json.loads(data)
        if not isinstance(parsed, list):
            return

        for leak in parsed:
            rule_id = leak.get("RuleID", "unknown")
            file_path = leak.get("File", "")
            line_start = leak.get("StartLine")
            line_end = leak.get("EndLine")
            description = leak.get("Description", "")
            fingerprint_raw = leak.get("Fingerprint", "")

            evidence_str = f"{rule_id}:{file_path}:{line_start}:{fingerprint_raw}"
            evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()

            location_fp = f"{file_path}:{line_start or 0}"

            if line_start is not None and line_end is not None and line_start != line_end:
                precision = LocationPrecision.LINE_RANGE
            elif line_start is not None:
                precision = LocationPrecision.EXACT_LINE
            else:
                precision = LocationPrecision.FILE

            yield RawFinding(
                id=str(uuid.uuid4()),
                scan_task_id=scan_task_id,
                scan_id=scan_id,
                tool="gitleaks",
                raw_severity="secret",
                title=rule_id,
                description=description,
                file_path=file_path or None,
                line_start=line_start,
                line_end=line_end,
                evidence=leak.get("Match", ""),
                evidence_quality=EvidenceQuality.STRUCTURED,
                evidence_hash=evidence_hash,
                cwe="CWE-798",  # Hardcoded credentials
                location_fingerprint=location_fp,
                location_precision=precision,
                parser_version=self.version,
                parser_confidence=self.confidence_tier,
                discovered_at=datetime.now(timezone.utc),
            )
