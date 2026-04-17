"""Nuclei JSONL output parser."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Iterator

import orjson

from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)


class NucleiParser:
    """Parses Nuclei JSONL output (one JSON object per line) into RawFindings.

    Each matched template becomes a finding with URL-level location precision.
    Severity is mapped directly from Nuclei's severity field.
    """

    name = "nuclei"
    version = "1.0.0"
    confidence_tier = 0.8

    def validate(self, data: bytes) -> bool:
        """At least one non-empty line must parse as a JSON object with 'info'."""
        if not data.strip():
            return False
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = orjson.loads(line)
                if isinstance(obj, dict) and "info" in obj:
                    return True
            except orjson.JSONDecodeError:
                continue
        return False

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        for line in data.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                result = orjson.loads(line)
            except orjson.JSONDecodeError:
                continue
            if not isinstance(result, dict):
                continue

            info = result.get("info", {}) or {}
            template_id = result.get("template-id", "unknown")
            severity = str(info.get("severity", "info")).lower()
            matched_at = result.get("matched-at", "") or result.get("host", "")
            host = result.get("host", "")

            # CWE: may be a list under classification.cwe-id
            cwe = None
            classification = info.get("classification", {}) or {}
            cwe_list = classification.get("cwe-id") or []
            if isinstance(cwe_list, list) and cwe_list:
                cwe = str(cwe_list[0]).upper()
                if not cwe.startswith("CWE-"):
                    cwe = f"CWE-{cwe.lstrip('cweCWE-:')}"

            title = info.get("name") or template_id
            description_parts = []
            if info.get("description"):
                description_parts.append(str(info["description"]).strip())
            if matched_at:
                description_parts.append(f"Matched at: {matched_at}")
            description = "\n".join(description_parts) if description_parts else None

            evidence_str = f"nuclei:{template_id}:{matched_at}"
            evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()
            location_fp = matched_at or host or template_id

            yield RawFinding(
                id=str(uuid.uuid4()),
                scan_task_id=scan_task_id,
                scan_id=scan_id,
                tool="nuclei",
                raw_severity=severity,
                title=title,
                description=description,
                file_path=None,
                line_start=None,
                line_end=None,
                url=matched_at or host or None,
                evidence=str(result.get("matcher-name", "")) or matched_at or None,
                evidence_quality=EvidenceQuality.STRUCTURED,
                evidence_hash=evidence_hash,
                cwe=cwe,
                location_fingerprint=location_fp,
                location_precision=LocationPrecision.ENDPOINT,
                parser_version=self.version,
                parser_confidence=self.confidence_tier,
                discovered_at=datetime.now(timezone.utc),
            )
