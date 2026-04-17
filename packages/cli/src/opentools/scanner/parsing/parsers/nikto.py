"""Nikto JSON output parser."""

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


_HIGH_PATTERNS = (
    "default password",
    "default credential",
    "directory listing",
    "directory indexing",
    "remote code execution",
    "command injection",
)
_LOW_PATTERNS = (
    "server banner",
    "version disclosure",
    "x-powered-by",
    "server leaks",
)


def _classify_severity(msg: str) -> str:
    msg_lower = msg.lower()
    for pattern in _HIGH_PATTERNS:
        if pattern in msg_lower:
            return "high"
    for pattern in _LOW_PATTERNS:
        if pattern in msg_lower:
            return "low"
    return "medium"


class NiktoParser:
    """Parses Nikto JSON output (`-Format json`) into RawFindings.

    Each vulnerability entry becomes a finding with endpoint-level precision.
    Severity is heuristically assigned based on message patterns.
    """

    name = "nikto"
    version = "1.0.0"
    confidence_tier = 0.6

    def validate(self, data: bytes) -> bool:
        """Accept either a target-result dict or an array of them."""
        try:
            parsed = orjson.loads(data)
        except (orjson.JSONDecodeError, UnicodeDecodeError):
            return False
        if isinstance(parsed, dict) and "vulnerabilities" in parsed:
            return True
        if isinstance(parsed, list):
            return any(
                isinstance(item, dict) and "vulnerabilities" in item
                for item in parsed
            )
        return False

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        try:
            parsed = orjson.loads(data)
        except orjson.JSONDecodeError:
            return

        # Normalize to a list of target-result dicts.
        if isinstance(parsed, dict):
            targets = [parsed]
        elif isinstance(parsed, list):
            targets = [t for t in parsed if isinstance(t, dict)]
        else:
            return

        for target_result in targets:
            yield from self._parse_target(target_result, scan_id, scan_task_id)

    def _parse_target(
        self,
        parsed: dict,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        host = parsed.get("host") or parsed.get("ip") or "unknown"
        port = str(parsed.get("port", "") or "")

        for vuln in parsed.get("vulnerabilities", []) or []:
            if not isinstance(vuln, dict):
                continue
            msg = vuln.get("msg", "Unknown finding") or "Unknown finding"
            url = vuln.get("url", "/") or "/"
            method = vuln.get("method", "GET") or "GET"
            nikto_id = str(vuln.get("id", "") or "")
            osvdb = str(vuln.get("OSVDB", "") or "")

            location_url = f"{host}:{port}{url}" if port else f"{host}{url}"
            evidence_str = f"nikto:{nikto_id}:{location_url}:{msg}"
            evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()

            yield RawFinding(
                id=str(uuid.uuid4()),
                scan_task_id=scan_task_id,
                scan_id=scan_id,
                tool="nikto",
                raw_severity=_classify_severity(msg),
                title=msg,
                description=msg,
                file_path=None,
                url=location_url,
                evidence=f"Method: {method}, Nikto ID: {nikto_id}" + (f", OSVDB: {osvdb}" if osvdb else ""),
                evidence_quality=EvidenceQuality.PATTERN,
                evidence_hash=evidence_hash,
                cwe=None,
                location_fingerprint=location_url,
                location_precision=LocationPrecision.ENDPOINT,
                parser_version=self.version,
                parser_confidence=self.confidence_tier,
                discovered_at=datetime.now(timezone.utc),
            )
