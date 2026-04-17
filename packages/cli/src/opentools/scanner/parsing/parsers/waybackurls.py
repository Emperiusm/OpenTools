"""Waybackurls plain-text URL list parser.

Waybackurls outputs one URL per line. Each URL becomes an informational
RawFinding representing a historically-known endpoint worth probing
further in subsequent scans. Deduplicated on URL.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Iterator

from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)


class WaybackurlsParser:
    name = "waybackurls"
    version = "1.0.0"
    confidence_tier = 0.4

    def validate(self, data: bytes) -> bool:
        """Any non-empty input with at least one URL-shaped line."""
        if not data.strip():
            return False
        for raw_line in data.splitlines():
            line = raw_line.strip()
            if line.startswith(b"http://") or line.startswith(b"https://"):
                return True
        return False

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        seen: set[str] = set()
        for raw_line in data.splitlines():
            try:
                url = raw_line.decode("utf-8", errors="replace").strip()
            except Exception:
                continue
            if not url or not (url.startswith("http://") or url.startswith("https://")):
                continue
            if url in seen:
                continue
            seen.add(url)

            evidence_hash = hashlib.sha256(f"waybackurls:{url}".encode()).hexdigest()

            yield RawFinding(
                id=str(uuid.uuid4()),
                scan_task_id=scan_task_id,
                scan_id=scan_id,
                tool="waybackurls",
                raw_severity="info",
                title=f"Historical URL: {url[:80]}",
                description=f"Discovered via Wayback Machine archives: {url}",
                file_path=None,
                url=url,
                evidence=url,
                evidence_quality=EvidenceQuality.HEURISTIC,
                evidence_hash=evidence_hash,
                cwe=None,
                location_fingerprint=url,
                location_precision=LocationPrecision.ENDPOINT,
                parser_version=self.version,
                parser_confidence=self.confidence_tier,
                discovered_at=datetime.now(timezone.utc),
            )
