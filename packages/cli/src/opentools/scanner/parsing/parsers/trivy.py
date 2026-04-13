"""Trivy JSON output parser."""

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


class TrivyParser:
    """Parses Trivy JSON output (schema v2 with Results array)."""

    name = "trivy"
    version = "1.0.0"
    confidence_tier = 0.9

    def validate(self, data: bytes) -> bool:
        """Check for Trivy JSON structure with ``Results`` key."""
        try:
            parsed = json.loads(data)
            return isinstance(parsed, dict) and "Results" in parsed
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        parsed = json.loads(data)
        results = parsed.get("Results", [])

        for result in results:
            target = result.get("Target", "")
            vulns = result.get("Vulnerabilities") or []

            for vuln in vulns:
                vuln_id = vuln.get("VulnerabilityID", "unknown")
                pkg_name = vuln.get("PkgName", "")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                severity = vuln.get("Severity", "UNKNOWN")
                title_raw = vuln.get("Title", vuln_id)
                description = vuln.get("Description", "")
                primary_url = vuln.get("PrimaryURL", "")

                # Extract CWE
                cwe_ids = vuln.get("CweIDs") or []
                cwe = cwe_ids[0] if cwe_ids else None

                title = f"{vuln_id}: {title_raw}" if title_raw != vuln_id else vuln_id

                evidence_str = f"{vuln_id}:{pkg_name}:{installed}:{target}"
                evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()
                location_fp = f"{target}:{pkg_name}:{installed}"

                desc_full = description
                if fixed:
                    desc_full += f" (fix: upgrade {pkg_name} to {fixed})"

                yield RawFinding(
                    id=str(uuid.uuid4()),
                    scan_task_id=scan_task_id,
                    scan_id=scan_id,
                    tool="trivy",
                    raw_severity=severity,
                    title=title,
                    description=desc_full,
                    file_path=target or None,
                    line_start=None,
                    line_end=None,
                    url=primary_url or None,
                    evidence=f"{pkg_name}@{installed}",
                    evidence_quality=EvidenceQuality.STRUCTURED,
                    evidence_hash=evidence_hash,
                    cwe=cwe,
                    location_fingerprint=location_fp,
                    location_precision=LocationPrecision.FILE,
                    parser_version=self.version,
                    parser_confidence=self.confidence_tier,
                    discovered_at=datetime.now(timezone.utc),
                )
