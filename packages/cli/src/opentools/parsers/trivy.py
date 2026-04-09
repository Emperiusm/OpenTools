"""Parser for Trivy JSON output."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from opentools.models import Finding, Severity


_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


def parse(raw_output: str) -> list[Finding]:
    """Parse Trivy JSON output into Finding objects.

    Expected input format::

        {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-...",
                            "PkgName": "...",
                            "Severity": "CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN",
                            "Title": "...",
                            "Description": "..."
                        }
                    ]
                }
            ]
        }
    """
    data = json.loads(raw_output)
    findings: list[Finding] = []

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            raw_severity = vuln.get("Severity", "UNKNOWN").upper()
            severity = _SEVERITY_MAP.get(raw_severity, Severity.INFO)

            vuln_id = vuln.get("VulnerabilityID", "")
            pkg_name = vuln.get("PkgName", "")
            title = vuln.get("Title") or f"{vuln_id} in {pkg_name}"

            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    engagement_id="",
                    tool="trivy",
                    title=title,
                    description=vuln.get("Description"),
                    severity=severity,
                    cwe=None,
                    created_at=datetime.now(timezone.utc),
                )
            )

    return findings
