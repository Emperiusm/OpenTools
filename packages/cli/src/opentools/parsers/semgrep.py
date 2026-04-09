"""Parser for Semgrep JSON output."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from opentools.models import Finding, Severity


_SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.INFO,
}


def parse(raw_output: str) -> list[Finding]:
    """Parse Semgrep JSON output into Finding objects.

    Expected input format::

        {
            "results": [
                {
                    "check_id": "...",
                    "path": "...",
                    "start": {"line": N},
                    "end": {"line": N},
                    "extra": {
                        "message": "...",
                        "severity": "ERROR|WARNING|INFO",
                        "metadata": {"cwe": ["CWE-89"]}
                    }
                }
            ]
        }
    """
    data = json.loads(raw_output)
    findings: list[Finding] = []

    for result in data.get("results", []):
        extra = result.get("extra", {})
        raw_severity = extra.get("severity", "INFO").upper()
        severity = _SEVERITY_MAP.get(raw_severity, Severity.INFO)

        metadata = extra.get("metadata", {})
        cwe_list = metadata.get("cwe", [])
        cwe = cwe_list[0].split(":")[0].strip() if cwe_list else None

        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                engagement_id="",
                tool="semgrep",
                title=result.get("check_id", "semgrep finding"),
                description=extra.get("message"),
                severity=severity,
                cwe=cwe,
                file_path=result.get("path"),
                line_start=result.get("start", {}).get("line"),
                line_end=result.get("end", {}).get("line"),
                created_at=datetime.now(timezone.utc),
            )
        )

    return findings
