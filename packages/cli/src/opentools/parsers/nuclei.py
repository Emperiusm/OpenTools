"""Parser for Nuclei JSONL output."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from opentools.models import Finding, Severity


_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def parse(raw_output: str) -> list[Finding]:
    """Parse Nuclei JSONL output (one JSON object per line) into Finding objects.

    Expected input format (one JSON per line)::

        {
            "template-id": "...",
            "info": {
                "name": "...",
                "severity": "critical|high|medium|low|info",
                "classification": {"cwe-id": ["CWE-89"]}
            },
            "matched-at": "...",
            "host": "..."
        }
    """
    findings: list[Finding] = []

    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue

        result = json.loads(line)
        info = result.get("info", {})
        raw_severity = info.get("severity", "info").lower()
        severity = _SEVERITY_MAP.get(raw_severity, Severity.INFO)

        classification = info.get("classification", {})
        cwe_list = classification.get("cwe-id", [])
        cwe = cwe_list[0].split(":")[0].strip() if cwe_list else None

        matched_at = result.get("matched-at", "")
        host = result.get("host", "")
        description = f"Matched at: {matched_at}" if matched_at else None

        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                engagement_id="",
                tool="nuclei",
                title=info.get("name", result.get("template-id", "nuclei finding")),
                description=description,
                severity=severity,
                cwe=cwe,
                file_path=host or None,
                created_at=datetime.now(timezone.utc),
            )
        )

    return findings
