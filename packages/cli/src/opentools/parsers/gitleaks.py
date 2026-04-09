"""Parser for Gitleaks JSON output."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from opentools.models import Finding, Severity


def parse(raw_output: str) -> list[Finding]:
    """Parse Gitleaks JSON array output into Finding objects.

    All gitleaks findings are classified as CWE-798 (hardcoded credentials)
    with severity=high.

    Expected input format::

        [
            {
                "Description": "...",
                "File": "...",
                "StartLine": N,
                "EndLine": N,
                "Secret": "...",
                "RuleID": "..."
            }
        ]
    """
    data = json.loads(raw_output)
    findings: list[Finding] = []

    for leak in data:
        rule_id = leak.get("RuleID", "unknown-rule")
        description = leak.get("Description", "Hardcoded secret detected")
        secret = leak.get("Secret", "")

        evidence = f"Secret: {secret}" if secret else None

        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                engagement_id="",
                tool="gitleaks",
                title=f"{description} [{rule_id}]",
                description=description,
                severity=Severity.HIGH,
                cwe="CWE-798",
                file_path=leak.get("File"),
                line_start=leak.get("StartLine"),
                line_end=leak.get("EndLine"),
                evidence=evidence,
                created_at=datetime.now(timezone.utc),
            )
        )

    return findings
