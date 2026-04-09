"""Parse SQLmap JSON output into Finding models."""

import json
from datetime import datetime, timezone
from uuid import uuid4

from opentools.models import Finding, Severity


def parse(raw_output: str) -> list[Finding]:
    """Parse SQLmap API JSON output."""
    findings = []
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return []

    now = datetime.now(timezone.utc)
    for entry in data.get("data", []):
        for injection in entry.get("value", []):
            if not isinstance(injection, dict):
                continue
            param = injection.get("parameter", "unknown")
            technique = injection.get("title", "unknown technique")
            dbms = injection.get("dbms", "unknown")
            place = injection.get("place", "")

            findings.append(Finding(
                id=str(uuid4()),
                engagement_id="",
                tool="sqlmap",
                title=f"SQL Injection ({technique}) in {param}",
                severity=Severity.CRITICAL,
                cwe="CWE-89",
                description=f"Confirmed SQL injection via {place} parameter '{param}'. DBMS: {dbms}. Technique: {technique}.",
                evidence=f"Parameter: {param}, Place: {place}, DBMS: {dbms}, Technique: {technique}",
                created_at=now,
            ))
    return findings
