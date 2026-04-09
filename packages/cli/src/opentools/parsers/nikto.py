"""Parse Nikto JSON output into Finding models."""

import json
from datetime import datetime, timezone
from uuid import uuid4

from opentools.models import Finding, Severity

_HIGH_PATTERNS = ["default password", "default credential", "directory listing", "directory indexing"]
_LOW_PATTERNS = ["server banner", "version disclosure", "x-powered-by"]


def _classify_severity(msg: str) -> Severity:
    msg_lower = msg.lower()
    for pattern in _HIGH_PATTERNS:
        if pattern in msg_lower:
            return Severity.HIGH
    for pattern in _LOW_PATTERNS:
        if pattern in msg_lower:
            return Severity.LOW
    return Severity.MEDIUM


def parse(raw_output: str) -> list[Finding]:
    """Parse Nikto JSON output."""
    findings = []
    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
        return []

    now = datetime.now(timezone.utc)
    host = data.get("ip", data.get("host", "unknown"))
    port = data.get("port", "")

    for vuln in data.get("vulnerabilities", []):
        if not isinstance(vuln, dict):
            continue
        msg = vuln.get("msg", "Unknown finding")
        url = vuln.get("url", "/")
        method = vuln.get("method", "GET")
        nikto_id = vuln.get("id", "")
        osvdb = vuln.get("OSVDB", "")

        findings.append(Finding(
            id=str(uuid4()),
            engagement_id="",
            tool="nikto",
            title=msg,
            severity=_classify_severity(msg),
            file_path=f"{host}:{port}{url}" if port else f"{host}{url}",
            evidence=f"Method: {method}, Nikto ID: {nikto_id}, OSVDB: {osvdb}",
            description=msg,
            created_at=now,
        ))
    return findings
