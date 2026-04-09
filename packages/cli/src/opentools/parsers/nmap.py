"""Parse nmap XML output into Finding models."""

import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from uuid import uuid4

from opentools.models import Finding, Severity


# NSE script ID → (CWE, severity) mapping
_NSE_VULN_MAP = {
    "ssl-heartbleed": ("CWE-119", Severity.CRITICAL),
    "ssl-poodle": ("CWE-327", Severity.HIGH),
    "ssl-ccs-injection": ("CWE-327", Severity.HIGH),
}

_NSE_PATTERN_MAP = {
    "ssl-enum-ciphers": ("CWE-327", Severity.MEDIUM),
    "http-vuln-": (None, Severity.HIGH),
    "smb-vuln-": (None, Severity.HIGH),
}


def parse(raw_output: str) -> list[Finding]:
    """Parse nmap XML output (-oX)."""
    findings = []
    if not raw_output.strip():
        return []

    try:
        root = ET.fromstring(raw_output)
    except ET.ParseError:
        return []

    now = datetime.now(timezone.utc)

    for host in root.findall(".//host"):
        addr_elem = host.find("address")
        addr = addr_elem.get("addr", "unknown") if addr_elem is not None else "unknown"

        for port in host.findall(".//port"):
            protocol = port.get("protocol", "tcp")
            portid = port.get("portid", "?")
            state_elem = port.find("state")
            state = state_elem.get("state", "") if state_elem is not None else ""

            if state != "open":
                continue

            service_elem = port.find("service")
            service_name = service_elem.get("name", "") if service_elem is not None else ""
            service_version = service_elem.get("version", "") if service_elem is not None else ""
            product = service_elem.get("product", "") if service_elem is not None else ""

            svc_desc = " ".join(filter(None, [product, service_name, service_version])).strip()

            # Port/service finding (informational)
            findings.append(Finding(
                id=str(uuid4()),
                engagement_id="",
                tool="nmap",
                title=f"Open port {portid}/{protocol}: {svc_desc or 'unknown service'}",
                severity=Severity.INFO,
                file_path=f"{addr}:{portid}",
                description=f"Host {addr} has {protocol}/{portid} open running {svc_desc}.",
                created_at=now,
            ))

            # NSE script findings
            for script in port.findall("script"):
                script_id = script.get("id", "")
                output = script.get("output", "")
                _parse_nse_script(findings, script_id, output, addr, portid, now)

    return findings


def _parse_nse_script(findings, script_id, output, addr, portid, now):
    """Parse an NSE script result into findings."""
    # Direct match
    if script_id in _NSE_VULN_MAP:
        cwe, severity = _NSE_VULN_MAP[script_id]
        findings.append(Finding(
            id=str(uuid4()), engagement_id="", tool="nmap",
            title=f"{script_id} on {addr}:{portid}",
            severity=severity, cwe=cwe,
            file_path=f"{addr}:{portid}",
            evidence=output[:1000],
            created_at=now,
        ))
        return

    # Pattern match
    for pattern, (cwe, severity) in _NSE_PATTERN_MAP.items():
        if script_id.startswith(pattern) or script_id == pattern.rstrip("-"):
            findings.append(Finding(
                id=str(uuid4()), engagement_id="", tool="nmap",
                title=f"{script_id} on {addr}:{portid}",
                severity=severity, cwe=cwe,
                file_path=f"{addr}:{portid}",
                evidence=output[:1000],
                created_at=now,
            ))
            return

    # Generic "VULNERABLE" detection in output
    if "VULNERABLE" in output.upper():
        findings.append(Finding(
            id=str(uuid4()), engagement_id="", tool="nmap",
            title=f"{script_id} on {addr}:{portid}",
            severity=Severity.MEDIUM,
            file_path=f"{addr}:{portid}",
            evidence=output[:1000],
            created_at=now,
        ))
