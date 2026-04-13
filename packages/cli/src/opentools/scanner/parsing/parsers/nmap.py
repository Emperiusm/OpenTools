"""Nmap XML output parser."""

from __future__ import annotations

import hashlib
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Iterator

from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)


class NmapParser:
    """Parses Nmap XML output (``-oX`` format) into RawFinding objects.

    Only reports open ports. Each open port becomes a finding with host-level
    location precision.
    """

    name = "nmap"
    version = "1.0.0"
    confidence_tier = 0.5

    def validate(self, data: bytes) -> bool:
        """Check that data is valid Nmap XML (has ``<nmaprun>`` root)."""
        try:
            root = ET.fromstring(data)
            return root.tag == "nmaprun"
        except ET.ParseError:
            return False

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        root = ET.fromstring(data)

        for host in root.findall("host"):
            # Get host address
            addr_el = host.find("address")
            addr = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

            # Get hostname if available
            hostname = None
            hostnames_el = host.find("hostnames")
            if hostnames_el is not None:
                hn_el = hostnames_el.find("hostname")
                if hn_el is not None:
                    hostname = hn_el.get("name")

            host_display = hostname or addr

            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port in ports_el.findall("port"):
                state_el = port.find("state")
                if state_el is None:
                    continue
                state = state_el.get("state", "")
                if state != "open":
                    continue

                protocol = port.get("protocol", "tcp")
                portid = port.get("portid", "0")

                service_el = port.find("service")
                service_name = ""
                product = ""
                version = ""
                if service_el is not None:
                    service_name = service_el.get("name", "")
                    product = service_el.get("product", "")
                    version = service_el.get("version", "")

                title = f"Open port {portid}/{protocol} ({service_name})"
                service_detail = f"{product} {version}".strip() if product else service_name
                description = (
                    f"Open port {portid}/{protocol} on {host_display}: "
                    f"{service_detail}"
                )

                evidence_str = f"nmap:{addr}:{protocol}:{portid}:{service_name}"
                evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()
                location_fp = f"{addr}:{portid}/{protocol}"

                yield RawFinding(
                    id=str(uuid.uuid4()),
                    scan_task_id=scan_task_id,
                    scan_id=scan_id,
                    tool="nmap",
                    raw_severity="info",
                    title=title,
                    description=description,
                    file_path=None,
                    line_start=None,
                    line_end=None,
                    url=None,
                    evidence=description,
                    evidence_quality=EvidenceQuality.HEURISTIC,
                    evidence_hash=evidence_hash,
                    cwe=None,
                    location_fingerprint=location_fp,
                    location_precision=LocationPrecision.HOST,
                    parser_version=self.version,
                    parser_confidence=self.confidence_tier,
                    discovered_at=datetime.now(timezone.utc),
                )
