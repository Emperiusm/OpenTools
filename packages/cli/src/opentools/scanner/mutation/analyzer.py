"""OutputAnalyzer protocol and built-in analyzers for Nmap and Nuclei."""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Protocol, runtime_checkable

from opentools.scanner.mutation.models import (
    DiscoveredService,
    DiscoveredVuln,
    IntelBundle,
)


@runtime_checkable
class OutputAnalyzer(Protocol):
    """Protocol for extracting structured intel from raw tool stdout/stderr."""

    tool: str

    def analyze(self, stdout: str, stderr: str) -> IntelBundle:
        """Parse tool output and return structured intel."""
        ...


class NmapAnalyzer:
    """Parses nmap XML output (``-oX`` format) into an IntelBundle.

    Extracts open ports as DiscoveredService objects.  Closed/filtered ports
    are silently skipped.  Returns an empty IntelBundle on invalid XML or
    empty stdout.
    """

    tool: str = "nmap"

    def analyze(self, stdout: str, stderr: str) -> IntelBundle:
        if not stdout.strip():
            return IntelBundle()

        try:
            root = ET.fromstring(stdout)
        except ET.ParseError:
            return IntelBundle()

        if root.tag != "nmaprun":
            return IntelBundle()

        services: list[DiscoveredService] = []

        for host in root.findall("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port in ports_el.findall("port"):
                state_el = port.find("state")
                if state_el is None:
                    continue
                if state_el.get("state", "") != "open":
                    continue

                protocol = port.get("protocol", "tcp")
                portid_str = port.get("portid", "0")
                try:
                    portid = int(portid_str)
                except ValueError:
                    portid = 0

                service_el = port.find("service")
                service_name = ""
                product: str | None = None
                version: str | None = None
                if service_el is not None:
                    service_name = service_el.get("name", "")
                    raw_product = service_el.get("product", "")
                    product = raw_product if raw_product else None
                    raw_version = service_el.get("version", "")
                    version = raw_version if raw_version else None

                services.append(
                    DiscoveredService(
                        host=addr,
                        port=portid,
                        protocol=protocol,
                        service=service_name,
                        product=product,
                        version=version,
                    )
                )

        return IntelBundle(services=services)


class NucleiAnalyzer:
    """Parses nuclei JSON-lines output into an IntelBundle.

    Each line is expected to be a JSON object.  Invalid JSON lines are silently
    skipped.  Extracts DiscoveredVuln objects and collects ``matched-at`` URLs.
    """

    tool: str = "nuclei"

    def analyze(self, stdout: str, stderr: str) -> IntelBundle:
        if not stdout.strip():
            return IntelBundle()

        vulns: list[DiscoveredVuln] = []
        urls: list[str] = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = obj.get("template-id", "")
            host = obj.get("host", "")
            matched_at = obj.get("matched-at", "")

            # Port: prefer explicit "port" key, fall back to None
            raw_port = obj.get("port")
            port: int | None = None
            if raw_port is not None:
                try:
                    port = int(raw_port)
                except (ValueError, TypeError):
                    port = None

            info = obj.get("info", {})
            severity = info.get("severity", "unknown") if isinstance(info, dict) else "unknown"

            extracted_results = obj.get("extracted-results", [])
            extracted_data: dict = {}
            if extracted_results:
                extracted_data["extracted_results"] = extracted_results

            vulns.append(
                DiscoveredVuln(
                    host=host,
                    port=port,
                    template_id=template_id,
                    severity=severity,
                    matched_at=matched_at,
                    extracted_data=extracted_data,
                )
            )

            if matched_at:
                urls.append(matched_at)

        return IntelBundle(vulns=vulns, urls=urls)


class AnalyzerRegistry:
    """Simple registry mapping tool names to OutputAnalyzer instances."""

    def __init__(self) -> None:
        self._registry: dict[str, OutputAnalyzer] = {}

    def register(self, analyzer: OutputAnalyzer) -> None:
        """Register an analyzer, keyed by its ``tool`` attribute."""
        self._registry[analyzer.tool] = analyzer

    def get(self, tool: str) -> OutputAnalyzer | None:
        """Return the analyzer for *tool*, or None if not registered."""
        return self._registry.get(tool)

    def register_builtins(self) -> None:
        """Register the built-in NmapAnalyzer and NucleiAnalyzer."""
        self.register(NmapAnalyzer())
        self.register(NucleiAnalyzer())
