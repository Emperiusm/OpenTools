"""Parser-aware entity extractors.

These extractors consume structured parser output stored in the
``finding_parser_output`` table. They do not re-parse tool output —
the parser has already done that. Each extractor reads a dict and
emits ExtractedEntity rows with confidence 1.0 (structured data is
authoritative) and ``field = MentionField.EVIDENCE``. Missing keys
and malformed values are silently skipped.
"""
from __future__ import annotations

from urllib.parse import urljoin

from opentools.chain.extractors.base import ExtractedEntity, ExtractionContext
from opentools.chain.types import MentionField
from opentools.models import Finding


_EVIDENCE = MentionField.EVIDENCE
_CONFIDENCE = 1.0


def _make(entity_type: str, value: str, extractor: str) -> ExtractedEntity:
    return ExtractedEntity(
        type=entity_type,
        value=value,
        field=_EVIDENCE,
        offset_start=None,
        offset_end=None,
        extractor=extractor,
        confidence=_CONFIDENCE,
    )


class NmapEntityExtractor:
    """Extract hosts and ports from Nmap structured output."""

    tool_name = "nmap"

    def extract(
        self,
        finding: Finding,
        parser_output: dict,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        for host in parser_output.get("hosts") or []:
            if not isinstance(host, dict):
                continue
            addr = host.get("addr")
            if isinstance(addr, str) and addr:
                out.append(_make("ip", addr, "nmap_parser"))
            for port in host.get("ports") or []:
                if not isinstance(port, dict):
                    continue
                number = port.get("number")
                if isinstance(number, int):
                    out.append(_make("port", str(number), "nmap_parser"))
                elif isinstance(number, str) and number.isdigit():
                    out.append(_make("port", number, "nmap_parser"))
        return out


class NiktoEntityExtractor:
    """Extract target URL and per-item URLs from Nikto structured output."""

    tool_name = "nikto"

    def extract(
        self,
        finding: Finding,
        parser_output: dict,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        target = parser_output.get("target")
        if isinstance(target, str) and target:
            out.append(_make("url", target, "nikto_parser"))
            for item in parser_output.get("items") or []:
                if not isinstance(item, dict):
                    continue
                uri = item.get("uri")
                if isinstance(uri, str) and uri:
                    full = urljoin(target.rstrip("/") + "/", uri.lstrip("/"))
                    out.append(_make("url", full, "nikto_parser"))
        return out


class BurpEntityExtractor:
    """Extract issue URLs from Burp structured output.

    Note: Burp issues may include CWE references. We intentionally do not
    emit CWE values as entities here because the chain entity layer does not
    distinguish CWE from CVE, and conflating them would produce misleading
    data. Only the URL per issue is emitted.
    """

    tool_name = "burp"

    def extract(
        self,
        finding: Finding,
        parser_output: dict,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        for issue in parser_output.get("issues") or []:
            if not isinstance(issue, dict):
                continue
            url = issue.get("url")
            if isinstance(url, str) and url:
                out.append(_make("url", url, "burp_parser"))
        return out


class NucleiEntityExtractor:
    """Extract matched URLs and hosts from Nuclei structured output."""

    tool_name = "nuclei"

    def extract(
        self,
        finding: Finding,
        parser_output: dict,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        for item in parser_output.get("findings") or []:
            if not isinstance(item, dict):
                continue
            matched = item.get("matched_at")
            if isinstance(matched, str) and matched:
                out.append(_make("url", matched, "nuclei_parser"))
            host = item.get("host")
            if isinstance(host, str) and host:
                out.append(_make("host", host, "nuclei_parser"))
        return out


class SemgrepEntityExtractor:
    """Extract source file paths from Semgrep structured output."""

    tool_name = "semgrep"

    def extract(
        self,
        finding: Finding,
        parser_output: dict,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        for result in parser_output.get("results") or []:
            if not isinstance(result, dict):
                continue
            path = result.get("path")
            if isinstance(path, str) and path:
                out.append(_make("file_path", path, "semgrep_parser"))
        return out


BUILTIN_PARSER_EXTRACTORS: list = [
    NmapEntityExtractor(),
    NiktoEntityExtractor(),
    BurpEntityExtractor(),
    NucleiEntityExtractor(),
    SemgrepEntityExtractor(),
]
