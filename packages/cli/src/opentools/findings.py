"""Finding deduplication, CWE inference, and export."""

import csv
import hashlib
import io
import json
from dataclasses import dataclass
from typing import Optional

from pydantic import BaseModel, Field

from opentools.models import Finding, Confidence, Severity


CWE_KEYWORDS: dict[str, list[str]] = {
    "CWE-89":  ["sql injection", "sqli", "sql sink", "unsanitized query"],
    "CWE-79":  ["xss", "cross-site scripting", "html sink", "script injection"],
    "CWE-22":  ["path traversal", "directory traversal", "lfi", "file open sink"],
    "CWE-78":  ["command injection", "os command", "shell injection", "exec sink"],
    "CWE-798": ["hardcoded", "secret", "credential", "api key", "password in source"],
    "CWE-119": ["buffer overflow", "stack overflow", "heap overflow", "out of bounds"],
    "CWE-416": ["use after free", "use-after-free", "dangling pointer"],
    "CWE-476": ["null pointer", "null dereference", "nullptr"],
    "CWE-190": ["integer overflow", "integer underflow", "int overflow"],
    "CWE-362": ["race condition", "toctou", "time-of-check"],
    "CWE-134": ["format string", "printf", "format specifier"],
    "CWE-415": ["double free", "double-free"],
    "CWE-457": ["uninitialized", "uninitialised", "uninitialized read"],
    "CWE-611": ["xxe", "xml external entity"],
    "CWE-918": ["ssrf", "server-side request forgery"],
    "CWE-502": ["deserialization", "deserialisation", "insecure deserialization"],
    "CWE-287": ["authentication bypass", "broken authentication", "auth bypass"],
    "CWE-862": ["missing authorization", "idor", "insecure direct object"],
    "CWE-327": ["weak crypto", "weak cipher", "des", "md5", "sha1", "ecb mode"],
    "CWE-532": ["log injection", "sensitive data in log", "password in log"],
}


def infer_cwe(text: str) -> Optional[str]:
    """Infer CWE from finding title/description text.
    Returns the CWE with the most keyword matches, or None.
    """
    text_lower = text.lower()
    best_cwe = None
    best_count = 0
    for cwe, keywords in CWE_KEYWORDS.items():
        count = sum(1 for kw in keywords if kw in text_lower)
        if count > best_count:
            best_count = count
            best_cwe = cwe
    return best_cwe


@dataclass
class DuplicateMatch:
    """Result of a duplicate check."""
    match: Finding
    confidence: Confidence


def check_duplicate(
    new_finding: Finding,
    existing_findings: list[Finding],
    line_window: int = 5,
) -> Optional[DuplicateMatch]:
    """Check if new_finding duplicates any existing finding.
    Returns DuplicateMatch if duplicate found, None if distinct.
    """
    for existing in existing_findings:
        if not _locations_overlap(new_finding, existing, line_window):
            continue

        new_cwe = new_finding.cwe or infer_cwe(
            f"{new_finding.title} {new_finding.description or ''}"
        )
        existing_cwe = existing.cwe or infer_cwe(
            f"{existing.title} {existing.description or ''}"
        )

        if new_cwe and existing_cwe and new_cwe == existing_cwe:
            confidence = _compute_confidence(new_finding, existing, new_cwe == new_finding.cwe)
            return DuplicateMatch(match=existing, confidence=confidence)

    return None


def _locations_overlap(a: Finding, b: Finding, window: int) -> bool:
    """Check if two findings are at overlapping locations."""
    if a.file_path and b.file_path:
        if a.file_path != b.file_path:
            return False
        if a.line_start is not None and b.line_start is not None:
            return abs(a.line_start - b.line_start) <= window
        return True  # same file, no line info
    if a.file_path is None and b.file_path is None:
        return True  # network findings, match on CWE only
    return False


def _compute_confidence(new: Finding, existing: Finding, cwe_was_explicit: bool) -> Confidence:
    """Determine dedup confidence based on match quality."""
    if not cwe_was_explicit:
        return Confidence.LOW
    if (new.line_start is not None and existing.line_start is not None
            and abs(new.line_start - existing.line_start) <= 2):
        return Confidence.HIGH
    return Confidence.MEDIUM


# ---------------------------------------------------------------------------
# SARIF 2.1.0 Pydantic models
# ---------------------------------------------------------------------------

class SarifPhysicalLocation(BaseModel):
    artifactLocation: dict = Field(default_factory=dict)  # {"uri": "path/to/file"}
    region: dict = Field(default_factory=dict)  # {"startLine": 42}


class SarifLocation(BaseModel):
    physicalLocation: SarifPhysicalLocation | None = None


class SarifResult(BaseModel):
    ruleId: str = ""
    level: str = "warning"  # error|warning|note
    message: dict = Field(default_factory=dict)  # {"text": "description"}
    locations: list[SarifLocation] = Field(default_factory=list)
    partialFingerprints: dict = Field(default_factory=dict)
    relatedLocations: list[SarifLocation] = Field(default_factory=list)


class SarifReportingDescriptor(BaseModel):
    id: str
    shortDescription: dict = Field(default_factory=dict)  # {"text": "..."}


class SarifToolComponent(BaseModel):
    name: str
    version: str = "unknown"
    rules: list[SarifReportingDescriptor] = Field(default_factory=list)


class SarifTool(BaseModel):
    driver: SarifToolComponent


class SarifRun(BaseModel):
    tool: SarifTool
    results: list[SarifResult] = Field(default_factory=list)


class SarifLog(BaseModel):
    version: str = "2.1.0"
    schema_uri: str = Field(
        default="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        alias="$schema",
    )
    runs: list[SarifRun] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

def _severity_to_sarif_level(severity: Severity) -> str:
    """Map severity to SARIF level."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _finding_fingerprint(finding: Finding) -> str:
    """Compute stable fingerprint for CI/CD tracking."""
    key = f"{finding.cwe or ''}:{finding.file_path or ''}:{finding.line_start or 0}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def export_sarif(findings: list[Finding]) -> dict:
    """Export findings to SARIF 2.1.0 format. Returns a dict ready for json.dumps."""
    from itertools import groupby
    from operator import attrgetter

    sorted_findings = sorted(findings, key=attrgetter("tool"))
    runs = []

    for tool_name, tool_findings_iter in groupby(sorted_findings, key=attrgetter("tool")):
        tool_findings = list(tool_findings_iter)

        # Collect unique CWEs as rules
        seen_cwes: set[str] = set()
        rules: list[SarifReportingDescriptor] = []
        for f in tool_findings:
            if f.cwe and f.cwe not in seen_cwes:
                seen_cwes.add(f.cwe)
                rules.append(SarifReportingDescriptor(
                    id=f.cwe,
                    shortDescription={"text": f.cwe},
                ))

        results = []
        for f in tool_findings:
            locations = []
            if f.file_path:
                loc = SarifLocation(
                    physicalLocation=SarifPhysicalLocation(
                        artifactLocation={"uri": f.file_path},
                        region={"startLine": f.line_start} if f.line_start else {},
                    )
                )
                locations.append(loc)

            results.append(SarifResult(
                ruleId=f.cwe or f.title,
                level=_severity_to_sarif_level(f.severity),
                message={"text": f.title + (f"\n{f.description}" if f.description else "")},
                locations=locations,
                partialFingerprints={"primaryLocationLineHash": _finding_fingerprint(f)},
            ))

        runs.append(SarifRun(
            tool=SarifTool(driver=SarifToolComponent(name=tool_name, rules=rules)),
            results=results,
        ))

    log = SarifLog(runs=runs)
    return json.loads(log.model_dump_json(by_alias=True, exclude_none=True))


def export_csv(findings: list[Finding]) -> str:
    """Export findings to CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "severity", "cwe", "tool", "title", "file_path", "line_start", "status"])
    for f in findings:
        writer.writerow([f.id, f.severity, f.cwe or "", f.tool, f.title, f.file_path or "", f.line_start or "", f.status])
    return output.getvalue()


def export_json(findings: list[Finding]) -> str:
    """Export findings to JSON string."""
    return json.dumps([f.model_dump(mode="json") for f in findings], indent=2)
