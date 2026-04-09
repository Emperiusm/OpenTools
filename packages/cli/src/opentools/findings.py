"""Finding deduplication, CWE inference, and export."""

from dataclasses import dataclass
from typing import Optional

from opentools.models import Finding, Confidence


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
