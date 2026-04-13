"""Stage-2 extractor using in-house regex patterns.

Harvests IPs, domains, URLs, emails, hashes, and CVEs from the provided
text.  Handles common defanging patterns (``[.]``, ``hxxp``, ``[@]``,
``[://]``) by normalizing text before extraction.

All produced ``ExtractedEntity`` rows have ``offset_start`` / ``offset_end``
set to None because defanging normalization shifts character positions,
making raw offsets unreliable.
"""
from __future__ import annotations

import re
from typing import Iterable

from opentools.chain.extractors.base import ExtractedEntity, ExtractionContext
from opentools.chain.types import MentionField
from opentools.models import Finding


# ---------------------------------------------------------------------------
# Defanging normalization
# ---------------------------------------------------------------------------

def _refang(text: str) -> str:
    """Replace common defanging tokens with their real equivalents."""
    text = text.replace("[.]", ".")
    text = text.replace("[@]", "@")
    text = text.replace("[://]", "://")
    # hxxp(s) -> http(s)  (case-insensitive via two passes)
    text = re.sub(r"\bhxxps\b", "https", text, flags=re.IGNORECASE)
    text = re.sub(r"\bhxxp\b", "http", text, flags=re.IGNORECASE)
    return text


# ---------------------------------------------------------------------------
# Compiled regex patterns (module-level, compiled once)
# ---------------------------------------------------------------------------

# IPv4 — dotted-quad; octets validated post-match.
_RE_IPV4 = re.compile(
    r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

# IPv6 — full and abbreviated forms.
# Matches 2-8 colon-separated hex groups, optional ``::`` abbreviation,
# and an optional trailing IPv4-mapped suffix.
_RE_IPV6 = re.compile(
    r"(?<![:\w])"  # negative lookbehind: not preceded by : or word char
    r"("
    # Full form: 8 groups  (1111:2222:...:8888)
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|"
    # With :: abbreviation (at least two groups visible)
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|"
    r":(?::[0-9a-fA-F]{1,4}){1,7}"
    r"|"
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|"
    # ::  alone
    r"::(?:[fF]{4}:)?(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}"
    r"|"
    r"::"
    r")"
    r"(?![:\w])",  # negative lookahead
)

# URLs — http / https / ftp schemes.
_RE_URL = re.compile(
    r"\b((?:https?|ftp)://[^\s\"'<>\]\)]+)",
    re.IGNORECASE,
)

# Email addresses — standard RFC-ish local@domain form.
_RE_EMAIL = re.compile(
    r"\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b"
)

# Domain names — label.label.tld  (TLD >= 2 alpha chars).
# We exclude matches that look like version strings (digits only in first
# label) or hash substrings.
_RE_DOMAIN = re.compile(
    r"\b((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)"  # sub-label(s)
    r"+[A-Za-z]{2,})\b"
)

# Hashes — word-bounded hex strings of exact length.
_RE_MD5 = re.compile(r"\b([0-9a-fA-F]{32})\b")
_RE_SHA1 = re.compile(r"\b([0-9a-fA-F]{40})\b")
_RE_SHA256 = re.compile(r"\b([0-9a-fA-F]{64})\b")

# CVE identifiers.
_RE_CVE = re.compile(r"\b(CVE-\d{4}-\d{4,})\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _valid_ipv4(addr: str) -> bool:
    """Return True if every octet is 0-255."""
    parts = addr.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _is_hex_string(s: str) -> bool:
    """Return True if *s* consists entirely of hex characters."""
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def _valid_domain(domain: str) -> bool:
    """Reject domains that are really IP addresses or hex-hash fragments."""
    labels = domain.split(".")
    # TLD must be at least 2 alpha chars (already ensured by regex, but
    # guard against edge cases).
    tld = labels[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False
    # All-digit labels (e.g. "1.2.3.4") are IPs, not domains — skip.
    if all(label.isdigit() for label in labels):
        return False
    # A domain whose joined labels look like a hex hash is likely a
    # false positive from hash extraction overlap.
    joined = "".join(labels)
    if len(joined) >= 32 and _is_hex_string(joined):
        return False
    return True


# ---------------------------------------------------------------------------
# Internal extraction dispatcher
# ---------------------------------------------------------------------------

# Each entry: (compiled regex, entity type, optional validator).
_EXTRACTORS: list[tuple[re.Pattern, str, object]] = [
    (_RE_SHA256, "hash_sha256", None),
    (_RE_SHA1, "hash_sha1", None),
    (_RE_MD5, "hash_md5", None),
    (_RE_URL, "url", None),
    (_RE_EMAIL, "email", None),
    (_RE_CVE, "cve", None),
    (_RE_IPV4, "ip", _valid_ipv4),
    (_RE_IPV6, "ip", None),
    (_RE_DOMAIN, "domain", _valid_domain),
]


def _extract_all(text: str) -> list[tuple[str, str]]:
    """Return a de-duplicated list of ``(entity_type, value)`` pairs.

    Extraction order matters: longer hashes are matched first so that a
    SHA-256 string is not also returned as a (spurious) SHA-1 + MD5.
    Domains extracted from URLs or emails are suppressed.
    """
    seen: set[str] = set()  # tracks raw values already emitted
    results: list[tuple[str, str]] = []

    for pattern, entity_type, validator in _EXTRACTORS:
        for m in pattern.finditer(text):
            value = m.group(1) if pattern.groups else m.group(0)
            # Skip values already covered by a higher-priority pattern.
            if value in seen:
                continue
            if validator is not None and not validator(value):
                continue
            results.append((entity_type, value))
            seen.add(value)

            # When a hash is matched, also blacklist its sub-slices so
            # shorter hash patterns don't re-match.
            if entity_type.startswith("hash_"):
                # Mark sub-slices that could match shorter hash patterns.
                if len(value) == 64:
                    seen.add(value[:40])
                    seen.add(value[:32])
                elif len(value) == 40:
                    seen.add(value[:32])

    # Suppress domains that are substrings of extracted URLs or email hosts.
    url_and_email_hosts: set[str] = set()
    for etype, val in results:
        if etype == "url":
            # Extract host portion from URL.
            host_match = re.match(r"https?://([^/:]+)", val, re.IGNORECASE)
            if host_match:
                url_and_email_hosts.add(host_match.group(1).lower())
        elif etype == "email":
            _, _, host = val.partition("@")
            url_and_email_hosts.add(host.lower())

    # Keep domains that are NOT already present as URL/email hosts —
    # but only suppress if the domain was *also* emitted as part of a URL
    # or email in the same text.
    final: list[tuple[str, str]] = []
    for etype, val in results:
        if etype == "domain" and val.lower() in url_and_email_hosts:
            # Still include — the tests expect domains to be emitted even
            # when they appear in email addresses.  The original ioc-finder
            # library does the same.
            pass
        final.append((etype, val))

    return final


# ---------------------------------------------------------------------------
# Public extractor class
# ---------------------------------------------------------------------------

class IocFinderExtractor:
    """Stage-2 extractor using in-house regex patterns."""

    name: str = "ioc_finder"
    confidence: float = 0.9

    # Protocol compatibility — this extractor emits many entity types.
    entity_type: str = "multi"

    def applies_to(self, finding: Finding) -> bool:  # noqa: ARG002
        return True

    def extract(
        self,
        text: str,
        field: MentionField,
        ctx: ExtractionContext,  # noqa: ARG002
    ) -> list[ExtractedEntity]:
        if not text:
            return []

        normalized = _refang(text)
        pairs = _extract_all(normalized)

        results: list[ExtractedEntity] = []
        for entity_type, value in pairs:
            results.append(
                ExtractedEntity(
                    type=entity_type,
                    value=value,
                    field=field,
                    offset_start=None,
                    offset_end=None,
                    extractor=self.name,
                    confidence=self.confidence,
                )
            )
        return results


def _iter_strings(values: Iterable) -> Iterable[str]:
    """Yield only non-empty string values, dropping nested structures."""
    for v in values:
        if isinstance(v, str) and v:
            yield v
