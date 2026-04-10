"""Static stopwords used by the linker to skip meaningless shared-entity signal.

Extractors still extract these values (for provenance). The linker ignores them
as linking evidence via the frequency cap / stopword filter.
"""
from __future__ import annotations


STATIC_STOPWORDS: dict[str, set[str]] = {
    "host": {"localhost"},
    "ip": {"127.0.0.1", "::1", "0.0.0.0"},
    "user": {"root", "admin", "administrator", "system", "nobody"},
    "file_path": {"/tmp", "c:\\windows", "c:\\windows\\system32"},
    "port": {"80", "443", "22"},
    "domain": {"localhost"},
    "registered_domain": {"localhost"},
}


def is_stopword(
    entity_type: str,
    canonical_value: str,
    *,
    extras: list[str] | None = None,
) -> bool:
    """Return True if the canonical value is a stopword for its type."""
    if canonical_value in STATIC_STOPWORDS.get(entity_type, set()):
        return True
    if extras:
        needle = f"{entity_type}:{canonical_value}"
        for e in extras:
            if e == needle:
                return True
    return False
