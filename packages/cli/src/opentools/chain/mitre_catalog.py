"""MITRE ATT&CK technique ID catalog with lazy loading.

Used to validate regex-extracted technique IDs. The catalog is a baked-in
subset of common ATT&CK techniques loaded from the official STIX bundle
(optionally, behind an env var gate) for cases where the regex matches
something that looks like a technique ID but isn't real.

The live STIX fetch is gated behind OPENTOOLS_MITRE_FETCH=1 to keep CI
offline-safe; by default the baked-in fallback set is used.
"""
from __future__ import annotations

import os
import re


_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_TACTIC_PATTERN = re.compile(r"^TA\d{4}$")


# Tactic IDs (TA0001..TA0043 are the official ATT&CK tactics).
_VALID_TACTICS: set[str] = {f"TA{n:04d}" for n in range(1, 44)}


# Baked-in fallback set — a curated subset of common ATT&CK enterprise
# techniques. Covers the case where the STIX fetch is disabled (default).
_FALLBACK_TECHNIQUES: set[str] = {
    # Initial Access
    "T1189", "T1190", "T1133", "T1200",
    "T1566", "T1566.001", "T1566.002", "T1566.003",
    "T1078", "T1078.001", "T1078.002", "T1078.003", "T1078.004",
    "T1091", "T1195", "T1199",
    # Execution
    "T1059", "T1059.001", "T1059.002", "T1059.003",
    "T1059.004", "T1059.005", "T1059.006",
    "T1053", "T1053.002", "T1053.003", "T1053.005", "T1053.006",
    "T1203", "T1106", "T1204", "T1204.001", "T1204.002",
    # Persistence
    "T1098", "T1197", "T1547", "T1547.001", "T1543", "T1543.003",
    # Privilege Escalation
    "T1068", "T1134", "T1548",
    # Defense Evasion
    "T1027", "T1070", "T1070.004",
    # Credential Access
    "T1003", "T1003.001", "T1003.002", "T1003.003",
    "T1003.004", "T1003.005", "T1003.006",
    "T1110", "T1110.001", "T1110.002", "T1110.003", "T1110.004",
    "T1555", "T1558", "T1558.003",
    # Discovery
    "T1018", "T1046", "T1057", "T1082", "T1083", "T1087",
    # Lateral Movement
    "T1021", "T1021.001", "T1021.002", "T1021.003",
    "T1021.004", "T1021.005", "T1021.006",
    "T1570",
    # Collection
    "T1005", "T1056", "T1113", "T1114",
    # Command and Control
    "T1071", "T1071.001", "T1071.002", "T1071.003", "T1071.004",
    "T1090", "T1090.001", "T1090.002", "T1090.003", "T1090.004",
    "T1095", "T1102", "T1105", "T1572",
    # Exfiltration
    "T1041", "T1048", "T1048.001", "T1048.002", "T1048.003",
    # Impact
    "T1485", "T1486", "T1490", "T1491", "T1496", "T1498", "T1499",
}


_catalog: set[str] | None = None


def _load_catalog() -> set[str]:
    """Return the authoritative ATT&CK enterprise technique set.

    Live STIX fetch is not implemented in 3C.1 — a future task can
    flesh out the live path. Gated behind OPENTOOLS_MITRE_FETCH=1 so
    the knob exists even though the current implementation always
    returns the fallback set.
    """
    if os.getenv("OPENTOOLS_MITRE_FETCH") == "1":
        # Live fetch placeholder; will be implemented in a future phase.
        # For now fall through to the baked-in set so behavior is stable.
        return _FALLBACK_TECHNIQUES
    return _FALLBACK_TECHNIQUES


def _get_catalog() -> set[str]:
    global _catalog
    if _catalog is None:
        _catalog = _load_catalog()
    return _catalog


def is_valid_technique(technique_id: str) -> bool:
    """Validate a technique or tactic ID string.

    Accepts:
    - Technique format: T1234 or T1234.567 (uppercase or lowercase)
    - Tactic format: TA0001 through TA0043

    Returns True only if the ID matches the format AND is present in
    the catalog (or is in the valid tactic range).
    """
    upper = technique_id.upper()
    if _TACTIC_PATTERN.match(upper):
        return upper in _VALID_TACTICS
    if not _TECHNIQUE_PATTERN.match(upper):
        return False
    return upper in _get_catalog()


def validate_technique_ids(candidates: list[str]) -> list[str]:
    """Filter a list of candidate IDs to those that are valid, uppercased."""
    return [c.upper() for c in candidates if is_valid_technique(c)]
