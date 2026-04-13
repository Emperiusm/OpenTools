"""STIX 2.1 export module for OpenTools.

Converts IOC lists into a fully-validated STIX 2.1 Bundle containing
Indicator, Malware, Infrastructure, Relationship, Identity, and Report objects.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import orjson

from opentools.models import (
    Confidence,
    Engagement,
    Finding,
    IOC,
    IOCType,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OPENTOOLS_NAMESPACE = uuid.UUID("f47ac10b-58cc-4372-a567-0e02b2c3d479")

# Known malware families — word-boundary matched against IOC context
_MALWARE_FAMILIES: list[str] = [
    "Emotet",
    "TrickBot",
    "Ryuk",
    "Cobalt Strike",
    "Metasploit",
    "Sliver",
    "Havoc",
    "Brute Ratel",
    "IcedID",
    "Qakbot",
    "LockBit",
    "BlackCat",
    "Conti",
    "REvil",
    "DarkSide",
    "BlackMatter",
]

# Keywords that suggest C2 or exfiltration infrastructure
_INFRA_KEYWORDS: dict[str, str] = {
    "c2": "command-and-control",
    "command and control": "command-and-control",
    "command-and-control": "command-and-control",
    "exfil": "exfiltration",
    "exfiltration": "exfiltration",
    "beacon": "command-and-control",
}

# IOC types treated as network observables (eligible for Infrastructure enrichment)
_NETWORK_IOC_TYPES: frozenset[IOCType] = frozenset(
    [IOCType.IP, IOCType.DOMAIN, IOCType.URL]
)

# IOC types treated as file/hash observables (eligible for Malware enrichment)
_HASH_IOC_TYPES: frozenset[IOCType] = frozenset(
    [IOCType.HASH_MD5, IOCType.HASH_SHA256]
)

# Well-known TLP marking definition IDs (STIX 2.1)
_TLP_MAP: dict[str, str] = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}

# Confidence mapping: Confidence enum → STIX integer (0-100)
_CONFIDENCE_MAP: dict[Confidence, int] = {
    Confidence.HIGH: 85,
    Confidence.MEDIUM: 60,
    Confidence.LOW: 35,
}
_DEFAULT_CONFIDENCE = 50


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _deterministic_id(stix_type: str, *key_parts: str) -> str:
    """Generate a deterministic STIX ID using UUID5."""
    key = ":".join(str(p) for p in key_parts)
    return f"{stix_type}--{uuid.uuid5(OPENTOOLS_NAMESPACE, key)}"


def _escape_stix_string(value: str) -> str:
    """Escape a string value for use inside a STIX pattern StringLiteral.

    STIX 2.1 pattern language requires backslashes to be doubled and
    single quotes to be backslash-escaped within single-quoted literals.
    """
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _build_pattern(ioc: IOC) -> str:
    """Map an IOC to a STIX 2.1 pattern string."""
    v = _escape_stix_string(ioc.value)

    if ioc.ioc_type == IOCType.IP:
        try:
            ipaddress.IPv6Address(ioc.value)
            return f"[ipv6-addr:value = '{v}']"
        except ValueError:
            pass
        try:
            ipaddress.IPv4Address(ioc.value)
            return f"[ipv4-addr:value = '{v}']"
        except ValueError:
            pass
        # Fallback: treat as IPv4
        return f"[ipv4-addr:value = '{v}']"

    if ioc.ioc_type == IOCType.DOMAIN:
        return f"[domain-name:value = '{v}']"

    if ioc.ioc_type == IOCType.URL:
        return f"[url:value = '{v}']"

    if ioc.ioc_type == IOCType.HASH_MD5:
        return f"[file:hashes.'MD5' = '{v}']"

    if ioc.ioc_type == IOCType.HASH_SHA256:
        return f"[file:hashes.'SHA-256' = '{v}']"

    if ioc.ioc_type == IOCType.FILE_PATH:
        return f"[file:name = '{v}']"

    if ioc.ioc_type == IOCType.REGISTRY:
        return f"[windows-registry-key:key = '{v}']"

    if ioc.ioc_type == IOCType.MUTEX:
        return f"[mutex:name = '{v}']"

    if ioc.ioc_type == IOCType.USER_AGENT:
        return f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{v}']"

    if ioc.ioc_type == IOCType.EMAIL:
        return f"[email-addr:value = '{v}']"

    # Generic fallback
    return f"[artifact:mime_type = '{v}']"


def _build_labels(ioc: IOC) -> list[str]:
    """Build STIX labels from IOC type and context keywords."""
    # Base label determined by IOC type
    if ioc.ioc_type in (
        IOCType.IP,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.HASH_MD5,
        IOCType.HASH_SHA256,
        IOCType.EMAIL,
    ):
        labels: list[str] = ["malicious-activity"]
    else:
        labels = ["anomalous-activity"]

    # Context-based keyword labels
    if ioc.context:
        ctx_lower = ioc.context.lower()
        if "c2" in ctx_lower or "command" in ctx_lower or "beacon" in ctx_lower:
            labels.append("c2")
        if "exfil" in ctx_lower:
            labels.append("exfiltration")

    return labels


def _detect_malware_family(context: str) -> str | None:
    """Return a matched malware family name (word-boundary) or None."""
    if not context:
        return None
    for family in _MALWARE_FAMILIES:
        pattern = r"\b" + re.escape(family) + r"\b"
        if re.search(pattern, context, re.IGNORECASE):
            return family
    return None


def _detect_infra_type(context: str) -> str | None:
    """Return a STIX infrastructure-type string if context matches, else None."""
    if not context:
        return None
    ctx_lower = context.lower()
    for keyword, infra_type in _INFRA_KEYWORDS.items():
        if keyword in ctx_lower:
            return infra_type
    return None


def _get_confidence(ioc: IOC, finding_index: dict[str, Finding]) -> int:
    """Resolve STIX confidence integer from linked finding."""
    if ioc.source_finding_id and ioc.source_finding_id in finding_index:
        finding = finding_index[ioc.source_finding_id]
        if finding.dedup_confidence is not None:
            return _CONFIDENCE_MAP.get(finding.dedup_confidence, _DEFAULT_CONFIDENCE)
    return _DEFAULT_CONFIDENCE


def _format_dt(dt: datetime) -> str:
    """Format a datetime as ISO 8601 with 'Z' suffix (UTC)."""
    # Ensure UTC, strip tzinfo for clean isoformat, append 'Z'
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    # Use isoformat with millisecond precision and append Z
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def export_stix(
    iocs: list[IOC],
    engagement: Engagement,
    *,
    findings: Optional[list[Finding]] = None,
    tlp: Optional[str] = None,
    valid_days: Optional[int] = None,
) -> str:
    """Export IOCs as a STIX 2.1 bundle serialised to a JSON string.

    Args:
        iocs:        List of IOC objects to export.
        engagement:  The parent Engagement (used for Report metadata).
        findings:    Optional list of Findings (for confidence lookup).
        tlp:         Optional TLP level string: "white", "green", "amber", "red".
        valid_days:  If set, indicators get a ``valid_until`` this many days
                     from now.

    Returns:
        A JSON string containing a STIX 2.1 Bundle.
    """
    now = datetime.now(timezone.utc)
    now_str = _format_dt(now)

    # Build finding index for confidence lookups
    finding_index: dict[str, Finding] = {}
    if findings:
        for f in findings:
            finding_index[f.id] = f

    # Resolve optional TLP marking
    tlp_marking_id: Optional[str] = None
    if tlp:
        tlp_marking_id = _TLP_MAP.get(tlp.lower())

    # Compute valid_until if requested
    valid_until: Optional[datetime] = None
    if valid_days is not None:
        valid_until = now + timedelta(days=valid_days)

    # --- Identity (self-referential creator) ---
    identity_id = _deterministic_id("identity", "opentools")
    identity: dict = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now_str,
        "modified": now_str,
        "name": "OpenTools",
        "identity_class": "organization",
        "description": "OpenTools security toolkit",
        "created_by_ref": identity_id,
    }

    # --- Per-IOC processing ---
    all_objects: list[dict] = [identity]
    indicator_ids: list[str] = []

    # Track deduplicated Malware and Infrastructure SDOs
    malware_by_family: dict[str, dict] = {}
    infra_by_key: dict[str, dict] = {}

    for ioc in iocs:
        pattern = _build_pattern(ioc)
        labels = _build_labels(ioc)
        confidence = _get_confidence(ioc, finding_index)

        indicator_id = _deterministic_id("indicator", ioc.ioc_type, ioc.value)

        valid_from_dt = ioc.first_seen or now
        indicator: dict = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now_str,
            "modified": now_str,
            "name": f"{ioc.ioc_type.upper()}: {ioc.value}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": _format_dt(valid_from_dt),
            "labels": labels,
            "created_by_ref": identity_id,
            "confidence": confidence,
        }

        if valid_until is not None:
            indicator["valid_until"] = _format_dt(valid_until)

        if tlp_marking_id is not None:
            indicator["object_marking_refs"] = [tlp_marking_id]

        all_objects.append(indicator)
        indicator_ids.append(indicator_id)

        # --- Malware enrichment (hash IOCs only) ---
        if ioc.ioc_type in _HASH_IOC_TYPES and ioc.context:
            family = _detect_malware_family(ioc.context)
            if family:
                family_key = family.lower()
                if family_key not in malware_by_family:
                    malware_id = _deterministic_id("malware", family_key)
                    malware_obj: dict = {
                        "type": "malware",
                        "spec_version": "2.1",
                        "id": malware_id,
                        "created": now_str,
                        "modified": now_str,
                        "name": family,
                        "is_family": True,
                        "created_by_ref": identity_id,
                    }
                    malware_by_family[family_key] = malware_obj
                    all_objects.append(malware_obj)

                malware_ref = malware_by_family[family_key]
                rel_id = _deterministic_id(
                    "relationship", "indicates", indicator_id, malware_ref["id"]
                )
                rel: dict = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created": now_str,
                    "modified": now_str,
                    "relationship_type": "indicates",
                    "source_ref": indicator_id,
                    "target_ref": malware_ref["id"],
                    "created_by_ref": identity_id,
                }
                all_objects.append(rel)

        # --- Infrastructure enrichment (network IOCs only) ---
        if ioc.ioc_type in _NETWORK_IOC_TYPES and ioc.context:
            infra_type = _detect_infra_type(ioc.context)
            if infra_type:
                infra_key = f"{infra_type}:{ioc.value}"
                if infra_key not in infra_by_key:
                    infra_id = _deterministic_id("infrastructure", infra_key)
                    infra_obj: dict = {
                        "type": "infrastructure",
                        "spec_version": "2.1",
                        "id": infra_id,
                        "created": now_str,
                        "modified": now_str,
                        "name": f"{infra_type.replace('-', ' ').title()} Server: {ioc.value}",
                        "infrastructure_types": [infra_type],
                        "created_by_ref": identity_id,
                    }
                    infra_by_key[infra_key] = infra_obj
                    all_objects.append(infra_obj)

                infra_ref = infra_by_key[infra_key]
                rel_id = _deterministic_id(
                    "relationship", "uses", indicator_id, infra_ref["id"]
                )
                rel = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": rel_id,
                    "created": now_str,
                    "modified": now_str,
                    "relationship_type": "uses",
                    "source_ref": indicator_id,
                    "target_ref": infra_ref["id"],
                    "created_by_ref": identity_id,
                }
                all_objects.append(rel)

    # --- Report ---
    # object_refs must not be empty per STIX spec
    report_refs = indicator_ids if indicator_ids else [identity_id]
    report_id = _deterministic_id("report", engagement.id)
    report: dict = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": now_str,
        "modified": now_str,
        "name": f"IOC Export \u2014 {engagement.name}",
        "description": f"STIX 2.1 IOC export for engagement: {engagement.name} (target: {engagement.target})",
        "published": now_str,
        "object_refs": report_refs,
        "created_by_ref": identity_id,
    }
    all_objects.append(report)

    # --- Bundle ---
    bundle: dict = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": all_objects,
    }
    return orjson.dumps(bundle).decode()
