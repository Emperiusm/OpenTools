# Phase 2C: STIX 2.1 IOC Export — Design Specification

**Date:** 2026-04-09
**Status:** Approved
**Author:** slabl + Claude
**Depends on:** Phase 1 CLI toolkit + Phase 2B core improvements (both merged)

## 1. Overview

Add STIX 2.1 export for IOCs. Every IOC becomes an Indicator with a STIX Pattern. When IOC context provides enough information, enrichment objects (Malware, Infrastructure) are created and linked via Relationships. All consumers can process the Indicators; rich consumers additionally get the full object graph.

Uses the `stix2` Python library (>=3.0) for object creation, validation, and serialization.

## 2. New Dependency

Add to `packages/cli/pyproject.toml`:

```toml
dependencies = [
    ...,
    "stix2>=3.0",
]
```

## 3. Module: `stix_export.py`

New file at `packages/cli/src/opentools/stix_export.py`. Standalone module — STIX is a distinct serialization format with its own library, separate from the Pydantic-based SARIF/CSV/JSON exports in `findings.py`.

### 3.1 Public API

```python
def export_stix(
    iocs: list[IOC],
    engagement: Engagement,
    findings: list[Finding] | None = None,
    tlp: str = "amber",
    valid_days: int | None = None,
) -> str:
    """Export IOCs as a STIX 2.1 Bundle JSON string.
    
    Args:
        iocs: IOC objects from the engagement store
        engagement: The source engagement (for Identity and Report metadata)
        findings: Optional findings list for confidence mapping via source_finding_id
        tlp: Traffic Light Protocol marking (white|green|amber|red)
        valid_days: If set, indicators expire this many days after first_seen
    
    Returns:
        JSON string of the STIX 2.1 Bundle
    """
```

### 3.2 Deterministic IDs

All STIX objects use UUID5 (deterministic, namespace-based) so re-exporting the same engagement produces identical IDs. Consumers can re-import without creating duplicates.

```python
import uuid

OPENTOOLS_NAMESPACE = uuid.UUID("f47ac10b-58cc-4372-a567-0e02b2c3d479")

def _deterministic_id(stix_type: str, *key_parts: str) -> str:
    key = ":".join(key_parts)
    return f"{stix_type}--{uuid.uuid5(OPENTOOLS_NAMESPACE, key)}"
```

Examples:
- Indicator: `_deterministic_id("indicator", ioc.ioc_type, ioc.value)`
- Malware: `_deterministic_id("malware", family_name)`
- Infrastructure: `_deterministic_id("infrastructure", ioc.value, infra_type)`

### 3.3 IOC Type → STIX Pattern Mapping

```python
def _build_pattern(ioc: IOC) -> str:
```

| IOC Type | STIX Pattern |
|----------|-------------|
| `ip` | `[ipv4-addr:value = '...']` or `[ipv6-addr:value = '...']` (auto-detected via `ipaddress` module) |
| `domain` | `[domain-name:value = '...']` |
| `url` | `[url:value = '...']` |
| `hash_md5` | `[file:hashes.MD5 = '...']` |
| `hash_sha256` | `[file:hashes.'SHA-256' = '...']` |
| `file_path` | `[file:name = '...']` |
| `registry` | `[windows-registry-key:key = '...']` |
| `mutex` | `[mutex:name = '...']` |
| `user_agent` | `[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '...']` (note: some consumers may not support nested extensions; raw string also in indicator description) |
| `email` | `[email-addr:value = '...']` |

STIX Pattern values are escaped (single quotes doubled).

### 3.4 Indicator Properties

Every IOC becomes an `stix2.Indicator`:

```python
stix2.Indicator(
    id=_deterministic_id("indicator", ioc.ioc_type, ioc.value),
    name=f"{ioc.ioc_type}: {ioc.value}",
    description=ioc.context or f"{ioc.ioc_type} indicator from engagement",
    pattern=_build_pattern(ioc),
    pattern_type="stix",
    valid_from=ioc.first_seen or engagement.created_at,
    valid_until=valid_until,  # None or first_seen + valid_days
    confidence=_map_confidence(ioc),
    labels=_build_labels(ioc),
    created_by_ref=identity.id,
    object_marking_refs=[tlp_marking.id],
)
```

### 3.5 Confidence Mapping

If the IOC has a `source_finding_id`, look up the finding's `dedup_confidence`:

| Finding Confidence | STIX Confidence (0-100) |
|-------------------|------------------------|
| high | 85 |
| medium | 60 |
| low | 35 |
| No linked finding | 50 |

Since the export function receives `list[IOC]` (not findings), confidence mapping requires the optional `findings` parameter (already in the signature in 3.1). If provided, build a `{finding_id: dedup_confidence}` lookup dict.

```python
_CONFIDENCE_MAP = {"high": 85, "medium": 60, "low": 35}

def _map_confidence(ioc: IOC, confidence_lookup: dict[str, str]) -> int:
    """Map IOC to STIX confidence (0-100) via linked finding."""
    if ioc.source_finding_id and ioc.source_finding_id in confidence_lookup:
        return _CONFIDENCE_MAP.get(confidence_lookup[ioc.source_finding_id], 50)
    return 50
```

```python
def _build_labels(ioc: IOC) -> list[str]:
    """Generate STIX labels from IOC type and context."""
    labels = list(_TYPE_LABELS.get(str(ioc.ioc_type), []))
    if ioc.context:
        ctx = ioc.context.lower()
        if any(kw in ctx for kw in _C2_KEYWORDS):
            labels.append("c2")
        if any(kw in ctx for kw in _EXFIL_KEYWORDS):
            labels.append("exfiltration")
    return labels
```

### 3.6 Labels

Auto-generated from IOC type and context:

```python
_TYPE_LABELS = {
    "ip": ["malicious-activity"],
    "domain": ["malicious-activity"],
    "url": ["malicious-activity"],
    "hash_md5": ["malicious-activity"],
    "hash_sha256": ["malicious-activity"],
    "file_path": ["anomalous-activity"],
    "registry": ["anomalous-activity"],
    "mutex": ["anomalous-activity"],
    "user_agent": ["anomalous-activity"],
    "email": ["anomalous-activity"],
}
```

Additional labels from context:
- C2 keywords in context → add `"c2"`
- Exfil keywords in context → add `"exfiltration"`

### 3.7 TLP Marking

```python
_TLP_MAP = {
    "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red": stix2.TLP_RED,
}
```

Default: `TLP:AMBER`. All objects in the bundle reference the selected TLP marking.

### 3.8 Enrichment Objects

#### Malware SDO

Created when a **hash IOC** (`ioc_type in ("hash_md5", "hash_sha256")`) has a `context` containing a recognized malware family name. Non-hash IOCs skip this check.

```python
_MALWARE_FAMILIES = [
    "emotet", "trickbot", "cobalt strike", "cobaltstrike", "qakbot", "qbot",
    "lockbit", "blackcat", "alphv", "conti", "ryuk", "revil", "sodinokibi",
    "mimikatz", "sliver", "metasploit", "meterpreter", "havoc", "bruteratel",
    "icedid", "bumblebee", "raccoon", "redline", "vidar", "asyncrat",
]

_MALWARE_PATTERNS = {
    family: re.compile(rf"\b{re.escape(family)}\b", re.IGNORECASE)
    for family in _MALWARE_FAMILIES
}

def _detect_malware_family(context: str | None) -> str | None:
    """Detect malware family from IOC context using word-boundary matching."""
    if not context:
        return None
    for family, pattern in _MALWARE_PATTERNS.items():
        if pattern.search(context):
            return family
    return None
```

When detected:

```python
malware = stix2.Malware(
    id=_deterministic_id("malware", family_name),
    name=family_name,
    is_family=True,
    malware_types=["unknown"],
    created_by_ref=identity.id,
    object_marking_refs=[tlp_marking.id],
)

relationship = stix2.Relationship(
    id=_deterministic_id("relationship", indicator.id, "indicates", malware.id),
    relationship_type="indicates",
    source_ref=indicator.id,
    target_ref=malware.id,
    created_by_ref=identity.id,
)
```

#### Infrastructure SDO

Created when a **network IOC** (`ioc_type in ("ip", "domain", "url")`) has a `context` containing C2 or exfiltration keywords. Non-network IOCs skip this check.

```python
_C2_KEYWORDS = ["c2", "c&c", "command and control", "command-and-control", "callback", "beacon"]
_EXFIL_KEYWORDS = ["exfil", "exfiltration", "data theft", "staging"]

def _detect_infrastructure_type(context: str | None) -> str | None:
    if not context:
        return None
    context_lower = context.lower()
    for kw in _C2_KEYWORDS:
        if kw in context_lower:
            return "command-and-control"
    for kw in _EXFIL_KEYWORDS:
        if kw in context_lower:
            return "exfiltration"
    return None
```

When detected:

```python
infrastructure = stix2.Infrastructure(
    id=_deterministic_id("infrastructure", ioc.value, infra_type),
    name=f"{infra_type} infrastructure at {ioc.value}",
    infrastructure_types=[infra_type],
    created_by_ref=identity.id,
    object_marking_refs=[tlp_marking.id],
)

relationship = stix2.Relationship(
    id=_deterministic_id("relationship", indicator.id, "uses", infrastructure.id),
    relationship_type="uses",
    source_ref=indicator.id,
    target_ref=infrastructure.id,
    created_by_ref=identity.id,
)
```

### 3.9 Identity and Report

One `Identity` per export (representing OpenTools as the source):

```python
identity = stix2.Identity(
    id=_deterministic_id("identity", "opentools", engagement.name),
    name=f"OpenTools: {engagement.name}",
    identity_class="system",
)
```

One `Report` wrapping all objects:

```python
report = stix2.Report(
    id=_deterministic_id("report", engagement.id),
    name=f"IOCs from engagement: {engagement.name}",
    report_types=["threat-report"],
    published=datetime.now(timezone.utc),
    object_refs=[obj.id for obj in all_objects],
    created_by_ref=identity.id,
    object_marking_refs=[tlp_marking.id],
)
```

### 3.10 Bundle Assembly

```python
all_objects = [identity] + indicators + malware_objects + infrastructure_objects + relationships + [report]
bundle = stix2.Bundle(objects=all_objects)
return bundle.serialize(pretty=True)
```

### 3.11 Empty Engagement

Zero IOCs produces a valid bundle with Identity and Report (empty `object_refs`). No error.

## 4. CLI Integration

Modify the existing `iocs export` command in `cli.py` to add `stix` as a format option:

```bash
opentools iocs export <engagement> --format stix [--tlp amber] [--valid-days 90] [--output iocs.stix.json]
```

New flags:
- `--tlp` — TLP marking (white|green|amber|red), default amber
- `--valid-days` — optional indicator expiry in days

## 5. Files Changed

| File | Action | Description |
|------|--------|-------------|
| `packages/cli/pyproject.toml` | Modify | Add `stix2>=3.0` dependency |
| `packages/cli/src/opentools/stix_export.py` | Create | STIX 2.1 export module (~150 lines) |
| `packages/cli/tests/test_stix_export.py` | Create | Tests (~100 lines) |
| `packages/cli/src/opentools/cli.py` | Modify | Add `--format stix` to iocs export, add `--tlp` and `--valid-days` flags |

## 6. Testing Strategy

| Test | What It Verifies |
|------|-----------------|
| Export with basic IOCs (IP, domain, hash) | Indicators created with correct patterns |
| IPv6 detection | `ipv6-addr` pattern used for IPv6 addresses |
| Deterministic IDs | Same IOCs produce same STIX IDs on re-export |
| TLP marking | All objects reference the selected TLP |
| Malware enrichment | Hash IOC with "Emotet" context creates Malware SDO + Relationship |
| Infrastructure enrichment | IP IOC with "C2" context creates Infrastructure SDO + Relationship |
| Confidence mapping | IOC linked to finding with high confidence → STIX confidence 85 |
| Empty engagement | Valid bundle with Identity and Report, no indicators |
| Labels | IOC type and context mapped to correct STIX labels |
| Valid time range | `valid_from` from first_seen, `valid_until` from valid_days |
| All IOC types | Each of the 10 IOC types produces a valid STIX pattern |
