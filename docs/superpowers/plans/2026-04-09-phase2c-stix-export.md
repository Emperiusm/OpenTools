# Phase 2C: STIX 2.1 IOC Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Export engagement IOCs as STIX 2.1 bundles with Indicators, Malware/Infrastructure enrichment objects, TLP marking, deterministic IDs, and confidence mapping.

**Architecture:** New `stix_export.py` module uses the `stix2` library (>=3.0) for object creation and serialization. Every IOC becomes an Indicator; hash IOCs with malware family context get linked Malware SDOs; network IOCs with C2/exfil context get linked Infrastructure SDOs. CLI gains `--format stix` on the iocs export command.

**Tech Stack:** Python 3.14, stix2>=3.0, pytest

**Spec:** `docs/superpowers/specs/2026-04-09-phase2c-stix-export-design.md`

---

## File Map

| File | Action | Task |
|------|--------|------|
| `packages/cli/pyproject.toml` | Modify | 1 |
| `packages/cli/src/opentools/stix_export.py` | Create | 1 |
| `packages/cli/tests/test_stix_export.py` | Create | 1 |
| `packages/cli/src/opentools/cli.py` | Modify | 2 |

---

## Task 1: STIX Export Module + Tests

**Files:**
- Modify: `packages/cli/pyproject.toml` (add `stix2>=3.0` dependency)
- Create: `packages/cli/src/opentools/stix_export.py`
- Create: `packages/cli/tests/test_stix_export.py`

- [ ] **Step 1: Add stix2 dependency**

Add `"stix2>=3.0"` to the dependencies list in `packages/cli/pyproject.toml`:

```toml
dependencies = [
    "typer>=0.15.0",
    "pydantic>=2.0",
    "rich>=13.0",
    "ruamel.yaml>=0.18",
    "sqlite-utils>=3.37",
    "jinja2>=3.1",
    "stix2>=3.0",
]
```

Then install: `cd packages/cli && pip install -e .`

- [ ] **Step 2: Write the failing tests**

Create `packages/cli/tests/test_stix_export.py`:

```python
"""Tests for STIX 2.1 IOC export."""

import json
from datetime import datetime, timezone

import pytest

from opentools.models import (
    IOC, IOCType, Engagement, EngagementType, EngagementStatus,
    Finding, Severity, Confidence,
)


@pytest.fixture
def sample_engagement():
    now = datetime.now(timezone.utc)
    return Engagement(
        id="eng-001", name="test-pentest", target="192.168.1.0/24",
        type=EngagementType.PENTEST, status=EngagementStatus.ACTIVE,
        skills_used=["pentest"], created_at=now, updated_at=now,
    )


@pytest.fixture
def sample_iocs():
    now = datetime.now(timezone.utc)
    return [
        IOC(id="ioc-1", engagement_id="eng-001", ioc_type=IOCType.IP,
            value="10.0.0.1", context="C2 callback server",
            first_seen=now),
        IOC(id="ioc-2", engagement_id="eng-001", ioc_type=IOCType.DOMAIN,
            value="evil.example.com", context="exfiltration endpoint"),
        IOC(id="ioc-3", engagement_id="eng-001", ioc_type=IOCType.HASH_SHA256,
            value="a" * 64, context="Emotet dropper sample"),
        IOC(id="ioc-4", engagement_id="eng-001", ioc_type=IOCType.URL,
            value="https://evil.com/payload.bin", context="payload download"),
        IOC(id="ioc-5", engagement_id="eng-001", ioc_type=IOCType.REGISTRY,
            value="HKLM\\Software\\Malware\\Key", context="persistence"),
        IOC(id="ioc-6", engagement_id="eng-001", ioc_type=IOCType.MUTEX,
            value="Global\\EvilMutex", context="mutex"),
        IOC(id="ioc-7", engagement_id="eng-001", ioc_type=IOCType.EMAIL,
            value="attacker@evil.com"),
        IOC(id="ioc-8", engagement_id="eng-001", ioc_type=IOCType.HASH_MD5,
            value="d" * 32, context="Cobalt Strike beacon"),
        IOC(id="ioc-9", engagement_id="eng-001", ioc_type=IOCType.FILE_PATH,
            value="C:\\Windows\\Temp\\evil.exe"),
        IOC(id="ioc-10", engagement_id="eng-001", ioc_type=IOCType.USER_AGENT,
            value="Mozilla/5.0 (compatible; EvilBot/1.0)"),
    ]


def test_export_basic_indicators(sample_engagement, sample_iocs):
    from opentools.stix_export import export_stix
    result = export_stix(sample_iocs, sample_engagement)
    bundle = json.loads(result)
    assert bundle["type"] == "bundle"
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 10


def test_export_ipv4_pattern(sample_engagement):
    from opentools.stix_export import export_stix
    ioc = IOC(id="ioc-1", engagement_id="eng-001", ioc_type=IOCType.IP,
              value="192.168.1.1")
    bundle = json.loads(export_stix([ioc], sample_engagement))
    indicator = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
    assert "ipv4-addr:value = '192.168.1.1'" in indicator["pattern"]


def test_export_ipv6_pattern(sample_engagement):
    from opentools.stix_export import export_stix
    ioc = IOC(id="ioc-1", engagement_id="eng-001", ioc_type=IOCType.IP,
              value="2001:db8::1")
    bundle = json.loads(export_stix([ioc], sample_engagement))
    indicator = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
    assert "ipv6-addr:value = '2001:db8::1'" in indicator["pattern"]


def test_deterministic_ids(sample_engagement, sample_iocs):
    from opentools.stix_export import export_stix
    result1 = json.loads(export_stix(sample_iocs[:1], sample_engagement))
    result2 = json.loads(export_stix(sample_iocs[:1], sample_engagement))
    ids1 = {o["id"] for o in result1["objects"]}
    ids2 = {o["id"] for o in result2["objects"]}
    assert ids1 == ids2


def test_tlp_marking(sample_engagement, sample_iocs):
    from opentools.stix_export import export_stix
    bundle = json.loads(export_stix(sample_iocs[:1], sample_engagement, tlp="red"))
    indicator = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
    assert "object_marking_refs" in indicator
    assert any("marking-definition" in ref for ref in indicator["object_marking_refs"])


def test_malware_enrichment(sample_engagement):
    from opentools.stix_export import export_stix
    ioc = IOC(id="ioc-1", engagement_id="eng-001", ioc_type=IOCType.HASH_SHA256,
              value="a" * 64, context="Emotet dropper sample")
    bundle = json.loads(export_stix([ioc], sample_engagement))
    malware = [o for o in bundle["objects"] if o["type"] == "malware"]
    assert len(malware) == 1
    assert "emotet" in malware[0]["name"].lower()
    relationships = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert any(r["relationship_type"] == "indicates" for r in relationships)


def test_malware_not_on_non_hash(sample_engagement):
    from opentools.stix_export import export_stix
    ioc = IOC(id="ioc-1", engagement_id="eng-001", ioc_type=IOCType.IP,
              value="10.0.0.1", context="Emotet C2 server")
    bundle = json.loads(export_stix([ioc], sample_engagement))
    malware = [o for o in bundle["objects"] if o["type"] == "malware"]
    assert len(malware) == 0


def test_infrastructure_enrichment(sample_engagement):
    from opentools.stix_export import export_stix
    ioc = IOC(id="ioc-1", engagement_id="eng-001", ioc_type=IOCType.IP,
              value="10.0.0.1", context="C2 callback server")
    bundle = json.loads(export_stix([ioc], sample_engagement))
    infra = [o for o in bundle["objects"] if o["type"] == "infrastructure"]
    assert len(infra) == 1
    assert "command-and-control" in infra[0]["infrastructure_types"]


def test_infrastructure_not_on_non_network(sample_engagement):
    from opentools.stix_export import export_stix
    ioc = IOC(id="ioc-1", engagement_id="eng-001", ioc_type=IOCType.REGISTRY,
              value="HKLM\\key", context="C2 callback config")
    bundle = json.loads(export_stix([ioc], sample_engagement))
    infra = [o for o in bundle["objects"] if o["type"] == "infrastructure"]
    assert len(infra) == 0


def test_confidence_mapping(sample_engagement):
    from opentools.stix_export import export_stix
    now = datetime.now(timezone.utc)
    finding = Finding(
        id="f-1", engagement_id="eng-001", tool="test", title="Test",
        severity=Severity.HIGH, dedup_confidence=Confidence.HIGH, created_at=now,
    )
    ioc = IOC(id="ioc-1", engagement_id="eng-001", ioc_type=IOCType.IP,
              value="10.0.0.1", source_finding_id="f-1")
    bundle = json.loads(export_stix([ioc], sample_engagement, findings=[finding]))
    indicator = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
    assert indicator["confidence"] == 85


def test_empty_iocs(sample_engagement):
    from opentools.stix_export import export_stix
    bundle = json.loads(export_stix([], sample_engagement))
    assert bundle["type"] == "bundle"
    assert any(o["type"] == "identity" for o in bundle["objects"])
    assert any(o["type"] == "report" for o in bundle["objects"])
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 0


def test_labels(sample_engagement):
    from opentools.stix_export import export_stix
    ioc = IOC(id="ioc-1", engagement_id="eng-001", ioc_type=IOCType.IP,
              value="10.0.0.1", context="C2 beacon")
    bundle = json.loads(export_stix([ioc], sample_engagement))
    indicator = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
    assert "malicious-activity" in indicator["labels"]
    assert "c2" in indicator["labels"]


def test_valid_days(sample_engagement):
    from opentools.stix_export import export_stix
    now = datetime.now(timezone.utc)
    ioc = IOC(id="ioc-1", engagement_id="eng-001", ioc_type=IOCType.IP,
              value="10.0.0.1", first_seen=now)
    bundle = json.loads(export_stix([ioc], sample_engagement, valid_days=90))
    indicator = [o for o in bundle["objects"] if o["type"] == "indicator"][0]
    assert "valid_until" in indicator


def test_all_ioc_types_produce_valid_patterns(sample_engagement, sample_iocs):
    from opentools.stix_export import export_stix
    bundle = json.loads(export_stix(sample_iocs, sample_engagement))
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    for ind in indicators:
        assert "pattern" in ind
        assert ind["pattern"].startswith("[")
        assert ind["pattern"].endswith("]")


def test_identity_and_report_present(sample_engagement, sample_iocs):
    from opentools.stix_export import export_stix
    bundle = json.loads(export_stix(sample_iocs[:1], sample_engagement))
    types = {o["type"] for o in bundle["objects"]}
    assert "identity" in types
    assert "report" in types


def test_word_boundary_malware_detection(sample_engagement):
    """'sliver' should match but 'a silver lining' should not."""
    from opentools.stix_export import export_stix
    ioc_match = IOC(id="ioc-1", engagement_id="eng-001", ioc_type=IOCType.HASH_SHA256,
                    value="a" * 64, context="Sliver implant payload")
    bundle = json.loads(export_stix([ioc_match], sample_engagement))
    assert any(o["type"] == "malware" for o in bundle["objects"])

    ioc_no_match = IOC(id="ioc-2", engagement_id="eng-001", ioc_type=IOCType.HASH_SHA256,
                       value="b" * 64, context="a silver lining in the report")
    bundle2 = json.loads(export_stix([ioc_no_match], sample_engagement))
    assert not any(o["type"] == "malware" for o in bundle2["objects"])
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd packages/cli && python -m pytest tests/test_stix_export.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'opentools.stix_export'`

- [ ] **Step 4: Write stix_export.py**

Create `packages/cli/src/opentools/stix_export.py`:

```python
"""STIX 2.1 IOC export using the stix2 library."""

import ipaddress
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import stix2

from opentools.models import (
    Engagement, Finding, IOC, IOCType, Confidence,
)

# ─── Deterministic IDs ──────────────────────────────────────────────────────

OPENTOOLS_NAMESPACE = uuid.UUID("f47ac10b-58cc-4372-a567-0e02b2c3d479")


def _deterministic_id(stix_type: str, *key_parts: str) -> str:
    key = ":".join(str(p) for p in key_parts)
    return f"{stix_type}--{uuid.uuid5(OPENTOOLS_NAMESPACE, key)}"


# ─── TLP Marking ────────────────────────────────────────────────────────────

_TLP_MAP = {
    "white": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "red": stix2.TLP_RED,
}

# ─── STIX Pattern Builders ──────────────────────────────────────────────────


def _escape_stix(value: str) -> str:
    """Escape single quotes in STIX pattern values."""
    return value.replace("'", "\\'")


def _build_pattern(ioc: IOC) -> str:
    val = _escape_stix(ioc.value)
    ioc_type = str(ioc.ioc_type)

    if ioc_type == "ip":
        try:
            addr = ipaddress.ip_address(ioc.value)
            addr_type = "ipv6-addr" if addr.version == 6 else "ipv4-addr"
        except ValueError:
            addr_type = "ipv4-addr"
        return f"[{addr_type}:value = '{val}']"

    patterns = {
        "domain": f"[domain-name:value = '{val}']",
        "url": f"[url:value = '{val}']",
        "hash_md5": f"[file:hashes.MD5 = '{val}']",
        "hash_sha256": f"[file:hashes.'SHA-256' = '{val}']",
        "file_path": f"[file:name = '{val}']",
        "registry": f"[windows-registry-key:key = '{val}']",
        "mutex": f"[mutex:name = '{val}']",
        "user_agent": f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{val}']",
        "email": f"[email-addr:value = '{val}']",
    }
    return patterns.get(ioc_type, f"[artifact:payload_bin = '{val}']")


# ─── Labels ─────────────────────────────────────────────────────────────────

_TYPE_LABELS: dict[str, list[str]] = {
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

_C2_KEYWORDS = ["c2", "c&c", "command and control", "command-and-control", "callback", "beacon"]
_EXFIL_KEYWORDS = ["exfil", "exfiltration", "data theft", "staging"]


def _build_labels(ioc: IOC) -> list[str]:
    labels = list(_TYPE_LABELS.get(str(ioc.ioc_type), ["anomalous-activity"]))
    if ioc.context:
        ctx = ioc.context.lower()
        if any(kw in ctx for kw in _C2_KEYWORDS):
            labels.append("c2")
        if any(kw in ctx for kw in _EXFIL_KEYWORDS):
            labels.append("exfiltration")
    return labels


# ─── Confidence ─────────────────────────────────────────────────────────────

_CONFIDENCE_MAP = {"high": 85, "medium": 60, "low": 35}


def _map_confidence(ioc: IOC, confidence_lookup: dict[str, str]) -> int:
    if ioc.source_finding_id and ioc.source_finding_id in confidence_lookup:
        return _CONFIDENCE_MAP.get(confidence_lookup[ioc.source_finding_id], 50)
    return 50


# ─── Enrichment Detection ───────────────────────────────────────────────────

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

_HASH_TYPES = {"hash_md5", "hash_sha256"}
_NETWORK_TYPES = {"ip", "domain", "url"}


def _detect_malware_family(ioc: IOC) -> Optional[str]:
    if str(ioc.ioc_type) not in _HASH_TYPES or not ioc.context:
        return None
    for family, pattern in _MALWARE_PATTERNS.items():
        if pattern.search(ioc.context):
            return family
    return None


def _detect_infrastructure_type(ioc: IOC) -> Optional[str]:
    if str(ioc.ioc_type) not in _NETWORK_TYPES or not ioc.context:
        return None
    ctx = ioc.context.lower()
    for kw in _C2_KEYWORDS:
        if kw in ctx:
            return "command-and-control"
    for kw in _EXFIL_KEYWORDS:
        if kw in ctx:
            return "exfiltration"
    return None


# ─── Main Export Function ────────────────────────────────────────────────────

def export_stix(
    iocs: list[IOC],
    engagement: Engagement,
    findings: list[Finding] | None = None,
    tlp: str = "amber",
    valid_days: int | None = None,
) -> str:
    """Export IOCs as a STIX 2.1 Bundle JSON string."""
    tlp_marking = _TLP_MAP.get(tlp.lower(), stix2.TLP_AMBER)

    # Build confidence lookup from findings
    confidence_lookup: dict[str, str] = {}
    if findings:
        for f in findings:
            if f.dedup_confidence:
                confidence_lookup[f.id] = str(f.dedup_confidence)

    # Identity
    identity = stix2.Identity(
        id=_deterministic_id("identity", "opentools", engagement.name),
        name=f"OpenTools: {engagement.name}",
        identity_class="system",
        created_by_ref=_deterministic_id("identity", "opentools", engagement.name),
        object_marking_refs=[tlp_marking.id],
    )

    indicators = []
    malware_objects = []
    infrastructure_objects = []
    relationships = []
    seen_malware: dict[str, stix2.Malware] = {}
    seen_infra: dict[str, stix2.Infrastructure] = {}

    for ioc in iocs:
        # Valid time
        valid_from = ioc.first_seen or engagement.created_at
        valid_until = None
        if valid_days is not None:
            valid_until = valid_from + timedelta(days=valid_days)

        # Create indicator
        indicator = stix2.Indicator(
            id=_deterministic_id("indicator", str(ioc.ioc_type), ioc.value),
            name=f"{ioc.ioc_type}: {ioc.value}",
            description=ioc.context or f"{ioc.ioc_type} indicator from engagement",
            pattern=_build_pattern(ioc),
            pattern_type="stix",
            valid_from=valid_from,
            **({"valid_until": valid_until} if valid_until else {}),
            confidence=_map_confidence(ioc, confidence_lookup),
            labels=_build_labels(ioc),
            created_by_ref=identity.id,
            object_marking_refs=[tlp_marking.id],
        )
        indicators.append(indicator)

        # Malware enrichment (hash IOCs only)
        family = _detect_malware_family(ioc)
        if family:
            if family not in seen_malware:
                mal = stix2.Malware(
                    id=_deterministic_id("malware", family),
                    name=family,
                    is_family=True,
                    malware_types=["unknown"],
                    created_by_ref=identity.id,
                    object_marking_refs=[tlp_marking.id],
                )
                seen_malware[family] = mal
                malware_objects.append(mal)

            relationships.append(stix2.Relationship(
                id=_deterministic_id("relationship", indicator.id, "indicates", seen_malware[family].id),
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=seen_malware[family].id,
                created_by_ref=identity.id,
                object_marking_refs=[tlp_marking.id],
            ))

        # Infrastructure enrichment (network IOCs only)
        infra_type = _detect_infrastructure_type(ioc)
        if infra_type:
            infra_key = f"{ioc.value}:{infra_type}"
            if infra_key not in seen_infra:
                infra = stix2.Infrastructure(
                    id=_deterministic_id("infrastructure", ioc.value, infra_type),
                    name=f"{infra_type} infrastructure at {ioc.value}",
                    infrastructure_types=[infra_type],
                    created_by_ref=identity.id,
                    object_marking_refs=[tlp_marking.id],
                )
                seen_infra[infra_key] = infra
                infrastructure_objects.append(infra)

            relationships.append(stix2.Relationship(
                id=_deterministic_id("relationship", indicator.id, "uses", seen_infra[infra_key].id),
                relationship_type="uses",
                source_ref=indicator.id,
                target_ref=seen_infra[infra_key].id,
                created_by_ref=identity.id,
                object_marking_refs=[tlp_marking.id],
            ))

    # Report wrapping all objects
    all_objects = [identity] + indicators + malware_objects + infrastructure_objects + relationships
    object_refs = [obj.id for obj in all_objects if obj.id != identity.id]

    report = stix2.Report(
        id=_deterministic_id("report", engagement.id),
        name=f"IOCs from engagement: {engagement.name}",
        report_types=["threat-report"],
        published=datetime.now(timezone.utc),
        object_refs=object_refs if object_refs else [identity.id],
        created_by_ref=identity.id,
        object_marking_refs=[tlp_marking.id],
    )
    all_objects.append(report)

    bundle = stix2.Bundle(objects=all_objects)
    return bundle.serialize(pretty=True)
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd packages/cli && python -m pytest tests/test_stix_export.py -v
```

Expected: All 17 tests PASS.

- [ ] **Step 6: Run full test suite**

```bash
cd packages/cli && python -m pytest tests/ -q
```

Expected: All pass (122 existing + 17 new = 139)

- [ ] **Step 7: Commit**

```bash
git add packages/cli/pyproject.toml packages/cli/src/opentools/stix_export.py packages/cli/tests/test_stix_export.py
git commit -m "feat: add STIX 2.1 IOC export with Indicator, Malware, and Infrastructure objects"
```

---

## Task 2: CLI Integration

**Files:**
- Modify: `packages/cli/src/opentools/cli.py`

- [ ] **Step 1: Add stix format to iocs export command**

In `cli.py`, find the iocs export command (or create one if it doesn't exist as a full command). Add `stix` as a format option and add `--tlp` and `--valid-days` flags.

The command should:
1. Get store and config
2. Load IOCs for the engagement
3. If format is "stix": also load findings (for confidence mapping), call `export_stix()`, write to file
4. If format is "csv" or "json": use existing export functions

```python
@iocs_app.command("export")
def iocs_export(
    engagement: str,
    format: str = typer.Option("csv", help="Export format: csv|json|stix"),
    output: str = typer.Option(None, help="Output file path"),
    tlp: str = typer.Option("amber", help="TLP marking for STIX (white|green|amber|red)"),
    valid_days: int = typer.Option(None, help="Indicator expiry in days (STIX only)"),
    json_output: bool = typer.Option(False, "--json", help="JSON output"),
):
    """Export IOCs from an engagement."""
    try:
        store = _get_store()
        iocs = store.get_iocs(engagement)

        if format == "stix":
            from opentools.stix_export import export_stix
            findings = store.get_findings(engagement)
            eng = store.get(engagement)
            result = export_stix(iocs, eng, findings=findings, tlp=tlp, valid_days=valid_days)
            if output:
                Path(output).write_text(result)
                console.print(f"STIX bundle written to {output}")
            else:
                console.print(result)
        elif format == "json":
            # serialize IOCs as JSON
            import json as _json
            data = [ioc.model_dump(mode="json") for ioc in iocs]
            result = _json.dumps(data, indent=2)
            if output:
                Path(output).write_text(result)
                console.print(f"JSON written to {output}")
            else:
                console.print(result)
        else:
            # CSV
            import csv, io
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["id", "type", "value", "context", "first_seen", "last_seen"])
            for ioc in iocs:
                writer.writerow([ioc.id, ioc.ioc_type, ioc.value, ioc.context or "", ioc.first_seen or "", ioc.last_seen or ""])
            result = buf.getvalue()
            if output:
                Path(output).write_text(result)
                console.print(f"CSV written to {output}")
            else:
                console.print(result)
    except Exception as e:
        _error(str(e))
```

- [ ] **Step 2: Run full test suite**

```bash
cd packages/cli && python -m pytest tests/ -q
```

Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add packages/cli/src/opentools/cli.py
git commit -m "feat: add --format stix to iocs export with --tlp and --valid-days flags"
```

---

## Self-Review

**1. Spec coverage:**
- Section 3.1 (Public API): Task 1 ✓
- Section 3.2 (Deterministic IDs): Task 1 ✓
- Section 3.3 (Pattern mapping, all 10 types): Task 1 ✓
- Section 3.4 (Indicator properties): Task 1 ✓
- Section 3.5 (Confidence mapping): Task 1 ✓
- Section 3.6 (Labels): Task 1 ✓
- Section 3.7 (TLP marking): Task 1 ✓
- Section 3.8 (Malware + Infrastructure enrichment with type gates): Task 1 ✓
- Section 3.9 (Identity + Report): Task 1 ✓
- Section 3.10 (Bundle assembly): Task 1 ✓
- Section 3.11 (Empty engagement): Task 1 ✓
- Section 4 (CLI integration): Task 2 ✓
- Word-boundary malware detection: Task 1 test ✓
- IPv6 detection: Task 1 test ✓

**2. Placeholder scan:** No TBDs. All code blocks are complete.

**3. Type consistency:** `export_stix` signature matches spec (iocs, engagement, findings, tlp, valid_days). `_deterministic_id`, `_build_pattern`, `_build_labels`, `_map_confidence`, `_detect_malware_family`, `_detect_infrastructure_type` all consistent between implementation and tests.
