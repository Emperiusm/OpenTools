"""Tests for the STIX 2.1 export module."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from opentools.models import (
    Confidence,
    Engagement,
    EngagementStatus,
    EngagementType,
    Finding,
    IOC,
    IOCType,
    Severity,
)
from opentools.stix_export import export_stix


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(timezone.utc)


def _make_engagement() -> Engagement:
    return Engagement(
        id="eng-001",
        name="Test Engagement",
        target="acme-corp",
        type=EngagementType.PENTEST,
        status=EngagementStatus.ACTIVE,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _make_ioc(ioc_type: IOCType, value: str, context: str | None = None) -> IOC:
    return IOC(
        id=f"ioc-{value[:20]}",
        engagement_id="eng-001",
        ioc_type=ioc_type,
        value=value,
        context=context,
        first_seen=_NOW,
        last_seen=_NOW,
    )


def _parse(json_str: str) -> dict:
    return json.loads(json_str)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_export_basic_indicators():
    """10 IOCs of all types → 10 indicators in bundle."""
    iocs = [
        _make_ioc(IOCType.IP, "1.2.3.4"),
        _make_ioc(IOCType.DOMAIN, "evil.example.com"),
        _make_ioc(IOCType.URL, "http://evil.example.com/path"),
        _make_ioc(IOCType.HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e"),
        _make_ioc(IOCType.HASH_SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        _make_ioc(IOCType.FILE_PATH, "C:\\Windows\\Temp\\evil.exe"),
        _make_ioc(IOCType.REGISTRY, "HKLM\\SOFTWARE\\Evil\\Key"),
        _make_ioc(IOCType.MUTEX, "Global\\EvilMutex"),
        _make_ioc(IOCType.USER_AGENT, "EvilBot/1.0"),
        _make_ioc(IOCType.EMAIL, "attacker@evil.com"),
    ]
    engagement = _make_engagement()
    result = export_stix(iocs, engagement)
    bundle = _parse(result)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 10


def test_export_ipv4_pattern():
    """IPv4 IOC → ipv4-addr:value pattern."""
    ioc = _make_ioc(IOCType.IP, "192.168.1.100")
    result = export_stix([ioc], _make_engagement())
    bundle = _parse(result)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 1
    assert "ipv4-addr:value" in indicators[0]["pattern"]


def test_export_ipv6_pattern():
    """IPv6 IOC → ipv6-addr:value pattern."""
    ioc = _make_ioc(IOCType.IP, "2001:db8::1")
    result = export_stix([ioc], _make_engagement())
    bundle = _parse(result)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 1
    assert "ipv6-addr:value" in indicators[0]["pattern"]


def test_deterministic_ids():
    """Same IOCs → same STIX IDs on re-export."""
    ioc = _make_ioc(IOCType.IP, "10.0.0.1")
    engagement = _make_engagement()
    result1 = export_stix([ioc], engagement)
    result2 = export_stix([ioc], engagement)
    b1 = _parse(result1)
    b2 = _parse(result2)
    ids1 = {o["id"] for o in b1["objects"]}
    ids2 = {o["id"] for o in b2["objects"]}
    assert ids1 == ids2


def test_tlp_marking():
    """tlp='red' → marking-definition ref on indicator."""
    ioc = _make_ioc(IOCType.IP, "10.0.0.2")
    result = export_stix([ioc], _make_engagement(), tlp="red")
    bundle = _parse(result)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 1
    markings = indicators[0].get("object_marking_refs", [])
    assert any("marking-definition" in m for m in markings)


def test_malware_enrichment():
    """Hash IOC with 'Emotet' context → Malware SDO + 'indicates' relationship."""
    ioc = _make_ioc(IOCType.HASH_MD5, "aabbcc1122334455aabbcc1122334455", context="Emotet dropper sample")
    result = export_stix([ioc], _make_engagement())
    bundle = _parse(result)
    malware_objs = [o for o in bundle["objects"] if o["type"] == "malware"]
    relationships = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert len(malware_objs) >= 1
    assert any("emotet" in m["name"].lower() for m in malware_objs)
    assert any(r["relationship_type"] == "indicates" for r in relationships)


def test_malware_not_on_non_hash():
    """IP IOC with 'Emotet' context → NO Malware SDO."""
    ioc = _make_ioc(IOCType.IP, "10.0.0.3", context="Emotet C2 server")
    result = export_stix([ioc], _make_engagement())
    bundle = _parse(result)
    malware_objs = [o for o in bundle["objects"] if o["type"] == "malware"]
    assert len(malware_objs) == 0


def test_infrastructure_enrichment():
    """IP IOC with 'C2' context → Infrastructure SDO + 'uses' relationship."""
    ioc = _make_ioc(IOCType.IP, "10.0.0.4", context="C2 beacon server")
    result = export_stix([ioc], _make_engagement())
    bundle = _parse(result)
    infra_objs = [o for o in bundle["objects"] if o["type"] == "infrastructure"]
    relationships = [o for o in bundle["objects"] if o["type"] == "relationship"]
    assert len(infra_objs) >= 1
    assert any(r["relationship_type"] == "uses" for r in relationships)


def test_infrastructure_not_on_non_network():
    """Registry IOC with 'C2' context → NO Infrastructure SDO."""
    ioc = _make_ioc(IOCType.REGISTRY, "HKLM\\SOFTWARE\\C2\\Config", context="C2 persistence")
    result = export_stix([ioc], _make_engagement())
    bundle = _parse(result)
    infra_objs = [o for o in bundle["objects"] if o["type"] == "infrastructure"]
    assert len(infra_objs) == 0


def test_confidence_mapping():
    """IOC linked to finding with HIGH confidence → STIX confidence 85."""
    finding = Finding(
        id="f-001",
        engagement_id="eng-001",
        tool="manual",
        title="Malware Hash",
        severity=Severity.HIGH,
        dedup_confidence=Confidence.HIGH,
        created_at=_NOW,
    )
    ioc = IOC(
        id="ioc-conf",
        engagement_id="eng-001",
        ioc_type=IOCType.HASH_MD5,
        value="cafebabe1234567890abcdef01234567",
        source_finding_id="f-001",
    )
    result = export_stix([ioc], _make_engagement(), findings=[finding])
    bundle = _parse(result)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 1
    assert indicators[0].get("confidence") == 85


def test_empty_iocs():
    """Empty list → valid bundle with identity + report, 0 indicators."""
    result = export_stix([], _make_engagement())
    bundle = _parse(result)
    assert bundle["type"] == "bundle"
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 0
    identity_objs = [o for o in bundle["objects"] if o["type"] == "identity"]
    report_objs = [o for o in bundle["objects"] if o["type"] == "report"]
    assert len(identity_objs) >= 1
    assert len(report_objs) >= 1


def test_labels():
    """IP IOC with 'C2 beacon' context → labels include 'malicious-activity' and 'c2'."""
    ioc = _make_ioc(IOCType.IP, "10.0.0.5", context="C2 beacon traffic observed")
    result = export_stix([ioc], _make_engagement())
    bundle = _parse(result)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 1
    labels = indicators[0].get("labels", [])
    assert "malicious-activity" in labels
    assert "c2" in labels


def test_valid_days():
    """valid_days=90 → indicator has valid_until."""
    ioc = _make_ioc(IOCType.DOMAIN, "c2.evil.net")
    result = export_stix([ioc], _make_engagement(), valid_days=90)
    bundle = _parse(result)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 1
    assert "valid_until" in indicators[0]


def test_all_ioc_types_produce_valid_patterns():
    """All 10 IOC types produce patterns starting with '[' ending with ']'."""
    iocs = [
        _make_ioc(IOCType.IP, "1.2.3.4"),
        _make_ioc(IOCType.DOMAIN, "evil.example.com"),
        _make_ioc(IOCType.URL, "http://evil.example.com/path"),
        _make_ioc(IOCType.HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e"),
        _make_ioc(IOCType.HASH_SHA256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        _make_ioc(IOCType.FILE_PATH, "C:\\Windows\\Temp\\evil.exe"),
        _make_ioc(IOCType.REGISTRY, "HKLM\\SOFTWARE\\Evil\\Key"),
        _make_ioc(IOCType.MUTEX, "Global\\EvilMutex"),
        _make_ioc(IOCType.USER_AGENT, "EvilBot/1.0"),
        _make_ioc(IOCType.EMAIL, "attacker@evil.com"),
    ]
    result = export_stix(iocs, _make_engagement())
    bundle = _parse(result)
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert len(indicators) == 10
    for ind in indicators:
        pattern = ind["pattern"]
        assert pattern.startswith("["), f"Pattern does not start with '[': {pattern}"
        assert pattern.endswith("]"), f"Pattern does not end with ']': {pattern}"


def test_identity_and_report_present():
    """Bundle has identity and report objects."""
    ioc = _make_ioc(IOCType.DOMAIN, "test.evil.com")
    result = export_stix([ioc], _make_engagement())
    bundle = _parse(result)
    identity_objs = [o for o in bundle["objects"] if o["type"] == "identity"]
    report_objs = [o for o in bundle["objects"] if o["type"] == "report"]
    assert len(identity_objs) >= 1
    assert len(report_objs) >= 1


def test_word_boundary_malware_detection():
    """'Sliver implant' matches, 'a silver lining' doesn't."""
    ioc_match = _make_ioc(IOCType.HASH_SHA256, "a" * 64, context="Sliver implant detected")
    ioc_no_match = _make_ioc(IOCType.HASH_SHA256, "b" * 64, context="a silver lining in the sky")

    result_match = export_stix([ioc_match], _make_engagement())
    bundle_match = _parse(result_match)
    malware_match = [o for o in bundle_match["objects"] if o["type"] == "malware"]
    assert len(malware_match) >= 1, "Expected Sliver to match as malware family"

    result_no = export_stix([ioc_no_match], _make_engagement())
    bundle_no = _parse(result_no)
    malware_no = [o for o in bundle_no["objects"] if o["type"] == "malware"]
    assert len(malware_no) == 0, "Expected 'silver' NOT to match Sliver (word boundary)"
