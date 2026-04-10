from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from opentools.chain.config import ChainConfig
from opentools.chain.linker.context import LinkerContext
from opentools.chain.linker.rules.base import ScopingViolation
from opentools.chain.linker.rules.shared_entity import (
    SharedStrongEntityRule,
    SharedWeakEntityRule,
)
from opentools.chain.linker.rules.temporal import TemporalProximityRule
from opentools.chain.linker.rules.tool_chain import ToolChainRule
from opentools.chain.linker.rules.cve_adjacency import CVEAdjacencyRule
from opentools.chain.linker.rules.kill_chain import KillChainAdjacencyRule
from opentools.chain.linker.rules.cross_engagement_ioc import SharedIOCCrossEngagementRule
from opentools.chain.models import Entity, entity_id_for
from opentools.models import Finding, FindingStatus, Severity


def _ctx(**overrides) -> LinkerContext:
    defaults = dict(
        user_id=None,
        is_web=False,
        scope_total_findings=100,
        avg_idf=1.0,
        stopwords_extra=[],
        common_entity_pct=0.20,
        common_entity_threshold=20,
        config=ChainConfig(),
        generation=1,
    )
    defaults.update(overrides)
    return LinkerContext(**defaults)


def _finding(id="f1", engagement_id="eng_1", tool="nmap", severity=Severity.HIGH, **kwargs) -> Finding:
    return Finding(
        id=id, engagement_id=engagement_id, tool=tool, severity=severity,
        status=FindingStatus.DISCOVERED, title="t", description="d",
        created_at=kwargs.get("created_at", datetime.now(timezone.utc)),
    )


def _entity(type_: str, value: str, mention_count: int = 1) -> Entity:
    now = datetime.now(timezone.utc)
    return Entity(
        id=entity_id_for(type_, value),
        type=type_,
        canonical_value=value,
        first_seen_at=now,
        last_seen_at=now,
        mention_count=mention_count,
    )


# ─── SharedStrongEntityRule ─────────────────────────────────────────────


def test_strong_entity_fires_on_host():
    rule = SharedStrongEntityRule()
    a, b = _finding("a"), _finding("b")
    shared = [_entity("host", "10.0.0.5", mention_count=2)]
    result = rule.apply(a, b, shared, _ctx())
    assert len(result) == 1
    assert result[0].rule == "shared_strong_entity"
    assert result[0].direction == "symmetric"
    assert result[0].weight > 0


def test_strong_entity_skips_stopword():
    rule = SharedStrongEntityRule()
    a, b = _finding("a"), _finding("b")
    shared = [_entity("host", "localhost")]
    result = rule.apply(a, b, shared, _ctx())
    assert result == []


def test_strong_entity_skips_common_entity():
    rule = SharedStrongEntityRule()
    a, b = _finding("a"), _finding("b")
    shared = [_entity("host", "10.0.0.5", mention_count=50)]  # >20 threshold
    result = rule.apply(a, b, shared, _ctx(common_entity_threshold=20))
    assert result == []


def test_strong_entity_skips_weak_types():
    rule = SharedStrongEntityRule()
    shared = [_entity("file_path", "/tmp/foo")]
    result = rule.apply(_finding("a"), _finding("b"), shared, _ctx())
    assert result == []


def test_weak_entity_rule_fires_on_file_path():
    rule = SharedWeakEntityRule()
    shared = [_entity("file_path", "/var/log/custom.log")]
    result = rule.apply(_finding("a"), _finding("b"), shared, _ctx())
    assert len(result) == 1
    assert result[0].rule == "shared_weak_entity"


# ─── TemporalProximityRule ──────────────────────────────────────────────


def test_temporal_fires_within_window():
    now = datetime.now(timezone.utc)
    rule = TemporalProximityRule()
    a = _finding("a", created_at=now)
    b = _finding("b", created_at=now + timedelta(minutes=5))
    shared = [_entity("host", "10.0.0.5")]
    result = rule.apply(a, b, shared, _ctx())
    assert len(result) == 1
    assert result[0].direction == "a_to_b"


def test_temporal_skips_outside_window():
    now = datetime.now(timezone.utc)
    rule = TemporalProximityRule()
    a = _finding("a", created_at=now)
    b = _finding("b", created_at=now + timedelta(minutes=30))
    shared = [_entity("host", "10.0.0.5")]
    result = rule.apply(a, b, shared, _ctx())
    assert result == []


def test_temporal_skips_different_engagement():
    now = datetime.now(timezone.utc)
    rule = TemporalProximityRule()
    a = _finding("a", engagement_id="eng_1", created_at=now)
    b = _finding("b", engagement_id="eng_2", created_at=now)
    shared = [_entity("host", "10.0.0.5")]
    assert rule.apply(a, b, shared, _ctx()) == []


def test_temporal_skips_no_host_entity():
    now = datetime.now(timezone.utc)
    rule = TemporalProximityRule()
    a = _finding("a", created_at=now)
    b = _finding("b", created_at=now)
    shared = [_entity("file_path", "/tmp/x")]
    assert rule.apply(a, b, shared, _ctx()) == []


# ─── ToolChainRule ──────────────────────────────────────────────────────


def test_tool_chain_fires_nmap_to_nuclei():
    now = datetime.now(timezone.utc)
    rule = ToolChainRule()
    a = _finding("a", tool="nmap", created_at=now)
    b = _finding("b", tool="nuclei", created_at=now + timedelta(minutes=5))
    shared = [_entity("host", "10.0.0.5")]
    result = rule.apply(a, b, shared, _ctx())
    assert len(result) == 1
    assert result[0].direction == "a_to_b"
    assert result[0].details["from"] == "nmap"
    assert result[0].details["to"] == "nuclei"


def test_tool_chain_reverses_when_b_first():
    now = datetime.now(timezone.utc)
    rule = ToolChainRule()
    a = _finding("a", tool="nuclei", created_at=now + timedelta(minutes=5))
    b = _finding("b", tool="nmap", created_at=now)
    shared = [_entity("host", "10.0.0.5")]
    result = rule.apply(a, b, shared, _ctx())
    assert len(result) == 1
    assert result[0].direction == "b_to_a"


def test_tool_chain_skips_unrelated_tools():
    rule = ToolChainRule()
    a = _finding("a", tool="semgrep")
    b = _finding("b", tool="burp")
    shared = [_entity("host", "10.0.0.5")]
    assert rule.apply(a, b, shared, _ctx()) == []


# ─── CVEAdjacencyRule ───────────────────────────────────────────────────


def test_cve_fires_when_severities_differ():
    rule = CVEAdjacencyRule()
    a = _finding("a", severity=Severity.MEDIUM)
    b = _finding("b", severity=Severity.CRITICAL)
    shared = [_entity("cve", "CVE-2024-1234")]
    result = rule.apply(a, b, shared, _ctx())
    assert len(result) == 1
    assert result[0].direction == "a_to_b"  # lower -> higher


def test_cve_skips_equal_severities():
    rule = CVEAdjacencyRule()
    a = _finding("a", severity=Severity.HIGH)
    b = _finding("b", severity=Severity.HIGH)
    shared = [_entity("cve", "CVE-2024-1234")]
    assert rule.apply(a, b, shared, _ctx()) == []


def test_cve_skips_no_shared_cve():
    rule = CVEAdjacencyRule()
    a = _finding("a", severity=Severity.LOW)
    b = _finding("b", severity=Severity.HIGH)
    shared = [_entity("host", "10.0.0.5")]
    assert rule.apply(a, b, shared, _ctx()) == []


# ─── KillChainAdjacencyRule ─────────────────────────────────────────────


def test_kill_chain_fires_adjacent_tactics():
    rule = KillChainAdjacencyRule()
    a = _finding("a")
    b = _finding("b")
    # T1566 (TA0001 Initial Access) and T1059 (TA0002 Execution) — distance 1
    shared = [
        _entity("mitre_technique", "T1566"),
        _entity("mitre_technique", "T1059"),
    ]
    result = rule.apply(a, b, shared, _ctx())
    assert len(result) >= 1


def test_kill_chain_skips_same_tactic():
    rule = KillChainAdjacencyRule()
    a = _finding("a")
    b = _finding("b")
    # T1566 and T1566.001 are both TA0001 — distance 0
    shared = [
        _entity("mitre_technique", "T1566"),
        _entity("mitre_technique", "T1566.001"),
    ]
    result = rule.apply(a, b, shared, _ctx())
    assert result == []


# ─── SharedIOCCrossEngagementRule ───────────────────────────────────────


def test_cross_engagement_fires():
    rule = SharedIOCCrossEngagementRule()
    a = _finding("a", engagement_id="eng_1")
    b = _finding("b", engagement_id="eng_2")
    shared = [_entity("ip", "10.0.0.5")]
    result = rule.apply(a, b, shared, _ctx())
    assert len(result) == 1
    assert result[0].direction == "symmetric"


def test_cross_engagement_skips_same_engagement():
    rule = SharedIOCCrossEngagementRule()
    a = _finding("a", engagement_id="eng_1")
    b = _finding("b", engagement_id="eng_1")
    shared = [_entity("ip", "10.0.0.5")]
    assert rule.apply(a, b, shared, _ctx()) == []


def test_cross_engagement_web_scoping_violation():
    """Web context with user_id=None must raise ScopingViolation."""
    rule = SharedIOCCrossEngagementRule()
    a = _finding("a", engagement_id="eng_1")
    b = _finding("b", engagement_id="eng_2")
    shared = [_entity("ip", "10.0.0.5")]
    ctx = _ctx(is_web=True, user_id=None)
    with pytest.raises(ScopingViolation):
        rule.apply(a, b, shared, ctx)


def test_cross_engagement_web_with_user_id_ok():
    rule = SharedIOCCrossEngagementRule()
    a = _finding("a", engagement_id="eng_1")
    b = _finding("b", engagement_id="eng_2")
    shared = [_entity("ip", "10.0.0.5")]
    result = rule.apply(a, b, shared, _ctx(is_web=True, user_id=uuid4()))
    assert len(result) == 1


def test_cross_engagement_cli_no_user_id_ok():
    """CLI context (is_web=False) with user_id=None must work fine."""
    rule = SharedIOCCrossEngagementRule()
    a = _finding("a", engagement_id="eng_1")
    b = _finding("b", engagement_id="eng_2")
    shared = [_entity("ip", "10.0.0.5")]
    result = rule.apply(a, b, shared, _ctx(is_web=False, user_id=None))
    assert len(result) == 1
