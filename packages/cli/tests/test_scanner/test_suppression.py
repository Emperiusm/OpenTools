"""Tests for SuppressionEngine — applies path/CWE/severity/tool suppression rules."""

import uuid
from datetime import datetime, timezone, timedelta

import pytest

from opentools.models import FindingStatus
from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
    SuppressionRule,
)
from opentools.scanner.parsing.suppression import SuppressionEngine


def _make_dedup(
    file_path: str = "src/api/users.py",
    cwe: str | None = "CWE-89",
    severity_consensus: str = "high",
    tools: list[str] | None = None,
    location_fingerprint: str | None = None,
) -> DeduplicatedFinding:
    now = datetime.now(timezone.utc)
    return DeduplicatedFinding(
        id=str(uuid.uuid4()),
        engagement_id="eng-1",
        fingerprint="fp1",
        raw_finding_ids=[str(uuid.uuid4())],
        tools=tools or ["semgrep"],
        corroboration_count=1,
        confidence_score=0.9,
        severity_consensus=severity_consensus,
        canonical_title="SQL Injection",
        cwe=cwe,
        location_fingerprint=location_fingerprint or f"{file_path}:42",
        location_precision=LocationPrecision.EXACT_LINE,
        evidence_quality_best=EvidenceQuality.STRUCTURED,
        status=FindingStatus.DISCOVERED,
        first_seen_scan_id="scan-1",
        created_at=now,
        updated_at=now,
    )


def _make_rule(
    rule_type: str = "path_pattern",
    pattern: str = "test/**",
    scope: str = "global",
    engagement_id: str | None = None,
    expires_at: datetime | None = None,
) -> SuppressionRule:
    return SuppressionRule(
        id=str(uuid.uuid4()),
        scope=scope,
        engagement_id=engagement_id,
        rule_type=rule_type,
        pattern=pattern,
        reason="Test suppression",
        created_by="user:test",
        created_at=datetime.now(timezone.utc),
        expires_at=expires_at,
    )


class TestPathSuppression:
    def test_path_glob_suppresses(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="path_pattern", pattern="test/**")]
        f = _make_dedup(location_fingerprint="test/test_auth.py:10")
        results = engine.apply(rules, [f])
        assert len(results) == 1
        assert results[0].suppressed is True

    def test_path_no_match_passes(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="path_pattern", pattern="test/**")]
        f = _make_dedup(location_fingerprint="src/api/users.py:42")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is False


class TestCWESuppression:
    def test_cwe_exact_match_suppresses(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="cwe", pattern="CWE-89")]
        f = _make_dedup(cwe="CWE-89")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is True

    def test_cwe_child_suppressed_by_parent(self):
        """Suppressing a parent CWE also suppresses child CWEs."""
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="cwe", pattern="CWE-74")]
        # CWE-89 is child of CWE-74
        f = _make_dedup(cwe="CWE-89")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is True

    def test_cwe_no_match(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="cwe", pattern="CWE-79")]
        f = _make_dedup(cwe="CWE-89")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is False


class TestSeveritySuppression:
    def test_severity_below_threshold(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="severity_below", pattern="medium")]
        f = _make_dedup(severity_consensus="low")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is True

    def test_severity_at_threshold_not_suppressed(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="severity_below", pattern="medium")]
        f = _make_dedup(severity_consensus="medium")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is False

    def test_severity_above_threshold_not_suppressed(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="severity_below", pattern="medium")]
        f = _make_dedup(severity_consensus="high")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is False


class TestToolSuppression:
    def test_tool_match_suppresses(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="tool", pattern="nmap")]
        f = _make_dedup(tools=["nmap"])
        results = engine.apply(rules, [f])
        assert results[0].suppressed is True

    def test_tool_no_match(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="tool", pattern="nmap")]
        f = _make_dedup(tools=["semgrep"])
        results = engine.apply(rules, [f])
        assert results[0].suppressed is False

    def test_tool_match_any_tool_in_list(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="tool", pattern="nmap")]
        f = _make_dedup(tools=["semgrep", "nmap"])
        results = engine.apply(rules, [f])
        assert results[0].suppressed is True


class TestExpiredRules:
    def test_expired_rule_not_applied(self):
        engine = SuppressionEngine()
        past = datetime.now(timezone.utc) - timedelta(days=1)
        rules = [_make_rule(rule_type="cwe", pattern="CWE-89", expires_at=past)]
        f = _make_dedup(cwe="CWE-89")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is False

    def test_non_expired_rule_applied(self):
        engine = SuppressionEngine()
        future = datetime.now(timezone.utc) + timedelta(days=30)
        rules = [_make_rule(rule_type="cwe", pattern="CWE-89", expires_at=future)]
        f = _make_dedup(cwe="CWE-89")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is True


class TestSuppressionRuleId:
    def test_suppressed_finding_gets_rule_id(self):
        engine = SuppressionEngine()
        rule = _make_rule(rule_type="cwe", pattern="CWE-89")
        f = _make_dedup(cwe="CWE-89")
        results = engine.apply([rule], [f])
        assert results[0].suppression_rule_id == rule.id
