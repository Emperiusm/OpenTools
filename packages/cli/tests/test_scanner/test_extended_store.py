"""Tests for extended ScanStoreProtocol — findings, events, FP memory, cache, effectiveness."""

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
import pytest_asyncio

from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
    ProgressEvent,
    ProgressEventType,
    RawFinding,
    SuppressionRule,
    ToolEffectiveness,
)
from opentools.scanner.store import SqliteScanStore


def _uid() -> str:
    return f"test-{uuid.uuid4().hex[:8]}"


def _raw_finding(**overrides) -> RawFinding:
    defaults = dict(
        id=_uid(),
        scan_task_id="task-1",
        scan_id="scan-1",
        tool="semgrep",
        raw_severity="high",
        title="SQL Injection",
        evidence_quality=EvidenceQuality.STRUCTURED,
        evidence_hash="abc123",
        location_fingerprint="src/app.py:42",
        location_precision=LocationPrecision.EXACT_LINE,
        parser_version="1.0",
        parser_confidence=0.9,
        discovered_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return RawFinding(**defaults)


def _dedup_finding(**overrides) -> DeduplicatedFinding:
    defaults = dict(
        id=_uid(),
        engagement_id="eng-1",
        fingerprint="fp-001",
        raw_finding_ids=["raw-1"],
        tools=["semgrep"],
        corroboration_count=1,
        confidence_score=0.9,
        severity_consensus="high",
        canonical_title="SQL Injection",
        location_fingerprint="src/app.py:42",
        location_precision=LocationPrecision.EXACT_LINE,
        evidence_quality_best=EvidenceQuality.STRUCTURED,
        first_seen_scan_id="scan-1",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return DeduplicatedFinding(**defaults)


def _progress_event(scan_id: str = "scan-1", sequence: int = 1, **overrides) -> ProgressEvent:
    defaults = dict(
        id=_uid(),
        type=ProgressEventType.TASK_COMPLETED,
        timestamp=datetime.now(timezone.utc),
        scan_id=scan_id,
        sequence=sequence,
        tasks_total=10,
        tasks_completed=sequence,
        tasks_running=1,
        findings_total=0,
        elapsed_seconds=float(sequence),
    )
    defaults.update(overrides)
    return ProgressEvent(**defaults)


@pytest_asyncio.fixture
async def store(tmp_path: Path):
    s = SqliteScanStore(tmp_path / "test.db")
    await s.initialize()
    try:
        yield s
    finally:
        await s.close()


# ---- Raw Findings ----

class TestRawFindingStore:
    @pytest.mark.asyncio
    async def test_save_and_get_raw_findings(self, store: SqliteScanStore):
        f1 = _raw_finding(scan_id="scan-1")
        f2 = _raw_finding(scan_id="scan-1")
        await store.save_raw_finding(f1)
        await store.save_raw_finding(f2)
        result = await store.get_raw_findings("scan-1")
        assert len(result) == 2
        ids = {f.id for f in result}
        assert f1.id in ids
        assert f2.id in ids

    @pytest.mark.asyncio
    async def test_get_raw_findings_empty(self, store: SqliteScanStore):
        result = await store.get_raw_findings("nonexistent")
        assert result == []


# ---- Dedup Findings ----

class TestDedupFindingStore:
    @pytest.mark.asyncio
    async def test_save_and_get_scan_findings(self, store: SqliteScanStore):
        f = _dedup_finding(first_seen_scan_id="scan-1")
        await store.save_dedup_finding(f)
        result = await store.get_scan_findings("scan-1")
        assert len(result) == 1
        assert result[0].id == f.id

    @pytest.mark.asyncio
    async def test_get_engagement_findings(self, store: SqliteScanStore):
        f1 = _dedup_finding(engagement_id="eng-1")
        f2 = _dedup_finding(engagement_id="eng-1")
        f3 = _dedup_finding(engagement_id="eng-2")
        await store.save_dedup_finding(f1)
        await store.save_dedup_finding(f2)
        await store.save_dedup_finding(f3)
        result = await store.get_engagement_findings("eng-1")
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_get_scan_findings_empty(self, store: SqliteScanStore):
        result = await store.get_scan_findings("nonexistent")
        assert result == []


# ---- Progress Events ----

class TestEventStore:
    @pytest.mark.asyncio
    async def test_save_and_get_events(self, store: SqliteScanStore):
        e1 = _progress_event(scan_id="scan-1", sequence=1)
        e2 = _progress_event(scan_id="scan-1", sequence=2)
        e3 = _progress_event(scan_id="scan-1", sequence=3)
        await store.save_event(e1)
        await store.save_event(e2)
        await store.save_event(e3)
        result = await store.get_events_after("scan-1", 0)
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_get_events_after_sequence(self, store: SqliteScanStore):
        for i in range(1, 6):
            await store.save_event(_progress_event(scan_id="scan-1", sequence=i))
        result = await store.get_events_after("scan-1", 3)
        assert len(result) == 2
        assert all(e.sequence > 3 for e in result)

    @pytest.mark.asyncio
    async def test_get_events_empty(self, store: SqliteScanStore):
        result = await store.get_events_after("nonexistent", 0)
        assert result == []


# ---- Suppression Rules ----

class TestSuppressionRuleStore:
    @pytest.mark.asyncio
    async def test_save_and_get_rules(self, store: SqliteScanStore):
        rule = SuppressionRule(
            id=_uid(),
            scope="global",
            rule_type="cwe",
            pattern="CWE-79",
            reason="known FP",
            created_by="user",
            created_at=datetime.now(timezone.utc),
        )
        await store.save_suppression_rule(rule)
        result = await store.get_suppression_rules()
        assert len(result) == 1
        assert result[0].id == rule.id

    @pytest.mark.asyncio
    async def test_get_rules_by_engagement(self, store: SqliteScanStore):
        r1 = SuppressionRule(
            id=_uid(), scope="global", rule_type="cwe",
            pattern="CWE-79", reason="test", created_by="user",
            created_at=datetime.now(timezone.utc),
        )
        r2 = SuppressionRule(
            id=_uid(), scope="engagement", engagement_id="eng-1",
            rule_type="tool", pattern="nikto", reason="noisy",
            created_by="user", created_at=datetime.now(timezone.utc),
        )
        await store.save_suppression_rule(r1)
        await store.save_suppression_rule(r2)
        # Global rules + engagement-scoped rules
        result = await store.get_suppression_rules(engagement_id="eng-1")
        assert len(result) == 2


# ---- FP Memory ----

class TestFPMemory:
    @pytest.mark.asyncio
    async def test_save_and_get_fp(self, store: SqliteScanStore):
        assert await store.get_fp_memory("target", "fp-1", "CWE-89") is False
        await store.save_fp_memory("target", "fp-1", "CWE-89")
        assert await store.get_fp_memory("target", "fp-1", "CWE-89") is True

    @pytest.mark.asyncio
    async def test_fp_memory_different_keys(self, store: SqliteScanStore):
        await store.save_fp_memory("target", "fp-1", "CWE-89")
        assert await store.get_fp_memory("target", "fp-1", "CWE-79") is False
        assert await store.get_fp_memory("other-target", "fp-1", "CWE-89") is False


# ---- Output Cache ----

class TestOutputCache:
    @pytest.mark.asyncio
    async def test_save_and_get_cache(self, store: SqliteScanStore):
        assert await store.get_output_cache("key-1") is None
        await store.save_output_cache("key-1", {"stdout": "hello", "exit_code": 0})
        result = await store.get_output_cache("key-1")
        assert result is not None
        assert result["stdout"] == "hello"

    @pytest.mark.asyncio
    async def test_cache_miss(self, store: SqliteScanStore):
        assert await store.get_output_cache("nonexistent") is None


# ---- Tool Effectiveness ----

class TestToolEffectiveness:
    @pytest.mark.asyncio
    async def test_save_and_get_effectiveness(self, store: SqliteScanStore):
        stats = ToolEffectiveness(
            tool="semgrep",
            target_type="source_code",
            total_findings=100,
            confirmed_findings=80,
            false_positive_count=5,
            false_positive_rate=0.05,
            avg_duration_seconds=12.5,
            sample_count=10,
            updated_at=datetime.now(timezone.utc),
        )
        await store.update_tool_effectiveness(stats)
        result = await store.get_tool_effectiveness("semgrep", "source_code")
        assert result is not None
        assert result.total_findings == 100
        assert result.sample_count == 10

    @pytest.mark.asyncio
    async def test_update_overwrites(self, store: SqliteScanStore):
        stats1 = ToolEffectiveness(
            tool="semgrep", target_type="source_code",
            total_findings=50, sample_count=5,
            updated_at=datetime.now(timezone.utc),
        )
        stats2 = ToolEffectiveness(
            tool="semgrep", target_type="source_code",
            total_findings=100, sample_count=10,
            updated_at=datetime.now(timezone.utc),
        )
        await store.update_tool_effectiveness(stats1)
        await store.update_tool_effectiveness(stats2)
        result = await store.get_tool_effectiveness("semgrep", "source_code")
        assert result.total_findings == 100

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, store: SqliteScanStore):
        result = await store.get_tool_effectiveness("nmap", "network")
        assert result is None


# ---- Protocol compliance ----

class TestProtocolCompliance:
    @pytest.mark.asyncio
    async def test_sqlite_store_is_protocol_compliant(self, store: SqliteScanStore):
        from opentools.scanner.store import ScanStoreProtocol
        assert isinstance(store, ScanStoreProtocol)
