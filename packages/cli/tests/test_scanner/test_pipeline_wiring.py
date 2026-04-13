"""Tests for ScanPipeline — wiring parser/normalization/dedup/etc into engine."""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import pytest
import pytest_asyncio

from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
    ProgressEventType,
    RawFinding,
    Scan,
    ScanConfig,
    ScanMode,
    ScanStatus,
    ScanTask,
    TaskStatus,
    TaskType,
)
from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.pipeline import ScanPipeline
from opentools.scanner.store import SqliteScanStore


def _uid() -> str:
    return f"test-{uuid.uuid4().hex[:8]}"


class FakeParser:
    """A fake parser that produces a RawFinding from any non-empty output."""

    name = "fake"
    version = "1.0"
    confidence_tier = 0.9

    def validate(self, data: bytes) -> bool:
        return len(data) > 0

    def parse(self, data: bytes, scan_id: str, scan_task_id: str) -> Iterator[RawFinding]:
        yield RawFinding(
            id=_uid(),
            scan_task_id=scan_task_id,
            scan_id=scan_id,
            tool="fake-tool",
            raw_severity="high",
            title="Fake Finding",
            evidence_quality=EvidenceQuality.STRUCTURED,
            evidence_hash="hash-" + _uid(),
            location_fingerprint="src/app.py:42",
            location_precision=LocationPrecision.EXACT_LINE,
            parser_version="1.0",
            parser_confidence=0.9,
            discovered_at=datetime.now(timezone.utc),
        )


@pytest_asyncio.fixture
async def store(tmp_path: Path):
    s = SqliteScanStore(tmp_path / "pipeline_test.db")
    await s.initialize()
    try:
        yield s
    finally:
        await s.close()


class TestScanPipeline:
    @pytest.mark.asyncio
    async def test_process_task_output_produces_findings(self, store: SqliteScanStore):
        """Pipeline processes tool output into raw + dedup findings in the store."""
        pipeline = ScanPipeline(store=store, engagement_id="eng-1", scan_id="scan-1")
        pipeline.router.register(FakeParser())

        task = ScanTask(
            id="task-1", scan_id="scan-1", name="fake-scan",
            tool="fake-tool", task_type=TaskType.SHELL,
            parser="fake",
        )
        output = TaskOutput(
            exit_code=0, stdout="some findings here", stderr="", duration_ms=100,
        )

        dedup_findings = await pipeline.process_task_output(task, output)
        assert len(dedup_findings) >= 1

        # Raw findings should be saved to store
        raw = await store.get_raw_findings("scan-1")
        assert len(raw) >= 1

        # Dedup findings should be saved to store
        saved = await store.get_scan_findings("scan-1")
        assert len(saved) >= 1

    @pytest.mark.asyncio
    async def test_process_task_output_no_parser_returns_empty(self, store: SqliteScanStore):
        """When no parser matches, output is skipped gracefully."""
        pipeline = ScanPipeline(store=store, engagement_id="eng-1", scan_id="scan-1")

        task = ScanTask(
            id="task-2", scan_id="scan-1", name="unknown",
            tool="unknown-tool", task_type=TaskType.SHELL,
            parser="nonexistent",
        )
        output = TaskOutput(exit_code=0, stdout="data", stderr="", duration_ms=50)

        dedup_findings = await pipeline.process_task_output(task, output)
        assert dedup_findings == []

    @pytest.mark.asyncio
    async def test_process_task_output_empty_stdout(self, store: SqliteScanStore):
        """Empty output yields no findings."""
        pipeline = ScanPipeline(store=store, engagement_id="eng-1", scan_id="scan-1")
        pipeline.router.register(FakeParser())

        task = ScanTask(
            id="task-3", scan_id="scan-1", name="fake-scan",
            tool="fake-tool", task_type=TaskType.SHELL,
            parser="fake",
        )
        output = TaskOutput(exit_code=0, stdout="", stderr="", duration_ms=10)

        dedup_findings = await pipeline.process_task_output(task, output)
        assert dedup_findings == []

    @pytest.mark.asyncio
    async def test_suppression_applied(self, store: SqliteScanStore):
        """Findings matching suppression rules are marked suppressed."""
        from opentools.scanner.models import SuppressionRule

        rule = SuppressionRule(
            id="rule-1", scope="global", rule_type="tool",
            pattern="fake-tool", reason="noisy",
            created_by="test", created_at=datetime.now(timezone.utc),
        )
        await store.save_suppression_rule(rule)

        pipeline = ScanPipeline(store=store, engagement_id="eng-1", scan_id="scan-1")
        pipeline.router.register(FakeParser())

        task = ScanTask(
            id="task-4", scan_id="scan-1", name="fake-scan",
            tool="fake-tool", task_type=TaskType.SHELL,
            parser="fake",
        )
        output = TaskOutput(exit_code=0, stdout="data", stderr="", duration_ms=10)

        dedup_findings = await pipeline.process_task_output(task, output)
        assert all(f.suppressed for f in dedup_findings)
