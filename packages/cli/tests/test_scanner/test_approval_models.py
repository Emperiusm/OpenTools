"""Tests for HITL approval gate model additions."""
from datetime import datetime, timezone
from opentools.scanner.models import (
    ApprovalRequirement, ScanTask, TaskStatus, TaskType,
)

class TestApprovalRequirement:
    def test_defaults(self):
        req = ApprovalRequirement()
        assert req.timeout_seconds == 3600
        assert req.description == ""

    def test_custom_values(self):
        req = ApprovalRequirement(timeout_seconds=600, description="Deploy agent")
        assert req.timeout_seconds == 600
        assert req.description == "Deploy agent"

class TestTaskStatusApproval:
    def test_awaiting_approval_value(self):
        assert TaskStatus.AWAITING_APPROVAL == "awaiting_approval"

    def test_awaiting_approval_in_enum(self):
        assert "awaiting_approval" in [s.value for s in TaskStatus]

class TestScanTaskApprovalFields:
    def test_requires_approval_default_none(self):
        task = ScanTask(id="t1", scan_id="s1", name="test", tool="nmap", task_type=TaskType.SHELL)
        assert task.requires_approval is None
        assert task.approval_ticket_id is None
        assert task.approval_expires_at is None

    def test_requires_approval_set(self):
        req = ApprovalRequirement(timeout_seconds=1800, description="Dangerous")
        task = ScanTask(id="t1", scan_id="s1", name="test", tool="c2", task_type=TaskType.SHELL, requires_approval=req)
        assert task.requires_approval.timeout_seconds == 1800

    def test_approval_ticket_fields(self):
        task = ScanTask(
            id="t1", scan_id="s1", name="test", tool="nmap", task_type=TaskType.SHELL,
            approval_ticket_id="gate-t1-abc123",
            approval_expires_at=datetime(2026, 4, 13, 15, 0, 0, tzinfo=timezone.utc),
        )
        assert task.approval_ticket_id == "gate-t1-abc123"
        assert task.approval_expires_at.year == 2026
