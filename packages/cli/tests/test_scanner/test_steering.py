# packages/cli/tests/test_scanner/test_steering.py
"""Tests for SteeringInterface protocol, SteeringDecision, and SteeringThrottle."""

import pytest

from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.models import (
    GraphSnapshot,
    ProgressEventType,
    ScanTask,
    SteeringAction,
    TaskType,
)
from opentools.scanner.steering import (
    SteeringDecision,
    SteeringInterface,
    SteeringThrottle,
)


class TestSteeringAction:
    def test_values(self):
        assert SteeringAction.CONTINUE == "continue"
        assert SteeringAction.ADD_TASKS == "add_tasks"
        assert SteeringAction.PAUSE == "pause"
        assert SteeringAction.ABORT == "abort"


class TestSteeringDecision:
    def test_continue_decision(self):
        d = SteeringDecision(
            action=SteeringAction.CONTINUE,
            reasoning="Everything looks good, continue scanning.",
        )
        assert d.action == SteeringAction.CONTINUE
        assert d.new_tasks == []
        assert d.authorization_required is False

    def test_add_tasks_decision(self):
        task = ScanTask(
            id="new-1",
            scan_id="scan1",
            name="extra-scan",
            tool="nuclei",
            task_type=TaskType.SHELL,
        )
        d = SteeringDecision(
            action=SteeringAction.ADD_TASKS,
            new_tasks=[task],
            reasoning="Found a promising endpoint, adding nuclei scan.",
        )
        assert len(d.new_tasks) == 1

    def test_serialization(self):
        d = SteeringDecision(
            action=SteeringAction.PAUSE,
            reasoning="Need user confirmation for active testing.",
            authorization_required=True,
        )
        restored = SteeringDecision.model_validate_json(d.model_dump_json())
        assert restored.action == SteeringAction.PAUSE
        assert restored.authorization_required is True


class TestGraphSnapshot:
    def test_basic_snapshot(self):
        snap = GraphSnapshot(
            tasks_total=10,
            tasks_completed=5,
            tasks_running=2,
            tasks_pending=3,
            tasks_failed=0,
            tasks_skipped=0,
            phases_completed=["discovery"],
            current_phase="scanning",
            finding_count=3,
        )
        assert snap.tasks_total == 10
        assert snap.current_phase == "scanning"


class TestSteeringInterface:
    def test_protocol_structural_subtyping(self):
        """A class with the correct methods satisfies the protocol."""

        class FakeSteering:
            async def on_task_completed(self, task, output, findings_so_far, graph_state):
                return SteeringDecision(action=SteeringAction.CONTINUE, reasoning="ok")

            async def on_phase_boundary(self, phase_name, graph_state):
                return SteeringDecision(action=SteeringAction.CONTINUE, reasoning="ok")

            async def on_scan_paused(self, reason, graph_state):
                return SteeringDecision(action=SteeringAction.CONTINUE, reasoning="ok")

            async def on_authorization_required(self, action_description, risk_level):
                return True

        assert isinstance(FakeSteering(), SteeringInterface)

    def test_non_conforming_rejected(self):

        class NotSteering:
            pass

        assert not isinstance(NotSteering(), SteeringInterface)


class TestSteeringThrottle:
    def test_every_task_always_true(self):
        throttle = SteeringThrottle(frequency="every_task")
        assert throttle.should_consult(
            event_type=ProgressEventType.TASK_COMPLETED,
            is_phase_boundary=False,
            has_finding=False,
            finding_severity=None,
        ) is True

    def test_phase_boundary_on_phase(self):
        throttle = SteeringThrottle(frequency="phase_boundary")
        assert throttle.should_consult(
            event_type=ProgressEventType.TASK_COMPLETED,
            is_phase_boundary=True,
            has_finding=False,
            finding_severity=None,
        ) is True

    def test_phase_boundary_mid_phase(self):
        throttle = SteeringThrottle(frequency="phase_boundary")
        assert throttle.should_consult(
            event_type=ProgressEventType.TASK_COMPLETED,
            is_phase_boundary=False,
            has_finding=False,
            finding_severity=None,
        ) is False

    def test_phase_boundary_always_on_critical(self):
        throttle = SteeringThrottle(frequency="phase_boundary")
        assert throttle.should_consult(
            event_type=ProgressEventType.FINDING_DISCOVERED,
            is_phase_boundary=False,
            has_finding=True,
            finding_severity="critical",
        ) is True

    def test_phase_boundary_always_on_high(self):
        throttle = SteeringThrottle(frequency="phase_boundary")
        assert throttle.should_consult(
            event_type=ProgressEventType.FINDING_DISCOVERED,
            is_phase_boundary=False,
            has_finding=True,
            finding_severity="high",
        ) is True

    def test_findings_only_on_finding(self):
        throttle = SteeringThrottle(frequency="findings_only")
        assert throttle.should_consult(
            event_type=ProgressEventType.FINDING_DISCOVERED,
            is_phase_boundary=False,
            has_finding=True,
            finding_severity="medium",
        ) is True

    def test_findings_only_no_finding(self):
        throttle = SteeringThrottle(frequency="findings_only")
        assert throttle.should_consult(
            event_type=ProgressEventType.TASK_COMPLETED,
            is_phase_boundary=True,
            has_finding=False,
            finding_severity=None,
        ) is False

    def test_manual_always_false(self):
        throttle = SteeringThrottle(frequency="manual")
        assert throttle.should_consult(
            event_type=ProgressEventType.TASK_COMPLETED,
            is_phase_boundary=True,
            has_finding=True,
            finding_severity="critical",
        ) is False

    def test_scan_completed_always_consulted(self):
        """Scan completion always triggers steering regardless of frequency."""
        for freq in ["phase_boundary", "findings_only", "manual"]:
            throttle = SteeringThrottle(frequency=freq)
            assert throttle.should_consult(
                event_type=ProgressEventType.SCAN_COMPLETED,
                is_phase_boundary=False,
                has_finding=False,
                finding_severity=None,
            ) is True
