# packages/cli/src/opentools/scanner/steering.py
"""Steering interface for assisted-mode scan control.

The SteeringInterface protocol defines how Claude (or any other
decision-maker) can influence scan execution at runtime. The
SteeringThrottle controls when steering is actually consulted,
managing LLM cost.
"""

from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable

from pydantic import BaseModel, Field

from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.models import (
    GraphSnapshot,
    ProgressEventType,
    ScanTask,
    SteeringAction,
)


# ---------------------------------------------------------------------------
# Steering decision model
# ---------------------------------------------------------------------------


class SteeringDecision(BaseModel):
    """A decision from the steering interface."""

    action: SteeringAction
    new_tasks: list[ScanTask] = Field(default_factory=list)
    reasoning: str
    authorization_required: bool = False


# ---------------------------------------------------------------------------
# Steering protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class SteeringInterface(Protocol):
    """Protocol for scan steering in assisted mode.

    Implementors receive events from the scan engine and return
    decisions about how to proceed. The ``SteeringThrottle``
    controls which events actually reach the steering interface.
    """

    async def on_task_completed(
        self,
        task: ScanTask,
        output: TaskOutput,
        findings_so_far: list,
        graph_state: GraphSnapshot,
    ) -> SteeringDecision:
        """Called when a task completes (subject to throttle)."""
        ...

    async def on_phase_boundary(
        self,
        phase_name: str,
        graph_state: GraphSnapshot,
    ) -> SteeringDecision:
        """Called when all tasks in a phase are complete."""
        ...

    async def on_scan_paused(
        self,
        reason: str,
        graph_state: GraphSnapshot,
    ) -> SteeringDecision:
        """Called when the scan is paused."""
        ...

    async def on_authorization_required(
        self,
        action_description: str,
        risk_level: str,
    ) -> bool:
        """Called when user authorization is needed for a risky action."""
        ...


# ---------------------------------------------------------------------------
# Steering throttle
# ---------------------------------------------------------------------------

# Severities that always trigger steering
_ALWAYS_CONSULT_SEVERITIES = frozenset({"critical", "high"})

# Event types that always trigger steering
_ALWAYS_CONSULT_EVENTS = frozenset({
    ProgressEventType.SCAN_COMPLETED,
    ProgressEventType.SCAN_FAILED,
})


class SteeringThrottle:
    """Controls when the steering interface is actually consulted.

    Frequencies:
    - ``every_task``: consult on every task completion (expensive)
    - ``phase_boundary``: consult at phase transitions + critical/high findings
    - ``findings_only``: consult only when findings are discovered
    - ``manual``: only when explicitly triggered (never auto-consults)

    Critical/high findings and scan completion always trigger consultation
    regardless of frequency setting (except ``manual``).
    """

    def __init__(self, frequency: str = "phase_boundary") -> None:
        self._frequency = frequency

    @property
    def frequency(self) -> str:
        return self._frequency

    def should_consult(
        self,
        event_type: ProgressEventType,
        is_phase_boundary: bool,
        has_finding: bool,
        finding_severity: Optional[str],
    ) -> bool:
        """Determine whether to consult the steering interface.

        Args:
            event_type: The type of progress event that triggered this check.
            is_phase_boundary: Whether all tasks in the current phase are done.
            has_finding: Whether a new finding was discovered.
            finding_severity: Severity of the finding, if any.

        Returns:
            True if steering should be consulted.
        """
        # Scan completion always triggers regardless of frequency (including manual)
        if event_type in _ALWAYS_CONSULT_EVENTS:
            return True

        # Manual never auto-consults for anything else
        if self._frequency == "manual":
            return False

        # Critical/high findings always trigger (except manual)
        if has_finding and finding_severity in _ALWAYS_CONSULT_SEVERITIES:
            return True

        if self._frequency == "every_task":
            return True

        if self._frequency == "phase_boundary":
            return is_phase_boundary

        if self._frequency == "findings_only":
            return has_finding

        return False
