"""DashboardState — central data owner for the OpenTools TUI dashboard."""

from __future__ import annotations

from typing import Any, Optional

from opentools.containers import ContainerManager
from opentools.engagement.store import EngagementStore
from opentools.models import (
    ContainerStatus,
    Engagement,
    EngagementSummary,
    FindingStatus,
    IOC,
    TimelineEvent,
    ToolkitConfig,
)

_FINDING_STATUS_ORDER = [
    FindingStatus.DISCOVERED,
    FindingStatus.CONFIRMED,
    FindingStatus.REPORTED,
    FindingStatus.REMEDIATED,
    FindingStatus.VERIFIED,
]


class DashboardState:
    """Owns all data displayed by the dashboard and provides mutation methods.

    Attributes
    ----------
    engagements:
        Flat list of all engagements, refreshed by :meth:`refresh_engagements`.
    selected_id:
        ID of the currently selected engagement, or ``None``.
    summary:
        :class:`~opentools.models.EngagementSummary` for the selected engagement.
    findings:
        Active findings for the selected engagement.
    timeline:
        Timeline events for the selected engagement.
    iocs:
        IOCs for the selected engagement.
    containers:
        Live :class:`~opentools.models.ContainerStatus` list from Docker.
    """

    def __init__(
        self,
        store: EngagementStore,
        container_mgr: Optional[ContainerManager] = None,
        config: Optional[ToolkitConfig] = None,
    ) -> None:
        self.store = store
        self.container_mgr = container_mgr
        self.config = config

        self.engagements: list[Engagement] = []
        self.selected_id: Optional[str] = None
        self.summary: Optional[EngagementSummary] = None
        self.findings: list = []
        self.timeline: list[TimelineEvent] = []
        self.iocs: list[IOC] = []
        self.containers: list[ContainerStatus] = []

        # Change tracking for skip-refresh optimization
        self._last_finding_count: int = 0
        self._last_timeline_count: int = 0
        self._last_ioc_count: int = 0

    # ------------------------------------------------------------------
    # Refresh helpers
    # ------------------------------------------------------------------

    def refresh_engagements(self) -> None:
        """Reload engagement list from the store."""
        self.engagements = self.store.list_all()

    def refresh_selected(self) -> dict[str, Any]:
        """Reload findings/timeline/IOCs/containers for the selected engagement.

        Returns a change-notification dict.  When the finding count increased
        since the last load the dict contains::

            {
                "findings": {
                    "new": <int>,
                    "critical": <int>,
                    "high": <int>,
                }
            }
        """
        changes: dict[str, Any] = {}

        if self.selected_id is None:
            return changes

        prev_finding_count = len(self.findings)

        self.summary = self.store.get_summary(self.selected_id)
        self.findings = self.store.get_findings(self.selected_id)
        self.timeline = self.store.get_timeline(self.selected_id)
        self.iocs = self.store.get_iocs(self.selected_id)

        if self.container_mgr is not None:
            self.containers = self.container_mgr.status()

        new_count = len(self.findings)
        delta = new_count - prev_finding_count
        if delta > 0:
            fc = self.summary.finding_counts if self.summary else {}
            changes["findings"] = {
                "new": delta,
                "critical": fc.get("critical", 0),
                "high": fc.get("high", 0),
            }

        return changes

    # ------------------------------------------------------------------
    # Engagement CRUD
    # ------------------------------------------------------------------

    def create_engagement(self, name: str, target: str, eng_type: str,
                          scope: str | None = None) -> str:
        """Create a new engagement. Returns the new ID."""
        from uuid import uuid4
        from datetime import datetime, timezone
        from opentools.models import Engagement, EngagementType, EngagementStatus
        now = datetime.now(timezone.utc)
        eng = Engagement(
            id=str(uuid4()), name=name, target=target,
            type=EngagementType(eng_type),
            status=EngagementStatus.ACTIVE,
            scope=scope, created_at=now, updated_at=now,
        )
        return self.store.create(eng)

    def delete_engagement(self, engagement_id: str) -> None:
        """Delete engagement and all associated data."""
        self.store.delete_engagement(engagement_id)
        if self.selected_id == engagement_id:
            self.selected_id = None
            self.summary = None
            self.findings = []
            self.timeline = []
            self.iocs = []

    def add_finding(self, engagement_id: str, tool: str, title: str,
                    severity: str, cwe: str | None = None,
                    file_path: str | None = None, line_start: int | None = None,
                    description: str | None = None, evidence: str | None = None) -> str:
        """Add a finding to an engagement. Returns the new ID."""
        from uuid import uuid4
        from datetime import datetime, timezone
        from opentools.models import Finding, Severity
        finding = Finding(
            id=str(uuid4()), engagement_id=engagement_id,
            tool=tool, title=title, severity=Severity(severity),
            cwe=cwe, file_path=file_path, line_start=line_start,
            description=description, evidence=evidence,
            created_at=datetime.now(timezone.utc),
        )
        return self.store.add_finding(finding)

    def add_ioc(self, engagement_id: str, ioc_type: str, value: str,
                context: str | None = None) -> str:
        """Add an IOC to an engagement. Returns the new ID."""
        from uuid import uuid4
        from opentools.models import IOC, IOCType
        ioc = IOC(
            id=str(uuid4()), engagement_id=engagement_id,
            ioc_type=IOCType(ioc_type), value=value, context=context,
        )
        return self.store.add_ioc(ioc)

    # ------------------------------------------------------------------
    # Finding mutations
    # ------------------------------------------------------------------

    def flag_false_positive(self, finding_id: str) -> None:
        """Mark a finding as a false positive."""
        self.store.flag_false_positive(finding_id)

    def cycle_finding_status(self, finding_id: str) -> None:
        """Advance a finding to the next status in the cycle.

        Order: discovered → confirmed → reported → remediated → verified → discovered
        """
        current: Optional[FindingStatus] = None
        for f in self.findings:
            if f.id == finding_id:
                current = f.status
                break

        if current is None:
            return

        try:
            idx = _FINDING_STATUS_ORDER.index(current)
        except ValueError:
            idx = 0

        next_status = _FINDING_STATUS_ORDER[(idx + 1) % len(_FINDING_STATUS_ORDER)]
        self.store.update_finding_status(finding_id, next_status)

    # ------------------------------------------------------------------
    # Container mutations
    # ------------------------------------------------------------------

    def start_container(self, name: str) -> None:
        """Start a named container via ContainerManager."""
        if self.container_mgr is not None:
            self.container_mgr.start([name])

    def stop_container(self, name: str) -> None:
        """Stop a named container via ContainerManager."""
        if self.container_mgr is not None:
            self.container_mgr.stop([name])

    def restart_container(self, name: str) -> None:
        """Restart a named container via ContainerManager."""
        if self.container_mgr is not None:
            self.container_mgr.restart([name])
