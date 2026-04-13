# packages/cli/src/opentools/scanner/api.py
"""ScanAPI — unified entry point for scan orchestration.

Provides the public API surface for all scan operations:
plan, execute, pause, resume, cancel. Used by CLI, web API,
and Claude skill surfaces.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.models import (
    Scan,
    ScanConfig,
    ScanMode,
    ScanStatus,
    ScanTask,
    TargetType,
)
from opentools.scanner.planner import ScanPlanner
from opentools.scanner.target import TargetDetector, TargetValidator


class ScanAPI:
    """Unified entry point for scan orchestration.

    Usage::

        api = ScanAPI()
        scan, tasks = await api.plan(target="/path/to/code", engagement_id="eng-1")
        # Later: result = await api.execute(scan, tasks, on_progress=callback)
        # Or: await api.cancel(scan.id, reason="user requested")
    """

    def __init__(self) -> None:
        self._planner = ScanPlanner()
        self._detector = TargetDetector()
        self._validator = TargetValidator()

        # Track active scans for pause/resume/cancel
        self._active_scans: dict[str, dict[str, Any]] = {}

    async def plan(
        self,
        target: str,
        engagement_id: str,
        profile_name: Optional[str] = None,
        mode: ScanMode = ScanMode.AUTO,
        config: Optional[ScanConfig] = None,
        override_type: Optional[TargetType] = None,
        add_tools: Optional[list[str]] = None,
        remove_tools: Optional[list[str]] = None,
        baseline_scan_id: Optional[str] = None,
    ) -> tuple[Scan, list[ScanTask]]:
        """Plan a scan without executing it.

        Detects target type, loads profile, builds task DAG, and
        returns a Scan object + list of ScanTask objects ready for
        execution.

        Args:
            target: Target string (path, URL, IP, image name, etc.)
            engagement_id: Engagement to bind scan to.
            profile_name: Profile name, or None for auto-detect.
            mode: Scan mode (auto or assisted).
            config: Optional scan configuration.
            override_type: Force a specific target type.
            add_tools: Additional tool names to include.
            remove_tools: Tool names to exclude.
            baseline_scan_id: Previous scan ID for diffing.

        Returns:
            Tuple of (Scan, list[ScanTask]).

        Raises:
            ValueError: If target type cannot be determined.
            FileNotFoundError: If profile does not exist.
        """
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"

        # Detect target
        detected = self._detector.detect(target, override_type=override_type)

        # Resolve profile name for the scan record
        resolved_profile = profile_name
        if resolved_profile is None:
            from opentools.scanner.profiles import DEFAULT_PROFILES
            resolved_profile = DEFAULT_PROFILES.get(detected.target_type)

        # Build task DAG
        tasks = self._planner.plan(
            target=target,
            profile_name=profile_name,
            mode=mode,
            scan_id=scan_id,
            engagement_id=engagement_id,
            config=config,
            override_type=override_type,
            add_tools=add_tools,
            remove_tools=remove_tools,
        )

        # Build Scan record
        scan = Scan(
            id=scan_id,
            engagement_id=engagement_id,
            target=target,
            target_type=detected.target_type,
            resolved_path=detected.resolved_path,
            target_metadata=detected.metadata,
            profile=resolved_profile,
            profile_snapshot={},
            mode=mode,
            status=ScanStatus.PENDING,
            config=config,
            baseline_scan_id=baseline_scan_id,
            tools_planned=list({t.tool for t in tasks}),
            created_at=datetime.now(timezone.utc),
        )

        return scan, tasks

    async def execute(
        self,
        scan: Scan,
        tasks: list[ScanTask],
        on_progress: Optional[Callable] = None,
    ) -> Scan:
        """Execute a planned scan.

        Sets up the ScanEngine, loads tasks, runs the DAG, and returns
        the completed Scan. This method is a placeholder for full
        integration with ScanEngine (to be wired in Plan 4/5).

        Args:
            scan: The Scan object from plan().
            tasks: The task list from plan().
            on_progress: Optional progress callback.

        Returns:
            Updated Scan object with final status.
        """
        cancel = CancellationToken()
        self._active_scans[scan.id] = {
            "scan": scan,
            "cancel": cancel,
        }

        try:
            # Full engine integration will be wired in later plans.
            # For now, just update the scan status to indicate execution
            # would happen here.
            scan = scan.model_copy(
                update={
                    "status": ScanStatus.RUNNING,
                    "started_at": datetime.now(timezone.utc),
                }
            )
            self._active_scans[scan.id]["scan"] = scan
            return scan
        except Exception:
            scan = scan.model_copy(update={"status": ScanStatus.FAILED})
            return scan
        finally:
            # Cleanup will be more involved once engine is integrated
            pass

    async def pause(self, scan_id: str) -> None:
        """Pause a running scan.

        In-flight tasks run to completion; no new tasks are scheduled.

        Args:
            scan_id: ID of the scan to pause.

        Raises:
            KeyError: If scan_id is not active.
        """
        entry = self._active_scans.get(scan_id)
        if entry is None:
            raise KeyError(f"No active scan with id '{scan_id}'")

        engine = entry.get("engine")
        if engine is not None:
            await engine.pause()

    async def resume(self, scan_id: str) -> None:
        """Resume a paused scan.

        Args:
            scan_id: ID of the scan to resume.

        Raises:
            KeyError: If scan_id is not active.
        """
        entry = self._active_scans.get(scan_id)
        if entry is None:
            raise KeyError(f"No active scan with id '{scan_id}'")

        engine = entry.get("engine")
        if engine is not None:
            await engine.resume()

    async def cancel(self, scan_id: str, reason: str) -> None:
        """Cancel a running or paused scan.

        Args:
            scan_id: ID of the scan to cancel.
            reason: Reason for cancellation.

        Raises:
            KeyError: If scan_id is not active.
        """
        entry = self._active_scans.get(scan_id)
        if entry is None:
            raise KeyError(f"No active scan with id '{scan_id}'")

        cancel = entry.get("cancel")
        if cancel is not None:
            await cancel.cancel(reason)
