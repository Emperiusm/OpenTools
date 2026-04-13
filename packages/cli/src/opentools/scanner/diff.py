"""ScanDiffEngine — baseline comparison between scan results.

Compares current scan findings against a baseline using semantic fingerprints
(the same fingerprint used by the dedup engine).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from opentools.scanner.models import DeduplicatedFinding

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class DiffSummary:
    """Summary statistics for a scan diff."""

    new_count: int = 0
    resolved_count: int = 0
    persistent_count: int = 0
    severity_escalations: int = 0
    severity_deescalations: int = 0
    net_risk_change: str = "stable"  # "increased", "decreased", "stable"


@dataclass
class ScanDiffResult:
    """Full diff result between two scans."""

    scan_id: str
    baseline_id: str
    new_findings: list[DeduplicatedFinding] = field(default_factory=list)
    resolved_findings: list[DeduplicatedFinding] = field(default_factory=list)
    persistent_findings: list[DeduplicatedFinding] = field(default_factory=list)
    severity_changes: list[dict] = field(default_factory=list)
    new_tools_used: list[str] = field(default_factory=list)
    removed_tools: list[str] = field(default_factory=list)
    summary: DiffSummary = field(default_factory=DiffSummary)


class ScanDiffEngine:
    """Compares two sets of deduplicated findings by fingerprint."""

    def diff(
        self,
        current: list[DeduplicatedFinding],
        baseline: list[DeduplicatedFinding],
        scan_id: str,
        baseline_id: str,
    ) -> ScanDiffResult:
        """Compute diff between current and baseline scan findings."""
        baseline_by_fp = {f.fingerprint: f for f in baseline}
        current_by_fp = {f.fingerprint: f for f in current}

        baseline_fps = set(baseline_by_fp.keys())
        current_fps = set(current_by_fp.keys())

        new_fps = current_fps - baseline_fps
        resolved_fps = baseline_fps - current_fps
        persistent_fps = current_fps & baseline_fps

        new_findings = [current_by_fp[fp] for fp in new_fps]
        resolved_findings = [baseline_by_fp[fp] for fp in resolved_fps]
        persistent_findings = [current_by_fp[fp] for fp in persistent_fps]

        # Detect severity changes in persistent findings
        severity_changes = []
        severity_escalations = 0
        severity_deescalations = 0
        for fp in persistent_fps:
            old_sev = baseline_by_fp[fp].severity_consensus
            new_sev = current_by_fp[fp].severity_consensus
            if old_sev != new_sev:
                severity_changes.append({
                    "fingerprint": fp,
                    "from": old_sev,
                    "to": new_sev,
                })
                old_val = _SEVERITY_ORDER.get(old_sev.lower(), 0)
                new_val = _SEVERITY_ORDER.get(new_sev.lower(), 0)
                if new_val > old_val:
                    severity_escalations += 1
                else:
                    severity_deescalations += 1

        # Tool diff
        baseline_tools: set[str] = set()
        for f in baseline:
            baseline_tools.update(f.tools)
        current_tools: set[str] = set()
        for f in current:
            current_tools.update(f.tools)

        new_tools = sorted(current_tools - baseline_tools)
        removed_tools = sorted(baseline_tools - current_tools)

        # Net risk change
        # Weighted: new high/critical increases risk, resolved high/critical decreases
        new_risk = sum(
            _SEVERITY_ORDER.get(f.severity_consensus.lower(), 0) for f in new_findings
        )
        resolved_risk = sum(
            _SEVERITY_ORDER.get(f.severity_consensus.lower(), 0) for f in resolved_findings
        )

        if new_risk > resolved_risk:
            net_risk = "increased"
        elif resolved_risk > new_risk:
            net_risk = "decreased"
        else:
            net_risk = "stable"

        summary = DiffSummary(
            new_count=len(new_findings),
            resolved_count=len(resolved_findings),
            persistent_count=len(persistent_findings),
            severity_escalations=severity_escalations,
            severity_deescalations=severity_deescalations,
            net_risk_change=net_risk,
        )

        return ScanDiffResult(
            scan_id=scan_id,
            baseline_id=baseline_id,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            persistent_findings=persistent_findings,
            severity_changes=severity_changes,
            new_tools_used=new_tools,
            removed_tools=removed_tools,
            summary=summary,
        )
