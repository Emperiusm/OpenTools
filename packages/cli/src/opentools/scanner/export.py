"""ScanResultExporter — JSON, SARIF 2.1, CSV, and Markdown export.

Each method takes scan metadata and findings, returning a string in the
requested format.
"""

from __future__ import annotations

import csv
import io
import json

from opentools.scanner.models import (
    DeduplicatedFinding,
    Scan,
)

_SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


class ScanResultExporter:
    """Export scan results in multiple formats."""

    # -----------------------------------------------------------------------
    # JSON
    # -----------------------------------------------------------------------

    def to_json(
        self,
        scan: Scan,
        findings: list[DeduplicatedFinding],
    ) -> str:
        """Export as structured JSON."""
        data = {
            "scan": json.loads(scan.model_dump_json()),
            "findings": [json.loads(f.model_dump_json()) for f in findings],
            "metadata": {
                "export_format": "opentools-json",
                "export_version": "1.0.0",
            },
        }
        return json.dumps(data, indent=2, default=str)

    # -----------------------------------------------------------------------
    # SARIF 2.1
    # -----------------------------------------------------------------------

    def to_sarif(
        self,
        scan: Scan,
        findings: list[DeduplicatedFinding],
    ) -> str:
        """Export as SARIF 2.1.0 JSON."""
        results = []
        rules_seen: dict[str, dict] = {}

        for f in findings:
            rule_id = f.cwe or f.fingerprint
            level = _SEVERITY_TO_SARIF_LEVEL.get(
                f.severity_consensus.lower(), "note"
            )

            # Build location
            locations = []
            if f.location_fingerprint:
                parts = f.location_fingerprint.rsplit(":", 1)
                artifact_uri = parts[0] if parts else f.location_fingerprint
                try:
                    line = int(parts[1]) if len(parts) > 1 else None
                except ValueError:
                    line = None

                location: dict = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_uri},
                    },
                }
                if line is not None:
                    location["physicalLocation"]["region"] = {
                        "startLine": line,
                    }
                locations.append(location)

            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f.canonical_title},
                "locations": locations,
                "fingerprints": {"opentools/v1": f.fingerprint},
                "properties": {
                    "confidence": f.confidence_score,
                    "tools": f.tools,
                    "corroboration_count": f.corroboration_count,
                },
            }
            results.append(result)

            # Collect rules
            if rule_id not in rules_seen:
                rules_seen[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": f.canonical_title},
                }

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "opentools-scanner",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/opentools",
                            "rules": list(rules_seen.values()),
                        },
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": scan.status == "completed",
                            "startTimeUtc": scan.started_at.isoformat() if scan.started_at else None,
                            "endTimeUtc": scan.completed_at.isoformat() if scan.completed_at else None,
                        },
                    ],
                },
            ],
        }

        return json.dumps(sarif, indent=2, default=str)

    # -----------------------------------------------------------------------
    # CSV
    # -----------------------------------------------------------------------

    def to_csv(self, findings: list[DeduplicatedFinding]) -> str:
        """Export findings as CSV."""
        output = io.StringIO()
        fieldnames = [
            "id", "severity", "title", "cwe", "location", "confidence",
            "tools", "corroboration", "status", "evidence_quality",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for f in findings:
            writer.writerow({
                "id": f.id,
                "severity": f.severity_consensus,
                "title": f.canonical_title,
                "cwe": f.cwe or "",
                "location": f.location_fingerprint,
                "confidence": f"{f.confidence_score:.2f}",
                "tools": "; ".join(f.tools),
                "corroboration": f.corroboration_count,
                "status": f.status,
                "evidence_quality": f.evidence_quality_best,
            })

        return output.getvalue()

    # -----------------------------------------------------------------------
    # Markdown
    # -----------------------------------------------------------------------

    def to_markdown(
        self,
        scan: Scan,
        findings: list[DeduplicatedFinding],
    ) -> str:
        """Export as Markdown report."""
        lines: list[str] = []

        # Header
        lines.append(f"# Scan Report: {scan.id}")
        lines.append("")
        lines.append(f"**Target:** {scan.target}")
        lines.append(f"**Target Type:** {scan.target_type}")
        lines.append(f"**Mode:** {scan.mode}")
        lines.append(f"**Status:** {scan.status}")
        if scan.started_at:
            lines.append(f"**Started:** {scan.started_at.isoformat()}")
        if scan.completed_at:
            lines.append(f"**Completed:** {scan.completed_at.isoformat()}")
        lines.append(f"**Tools:** {', '.join(scan.tools_completed)}")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"**Total Findings:** {len(findings)}")

        # Severity breakdown
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = f.severity_consensus.lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sev_counts.get(sev, 0)
            if count > 0:
                lines.append(f"- **{sev.capitalize()}:** {count}")

        if not findings:
            lines.append("")
            lines.append("No findings discovered.")
            return "\n".join(lines)

        lines.append("")

        # Findings table
        lines.append("## Findings")
        lines.append("")
        lines.append("| # | Severity | Title | CWE | Location | Confidence | Tools |")
        lines.append("|---|----------|-------|-----|----------|------------|-------|")

        for i, f in enumerate(findings, 1):
            tools_str = ", ".join(f.tools)
            lines.append(
                f"| {i} | {f.severity_consensus} | {f.canonical_title} | "
                f"{f.cwe or 'N/A'} | {f.location_fingerprint} | "
                f"{f.confidence_score:.0%} | {tools_str} |"
            )

        lines.append("")
        lines.append("---")
        lines.append("*Generated by OpenTools Scanner*")

        return "\n".join(lines)
