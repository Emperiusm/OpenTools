"""FindingCorrelationEngine — attack chain and kill chain detection.

Detects:
- same_endpoint: multiple findings on the same file/endpoint
- same_cwe: multiple findings with the same CWE
- attack_chain: findings forming a known attack pattern
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone

from opentools.scanner.models import DeduplicatedFinding, FindingCorrelation

# Known attack chain patterns: lists of CWE sets that form escalation paths
_ATTACK_CHAIN_PATTERNS: list[dict] = [
    {
        "name": "Credential theft + injection",
        "cwes": [{"CWE-798", "CWE-200"}, {"CWE-89", "CWE-78", "CWE-77"}],
        "narrative": "Hardcoded credentials combined with injection vulnerabilities enable authenticated exploitation",
    },
    {
        "name": "File access + code execution",
        "cwes": [{"CWE-22", "CWE-434"}, {"CWE-94", "CWE-78", "CWE-95"}],
        "narrative": "Path traversal or file upload combined with code execution enables remote code execution",
    },
]


class FindingCorrelationEngine:
    """Detects correlations between findings within a scan."""

    def correlate(
        self,
        findings: list[DeduplicatedFinding],
        scan_id: str,
        engagement_id: str,
    ) -> list[FindingCorrelation]:
        """Detect correlations and return FindingCorrelation objects."""
        if len(findings) < 2:
            return []

        correlations: list[FindingCorrelation] = []
        now = datetime.now(timezone.utc)

        # 1. Same endpoint correlation
        correlations.extend(
            self._correlate_by_endpoint(findings, scan_id, engagement_id, now)
        )

        # 2. Same CWE correlation
        correlations.extend(
            self._correlate_by_cwe(findings, scan_id, engagement_id, now)
        )

        # 3. Attack chain detection
        correlations.extend(
            self._detect_attack_chains(findings, scan_id, engagement_id, now)
        )

        return correlations

    def _correlate_by_endpoint(
        self,
        findings: list[DeduplicatedFinding],
        scan_id: str,
        engagement_id: str,
        now: datetime,
    ) -> list[FindingCorrelation]:
        """Group findings by file/endpoint."""
        by_file: dict[str, list[DeduplicatedFinding]] = defaultdict(list)
        for f in findings:
            # Extract file path from location fingerprint
            file_part = f.location_fingerprint.rsplit(":", 1)[0] if ":" in f.location_fingerprint else f.location_fingerprint
            by_file[file_part].append(f)

        result = []
        for file_path, group in by_file.items():
            if len(group) < 2:
                continue
            # Only correlate if findings have different titles
            titles = {f.canonical_title for f in group}
            if len(titles) < 2:
                continue

            severity = max(
                (f.severity_consensus for f in group),
                key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(s, 0),
            )
            result.append(FindingCorrelation(
                id=str(uuid.uuid4()),
                engagement_id=engagement_id,
                scan_id=scan_id,
                finding_ids=[f.id for f in group],
                correlation_type="same_endpoint",
                narrative=f"Multiple vulnerability types found in {file_path}: {', '.join(sorted(titles))}",
                severity=severity,
                created_at=now,
            ))
        return result

    def _correlate_by_cwe(
        self,
        findings: list[DeduplicatedFinding],
        scan_id: str,
        engagement_id: str,
        now: datetime,
    ) -> list[FindingCorrelation]:
        """Group findings by CWE."""
        by_cwe: dict[str, list[DeduplicatedFinding]] = defaultdict(list)
        for f in findings:
            if f.cwe:
                by_cwe[f.cwe].append(f)

        result = []
        for cwe, group in by_cwe.items():
            if len(group) < 2:
                continue
            severity = max(
                (f.severity_consensus for f in group),
                key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(s, 0),
            )
            result.append(FindingCorrelation(
                id=str(uuid.uuid4()),
                engagement_id=engagement_id,
                scan_id=scan_id,
                finding_ids=[f.id for f in group],
                correlation_type="same_cwe",
                narrative=f"Multiple instances of {cwe} detected across {len(group)} locations",
                severity=severity,
                created_at=now,
            ))
        return result

    def _detect_attack_chains(
        self,
        findings: list[DeduplicatedFinding],
        scan_id: str,
        engagement_id: str,
        now: datetime,
    ) -> list[FindingCorrelation]:
        """Detect known attack chain patterns."""
        result = []

        for pattern in _ATTACK_CHAIN_PATTERNS:
            # Check if findings match each stage of the chain
            matched_stages = []
            matched_findings: list[str] = []
            for stage_cwes in pattern["cwes"]:
                stage_matches = [
                    f for f in findings if f.cwe in stage_cwes
                ]
                if stage_matches:
                    matched_stages.append(True)
                    matched_findings.extend(f.id for f in stage_matches)
                else:
                    matched_stages.append(False)

            if all(matched_stages) and len(matched_findings) >= 2:
                result.append(FindingCorrelation(
                    id=str(uuid.uuid4()),
                    engagement_id=engagement_id,
                    scan_id=scan_id,
                    finding_ids=list(set(matched_findings)),
                    correlation_type="attack_chain",
                    narrative=f"{pattern['name']}: {pattern['narrative']}",
                    severity="critical",
                    created_at=now,
                ))

        return result
