"""RemediationGrouper — groups findings by shared fix.

Groups findings that share the same CWE (and therefore likely the same
remediation strategy) into RemediationGroup objects.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone

from opentools.scanner.models import DeduplicatedFinding, RemediationGroup

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# CWE to remediation action mapping
_CWE_ACTIONS: dict[str, tuple[str, str]] = {
    "CWE-89": ("Use parameterized queries / prepared statements", "code_fix"),
    "CWE-79": ("Apply output encoding / Content Security Policy", "code_fix"),
    "CWE-78": ("Avoid shell commands; use safe APIs with allowlists", "code_fix"),
    "CWE-77": ("Use safe APIs instead of command construction", "code_fix"),
    "CWE-22": ("Validate and canonicalize file paths", "code_fix"),
    "CWE-798": ("Move credentials to secret management system", "config_change"),
    "CWE-502": ("Use safe serialization formats (JSON) or allowlists", "code_fix"),
    "CWE-611": ("Disable external entity processing in XML parsers", "code_fix"),
    "CWE-918": ("Validate and restrict outbound URLs", "code_fix"),
    "CWE-352": ("Implement anti-CSRF tokens", "code_fix"),
    "CWE-601": ("Validate redirect URLs against allowlist", "code_fix"),
    "CWE-327": ("Replace with strong cryptographic algorithms", "code_fix"),
    "CWE-434": ("Validate file types, use secure storage", "code_fix"),
    "CWE-94": ("Avoid dynamic code execution; use safe alternatives", "code_fix"),
    "CWE-95": ("Remove eval() usage; use safe alternatives", "code_fix"),
}


class RemediationGrouper:
    """Groups findings by shared remediation action."""

    def group(
        self,
        findings: list[DeduplicatedFinding],
        scan_id: str,
        engagement_id: str,
    ) -> list[RemediationGroup]:
        """Group findings and return RemediationGroup objects."""
        if not findings:
            return []

        now = datetime.now(timezone.utc)
        by_cwe: dict[str | None, list[DeduplicatedFinding]] = defaultdict(list)

        for f in findings:
            by_cwe[f.cwe].append(f)

        result: list[RemediationGroup] = []
        for cwe, group in by_cwe.items():
            if cwe is None:
                # Each finding with no CWE gets its own group
                for f in group:
                    result.append(self._build_group(
                        [f], cwe, scan_id, engagement_id, now
                    ))
            else:
                result.append(self._build_group(
                    group, cwe, scan_id, engagement_id, now
                ))

        return result

    def _build_group(
        self,
        findings: list[DeduplicatedFinding],
        cwe: str | None,
        scan_id: str,
        engagement_id: str,
        now: datetime,
    ) -> RemediationGroup:
        action_info = _CWE_ACTIONS.get(cwe or "", None)
        if action_info:
            action, action_type = action_info
        else:
            action = f"Review and remediate {cwe or 'unknown'} findings"
            action_type = "code_fix"

        max_sev = max(
            (f.severity_consensus for f in findings),
            key=lambda s: _SEVERITY_ORDER.get(s.lower(), 0),
        )

        # Effort estimate based on count
        count = len(findings)
        if count <= 2:
            effort = "low"
        elif count <= 5:
            effort = "medium"
        else:
            effort = "high"

        return RemediationGroup(
            id=str(uuid.uuid4()),
            engagement_id=engagement_id,
            scan_id=scan_id,
            action=action,
            action_type=action_type,
            finding_ids=[f.id for f in findings],
            findings_count=count,
            max_severity=max_sev,
            effort_estimate=effort,
            created_at=now,
        )
