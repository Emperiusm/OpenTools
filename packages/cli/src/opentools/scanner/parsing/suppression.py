"""SuppressionEngine — applies path/CWE/severity/tool suppression rules.

Supports:
- path_pattern: fnmatch-style glob against location_fingerprint
- cwe: exact CWE match + hierarchical (suppress parent suppresses children)
- severity_below: suppress all findings below a given severity
- tool: suppress findings from a specific tool
"""

from __future__ import annotations

import fnmatch
from datetime import datetime, timezone

from opentools.scanner.cwe import CWEHierarchy
from opentools.scanner.models import DeduplicatedFinding, SuppressionRule

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class SuppressionEngine:
    """Applies suppression rules to a list of deduplicated findings."""

    def __init__(self) -> None:
        self._cwe = CWEHierarchy()

    def apply(
        self,
        rules: list[SuppressionRule],
        findings: list[DeduplicatedFinding],
    ) -> list[DeduplicatedFinding]:
        """Return a new list of findings with suppression flags set."""
        now = datetime.now(timezone.utc)
        active_rules = [r for r in rules if r.expires_at is None or r.expires_at > now]

        result = []
        for f in findings:
            matched_rule = self._check_rules(active_rules, f)
            if matched_rule is not None:
                result.append(f.model_copy(update={
                    "suppressed": True,
                    "suppression_rule_id": matched_rule.id,
                }))
            else:
                result.append(f)
        return result

    def _check_rules(
        self,
        rules: list[SuppressionRule],
        finding: DeduplicatedFinding,
    ) -> SuppressionRule | None:
        """Return the first matching rule, or None."""
        for rule in rules:
            if self._rule_matches(rule, finding):
                return rule
        return None

    def _rule_matches(self, rule: SuppressionRule, finding: DeduplicatedFinding) -> bool:
        """Check if a single rule matches a finding."""
        if rule.rule_type == "path_pattern":
            return self._match_path(rule.pattern, finding.location_fingerprint)
        elif rule.rule_type == "cwe":
            return self._match_cwe(rule.pattern, finding.cwe)
        elif rule.rule_type == "severity_below":
            return self._match_severity_below(rule.pattern, finding.severity_consensus)
        elif rule.rule_type == "tool":
            return self._match_tool(rule.pattern, finding.tools)
        return False

    def _match_path(self, pattern: str, location_fingerprint: str) -> bool:
        """Match path pattern against location fingerprint (file part)."""
        # Location fingerprint is typically "path:line" — extract path
        file_part = location_fingerprint.rsplit(":", 1)[0] if ":" in location_fingerprint else location_fingerprint
        return fnmatch.fnmatch(file_part, pattern)

    def _match_cwe(self, pattern_cwe: str, finding_cwe: str | None) -> bool:
        """Match CWE with hierarchical support (parent suppresses children)."""
        if finding_cwe is None:
            return False
        if finding_cwe == pattern_cwe:
            return True

        # Check if finding's CWE is a descendant of the pattern CWE
        current = finding_cwe
        visited: set[str] = set()
        while current is not None and current not in visited:
            visited.add(current)
            parent = self._cwe.get_parent(current)
            if parent == pattern_cwe:
                return True
            current = parent

        return False

    def _match_severity_below(self, threshold: str, finding_severity: str) -> bool:
        """Suppress if finding severity is strictly below threshold."""
        threshold_val = _SEVERITY_ORDER.get(threshold.lower(), 0)
        finding_val = _SEVERITY_ORDER.get(finding_severity.lower(), 0)
        return finding_val < threshold_val

    def _match_tool(self, pattern_tool: str, finding_tools: list[str]) -> bool:
        """Suppress if any of the finding's tools match."""
        return pattern_tool in finding_tools
