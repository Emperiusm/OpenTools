"""CVEAdjacencyRule — findings sharing a CVE with differing severities."""
from __future__ import annotations

from opentools.chain.linker.context import LinkerContext
from opentools.chain.linker.rules.base import RuleContribution
from opentools.chain.models import Entity
from opentools.models import Finding, Severity


_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _rank(sev) -> int:
    try:
        return _SEVERITY_ORDER.get(sev, 0)
    except Exception:
        return 0


class CVEAdjacencyRule:
    name = "cve_adjacency"
    default_weight = 0.6
    enabled_by_default = True
    symmetric = False
    requires_shared_entity = True
    reads_cross_scope = False

    def __init__(self, weight: float = 0.6):
        self.default_weight = weight

    def apply(
        self,
        finding_a: Finding,
        finding_b: Finding,
        shared_entities: list[Entity],
        context: LinkerContext,
    ) -> list[RuleContribution]:
        cves = [e for e in shared_entities if e.type == "cve"]
        if not cves:
            return []
        rank_a = _rank(finding_a.severity)
        rank_b = _rank(finding_b.severity)
        if rank_a == rank_b:
            return []
        direction = "a_to_b" if rank_a < rank_b else "b_to_a"
        return [
            RuleContribution(
                rule=self.name,
                weight=self.default_weight,
                details={
                    "shared_cves": [e.canonical_value for e in cves],
                    "severity_direction": direction,
                },
                direction=direction,
            )
        ]
