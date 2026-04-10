"""KillChainAdjacencyRule — findings with MITRE techniques in adjacent tactics."""
from __future__ import annotations

from opentools.chain.linker.context import LinkerContext
from opentools.chain.linker.rules.base import RuleContribution
from opentools.chain.models import Entity
from opentools.models import Finding


# Hand-curated subset of the official ATT&CK technique→tactic mapping.
# Covers the most common techniques in pentest reports; a future task can
# replace this with a full STIX-loaded catalog.
TECHNIQUE_TO_TACTIC: dict[str, str] = {
    "T1566": "TA0001", "T1566.001": "TA0001", "T1566.002": "TA0001",
    "T1190": "TA0001", "T1078": "TA0001",
    "T1059": "TA0002", "T1059.001": "TA0002", "T1059.003": "TA0002",
    "T1203": "TA0002",
    "T1547": "TA0003", "T1547.001": "TA0003", "T1543": "TA0003",
    "T1068": "TA0004", "T1548": "TA0004",
    "T1027": "TA0005", "T1070": "TA0005",
    "T1003": "TA0006", "T1003.001": "TA0006", "T1110": "TA0006",
    "T1018": "TA0007", "T1046": "TA0007", "T1082": "TA0007",
    "T1021": "TA0008", "T1021.001": "TA0008",
    "T1005": "TA0009", "T1056": "TA0009",
    "T1071": "TA0011", "T1071.001": "TA0011", "T1090": "TA0011", "T1105": "TA0011",
    "T1041": "TA0010", "T1048": "TA0010",
    "T1486": "TA0040", "T1485": "TA0040", "T1490": "TA0040",
}

TACTIC_ORDER = [
    "TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006",
    "TA0007", "TA0008", "TA0009", "TA0011", "TA0010", "TA0040",
]


def _tactic_for(technique_id: str) -> str | None:
    return TECHNIQUE_TO_TACTIC.get(technique_id.upper())


def _tactic_position(tactic_id: str) -> int | None:
    try:
        return TACTIC_ORDER.index(tactic_id)
    except ValueError:
        return None


class KillChainAdjacencyRule:
    name = "kill_chain_adjacency"
    default_weight = 0.4
    enabled_by_default = True
    symmetric = False
    requires_shared_entity = False
    reads_cross_scope = False

    def __init__(self, weight: float = 0.4):
        self.default_weight = weight

    def apply(
        self,
        finding_a: Finding,
        finding_b: Finding,
        shared_entities: list[Entity],
        context: LinkerContext,
    ) -> list[RuleContribution]:
        # Extract techniques from shared entities (mitre_technique type)
        # Note: shared_entities will be empty most of the time because this
        # rule doesn't require shared entities. The CURRENT implementation
        # uses shared techniques only (technique entities shared between the two
        # findings). A full implementation would look up each finding's
        # mentioned techniques independently, which is a linker responsibility.
        techniques = [e.canonical_value for e in shared_entities if e.type == "mitre_technique"]
        if len(techniques) < 2:
            return []

        # For pairs of techniques, find the tactic distance
        contributions: list[RuleContribution] = []
        seen_pairs = set()
        for t1 in techniques:
            for t2 in techniques:
                if t1 >= t2:
                    continue
                if (t1, t2) in seen_pairs:
                    continue
                seen_pairs.add((t1, t2))
                tac_a = _tactic_for(t1)
                tac_b = _tactic_for(t2)
                if not tac_a or not tac_b:
                    continue
                pos_a = _tactic_position(tac_a)
                pos_b = _tactic_position(tac_b)
                if pos_a is None or pos_b is None:
                    continue
                distance = abs(pos_a - pos_b)
                if distance == 0 or distance > 2:
                    continue
                direction = "a_to_b" if pos_a < pos_b else "b_to_a"
                contributions.append(
                    RuleContribution(
                        rule=self.name,
                        weight=self.default_weight,
                        details={"tactic_a": tac_a, "tactic_b": tac_b, "distance": distance},
                        direction=direction,
                    )
                )
        return contributions
