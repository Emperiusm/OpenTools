"""TemporalProximityRule — findings close in time on the same target."""
from __future__ import annotations

from opentools.chain.linker.context import LinkerContext
from opentools.chain.linker.rules.base import RuleContribution
from opentools.chain.models import Entity
from opentools.models import Finding


class TemporalProximityRule:
    name = "temporal_proximity"
    default_weight = 0.5
    enabled_by_default = True
    symmetric = False
    requires_shared_entity = True
    reads_cross_scope = False

    def __init__(self, weight: float = 0.5, window_minutes: int = 15):
        self.default_weight = weight
        self.window_minutes = window_minutes

    def apply(
        self,
        finding_a: Finding,
        finding_b: Finding,
        shared_entities: list[Entity],
        context: LinkerContext,
    ) -> list[RuleContribution]:
        if finding_a.engagement_id != finding_b.engagement_id:
            return []
        # Require at least one shared host or ip
        target_entities = [e for e in shared_entities if e.type in {"host", "ip"}]
        if not target_entities:
            return []
        delta_min = abs((finding_a.created_at - finding_b.created_at).total_seconds()) / 60.0
        window = context.config.linker.rules.temporal_proximity.window_minutes or self.window_minutes
        if delta_min > window:
            return []
        direction = "a_to_b" if finding_a.created_at <= finding_b.created_at else "b_to_a"
        return [
            RuleContribution(
                rule=self.name,
                weight=self.default_weight,
                details={"window_minutes": window, "delta_minutes": delta_min},
                direction=direction,
            )
        ]
