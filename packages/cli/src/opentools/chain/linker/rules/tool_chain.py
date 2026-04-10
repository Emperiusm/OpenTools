"""ToolChainRule — findings from tools in a known handoff chain on the same host."""
from __future__ import annotations

from opentools.chain.linker.context import LinkerContext
from opentools.chain.linker.rules.base import RuleContribution
from opentools.chain.models import Entity
from opentools.models import Finding


class ToolChainRule:
    name = "tool_chain"
    default_weight = 0.7
    enabled_by_default = True
    symmetric = False
    requires_shared_entity = True
    reads_cross_scope = False

    def __init__(self, weight: float = 0.7):
        self.default_weight = weight

    def apply(
        self,
        finding_a: Finding,
        finding_b: Finding,
        shared_entities: list[Entity],
        context: LinkerContext,
    ) -> list[RuleContribution]:
        # Need at least one shared host/ip for the handoff to be meaningful
        if not any(e.type in {"host", "ip"} for e in shared_entities):
            return []
        chains = context.config.linker.tool_chains
        for tc in chains:
            if finding_a.tool == tc.from_tool and finding_b.tool == tc.to_tool and finding_b.created_at >= finding_a.created_at:
                return [
                    RuleContribution(
                        rule=self.name,
                        weight=tc.weight,
                        details={"from": tc.from_tool, "to": tc.to_tool},
                        direction="a_to_b",
                    )
                ]
            if finding_b.tool == tc.from_tool and finding_a.tool == tc.to_tool and finding_a.created_at >= finding_b.created_at:
                return [
                    RuleContribution(
                        rule=self.name,
                        weight=tc.weight,
                        details={"from": tc.from_tool, "to": tc.to_tool},
                        direction="b_to_a",
                    )
                ]
        return []
