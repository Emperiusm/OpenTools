"""SharedIOCCrossEngagementRule — IOCs linking findings across engagements.

This is the only built-in rule that reads cross-scope data. In web context
the caller MUST have filtered the candidate set by user_id or the rule
raises ScopingViolation to prevent privacy leaks between users.
"""
from __future__ import annotations

from opentools.chain.linker.context import LinkerContext
from opentools.chain.linker.rules.base import RuleContribution, ScopingViolation
from opentools.chain.models import Entity
from opentools.models import Finding


_IOC_TYPES = {"ip", "domain", "registered_domain", "url", "hash_md5", "hash_sha1", "hash_sha256"}


class SharedIOCCrossEngagementRule:
    name = "shared_ioc_cross_engagement"
    default_weight = 0.8
    enabled_by_default = True
    symmetric = True
    requires_shared_entity = True
    reads_cross_scope = True   # CRITICAL — linker enforces user_id filter

    def __init__(self, weight: float = 0.8):
        self.default_weight = weight

    def apply(
        self,
        finding_a: Finding,
        finding_b: Finding,
        shared_entities: list[Entity],
        context: LinkerContext,
    ) -> list[RuleContribution]:
        if context.is_web and context.user_id is None:
            raise ScopingViolation(
                f"{self.name} requires user_id in web context"
            )
        if finding_a.engagement_id == finding_b.engagement_id:
            return []
        ioc_entities = [e for e in shared_entities if e.type in _IOC_TYPES]
        if not ioc_entities:
            return []
        return [
            RuleContribution(
                rule=self.name,
                weight=self.default_weight,
                details={
                    "ioc_count": len(ioc_entities),
                    "iocs": [f"{e.type}:{e.canonical_value}" for e in ioc_entities[:5]],
                },
                direction="symmetric",
            )
        ]
