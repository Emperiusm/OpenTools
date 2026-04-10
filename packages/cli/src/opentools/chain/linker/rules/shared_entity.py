"""SharedStrongEntityRule and SharedWeakEntityRule.

Shared-entity rules contribute weight per distinct entity shared between
two findings. Strong entity types (host, ip, user, cve, etc.) contribute
the base weight; weak types (file_path, port, etc.) contribute less.
Both rules skip stopwords and entities above the common-entity threshold,
and multiply the base weight by the entity's IDF factor.
"""
from __future__ import annotations

from opentools.chain.linker.context import LinkerContext
from opentools.chain.linker.idf import idf_factor
from opentools.chain.linker.rules.base import RuleContribution
from opentools.chain.models import Entity
from opentools.chain.stopwords import is_stopword
from opentools.chain.types import is_strong_entity_type, is_weak_entity_type
from opentools.models import Finding


class SharedStrongEntityRule:
    name = "shared_strong_entity"
    default_weight = 1.0
    enabled_by_default = True
    symmetric = True
    requires_shared_entity = True
    reads_cross_scope = False

    def __init__(self, weight: float = 1.0):
        self.default_weight = weight

    def apply(
        self,
        finding_a: Finding,
        finding_b: Finding,
        shared_entities: list[Entity],
        context: LinkerContext,
    ) -> list[RuleContribution]:
        out: list[RuleContribution] = []
        for e in shared_entities:
            if not is_strong_entity_type(e.type):
                continue
            if is_stopword(e.type, e.canonical_value, extras=context.stopwords_extra):
                continue
            if e.mention_count > context.common_entity_threshold:
                continue
            factor = (
                idf_factor(e, context.scope_total_findings, context.avg_idf)
                if context.config.linker.idf_enabled else 1.0
            )
            out.append(
                RuleContribution(
                    rule=self.name,
                    weight=self.default_weight * factor,
                    details={"entity_id": e.id, "entity_type": e.type, "canonical_value": e.canonical_value},
                    direction="symmetric",
                    idf_factor=factor,
                )
            )
        return out


class SharedWeakEntityRule:
    name = "shared_weak_entity"
    default_weight = 0.3
    enabled_by_default = True
    symmetric = True
    requires_shared_entity = True
    reads_cross_scope = False

    def __init__(self, weight: float = 0.3):
        self.default_weight = weight

    def apply(
        self,
        finding_a: Finding,
        finding_b: Finding,
        shared_entities: list[Entity],
        context: LinkerContext,
    ) -> list[RuleContribution]:
        out: list[RuleContribution] = []
        for e in shared_entities:
            if not is_weak_entity_type(e.type):
                continue
            if is_stopword(e.type, e.canonical_value, extras=context.stopwords_extra):
                continue
            if e.mention_count > context.common_entity_threshold:
                continue
            factor = (
                idf_factor(e, context.scope_total_findings, context.avg_idf)
                if context.config.linker.idf_enabled else 1.0
            )
            out.append(
                RuleContribution(
                    rule=self.name,
                    weight=self.default_weight * factor,
                    details={"entity_id": e.id, "entity_type": e.type, "canonical_value": e.canonical_value},
                    direction="symmetric",
                    idf_factor=factor,
                )
            )
        return out
