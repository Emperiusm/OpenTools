"""Rule protocol, RuleContribution, and scoping violation exception."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol, runtime_checkable

from opentools.chain.linker.context import LinkerContext
from opentools.chain.models import Entity
from opentools.models import Finding


Direction = Literal["a_to_b", "b_to_a", "symmetric"]


@dataclass
class RuleContribution:
    """A single piece of evidence that two findings should be linked.

    One Rule can emit multiple contributions per pair (e.g. one per shared
    entity). The linker sums contributions per directed edge and stores
    them verbatim in FindingRelation.reasons for auditability.
    """
    rule: str
    weight: float
    details: dict
    direction: Direction
    idf_factor: float | None = None


class ScopingViolation(RuntimeError):
    """Raised when a cross-scope rule runs in a web context without user_id.

    Cross-scope rules (``reads_cross_scope=True``) MUST have their queries
    filtered by the current user_id to prevent privacy leaks between users.
    The linker enforces this invariant at rule-apply time.
    """


@runtime_checkable
class Rule(Protocol):
    """Pure function from (finding_a, finding_b, shared_entities, ctx) to contributions.

    Rules declare metadata as class attributes so the linker can route
    inputs efficiently (e.g. skip rules that require shared entities when
    there are none).
    """
    name: str
    default_weight: float
    enabled_by_default: bool
    symmetric: bool
    requires_shared_entity: bool
    reads_cross_scope: bool

    def apply(
        self,
        finding_a: Finding,
        finding_b: Finding,
        shared_entities: list[Entity],
        context: LinkerContext,
    ) -> list[RuleContribution]: ...
