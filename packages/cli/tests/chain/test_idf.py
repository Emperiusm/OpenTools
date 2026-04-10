import math
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

from opentools.chain.linker.idf import compute_avg_idf, idf_factor
from opentools.chain.linker.context import LinkerContext
from opentools.chain.linker.rules.base import (
    Rule,
    RuleContribution,
    ScopingViolation,
)
from opentools.chain.models import Entity
from opentools.chain.config import ChainConfig


def _entity(mention_count: int) -> Entity:
    now = datetime.now(timezone.utc)
    return Entity(
        id=f"ent_{mention_count}",
        type="host",
        canonical_value=f"10.0.0.{mention_count}",
        first_seen_at=now,
        last_seen_at=now,
        mention_count=mention_count,
    )


def test_idf_factor_rare_entity_amplified():
    # scope_total=100, mention_count=1 -> high IDF
    e = _entity(1)
    avg = 1.0  # baseline
    factor = idf_factor(e, scope_total=100, avg_idf=avg)
    assert factor >= 1.5, f"rare entity should get factor >= 1.5, got {factor}"


def test_idf_factor_common_entity_dampened():
    e = _entity(50)  # 50% of 100 findings
    avg = 1.0
    factor = idf_factor(e, scope_total=100, avg_idf=avg)
    assert factor <= 0.5


def test_idf_factor_clamped_lower():
    e = _entity(200)
    factor = idf_factor(e, scope_total=100, avg_idf=1.0)
    assert factor >= 0.2


def test_idf_factor_clamped_upper():
    e = _entity(1)
    factor = idf_factor(e, scope_total=100, avg_idf=0.001)
    assert factor <= 2.0


def test_compute_avg_idf_empty_returns_one():
    assert compute_avg_idf([], 100) == 1.0


def test_compute_avg_idf_basic():
    entities = [_entity(1), _entity(10), _entity(50)]
    avg = compute_avg_idf(entities, 100)
    assert avg > 0
    # Manual calc: log(101/2) + log(101/11) + log(101/51) / 3
    expected = (math.log(101/2) + math.log(101/11) + math.log(101/51)) / 3
    assert abs(avg - expected) < 0.001


# ─── LinkerContext ────────────────────────────────────────────────────


def test_linker_context_construction():
    cfg = ChainConfig()
    ctx = LinkerContext(
        user_id=None,
        is_web=False,
        scope_total_findings=100,
        avg_idf=1.0,
        stopwords_extra=[],
        common_entity_pct=0.20,
        common_entity_threshold=20,
        config=cfg,
        generation=1,
    )
    assert ctx.scope_total_findings == 100
    assert ctx.common_entity_threshold == 20
    assert ctx.user_id is None
    assert ctx.is_web is False


def test_linker_context_threshold_auto():
    """common_entity_threshold should be derivable from scope_total and pct."""
    from opentools.chain.linker.context import derive_common_entity_threshold
    assert derive_common_entity_threshold(100, 0.20) == 20
    assert derive_common_entity_threshold(50, 0.20) == 10
    assert derive_common_entity_threshold(7, 0.20) == 2  # ceil(1.4)


# ─── Rule base ────────────────────────────────────────────────────────


def test_rule_contribution_dataclass():
    c = RuleContribution(
        rule="shared_strong_entity",
        weight=1.2,
        details={"entity_id": "abc"},
        direction="symmetric",
        idf_factor=1.5,
    )
    assert c.rule == "shared_strong_entity"
    assert c.weight == 1.2
    assert c.direction == "symmetric"


def test_scoping_violation_is_runtime_error():
    # Used by cross-scope rules in web contexts without user_id
    with pytest.raises(ScopingViolation):
        raise ScopingViolation("test")

    assert issubclass(ScopingViolation, RuntimeError)
