"""Bayesian weight calibration service.

Uses Beta distribution priors per linking rule, updated from user
confirm/reject decisions. Posterior mean = alpha / (alpha + beta_param)
estimates each rule's reliability.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ChainCalibrationState, ChainFindingRelation

# Default Beta priors per rule
DEFAULT_PRIORS: dict[str, tuple[float, float]] = {
    "shared_strong_entity": (2.0, 1.0),
    "cve_adjacency": (2.0, 1.0),
    "temporal_proximity": (1.0, 1.0),
    "kill_chain": (1.0, 1.0),
    "tool_chain": (1.0, 1.0),
    "cross_engagement_ioc": (1.0, 1.0),
}

MINIMUM_DECISIONS = 20


async def get_or_create_priors(
    session: AsyncSession, user_id: uuid.UUID
) -> dict[str, ChainCalibrationState]:
    """Load existing calibration state or seed defaults."""
    stmt = select(ChainCalibrationState).where(
        ChainCalibrationState.user_id == user_id
    )
    result = await session.execute(stmt)
    existing = {row.rule: row for row in result.scalars()}

    now = datetime.now(timezone.utc)
    for rule, (alpha, beta) in DEFAULT_PRIORS.items():
        if rule not in existing:
            row = ChainCalibrationState(
                id=f"cal-{user_id}-{rule}",
                user_id=user_id,
                rule=rule,
                alpha=alpha,
                beta_param=beta,
                observations=0,
                last_calibrated_at=now,
            )
            session.add(row)
            existing[rule] = row

    await session.flush()
    return existing


async def count_user_decisions(
    session: AsyncSession, user_id: uuid.UUID, engagement_id: str | None = None
) -> int:
    """Count total user-confirmed + user-rejected edges."""
    stmt = select(func.count()).select_from(ChainFindingRelation).where(
        ChainFindingRelation.user_id == user_id,
        ChainFindingRelation.status.in_(["user_confirmed", "user_rejected"]),
    )
    if engagement_id:
        from app.models import Finding
        finding_ids_stmt = select(Finding.id).where(
            Finding.engagement_id == engagement_id,
            Finding.user_id == user_id,
        )
        stmt = stmt.where(
            ChainFindingRelation.source_finding_id.in_(finding_ids_stmt)
        )
    result = await session.execute(stmt)
    return result.scalar() or 0


async def calibrate(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    engagement_id: str | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run Bayesian calibration from user decisions.

    Returns dict with 'rules' (per-rule posteriors), 'edges_updated',
    'below_threshold'.
    """
    import orjson

    total_decisions = await count_user_decisions(session, user_id, engagement_id)
    if total_decisions < MINIMUM_DECISIONS:
        return {
            "rules": [],
            "edges_updated": 0,
            "below_threshold": True,
            "total_decisions": total_decisions,
            "minimum_required": MINIMUM_DECISIONS,
        }

    # Load or seed priors
    priors = await get_or_create_priors(session, user_id)

    # Reset to defaults before re-counting
    for rule, (alpha, beta) in DEFAULT_PRIORS.items():
        if rule in priors:
            priors[rule].alpha = alpha
            priors[rule].beta_param = beta
            priors[rule].observations = 0

    # Fetch all user-decided edges
    decided_stmt = select(ChainFindingRelation).where(
        ChainFindingRelation.user_id == user_id,
        ChainFindingRelation.status.in_(["user_confirmed", "user_rejected"]),
    )
    if engagement_id:
        from app.models import Finding
        finding_ids_stmt = select(Finding.id).where(
            Finding.engagement_id == engagement_id,
            Finding.user_id == user_id,
        )
        decided_stmt = decided_stmt.where(
            ChainFindingRelation.source_finding_id.in_(finding_ids_stmt)
        )

    decided_result = await session.execute(decided_stmt)
    decided_edges = list(decided_result.scalars())

    # Update priors from decisions
    for edge in decided_edges:
        reasons_data = orjson.loads(edge.reasons_json) if edge.reasons_json else []
        rules_fired = {r["rule"] for r in reasons_data if "rule" in r}

        for rule in rules_fired:
            if rule not in priors:
                continue
            if edge.status == "user_confirmed":
                priors[rule].alpha += 1
            elif edge.status == "user_rejected":
                priors[rule].beta_param += 1
            priors[rule].observations += 1

    now = datetime.now(timezone.utc)
    for p in priors.values():
        p.last_calibrated_at = now

    # Build posteriors summary
    rules_summary = [
        {
            "rule": rule,
            "alpha": priors[rule].alpha,
            "beta": priors[rule].beta_param,
            "posterior": priors[rule].alpha / (priors[rule].alpha + priors[rule].beta_param),
            "observations": priors[rule].observations,
        }
        for rule in sorted(priors.keys())
    ]

    edges_updated = 0
    if not dry_run:
        # Re-score all non-rejected edges with bayesian weights
        posteriors = {
            rule: priors[rule].alpha / (priors[rule].alpha + priors[rule].beta_param)
            for rule in priors
        }

        all_edges_stmt = select(ChainFindingRelation).where(
            ChainFindingRelation.user_id == user_id,
            ChainFindingRelation.status.notin_(["rejected", "user_rejected"]),
        )
        all_result = await session.execute(all_edges_stmt)
        all_edges = list(all_result.scalars())

        for edge in all_edges:
            reasons_data = orjson.loads(edge.reasons_json) if edge.reasons_json else []
            new_weight = 0.0
            for reason in reasons_data:
                rule = reason.get("rule", "")
                contribution = reason.get("weight_contribution", 0.0)
                posterior = posteriors.get(rule, 1.0)
                new_weight += contribution * posterior

            # Cap at 1.0
            new_weight = min(new_weight, 1.0)

            if abs(edge.weight - new_weight) > 0.001:
                edge.weight = new_weight
                edge.weight_model_version = "bayesian_v1"
                edge.updated_at = now
                edges_updated += 1

        # Persist calibration state and edge updates
        for p in priors.values():
            session.add(p)
        await session.commit()

    return {
        "rules": rules_summary,
        "edges_updated": edges_updated,
        "below_threshold": False,
        "total_decisions": total_decisions,
        "minimum_required": MINIMUM_DECISIONS,
    }
