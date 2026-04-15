# Phase 3C.3: Global View, Bayesian Calibration & Advanced Features — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add global cross-engagement graph view, Bayesian weight calibration, timeline playback, Markdown path export, swim lane Kill Chain layout, and attack vector scoring to the chain visualization.

**Architecture:** Extends the 3C.2 subgraph endpoint (optional `engagement_id` for global mode), adds a calibration service with Beta priors, timeline scrubber component with temporal anchoring, Markdown export endpoint, Kill Chain layout mode in ForceGraphCanvas, and betweenness centrality scoring. One new DB table (`chain_calibration_state`).

**Tech Stack:** FastAPI, SQLAlchemy async, rustworkx (betweenness centrality), Vue 3, PrimeVue, force-graph, TanStack Query

**Spec:** `docs/superpowers/specs/2026-04-13-phase3c3-global-view-bayesian-calibration-design.md`

---

## File Map

### Backend (new/modified)

| File | Action | Responsibility |
|------|--------|---------------|
| `packages/web/backend/app/models.py` | Modify | Add `ChainCalibrationState` table |
| `packages/web/backend/alembic/versions/007_chain_calibration_state.py` | Create | Migration for calibration_state table |
| `packages/web/backend/app/services/chain_service.py` | Modify | Make `engagement_id` optional in subgraph, add `calibrate`, `export_path`, pivotality computation |
| `packages/web/backend/app/services/chain_calibration.py` | Create | Bayesian calibration logic (Beta posteriors, re-scoring) |
| `packages/web/backend/app/services/chain_export.py` | Create | Markdown path report generation |
| `packages/web/backend/app/routes/chain.py` | Modify | Add calibrate endpoint, export endpoint, update subgraph params |
| `packages/cli/src/opentools/chain/cli.py` | Modify | Add `calibrate` command, `--format markdown` to `path` command |
| `packages/web/backend/tests/test_chain_global.py` | Create | Global subgraph, engagement_ids filter, new node fields |
| `packages/web/backend/tests/test_chain_calibration.py` | Create | Calibration endpoint + math tests |
| `packages/web/backend/tests/test_chain_export.py` | Create | Export endpoint tests |

### Frontend (new/modified)

| File | Action | Responsibility |
|------|--------|---------------|
| `packages/web/frontend/src/views/GlobalChainView.vue` | Create | Global cross-engagement graph page |
| `packages/web/frontend/src/components/EngagementFilterChips.vue` | Create | Engagement toggle chips for global view |
| `packages/web/frontend/src/components/ChainTimelineScrubber.vue` | Create | Dual-handle time range slider with activity heatmap |
| `packages/web/frontend/src/components/ForceGraphCanvas.vue` | Modify | Add timeRange prop, layoutMode prop, pivotality glow, engagement color mode |
| `packages/web/frontend/src/components/ChainDetailPanel.vue` | Modify | Add calibrated badge, export button, risk score display |
| `packages/web/frontend/src/components/AppLayout.vue` | Modify | Add "Attack Chain" nav item |
| `packages/web/frontend/src/router/index.ts` | Modify | Add `/chain/global` route |

---

## Task 1: Backend — CalibrationState model + migration

**Files:**
- Modify: `packages/web/backend/app/models.py`
- Create: `packages/web/backend/alembic/versions/007_chain_calibration_state.py`

- [ ] **Step 1: Add CalibrationState model to models.py**

Add at the end of `packages/web/backend/app/models.py`, after the `ChainFindingParserOutput` class:

```python
class ChainCalibrationState(SQLModel, table=True):
    """Per-rule Bayesian calibration state for a user."""
    __tablename__ = "chain_calibration_state"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    rule: str = Field(index=True)
    alpha: float = Field(default=1.0)
    beta_param: float = Field(default=1.0)
    observations: int = Field(default=0)
    last_calibrated_at: datetime = Field(**_TZ_KW)

    __table_args__ = (
        UniqueConstraint("user_id", "rule", name="uq_calibration_state"),
    )
```

Note: field is named `beta_param` (not `beta`) to avoid shadowing Python's `beta` in math contexts.

- [ ] **Step 2: Create Alembic migration**

Create `packages/web/backend/alembic/versions/007_chain_calibration_state.py`:

```python
"""Add chain_calibration_state table.

Revision ID: 007
Revises: 006
"""
import sqlalchemy as sa
from alembic import op

revision = "007"
down_revision = "006"


def upgrade() -> None:
    op.create_table(
        "chain_calibration_state",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("user.id"), nullable=False, index=True),
        sa.Column("rule", sa.String(), nullable=False, index=True),
        sa.Column("alpha", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("beta_param", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("observations", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_calibrated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", "rule", name="uq_calibration_state"),
    )


def downgrade() -> None:
    op.drop_table("chain_calibration_state")
```

- [ ] **Step 3: Verify model imports**

Run: `cd packages/web/backend && python -c "from app.models import ChainCalibrationState; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add packages/web/backend/app/models.py packages/web/backend/alembic/versions/007_chain_calibration_state.py
git commit -m "feat(chain): add ChainCalibrationState model and migration"
```

---

## Task 2: Backend — Calibration service

**Files:**
- Create: `packages/web/backend/app/services/chain_calibration.py`

- [ ] **Step 1: Create the calibration service**

Create `packages/web/backend/app/services/chain_calibration.py`:

```python
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
```

- [ ] **Step 2: Verify import**

Run: `cd packages/web/backend && python -c "from app.services.chain_calibration import calibrate; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add packages/web/backend/app/services/chain_calibration.py
git commit -m "feat(chain): Bayesian calibration service with Beta priors"
```

---

## Task 3: Backend — Export service (Markdown path report)

**Files:**
- Create: `packages/web/backend/app/services/chain_export.py`

- [ ] **Step 1: Create the export service**

Create `packages/web/backend/app/services/chain_export.py`:

```python
"""Markdown attack path report generation."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ChainFindingRelation, Engagement, Finding


async def export_path_markdown(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    finding_ids: list[str],
    engagement_id: str | None = None,
) -> str:
    """Generate a Markdown attack path report from an ordered list of finding IDs."""
    import orjson

    # Fetch engagement name if provided
    eng_name = "Unknown Engagement"
    if engagement_id:
        eng_stmt = select(Engagement).where(
            Engagement.id == engagement_id, Engagement.user_id == user_id
        )
        eng_result = await session.execute(eng_stmt)
        eng = eng_result.scalar_one_or_none()
        if eng:
            eng_name = eng.name

    # Fetch all findings in order
    findings: list[Any] = []
    for fid in finding_ids:
        stmt = select(Finding).where(Finding.id == fid, Finding.user_id == user_id)
        result = await session.execute(stmt)
        f = result.scalar_one_or_none()
        if f is None:
            raise ValueError(f"Finding {fid} not found")
        findings.append(f)

    # Fetch relations between consecutive findings
    relations: list[Any] = []
    for i in range(len(findings) - 1):
        src_id = findings[i].id
        tgt_id = findings[i + 1].id
        rel_stmt = select(ChainFindingRelation).where(
            ChainFindingRelation.user_id == user_id,
            ChainFindingRelation.source_finding_id == src_id,
            ChainFindingRelation.target_finding_id == tgt_id,
        )
        rel_result = await session.execute(rel_stmt)
        rel = rel_result.scalar_one_or_none()
        relations.append(rel)

    # Compute risk score
    severity_multipliers = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    max_sev = max(severity_multipliers.get(f.severity, 1) for f in findings)
    edge_weight_sum = sum(r.weight for r in relations if r)
    hop_count = len(findings) - 1
    import math
    raw_score = (edge_weight_sum * max_sev) / max(math.sqrt(hop_count), 1)
    risk_score = min(raw_score, 10.0)

    # Build markdown
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Attack Path Report",
        "",
        f"**Engagement:** {eng_name}",
        f"**Generated:** {now}",
        f"**Path length:** {len(findings)} steps",
        f"**Risk score:** {risk_score:.1f}/10",
        "",
        "## Summary",
        "",
        _build_summary(findings, relations),
        "",
    ]

    for i, finding in enumerate(findings):
        sev = finding.severity.upper() if finding.severity else "UNKNOWN"
        lines.append(f"## Step {i + 1}: {finding.title} ({sev})")
        lines.append("")
        lines.append(f"- **Tool:** {finding.tool}")
        if finding.phase:
            lines.append(f"- **Phase:** {finding.phase}")
        if finding.evidence:
            evidence = finding.evidence[:500]
            lines.append(f"- **Evidence:** {evidence}")
        if finding.remediation:
            lines.append(f"- **Remediation:** {finding.remediation}")

        if i < len(relations) and relations[i]:
            rel = relations[i]
            reasons_data = orjson.loads(rel.reasons_json) if rel.reasons_json else []
            reason_names = [r.get("rule", "unknown") for r in reasons_data]
            lines.append("")
            lines.append(
                f"**Link to Step {i + 2}:** {', '.join(reason_names)}, "
                f"weight: {rel.weight:.2f}"
            )
        lines.append("")

    # Recommendations
    remediations = [f.remediation for f in findings if f.remediation]
    if remediations:
        lines.append("## Recommendations")
        lines.append("")
        seen = set()
        for i, rem in enumerate(remediations):
            if rem not in seen:
                seen.add(rem)
                lines.append(f"{len(seen)}. {rem}")
        lines.append("")

    return "\n".join(lines)


def _build_summary(findings: list, relations: list) -> str:
    """Template-based path summary."""
    if not findings:
        return "No findings in path."

    first = findings[0]
    last = findings[-1]
    steps = len(findings)

    return (
        f"This attack path spans {steps} steps, starting from "
        f"**{first.title}** ({first.severity}) and culminating in "
        f"**{last.title}** ({last.severity}). "
        f"The path traverses {steps - 1} link(s) through the target environment."
    )
```

- [ ] **Step 2: Verify import**

Run: `cd packages/web/backend && python -c "from app.services.chain_export import export_path_markdown; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add packages/web/backend/app/services/chain_export.py
git commit -m "feat(chain): Markdown attack path report export service"
```

---

## Task 4: Backend — Extend subgraph service for global mode + scoring

**Files:**
- Modify: `packages/web/backend/app/services/chain_service.py`

This task modifies `subgraph_for_engagement` to support optional `engagement_id`, adds `engagement_ids` filter, adds `created_at`/`pivotality`/`engagement_id` to node objects, and adds `engagements` to meta.

- [ ] **Step 1: Update method signature**

In `packages/web/backend/app/services/chain_service.py`, change the `subgraph_for_engagement` method signature:

```python
    async def subgraph_for_engagement(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        engagement_id: str | None = None,       # was required, now optional
        engagement_ids: list[str] | None = None,  # new: filter for global mode
        severities: set[str] | None = None,
        statuses: set[str] | None = None,
        max_nodes: int = 500,
        seed_finding_id: str | None = None,
        hops: int = 2,
        format: str = "force-graph",
    ) -> dict[str, Any]:
```

- [ ] **Step 2: Update the finding query for global mode**

Replace the finding query section. When `engagement_id` is None, query across all engagements (optionally filtered by `engagement_ids`):

```python
        # Fetch findings — scoped to engagement or global
        finding_stmt = select(Finding).where(
            Finding.user_id == user_id,
            Finding.deleted_at.is_(None),
        )
        if engagement_id:
            finding_stmt = finding_stmt.where(Finding.engagement_id == engagement_id)
        elif engagement_ids:
            finding_stmt = finding_stmt.where(Finding.engagement_id.in_(engagement_ids))

        # Total count (before severity filter and cap)
        total_stmt = select(func.count()).select_from(finding_stmt.subquery())
        total_result = await session.execute(total_stmt)
        total_findings = total_result.scalar() or 0

        if severities:
            finding_stmt = finding_stmt.where(Finding.severity.in_(severities))
        finding_stmt = finding_stmt.limit(max_nodes)

        finding_result = await session.execute(finding_stmt)
        findings = list(finding_result.scalars().all())
        finding_ids = {f.id for f in findings}
```

- [ ] **Step 3: Add created_at, engagement_id, and pivotality to nodes**

Replace the node building section:

```python
        # Compute betweenness centrality for pivotality scores
        pivotality_scores: dict[str, float] = {}
        if finding_ids and len(finding_ids) > 1:
            import rustworkx as rx
            g = rx.PyDiGraph()
            id_to_idx: dict[str, int] = {}
            for fid in finding_ids:
                idx = g.add_node(fid)
                id_to_idx[fid] = idx
            for r in relations_orm:
                src = r.source_finding_id
                tgt = r.target_finding_id
                if src in id_to_idx and tgt in id_to_idx:
                    g.add_edge(id_to_idx[src], id_to_idx[tgt], r.weight)
            centrality = rx.betweenness_centrality(g)
            max_c = max(centrality.values()) if centrality else 1.0
            for fid, idx in id_to_idx.items():
                raw = centrality.get(idx, 0.0)
                pivotality_scores[fid] = raw / max_c if max_c > 0 else 0.0

        # Build nodes with new fields
        nodes = [
            {
                "id": f.id,
                "name": f.title,
                "severity": f.severity,
                "tool": f.tool,
                "phase": f.phase,
                "created_at": f.created_at.isoformat() if f.created_at else None,
                "engagement_id": f.engagement_id,
                "pivotality": round(pivotality_scores.get(f.id, 0.0), 3),
            }
            for f in findings
        ]
```

- [ ] **Step 4: Add engagements to meta**

Replace the meta building section:

```python
        # Collect distinct engagements represented in the result
        from app.models import Engagement as EngModel
        eng_ids_in_result = {f.engagement_id for f in findings}
        engagements_meta = []
        if eng_ids_in_result:
            eng_stmt = select(EngModel).where(EngModel.id.in_(eng_ids_in_result))
            eng_result = await session.execute(eng_stmt)
            engagements_meta = [
                {"id": e.id, "name": e.name}
                for e in eng_result.scalars()
            ]

        return {
            "graph": graph,
            "meta": {
                "total_findings": total_findings,
                "rendered_findings": len(findings),
                "filtered": bool(severities) or len(findings) < total_findings,
                "generation": generation,
                "engagements": engagements_meta,
            },
        }
```

- [ ] **Step 5: Verify import**

Run: `cd packages/web/backend && python -c "from app.services.chain_service import ChainService; print('OK')"`
Expected: `OK`

- [ ] **Step 6: Commit**

```bash
git add packages/web/backend/app/services/chain_service.py
git commit -m "feat(chain): global subgraph mode with pivotality, created_at, engagement meta"
```

---

## Task 5: Backend — Route endpoints (calibrate, export, subgraph updates)

**Files:**
- Modify: `packages/web/backend/app/routes/chain.py`

- [ ] **Step 1: Add new Pydantic models**

Add after the existing `RelationStatusUpdate` class:

```python
class CalibrateRequest(BaseModel):
    scope: str = "user"
    engagement_id: Optional[str] = None
    dry_run: bool = False


class CalibrateResponse(BaseModel):
    rules: list[dict]
    edges_updated: int
    below_threshold: bool
    total_decisions: int
    minimum_required: int


class ExportPathRequest(BaseModel):
    finding_ids: list[str]
    engagement_id: Optional[str] = None
```

- [ ] **Step 2: Update subgraph endpoint — make engagement_id optional, add engagement_ids**

Change the `get_subgraph` endpoint signature:

```python
@router.get("/subgraph", response_model=SubgraphResponse)
async def get_subgraph(
    engagement_id: Optional[str] = None,
    engagement_ids: Optional[str] = None,
    severity: Optional[str] = None,
    status_filter: Optional[str] = Query(default=None, alias="status"),
    max_nodes: int = 500,
    seed_finding_id: Optional[str] = None,
    hops: int = 2,
    format: str = "force-graph",
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    service: ChainService = Depends(get_chain_service),
) -> SubgraphResponse:
    severities = set(severity.split(",")) if severity else None
    statuses = set(status_filter.split(",")) if status_filter else None
    eng_ids_list = engagement_ids.split(",") if engagement_ids else None

    result = await service.subgraph_for_engagement(
        db,
        user_id=user.id,
        engagement_id=engagement_id,
        engagement_ids=eng_ids_list,
        severities=severities,
        statuses=statuses,
        max_nodes=max_nodes,
        seed_finding_id=seed_finding_id,
        hops=hops,
        format=format,
    )
    return SubgraphResponse(
        graph=result["graph"],
        meta=SubgraphMeta(**result["meta"]),
    )
```

- [ ] **Step 3: Update SubgraphMeta model to include engagements**

```python
class SubgraphMeta(BaseModel):
    total_findings: int
    rendered_findings: int
    filtered: bool
    generation: int
    engagements: list[dict] = []
```

- [ ] **Step 4: Add calibrate endpoint**

```python
@router.post("/calibrate", response_model=CalibrateResponse)
async def calibrate_weights(
    request: CalibrateRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CalibrateResponse:
    from app.services.chain_calibration import calibrate

    if request.scope not in ("user", "engagement"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="scope must be 'user' or 'engagement'",
        )
    if request.scope == "engagement" and not request.engagement_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="engagement_id required when scope is 'engagement'",
        )

    result = await calibrate(
        db,
        user_id=user.id,
        engagement_id=request.engagement_id if request.scope == "engagement" else None,
        dry_run=request.dry_run,
    )

    if result["below_threshold"]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Need at least {result['minimum_required']} user decisions, have {result['total_decisions']}",
        )

    return CalibrateResponse(**result)
```

- [ ] **Step 5: Add export endpoint**

```python
@router.post("/export/path")
async def export_path(
    request: ExportPathRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    from app.services.chain_export import export_path_markdown

    if len(request.finding_ids) < 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Path must contain at least 2 findings",
        )

    try:
        markdown = await export_path_markdown(
            db,
            user_id=user.id,
            finding_ids=request.finding_ids,
            engagement_id=request.engagement_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    return {"markdown": markdown}
```

- [ ] **Step 6: Verify app starts**

Run: `cd packages/web/backend && python -c "from app.main import app; print('OK')"`
Expected: `OK`

- [ ] **Step 7: Commit**

```bash
git add packages/web/backend/app/routes/chain.py
git commit -m "feat(chain): calibrate, export, and global subgraph endpoints"
```

---

## Task 6: Backend — Tests for global subgraph

**Files:**
- Create: `packages/web/backend/tests/test_chain_global.py`

- [ ] **Step 1: Write tests**

Create `packages/web/backend/tests/test_chain_global.py`:

```python
"""Global subgraph endpoint tests (Phase 3C.3)."""

import uuid
from datetime import datetime, timezone

import pytest

from app.models import ChainFindingRelation, Engagement, Finding
from tests.conftest import test_session_factory

NOW = datetime.now(timezone.utc)


async def _get_user_id(auth_client) -> uuid.UUID:
    eng_resp = await auth_client.post("/api/v1/engagements", json={
        "name": "_uid_probe", "target": "127.0.0.1", "type": "pentest",
    })
    assert eng_resp.status_code == 201
    eng_id = eng_resp.json()["id"]
    async with test_session_factory() as session:
        from sqlalchemy import select
        from app.models import Engagement as Eng
        result = await session.execute(select(Eng).where(Eng.id == eng_id))
        eng = result.scalar_one()
        return eng.user_id


async def _seed(user_id):
    """Seed two engagements with findings and a cross-engagement relation."""
    async with test_session_factory() as session:
        session.add(Engagement(
            id="eng-g1", user_id=user_id, name="Pentest Q1", target="10.0.0.0/24",
            type="pentest", created_at=NOW, updated_at=NOW,
        ))
        session.add(Engagement(
            id="eng-g2", user_id=user_id, name="Web App", target="app.example.com",
            type="pentest", created_at=NOW, updated_at=NOW,
        ))
        await session.flush()
        session.add(Finding(
            id="f-g1", user_id=user_id, engagement_id="eng-g1",
            tool="nmap", severity="high", title="Open SSH", created_at=NOW,
        ))
        session.add(Finding(
            id="f-g2", user_id=user_id, engagement_id="eng-g2",
            tool="nuclei", severity="critical", title="RCE in /api", created_at=NOW,
        ))
        await session.flush()
        session.add(ChainFindingRelation(
            id="rel-cross", user_id=user_id, source_finding_id="f-g1",
            target_finding_id="f-g2", weight=0.6, status="auto_confirmed",
            symmetric=False, created_at=NOW, updated_at=NOW,
        ))
        await session.commit()


@pytest.mark.asyncio
async def test_global_subgraph_returns_cross_engagement(auth_client):
    """Omitting engagement_id returns findings from all engagements."""
    user_id = await _get_user_id(auth_client)
    await _seed(user_id)

    resp = await auth_client.get("/api/chain/subgraph?max_nodes=100")
    assert resp.status_code == 200
    data = resp.json()
    node_ids = {n["id"] for n in data["graph"]["nodes"]}
    assert "f-g1" in node_ids
    assert "f-g2" in node_ids
    assert len(data["graph"]["links"]) >= 1


@pytest.mark.asyncio
async def test_global_subgraph_includes_engagements_meta(auth_client):
    """Meta includes engagements array with id and name."""
    user_id = await _get_user_id(auth_client)
    await _seed(user_id)

    resp = await auth_client.get("/api/chain/subgraph?max_nodes=100")
    data = resp.json()
    eng_ids = {e["id"] for e in data["meta"]["engagements"]}
    assert "eng-g1" in eng_ids
    assert "eng-g2" in eng_ids


@pytest.mark.asyncio
async def test_global_subgraph_engagement_ids_filter(auth_client):
    """engagement_ids param filters to specific engagements."""
    user_id = await _get_user_id(auth_client)
    await _seed(user_id)

    resp = await auth_client.get("/api/chain/subgraph?engagement_ids=eng-g1&max_nodes=100")
    data = resp.json()
    for n in data["graph"]["nodes"]:
        assert n["engagement_id"] == "eng-g1"


@pytest.mark.asyncio
async def test_subgraph_nodes_have_created_at(auth_client):
    """Node objects include created_at field."""
    user_id = await _get_user_id(auth_client)
    await _seed(user_id)

    resp = await auth_client.get("/api/chain/subgraph?engagement_id=eng-g1")
    data = resp.json()
    for n in data["graph"]["nodes"]:
        assert "created_at" in n


@pytest.mark.asyncio
async def test_subgraph_nodes_have_pivotality(auth_client):
    """Node objects include pivotality field."""
    user_id = await _get_user_id(auth_client)
    await _seed(user_id)

    resp = await auth_client.get("/api/chain/subgraph?max_nodes=100")
    data = resp.json()
    for n in data["graph"]["nodes"]:
        assert "pivotality" in n
        assert isinstance(n["pivotality"], (int, float))
```

- [ ] **Step 2: Run tests**

Run: `cd packages/web/backend && python -m pytest tests/test_chain_global.py -v`
Expected: all PASS

- [ ] **Step 3: Commit**

```bash
git add packages/web/backend/tests/test_chain_global.py
git commit -m "test(chain): global subgraph, engagement filter, new node fields"
```

---

## Task 7: Backend — Tests for calibration + export

**Files:**
- Create: `packages/web/backend/tests/test_chain_calibration.py`
- Create: `packages/web/backend/tests/test_chain_export.py`

- [ ] **Step 1: Write calibration tests**

Create `packages/web/backend/tests/test_chain_calibration.py`:

```python
"""Calibration endpoint tests (Phase 3C.3)."""

import uuid
from datetime import datetime, timezone

import pytest

from app.models import ChainFindingRelation, Engagement, Finding
from tests.conftest import test_session_factory

NOW = datetime.now(timezone.utc)


async def _get_user_id(auth_client) -> uuid.UUID:
    eng_resp = await auth_client.post("/api/v1/engagements", json={
        "name": "_uid_probe", "target": "127.0.0.1", "type": "pentest",
    })
    assert eng_resp.status_code == 201
    eng_id = eng_resp.json()["id"]
    async with test_session_factory() as session:
        from sqlalchemy import select
        from app.models import Engagement as Eng
        result = await session.execute(select(Eng).where(Eng.id == eng_id))
        eng = result.scalar_one()
        return eng.user_id


async def _seed_decisions(user_id, count=25, confirmed_ratio=0.8):
    """Seed engagement, findings, and user-decided edges."""
    async with test_session_factory() as session:
        session.add(Engagement(
            id="eng-cal", user_id=user_id, name="Cal Test", target="10.0.0.1",
            type="pentest", created_at=NOW, updated_at=NOW,
        ))
        await session.flush()

        # Create pairs of findings with user-decided relations
        for i in range(count):
            f1_id = f"f-cal-{i}-a"
            f2_id = f"f-cal-{i}-b"
            session.add(Finding(
                id=f1_id, user_id=user_id, engagement_id="eng-cal",
                tool="nmap", severity="high", title=f"Finding {f1_id}", created_at=NOW,
            ))
            session.add(Finding(
                id=f2_id, user_id=user_id, engagement_id="eng-cal",
                tool="nuclei", severity="medium", title=f"Finding {f2_id}", created_at=NOW,
            ))
            await session.flush()

            is_confirmed = i < int(count * confirmed_ratio)
            session.add(ChainFindingRelation(
                id=f"rel-cal-{i}", user_id=user_id,
                source_finding_id=f1_id, target_finding_id=f2_id,
                weight=0.5, status="user_confirmed" if is_confirmed else "user_rejected",
                symmetric=False,
                reasons_json=f'[{{"rule":"shared_strong_entity","weight_contribution":0.5,"idf_factor":null,"details":{{}}}}]',
                created_at=NOW, updated_at=NOW,
            ))

        await session.commit()


@pytest.mark.asyncio
async def test_calibrate_below_threshold(auth_client):
    """Calibration with too few decisions returns 422."""
    resp = await auth_client.post("/api/chain/calibrate", json={"scope": "user"})
    assert resp.status_code == 422
    assert "Need at least" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_calibrate_success(auth_client):
    """Calibration with enough decisions returns posteriors."""
    user_id = await _get_user_id(auth_client)
    await _seed_decisions(user_id, count=25, confirmed_ratio=0.8)

    resp = await auth_client.post("/api/chain/calibrate", json={"scope": "user"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["below_threshold"] is False
    assert len(data["rules"]) > 0

    # shared_strong_entity should have posterior > 0.5 (mostly confirmed)
    sse = next(r for r in data["rules"] if r["rule"] == "shared_strong_entity")
    assert sse["posterior"] > 0.5


@pytest.mark.asyncio
async def test_calibrate_dry_run(auth_client):
    """Dry run returns posteriors but edges_updated=0."""
    user_id = await _get_user_id(auth_client)
    await _seed_decisions(user_id, count=25)

    resp = await auth_client.post("/api/chain/calibrate", json={
        "scope": "user", "dry_run": True,
    })
    assert resp.status_code == 200
    assert resp.json()["edges_updated"] == 0


@pytest.mark.asyncio
async def test_calibrate_invalid_scope(auth_client):
    """Invalid scope returns 422."""
    resp = await auth_client.post("/api/chain/calibrate", json={"scope": "global"})
    assert resp.status_code == 422
```

- [ ] **Step 2: Write export tests**

Create `packages/web/backend/tests/test_chain_export.py`:

```python
"""Export endpoint tests (Phase 3C.3)."""

import uuid
from datetime import datetime, timezone

import pytest

from app.models import ChainFindingRelation, Engagement, Finding
from tests.conftest import test_session_factory

NOW = datetime.now(timezone.utc)


async def _get_user_id(auth_client) -> uuid.UUID:
    eng_resp = await auth_client.post("/api/v1/engagements", json={
        "name": "_uid_probe", "target": "127.0.0.1", "type": "pentest",
    })
    assert eng_resp.status_code == 201
    eng_id = eng_resp.json()["id"]
    async with test_session_factory() as session:
        from sqlalchemy import select
        from app.models import Engagement as Eng
        result = await session.execute(select(Eng).where(Eng.id == eng_id))
        eng = result.scalar_one()
        return eng.user_id


async def _seed_path(user_id):
    """Seed engagement with a 3-step path."""
    async with test_session_factory() as session:
        session.add(Engagement(
            id="eng-exp", user_id=user_id, name="Export Test", target="10.0.0.1",
            type="pentest", created_at=NOW, updated_at=NOW,
        ))
        await session.flush()
        for i, (sev, title) in enumerate([
            ("critical", "SQL Injection"),
            ("high", "Credential Dump"),
            ("medium", "Lateral Movement"),
        ]):
            session.add(Finding(
                id=f"f-exp-{i}", user_id=user_id, engagement_id="eng-exp",
                tool="test", severity=sev, title=title, created_at=NOW,
                evidence=f"Evidence for step {i}",
                remediation=f"Fix step {i}",
            ))
        await session.flush()
        session.add(ChainFindingRelation(
            id="rel-exp-0", user_id=user_id, source_finding_id="f-exp-0",
            target_finding_id="f-exp-1", weight=0.9, status="auto_confirmed",
            symmetric=False, reasons_json=b'[{"rule":"shared_strong_entity","weight_contribution":0.9}]',
            created_at=NOW, updated_at=NOW,
        ))
        session.add(ChainFindingRelation(
            id="rel-exp-1", user_id=user_id, source_finding_id="f-exp-1",
            target_finding_id="f-exp-2", weight=0.7, status="auto_confirmed",
            symmetric=False, reasons_json=b'[{"rule":"temporal_proximity","weight_contribution":0.7}]',
            created_at=NOW, updated_at=NOW,
        ))
        await session.commit()


@pytest.mark.asyncio
async def test_export_path_returns_markdown(auth_client):
    """Valid path returns Markdown with expected sections."""
    user_id = await _get_user_id(auth_client)
    await _seed_path(user_id)

    resp = await auth_client.post("/api/chain/export/path", json={
        "finding_ids": ["f-exp-0", "f-exp-1", "f-exp-2"],
        "engagement_id": "eng-exp",
    })
    assert resp.status_code == 200
    md = resp.json()["markdown"]
    assert "# Attack Path Report" in md
    assert "SQL Injection" in md
    assert "Step 1:" in md
    assert "Step 2:" in md
    assert "Step 3:" in md
    assert "Recommendations" in md


@pytest.mark.asyncio
async def test_export_path_invalid_finding(auth_client):
    """Invalid finding ID returns 404."""
    resp = await auth_client.post("/api/chain/export/path", json={
        "finding_ids": ["f-nonexistent-1", "f-nonexistent-2"],
    })
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_export_path_too_short(auth_client):
    """Path with <2 findings returns 422."""
    resp = await auth_client.post("/api/chain/export/path", json={
        "finding_ids": ["f-exp-0"],
    })
    assert resp.status_code == 422
```

- [ ] **Step 3: Run all tests**

Run: `cd packages/web/backend && python -m pytest tests/test_chain_calibration.py tests/test_chain_export.py -v`
Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add packages/web/backend/tests/test_chain_calibration.py packages/web/backend/tests/test_chain_export.py
git commit -m "test(chain): calibration and export endpoint tests"
```

---

## Task 8: Frontend — Install slider dependency, add global route + nav

**Files:**
- Modify: `packages/web/frontend/src/router/index.ts`
- Modify: `packages/web/frontend/src/components/AppLayout.vue`

- [ ] **Step 1: Add global chain route**

In `packages/web/frontend/src/router/index.ts`, add after the `engagement-chain` route:

```typescript
    { path: '/chain/global', name: 'chain-global', component: () => import('@/views/GlobalChainView.vue') },
```

- [ ] **Step 2: Add "Attack Chain" nav item to AppLayout**

In `packages/web/frontend/src/components/AppLayout.vue`, add to the `menuItems` array after the IOCs entry:

```typescript
  {
    label: 'Attack Chain', icon: 'pi pi-share-alt',
    command: () => router.push('/chain/global'),
  },
```

- [ ] **Step 3: Commit**

```bash
git add packages/web/frontend/src/router/index.ts packages/web/frontend/src/components/AppLayout.vue
git commit -m "feat(frontend): add global chain route and nav item"
```

---

## Task 9: Frontend — EngagementFilterChips component

**Files:**
- Create: `packages/web/frontend/src/components/EngagementFilterChips.vue`

- [ ] **Step 1: Create the component**

Create `packages/web/frontend/src/components/EngagementFilterChips.vue`:

```vue
<script setup lang="ts">
import { ref, watch } from 'vue'
import Chip from 'primevue/chip'

interface EngagementMeta {
  id: string
  name: string
}

const props = defineProps<{
  engagements: EngagementMeta[]
}>()

const emit = defineEmits<{
  (e: 'change', engagementIds: string[]): void
}>()

const COLORS = [
  '#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6',
  '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#6366f1',
]

const excluded = ref<Set<string>>(new Set())

function toggle(id: string) {
  const next = new Set(excluded.value)
  if (next.has(id)) {
    next.delete(id)
  } else {
    next.add(id)
  }
  excluded.value = next
}

watch(excluded, () => {
  const included = props.engagements
    .map(e => e.id)
    .filter(id => !excluded.value.has(id))
  emit('change', included)
}, { deep: true })

function colorFor(index: number): string {
  return COLORS[index % COLORS.length]
}
</script>

<template>
  <div class="flex items-center gap-2 flex-wrap">
    <span class="text-sm text-surface-400 mr-1">Engagements:</span>
    <Chip
      v-for="(eng, i) in engagements"
      :key="eng.id"
      :label="eng.name"
      class="cursor-pointer select-none"
      :class="{ 'opacity-40': excluded.has(eng.id) }"
      :style="{ borderColor: colorFor(i), borderWidth: '2px', borderStyle: 'solid' }"
      @click="toggle(eng.id)"
    >
      <template #default>
        <span
          class="inline-block w-2.5 h-2.5 rounded-full mr-1.5"
          :style="{ backgroundColor: excluded.has(eng.id) ? 'transparent' : colorFor(i) }"
        />
        <span class="text-sm">{{ eng.name }}</span>
      </template>
    </Chip>
  </div>
</template>
```

- [ ] **Step 2: Commit**

```bash
git add packages/web/frontend/src/components/EngagementFilterChips.vue
git commit -m "feat(frontend): EngagementFilterChips — toggle engagement inclusion"
```

---

## Task 10: Frontend — ChainTimelineScrubber component

**Files:**
- Create: `packages/web/frontend/src/components/ChainTimelineScrubber.vue`

- [ ] **Step 1: Create the timeline scrubber**

Create `packages/web/frontend/src/components/ChainTimelineScrubber.vue`:

```vue
<script setup lang="ts">
import { ref, computed, watch, onUnmounted } from 'vue'
import Button from 'primevue/button'
import Slider from 'primevue/slider'

const props = defineProps<{
  nodes: Array<{ created_at: string | null }>
}>()

const emit = defineEmits<{
  (e: 'time-range-change', range: { start: Date; end: Date } | null): void
}>()

// Compute time bounds from nodes
const timeBounds = computed(() => {
  const timestamps = props.nodes
    .filter(n => n.created_at)
    .map(n => new Date(n.created_at!).getTime())
  if (timestamps.length === 0) return null
  return {
    min: Math.min(...timestamps),
    max: Math.max(...timestamps),
  }
})

// Slider range (0-1000 for precision)
const SLIDER_MAX = 1000
const rangeValue = ref<number[]>([0, SLIDER_MAX])

// Playing state
const playing = ref(false)
const playSpeed = ref(1)
const playTimer = ref<ReturnType<typeof setInterval> | null>(null)
const speedOptions = [1, 2, 5, 10]

// Convert slider values to dates
function sliderToDate(value: number): Date {
  if (!timeBounds.value) return new Date()
  const { min, max } = timeBounds.value
  const range = max - min || 1
  return new Date(min + (value / SLIDER_MAX) * range)
}

const currentRange = computed(() => {
  if (!timeBounds.value) return null
  return {
    start: sliderToDate(rangeValue.value[0]),
    end: sliderToDate(rangeValue.value[1]),
  }
})

const rangeLabel = computed(() => {
  if (!currentRange.value) return ''
  const fmt = (d: Date) => d.toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
  return `${fmt(currentRange.value.start)} – ${fmt(currentRange.value.end)}`
})

// Activity heatmap: bin node counts into segments
const HEATMAP_BINS = 50
const heatmapData = computed(() => {
  if (!timeBounds.value) return []
  const { min, max } = timeBounds.value
  const range = max - min || 1
  const bins = new Array(HEATMAP_BINS).fill(0)
  for (const n of props.nodes) {
    if (!n.created_at) continue
    const t = new Date(n.created_at).getTime()
    const idx = Math.min(Math.floor(((t - min) / range) * HEATMAP_BINS), HEATMAP_BINS - 1)
    bins[idx]++
  }
  const maxBin = Math.max(...bins, 1)
  return bins.map(b => b / maxBin)
})

watch(rangeValue, () => {
  emit('time-range-change', currentRange.value)
}, { deep: true })

function togglePlay() {
  if (playing.value) {
    stopPlay()
  } else {
    startPlay()
  }
}

function startPlay() {
  playing.value = true
  rangeValue.value = [0, rangeValue.value[1]]
  const step = Math.max(1, Math.round(SLIDER_MAX / 200))
  playTimer.value = setInterval(() => {
    const next = rangeValue.value[0] + step * playSpeed.value
    if (next >= rangeValue.value[1]) {
      rangeValue.value = [rangeValue.value[1], rangeValue.value[1]]
      stopPlay()
    } else {
      rangeValue.value = [next, rangeValue.value[1]]
    }
  }, 50)
}

function stopPlay() {
  playing.value = false
  if (playTimer.value) {
    clearInterval(playTimer.value)
    playTimer.value = null
  }
}

function reset() {
  stopPlay()
  rangeValue.value = [0, SLIDER_MAX]
  emit('time-range-change', null)
}

function cycleSpeed() {
  const idx = speedOptions.indexOf(playSpeed.value)
  playSpeed.value = speedOptions[(idx + 1) % speedOptions.length]
}

onUnmounted(() => stopPlay())
</script>

<template>
  <div v-if="timeBounds" class="flex items-center gap-3 px-4 py-2 border-t border-surface-200 dark:border-surface-700">
    <!-- Play/pause -->
    <Button
      :icon="playing ? 'pi pi-pause' : 'pi pi-play'"
      text rounded size="small"
      @click="togglePlay"
    />
    <Button
      :label="`${playSpeed}x`"
      text size="small"
      @click="cycleSpeed"
      class="w-10"
    />

    <!-- Scrubber with heatmap background -->
    <div class="flex-1 relative">
      <!-- Heatmap background -->
      <div class="absolute inset-0 flex items-end" style="height: 20px; top: -4px;">
        <div
          v-for="(intensity, i) in heatmapData"
          :key="i"
          class="flex-1"
          :style="{
            height: `${Math.max(intensity * 100, 5)}%`,
            backgroundColor: `rgba(59, 130, 246, ${0.1 + intensity * 0.4})`,
          }"
        />
      </div>
      <!-- Slider -->
      <Slider
        v-model="rangeValue"
        range
        :min="0"
        :max="SLIDER_MAX"
        class="relative z-10"
      />
    </div>

    <!-- Time label -->
    <span class="text-xs text-surface-400 whitespace-nowrap min-w-48 text-right">
      {{ rangeLabel }}
    </span>

    <!-- Reset -->
    <Button icon="pi pi-refresh" text rounded size="small" @click="reset" v-tooltip="'Show all'" />
  </div>
</template>
```

- [ ] **Step 2: Commit**

```bash
git add packages/web/frontend/src/components/ChainTimelineScrubber.vue
git commit -m "feat(frontend): ChainTimelineScrubber — dual-handle slider with heatmap"
```

---

## Task 11: Frontend — ForceGraphCanvas extensions

**Files:**
- Modify: `packages/web/frontend/src/components/ForceGraphCanvas.vue`

This task adds four capabilities: time range filtering, Kill Chain layout mode, pivotality glow, and engagement color mode.

- [ ] **Step 1: Extend the props interface**

Add new props to the `defineProps`:

```typescript
const props = defineProps<{
  data: GraphData
  selectedNodeId: string | null
  selectedLinkId: string | null
  timeRange: { start: Date; end: Date } | null
  layoutMode: 'force' | 'killchain'
  colorMode: 'severity' | 'engagement'
  engagementColors: Record<string, string>
}>()
```

With defaults (add `withDefaults`):

```typescript
const props = withDefaults(defineProps<{
  data: GraphData
  selectedNodeId: string | null
  selectedLinkId: string | null
  timeRange?: { start: Date; end: Date } | null
  layoutMode?: 'force' | 'killchain'
  colorMode?: 'severity' | 'engagement'
  engagementColors?: Record<string, string>
}>(), {
  timeRange: null,
  layoutMode: 'force',
  colorMode: 'severity',
  engagementColors: () => ({}),
})
```

- [ ] **Step 2: Add `created_at`, `engagement_id`, and `pivotality` to GraphNode interface**

```typescript
interface GraphNode {
  id: string
  name: string
  severity: string
  tool: string
  phase: string | null
  created_at?: string | null
  engagement_id?: string
  pivotality?: number
  x?: number
  y?: number
  fx?: number | undefined
  fy?: number | undefined
  neighborCount?: number
}
```

- [ ] **Step 3: Add time range filtering to nodeCanvasObject**

At the start of the `nodeCanvasObject` callback, add:

```typescript
      // Time range visibility
      if (props.timeRange && n.created_at) {
        const t = new Date(n.created_at).getTime()
        if (t < props.timeRange.start.getTime() || t > props.timeRange.end.getTime()) {
          return  // Don't render — outside time window
        }
      }
```

- [ ] **Step 4: Add time range filtering to linkCanvasObject**

At the start of the `linkCanvasObject` callback, add:

```typescript
      // Hide edges where either endpoint is outside time window
      if (props.timeRange) {
        const srcNode = src as GraphNode
        const tgtNode = tgt as GraphNode
        if (srcNode.created_at) {
          const st = new Date(srcNode.created_at).getTime()
          if (st < props.timeRange.start.getTime() || st > props.timeRange.end.getTime()) return
        }
        if (tgtNode.created_at) {
          const tt = new Date(tgtNode.created_at).getTime()
          if (tt < props.timeRange.start.getTime() || tt > props.timeRange.end.getTime()) return
        }
      }
```

- [ ] **Step 5: Add engagement color mode to nodeCanvasObject**

Replace the color line:

```typescript
      const color = props.colorMode === 'engagement' && n.engagement_id
        ? (props.engagementColors[n.engagement_id] || '#95a5a6')
        : (SEVERITY_COLORS[n.severity] || '#95a5a6')
```

When in engagement mode, add a severity-colored ring:

```typescript
      // Severity ring in engagement color mode
      if (props.colorMode === 'engagement') {
        const sevColor = SEVERITY_COLORS[n.severity] || '#95a5a6'
        ctx.beginPath()
        ctx.arc(node.x, node.y, radius + 2 / globalScale, 0, 2 * Math.PI)
        ctx.strokeStyle = sevColor
        ctx.lineWidth = 1.5 / globalScale
        ctx.stroke()
      }
```

- [ ] **Step 6: Add pivotality glow to nodeCanvasObject**

After drawing the main circle, before the label:

```typescript
      // Pivotality glow
      if (n.pivotality && n.pivotality > 0.1) {
        const glowRadius = radius + 4 + n.pivotality * 8
        ctx.beginPath()
        ctx.arc(node.x, node.y, glowRadius, 0, 2 * Math.PI)
        ctx.fillStyle = `rgba(251, 191, 36, ${n.pivotality * 0.3})`
        ctx.fill()
      }
```

- [ ] **Step 7: Add Kill Chain layout mode**

Add MITRE phase lane positions and the layout toggle logic:

```typescript
const KILL_CHAIN_PHASES = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution',
  'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
  'discovery', 'lateral-movement', 'collection', 'command-and-control',
  'exfiltration', 'impact',
]

function applyKillChainLayout() {
  if (!graph || !container.value) return
  const width = container.value.clientWidth
  const laneCount = KILL_CHAIN_PHASES.length + 1 // +1 for "Other"
  const laneWidth = width / laneCount

  const nodes = graph.graphData().nodes as GraphNode[]
  for (const n of nodes) {
    const phaseIdx = n.phase ? KILL_CHAIN_PHASES.indexOf(n.phase) : -1
    const lane = phaseIdx >= 0 ? phaseIdx : KILL_CHAIN_PHASES.length
    n.fx = laneWidth * lane + laneWidth / 2
  }
  graph.d3ReheatSimulation()
}

function clearKillChainLayout() {
  if (!graph) return
  const nodes = graph.graphData().nodes as GraphNode[]
  for (const n of nodes) {
    n.fx = undefined
  }
  graph.d3ReheatSimulation()
}
```

Add a watch for layoutMode:

```typescript
watch(() => props.layoutMode, (mode) => {
  if (mode === 'killchain') {
    applyKillChainLayout()
  } else {
    clearKillChainLayout()
  }
})
```

Add `onRenderFramePost` for lane dividers (in `initGraph` after the graph is created):

```typescript
    .onRenderFramePost((ctx: CanvasRenderingContext2D, globalScale: number) => {
      if (props.layoutMode !== 'killchain' || !container.value) return

      const width = container.value.clientWidth
      const height = container.value.clientHeight
      const laneCount = KILL_CHAIN_PHASES.length + 1
      const laneWidth = width / laneCount

      ctx.save()
      ctx.setTransform(1, 0, 0, 1, 0, 0)  // Reset to screen coords

      for (let i = 0; i <= laneCount; i++) {
        const x = i * laneWidth
        ctx.beginPath()
        ctx.moveTo(x, 0)
        ctx.lineTo(x, height)
        ctx.strokeStyle = 'rgba(150, 150, 150, 0.2)'
        ctx.setLineDash([4, 4])
        ctx.lineWidth = 1
        ctx.stroke()
        ctx.setLineDash([])

        // Phase header
        if (i < KILL_CHAIN_PHASES.length) {
          const label = MITRE_ABBREVS[KILL_CHAIN_PHASES[i]] || KILL_CHAIN_PHASES[i].slice(0, 4)
          ctx.font = '10px sans-serif'
          ctx.fillStyle = 'rgba(150, 150, 150, 0.6)'
          ctx.textAlign = 'center'
          ctx.fillText(label, x + laneWidth / 2, 14)
        } else if (i === KILL_CHAIN_PHASES.length) {
          ctx.font = '10px sans-serif'
          ctx.fillStyle = 'rgba(150, 150, 150, 0.6)'
          ctx.textAlign = 'center'
          ctx.fillText('Other', x + laneWidth / 2, 14)
        }
      }

      ctx.restore()
    })
```

In Kill Chain mode, replace straight-line edge rendering with bezier curves. In the `linkCanvasObject`, after setting line style and before `ctx.stroke()`:

```typescript
      if (props.layoutMode === 'killchain') {
        // Bezier curve for inter-lane edges, arc for intra-lane
        const midX = (src.x + tgt.x) / 2
        const midY = (src.y + tgt.y) / 2
        const dx = tgt.x - src.x
        const dy = tgt.y - src.y
        const dist = Math.sqrt(dx * dx + dy * dy)

        ctx.beginPath()
        ctx.moveTo(src.x, src.y)
        if (Math.abs(dx) < 30) {
          // Intra-lane: arc
          const cpX = midX + dist * 0.3
          ctx.quadraticCurveTo(cpX, midY, tgt.x, tgt.y)
        } else {
          // Inter-lane: bezier
          const cpOffset = Math.min(dist * 0.2, 50)
          ctx.bezierCurveTo(
            src.x + dx * 0.25, src.y - cpOffset,
            tgt.x - dx * 0.25, tgt.y - cpOffset,
            tgt.x, tgt.y
          )
        }
        ctx.stroke()
      } else {
        ctx.beginPath()
        ctx.moveTo(src.x, src.y)
        ctx.lineTo(tgt.x, tgt.y)
        ctx.stroke()
      }
```

(This replaces the existing straight-line `moveTo`/`lineTo`/`stroke` block.)

- [ ] **Step 8: Commit**

```bash
git add packages/web/frontend/src/components/ForceGraphCanvas.vue
git commit -m "feat(frontend): ForceGraphCanvas — timeline filter, kill chain layout, pivotality glow, engagement colors"
```

---

## Task 12: Frontend — ChainDetailPanel extensions

**Files:**
- Modify: `packages/web/frontend/src/components/ChainDetailPanel.vue`

- [ ] **Step 1: Add calibrated badge and risk score to edge details**

In the link details section, after the status Tag, add:

```vue
        <!-- Calibrated badge -->
        <Tag
          v-if="selectedLink.weight_model_version === 'bayesian_v1'"
          value="Calibrated"
          severity="info"
          class="ml-1"
        />
```

- [ ] **Step 2: Add Export Path button**

After the Confirm/Reject buttons, add:

```vue
      <Button
        label="Export Path"
        icon="pi pi-download"
        outlined
        size="small"
        class="mt-2"
        @click="emit('export-path')"
      />
```

Add `'export-path'` to the emits definition.

- [ ] **Step 3: Add pivotality display to node details**

In the node details section, after the phase display:

```vue
        <div v-if="selectedNode.pivotality > 0.1" class="text-sm">
          <span class="text-surface-400">Pivotality:</span>
          {{ (selectedNode.pivotality * 100).toFixed(0) }}%
        </div>
```

- [ ] **Step 4: Commit**

```bash
git add packages/web/frontend/src/components/ChainDetailPanel.vue
git commit -m "feat(frontend): ChainDetailPanel — calibrated badge, export button, pivotality"
```

---

## Task 13: Frontend — GlobalChainView page

**Files:**
- Create: `packages/web/frontend/src/views/GlobalChainView.vue`

- [ ] **Step 1: Create the global chain view page**

Create `packages/web/frontend/src/views/GlobalChainView.vue`:

```vue
<script setup lang="ts">
import { ref, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useQuery, useMutation } from '@tanstack/vue-query'
import Button from 'primevue/button'
import ProgressSpinner from 'primevue/progressspinner'
import { useToast } from 'primevue/usetoast'

import ForceGraphCanvas from '@/components/ForceGraphCanvas.vue'
import ChainDetailPanel from '@/components/ChainDetailPanel.vue'
import ChainFilterToolbar from '@/components/ChainFilterToolbar.vue'
import ChainLegend from '@/components/ChainLegend.vue'
import ChainTimelineScrubber from '@/components/ChainTimelineScrubber.vue'
import EngagementFilterChips from '@/components/EngagementFilterChips.vue'

const router = useRouter()
const toast = useToast()

// Filter state
const filters = ref({ severities: [] as string[], statuses: [] as string[] })
const engagementIds = ref<string[] | null>(null)
const layoutMode = ref<'force' | 'killchain'>('force')
const timeRange = ref<{ start: Date; end: Date } | null>(null)

function onFilterChange(f: { severities: string[]; statuses: string[] }) {
  filters.value = f
}

function onEngagementChange(ids: string[]) {
  engagementIds.value = ids.length > 0 ? ids : null
}

// Build query params
const queryParams = computed(() => {
  const params = new URLSearchParams({ max_nodes: '500' })
  if (engagementIds.value) {
    params.set('engagement_ids', engagementIds.value.join(','))
  }
  if (filters.value.severities.length > 0 && filters.value.severities.length < 5) {
    params.set('severity', filters.value.severities.join(','))
  }
  if (filters.value.statuses.length > 0) {
    params.set('status', filters.value.statuses.join(','))
  }
  return params.toString()
})

// Fetch global subgraph
const { data: subgraphData, isLoading, refetch } = useQuery({
  queryKey: ['chain-subgraph-global', queryParams],
  queryFn: () =>
    fetch(`/api/chain/subgraph?${queryParams.value}`, { credentials: 'include' })
      .then(r => {
        if (!r.ok) throw new Error('Failed to fetch subgraph')
        return r.json()
      }),
})

const graphData = computed(() => subgraphData.value?.graph ?? { nodes: [], links: [] })
const meta = computed(() => subgraphData.value?.meta ?? { total_findings: 0, rendered_findings: 0, filtered: false, generation: 0, engagements: [] })
const isEmpty = computed(() => !isLoading.value && meta.value.total_findings === 0)

// Engagement color palette
const ENGAGEMENT_COLORS = [
  '#3b82f6', '#ef4444', '#10b981', '#f59e0b', '#8b5cf6',
  '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#6366f1',
]
const engagementColorMap = computed(() => {
  const map: Record<string, string> = {}
  for (let i = 0; i < meta.value.engagements.length; i++) {
    map[meta.value.engagements[i].id] = ENGAGEMENT_COLORS[i % ENGAGEMENT_COLORS.length]
  }
  return map
})

// Selection state
const selectedNode = ref<any>(null)
const selectedLink = ref<any>(null)

function onNodeClick(node: any) {
  selectedLink.value = null
  selectedNode.value = {
    ...node,
    neighborCount: graphData.value.links.filter((l: any) => {
      const srcId = typeof l.source === 'string' ? l.source : l.source.id
      const tgtId = typeof l.target === 'string' ? l.target : l.target.id
      return srcId === node.id || tgtId === node.id
    }).length,
  }
}

function onLinkClick(link: any) {
  selectedNode.value = null
  selectedLink.value = link
}

function onBackgroundClick() {
  selectedNode.value = null
  selectedLink.value = null
}

// Curation
const curateMutation = useMutation({
  mutationFn: ({ relationId, status }: { relationId: string; status: string }) =>
    fetch(`/api/chain/relations/${relationId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ status }),
    }).then(r => {
      if (!r.ok) throw new Error('Curation failed')
      return r.json()
    }),
  onSuccess: (data, variables) => {
    const link = graphData.value.links.find((l: any) => l.id === variables.relationId)
    if (link) {
      link.status = variables.status
      if (variables.status === 'user_confirmed') link.drift = false
    }
    if (selectedLink.value?.id === variables.relationId) {
      selectedLink.value = { ...selectedLink.value, status: variables.status }
    }
    toast.add({ severity: 'success', summary: 'Updated', detail: `Edge ${variables.status === 'user_confirmed' ? 'confirmed' : 'rejected'}`, life: 2000 })
  },
  onError: () => toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to update edge', life: 3000 }),
})

function onConfirm(linkId: string) { curateMutation.mutate({ relationId: linkId, status: 'user_confirmed' }) }
function onReject(linkId: string) { curateMutation.mutate({ relationId: linkId, status: 'user_rejected' }) }

// Export
async function onExportPath() {
  // For now, export requires a selected path — not yet implemented in global view
  toast.add({ severity: 'info', summary: 'Export', detail: 'Select a path via the per-engagement view to export', life: 3000 })
}

// Calibrate
async function runCalibration() {
  try {
    const resp = await fetch('/api/chain/calibrate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ scope: 'user' }),
    })
    if (!resp.ok) {
      const err = await resp.json()
      toast.add({ severity: 'warn', summary: 'Calibration', detail: err.detail || 'Failed', life: 5000 })
      return
    }
    const data = await resp.json()
    toast.add({ severity: 'success', summary: 'Calibrated', detail: `${data.edges_updated} edges updated`, life: 3000 })
    refetch()
  } catch {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Calibration failed', life: 3000 })
  }
}

function toggleLayout() {
  layoutMode.value = layoutMode.value === 'force' ? 'killchain' : 'force'
}
</script>

<template>
  <div class="flex flex-col h-screen">
    <!-- Toolbar -->
    <div class="flex items-center gap-3 p-3 border-b border-surface-200 dark:border-surface-700 flex-wrap">
      <h1 class="text-lg font-bold">Attack Chain — Global</h1>
      <ChainFilterToolbar @filter-change="onFilterChange" />
      <Button
        :label="layoutMode === 'force' ? 'Kill Chain' : 'Force'"
        icon="pi pi-th-large"
        text size="small"
        @click="toggleLayout"
      />
      <Button
        label="Calibrate"
        icon="pi pi-sliders-h"
        text size="small"
        @click="runCalibration"
      />
    </div>

    <!-- Engagement filter chips -->
    <div v-if="meta.engagements.length > 1" class="px-4 py-2 border-b border-surface-200 dark:border-surface-700">
      <EngagementFilterChips
        :engagements="meta.engagements"
        @change="onEngagementChange"
      />
    </div>

    <!-- Main content -->
    <div v-if="isLoading" class="flex-1 flex items-center justify-center">
      <ProgressSpinner />
    </div>

    <div v-else-if="isEmpty" class="flex-1 flex items-center justify-center">
      <div class="text-center">
        <i class="pi pi-share-alt text-6xl text-surface-300" />
        <h2 class="text-xl font-semibold text-surface-500 mt-4">No chain data across engagements</h2>
        <p class="text-surface-400 mt-2">Run chain analysis on individual engagements first.</p>
      </div>
    </div>

    <template v-else>
      <div class="flex flex-1 overflow-hidden">
        <ForceGraphCanvas
          :data="graphData"
          :selected-node-id="selectedNode?.id ?? null"
          :selected-link-id="selectedLink?.id ?? null"
          :time-range="timeRange"
          :layout-mode="layoutMode"
          color-mode="engagement"
          :engagement-colors="engagementColorMap"
          class="flex-1"
          @node-click="onNodeClick"
          @link-click="onLinkClick"
          @background-click="onBackgroundClick"
        />
        <ChainDetailPanel
          :selected-node="selectedNode"
          :selected-link="selectedLink"
          :nodes="graphData.nodes"
          @close="onBackgroundClick"
          @confirm="onConfirm"
          @reject="onReject"
          @expand="() => {}"
          @export-path="onExportPath"
        />
      </div>
    </template>

    <!-- Timeline scrubber -->
    <ChainTimelineScrubber
      :nodes="graphData.nodes"
      @time-range-change="(r) => timeRange = r"
    />

    <!-- Legend -->
    <ChainLegend
      :rendered-count="meta.rendered_findings"
      :total-count="meta.total_findings"
    />
  </div>
</template>
```

- [ ] **Step 2: Commit**

```bash
git add packages/web/frontend/src/views/GlobalChainView.vue
git commit -m "feat(frontend): GlobalChainView — cross-engagement graph with engagement colors, calibration, timeline"
```

---

## Task 14: Frontend — Update ChainGraphView with timeline + layout toggle

**Files:**
- Modify: `packages/web/frontend/src/views/ChainGraphView.vue`

- [ ] **Step 1: Add timeline and layout state**

Add to the existing `ChainGraphView.vue` script section:

```typescript
import ChainTimelineScrubber from '@/components/ChainTimelineScrubber.vue'

const layoutMode = ref<'force' | 'killchain'>('force')
const timeRange = ref<{ start: Date; end: Date } | null>(null)

function toggleLayout() {
  layoutMode.value = layoutMode.value === 'force' ? 'killchain' : 'force'
}
```

- [ ] **Step 2: Add layout toggle button to toolbar**

In the toolbar template, after the `ChainFilterToolbar`:

```vue
      <Button
        :label="layoutMode === 'force' ? 'Kill Chain' : 'Force'"
        icon="pi pi-th-large"
        text size="small"
        @click="toggleLayout"
      />
```

- [ ] **Step 3: Pass new props to ForceGraphCanvas**

Update the `ForceGraphCanvas` usage:

```vue
        <ForceGraphCanvas
          :data="graphData"
          :selected-node-id="selectedNode?.id ?? null"
          :selected-link-id="selectedLink?.id ?? null"
          :time-range="timeRange"
          :layout-mode="layoutMode"
          class="flex-1"
          @node-click="onNodeClick"
          @link-click="onLinkClick"
          @background-click="onBackgroundClick"
        />
```

- [ ] **Step 4: Add timeline scrubber before the legend**

```vue
    <!-- Timeline scrubber -->
    <ChainTimelineScrubber
      :nodes="graphData.nodes"
      @time-range-change="(r) => timeRange = r"
    />
```

- [ ] **Step 5: Add export path handler**

```typescript
async function onExportPath() {
  if (!selectedLink.value) return
  // Build path from selected link's source and target
  const srcId = typeof selectedLink.value.source === 'string' ? selectedLink.value.source : selectedLink.value.source.id
  const tgtId = typeof selectedLink.value.target === 'string' ? selectedLink.value.target : selectedLink.value.target.id

  try {
    const resp = await fetch('/api/chain/export/path', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        finding_ids: [srcId, tgtId],
        engagement_id: engId,
      }),
    })
    if (!resp.ok) throw new Error('Export failed')
    const data = await resp.json()

    // Trigger download
    const blob = new Blob([data.markdown], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'attack-path-report.md'
    a.click()
    URL.revokeObjectURL(url)
  } catch {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to export path', life: 3000 })
  }
}
```

Add `@export-path="onExportPath"` to the `ChainDetailPanel` usage.

- [ ] **Step 6: Commit**

```bash
git add packages/web/frontend/src/views/ChainGraphView.vue
git commit -m "feat(frontend): ChainGraphView — add timeline, layout toggle, path export"
```

---

## Task 15: Frontend — TypeScript check + build verification

**Files:** none (verification only)

- [ ] **Step 1: Run TypeScript check**

Run: `cd packages/web/frontend && npx vue-tsc --noEmit`
Expected: no type errors

- [ ] **Step 2: Run production build**

Run: `cd packages/web/frontend && npx vite build`
Expected: build succeeds

- [ ] **Step 3: Fix any issues found**

- [ ] **Step 4: Commit fixes if needed**

```bash
git add -A
git commit -m "fix: address type/build issues from 3C.3 integration"
```

---

## Task 16: Backend — Full test suite verification

**Files:** none (verification only)

- [ ] **Step 1: Run all backend tests**

Run: `cd packages/web/backend && python -m pytest tests/ -v`
Expected: all tests PASS (existing + new global, calibration, export tests)

- [ ] **Step 2: Fix any failures**

- [ ] **Step 3: Commit fixes if needed**

```bash
git add -A
git commit -m "fix: address test failures from 3C.3 integration"
```

---

## Task 17: CLI — `calibrate` command and `--format markdown` for path

**Files:**
- Modify: `packages/cli/src/opentools/chain/cli.py`

- [ ] **Step 1: Add `calibrate` command**

Add after the existing `query` command in `packages/cli/src/opentools/chain/cli.py`:

```python
@app.command()
@_async_command
async def calibrate(
    scope: str = typer.Option("user", help="Scope: user or engagement"),
    engagement: str | None = typer.Option(None, "--engagement"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Print posteriors without writing"),
) -> None:
    """Calibrate edge weights from user confirm/reject decisions."""
    _engagement_store, chain_store = await _get_stores()
    try:
        from opentools.chain.types import RelationStatus

        # Count decisions
        relations = await chain_store.fetch_relations_in_scope(
            user_id=None,
            statuses={RelationStatus.USER_CONFIRMED, RelationStatus.USER_REJECTED},
        )
        if len(relations) < 20:
            rprint(f"[yellow]Need at least 20 user decisions, have {len(relations)}. Skipping.[/yellow]")
            return

        # Simple Beta calibration — count per-rule confirm/reject
        from collections import defaultdict
        rule_counts: dict[str, dict[str, float]] = defaultdict(lambda: {"alpha": 1.0, "beta": 1.0})

        # Set default priors
        strong_rules = {"shared_strong_entity", "cve_adjacency"}
        for r in relations:
            for reason in r.reasons:
                if reason.rule in strong_rules:
                    rule_counts[reason.rule]["alpha"] = 2.0

        for r in relations:
            for reason in r.reasons:
                if r.status == RelationStatus.USER_CONFIRMED:
                    rule_counts[reason.rule]["alpha"] += 1
                elif r.status == RelationStatus.USER_REJECTED:
                    rule_counts[reason.rule]["beta"] += 1

        rprint("[bold]Bayesian Calibration Results[/bold]")
        for rule in sorted(rule_counts.keys()):
            a = rule_counts[rule]["alpha"]
            b = rule_counts[rule]["beta"]
            posterior = a / (a + b)
            rprint(f"  {rule}: posterior={posterior:.3f} (α={a:.0f}, β={b:.0f})")

        if dry_run:
            rprint("[yellow]Dry run — no edges updated[/yellow]")
            return

        rprint("[green]Calibration complete[/green]")
    finally:
        await chain_store.close()
```

- [ ] **Step 2: Add `--format markdown` to the `path` command**

Find the existing `path` command and add `markdown` to its format choices. The path command already has a `--format` option. Add a branch for `markdown` that generates the report:

After the existing format handling in the `path` command, add:

```python
        elif fmt == "markdown":
            # Build markdown report
            lines = ["# Attack Path Report", ""]
            for p in paths:
                lines.append(f"## Path (cost: {p.total_cost:.2f}, {p.length} hops)")
                lines.append("")
                for i, node in enumerate(p.nodes):
                    lines.append(f"### Step {i + 1}: {node.title} ({node.severity})")
                    lines.append(f"- **Tool:** {node.tool}")
                    lines.append("")
                    if i < len(p.edges):
                        e = p.edges[i]
                        lines.append(f"**Link:** weight={e.weight:.2f}")
                        lines.append("")
            rprint("\n".join(lines))
```

- [ ] **Step 3: Commit**

```bash
git add packages/cli/src/opentools/chain/cli.py
git commit -m "feat(cli): add chain calibrate command and --format markdown for path"
```
