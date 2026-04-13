# Phase 3C.2: Attack Chain Graph View — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an interactive per-engagement attack chain graph visualization to the web dashboard, with edge curation (confirm/reject), MITRE ATT&CK phase coloring, and server-side filtering for scale.

**Architecture:** Standalone Vue page at `/engagements/:id/chain` wraps `force-graph` (vasturiano). Backend serves filtered subgraphs via a new `GET /api/chain/subgraph` endpoint that caps nodes and filters by severity/status. Edge curation uses `PATCH /api/chain/relations/:id`. No new database tables — builds on 3C.1 models.

**Tech Stack:** FastAPI, SQLAlchemy async, Vue 3, PrimeVue, `force-graph` (vasturiano), TanStack Query

**Spec:** `docs/superpowers/specs/2026-04-13-phase3c2-attack-chain-graph-view-design.md`

---

## File Map

### Backend (new/modified)

| File | Action | Responsibility |
|------|--------|---------------|
| `packages/web/backend/app/routes/chain.py` | Modify | Add `GET /api/chain/subgraph` and `PATCH /api/chain/relations/{relation_id}` endpoints |
| `packages/web/backend/app/services/chain_service.py` | Modify | Add `subgraph_for_engagement()` and `update_relation_status()` methods |
| `packages/web/backend/app/services/chain_dto.py` | Modify | Add `relation_to_link_dict()` for force-graph link shape with drift computation |
| `packages/web/backend/tests/test_chain_subgraph.py` | Create | Tests for subgraph endpoint filtering, capping, neighborhood, drift |
| `packages/web/backend/tests/test_chain_curation.py` | Create | Tests for relation PATCH (valid transitions, invalid status, auth scoping) |

### Frontend (new/modified)

| File | Action | Responsibility |
|------|--------|---------------|
| `packages/web/frontend/src/views/ChainGraphView.vue` | Create | Page component — data fetching, filter state, layout orchestration |
| `packages/web/frontend/src/components/ForceGraphCanvas.vue` | Create | Wrapper around `force-graph` — rendering config, custom draw callbacks, interaction events |
| `packages/web/frontend/src/components/ChainDetailPanel.vue` | Create | Right drawer — node details, edge details with reasons, curation buttons |
| `packages/web/frontend/src/components/ChainFilterToolbar.vue` | Create | Severity/status toggle buttons |
| `packages/web/frontend/src/components/ChainLegend.vue` | Create | Bottom bar — severity color key, edge style key, node count |
| `packages/web/frontend/src/components/ChainEmptyState.vue` | Create | Empty state + rebuild progress polling |
| `packages/web/frontend/src/router/index.ts` | Modify | Add `/engagements/:id/chain` route |
| `packages/web/frontend/src/views/EngagementDetailView.vue` | Modify | Add "View Attack Chain" button |

---

## Task 1: Backend — `relation_to_link_dict` DTO with drift computation

**Files:**
- Modify: `packages/web/backend/app/services/chain_dto.py`

This task adds the conversion function that produces the force-graph link shape with inline drift computation. All subsequent backend tasks depend on this.

- [ ] **Step 1: Write the `relation_to_link_dict` function**

Add to `packages/web/backend/app/services/chain_dto.py`:

```python
def relation_to_link_dict(relation: FindingRelation) -> dict[str, Any]:
    """Convert a CLI ``FindingRelation`` to a force-graph link dict.

    Includes drift detection: if the relation has status USER_CONFIRMED
    and the current reasons differ from the confirmed_at_reasons snapshot,
    drift is True.
    """
    status_value = (
        relation.status.value
        if hasattr(relation.status, "value")
        else str(relation.status)
    )

    # Drift: true if user confirmed but reasons have since changed
    drift = False
    if status_value == "user_confirmed" and relation.confirmed_at_reasons is not None:
        current_rules = sorted(r.rule for r in relation.reasons)
        confirmed_rules = sorted(r.rule for r in relation.confirmed_at_reasons)
        drift = current_rules != confirmed_rules

    return {
        "id": relation.id,
        "source": relation.source_finding_id,
        "target": relation.target_finding_id,
        "value": relation.weight,
        "status": status_value,
        "drift": drift,
        "reasons": [r.rule for r in relation.reasons],
        "relation_type": relation.llm_relation_type,
        "rationale": relation.llm_rationale,
    }
```

- [ ] **Step 2: Verify the module still imports cleanly**

Run: `cd packages/web/backend && python -c "from app.services.chain_dto import relation_to_link_dict; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add packages/web/backend/app/services/chain_dto.py
git commit -m "feat(chain): add relation_to_link_dict DTO with drift detection"
```

---

## Task 2: Backend — `subgraph_for_engagement` service method

**Files:**
- Modify: `packages/web/backend/app/services/chain_service.py`

Adds the service method that queries the store for findings + relations scoped to an engagement, applies severity/status filters, enforces max_nodes cap, and returns the force-graph-shaped response.

- [ ] **Step 1: Add imports at top of chain_service.py**

Add these imports to the existing import block:

```python
from app.services.chain_dto import relation_to_link_dict
```

- [ ] **Step 2: Add `subgraph_for_engagement` method to `ChainService`**

```python
    async def subgraph_for_engagement(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        engagement_id: str,
        severities: set[str] | None = None,
        statuses: set[str] | None = None,
        max_nodes: int = 500,
        seed_finding_id: str | None = None,
        hops: int = 2,
        format: str = "force-graph",
    ) -> dict[str, Any]:
        """Build a filtered subgraph for one engagement.

        Returns a dict with 'graph' (force-graph or canonical shape)
        and 'meta' (total_findings, rendered_findings, filtered, generation).
        """
        from opentools.chain.config import get_chain_config
        from opentools.chain.query.graph_cache import GraphCache
        from opentools.chain.query.adapters import to_canonical_json, to_force_graph
        from opentools.chain.types import RelationStatus

        from sqlalchemy import select, func
        from app.models import Finding, ChainFindingRelation

        store = chain_store_from_session(session)
        await store.initialize()

        # Count total findings in engagement (for meta)
        total_stmt = select(func.count()).select_from(Finding).where(
            Finding.engagement_id == engagement_id,
            Finding.user_id == user_id,
            Finding.deleted_at.is_(None),
        )
        total_result = await session.execute(total_stmt)
        total_findings = total_result.scalar() or 0

        # Fetch findings for this engagement, applying severity filter
        finding_stmt = select(Finding).where(
            Finding.engagement_id == engagement_id,
            Finding.user_id == user_id,
            Finding.deleted_at.is_(None),
        )
        if severities:
            finding_stmt = finding_stmt.where(Finding.severity.in_(severities))
        finding_stmt = finding_stmt.limit(max_nodes)

        finding_result = await session.execute(finding_stmt)
        findings = list(finding_result.scalars().all())
        finding_ids = {f.id for f in findings}

        if not finding_ids:
            empty_graph = {"nodes": [], "links": []} if format == "force-graph" else {"schema_version": "1.0", "nodes": [], "edges": [], "metadata": {}}
            return {
                "graph": empty_graph,
                "meta": {
                    "total_findings": total_findings,
                    "rendered_findings": 0,
                    "filtered": bool(severities) or total_findings > max_nodes,
                    "generation": 0,
                },
            }

        # Default status filter
        if statuses is None:
            statuses = {"auto_confirmed", "user_confirmed", "candidate"}

        # Fetch relations where both endpoints are in finding_ids
        rel_stmt = select(ChainFindingRelation).where(
            ChainFindingRelation.user_id == user_id,
            ChainFindingRelation.source_finding_id.in_(finding_ids),
            ChainFindingRelation.target_finding_id.in_(finding_ids),
            ChainFindingRelation.status.in_(statuses),
        )
        rel_result = await session.execute(rel_stmt)
        relations_orm = list(rel_result.scalars().all())

        # Build nodes
        nodes = [
            {
                "id": f.id,
                "name": f.title,
                "severity": f.severity,
                "tool": f.tool,
                "phase": f.phase,
            }
            for f in findings
        ]

        # Build links via DTO
        from opentools.chain.models import FindingRelation as DomainRelation, RelationReason
        from opentools.chain.stores.postgres_async import _orm_to_relation

        links = [
            relation_to_link_dict(_orm_to_relation(r))
            for r in relations_orm
        ]

        # Get latest generation from most recent linker run
        from app.models import ChainLinkerRun
        gen_stmt = (
            select(ChainLinkerRun.generation)
            .where(ChainLinkerRun.user_id == user_id)
            .order_by(ChainLinkerRun.started_at.desc())
            .limit(1)
        )
        gen_result = await session.execute(gen_stmt)
        generation = gen_result.scalar() or 0

        if format == "force-graph":
            graph = {"nodes": nodes, "links": links}
        else:
            graph = {
                "schema_version": "1.0",
                "nodes": [{"id": n["id"], "type": "finding", "severity": n["severity"], "tool": n["tool"], "title": n["name"]} for n in nodes],
                "edges": [{"source": l["source"], "target": l["target"], "weight": l["value"], "status": l["status"], "symmetric": False, "reasons": l["reasons"], "relation_type": l["relation_type"], "rationale": l["rationale"]} for l in links],
                "metadata": {"generation": generation, "max_weight": max((l["value"] for l in links), default=0)},
            }

        return {
            "graph": graph,
            "meta": {
                "total_findings": total_findings,
                "rendered_findings": len(findings),
                "filtered": bool(severities) or len(findings) < total_findings,
                "generation": generation,
            },
        }
```

- [ ] **Step 3: Verify the module still imports**

Run: `cd packages/web/backend && python -c "from app.services.chain_service import ChainService; print('OK')"`
Expected: `OK`

- [ ] **Step 4: Commit**

```bash
git add packages/web/backend/app/services/chain_service.py
git commit -m "feat(chain): add subgraph_for_engagement service method"
```

---

## Task 3: Backend — `update_relation_status` service method

**Files:**
- Modify: `packages/web/backend/app/services/chain_service.py`

Adds the service method for edge curation — updates relation status to `user_confirmed` or `user_rejected`, snapshots `confirmed_at_reasons_json` on confirm.

- [ ] **Step 1: Add `update_relation_status` method to `ChainService`**

```python
    async def update_relation_status(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        relation_id: str,
        new_status: str,
    ) -> dict[str, Any] | None:
        """Update a relation's status for edge curation.

        Only 'user_confirmed' and 'user_rejected' are valid.
        On confirm, snapshots current reasons_json into confirmed_at_reasons_json.
        Returns the updated relation dict, or None if not found.
        """
        from sqlalchemy import select, update
        from app.models import ChainFindingRelation
        from datetime import datetime, timezone
        from opentools.chain.stores.postgres_async import _orm_to_relation
        from app.services.chain_dto import relation_to_dict

        # Fetch the relation, scoped to user
        stmt = select(ChainFindingRelation).where(
            ChainFindingRelation.id == relation_id,
            ChainFindingRelation.user_id == user_id,
        )
        result = await session.execute(stmt)
        relation = result.scalar_one_or_none()
        if relation is None:
            return None

        # Update status
        relation.status = new_status
        relation.updated_at = datetime.now(timezone.utc)

        # On confirm, snapshot current reasons for drift detection
        if new_status == "user_confirmed":
            relation.confirmed_at_reasons_json = relation.reasons_json

        session.add(relation)
        await session.commit()
        await session.refresh(relation)

        return relation_to_dict(_orm_to_relation(relation))
```

- [ ] **Step 2: Verify import**

Run: `cd packages/web/backend && python -c "from app.services.chain_service import ChainService; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add packages/web/backend/app/services/chain_service.py
git commit -m "feat(chain): add update_relation_status for edge curation"
```

---

## Task 4: Backend — Subgraph and curation route endpoints

**Files:**
- Modify: `packages/web/backend/app/routes/chain.py`

Adds `GET /api/chain/subgraph` and `PATCH /api/chain/relations/{relation_id}`.

- [ ] **Step 1: Add new Pydantic models for the endpoints**

Add to `packages/web/backend/app/routes/chain.py`, after the existing model classes:

```python
class SubgraphMeta(BaseModel):
    total_findings: int
    rendered_findings: int
    filtered: bool
    generation: int


class SubgraphResponse(BaseModel):
    graph: dict
    meta: SubgraphMeta


class RelationStatusUpdate(BaseModel):
    status: str
```

- [ ] **Step 2: Add the subgraph endpoint**

```python
@router.get("/subgraph", response_model=SubgraphResponse)
async def get_subgraph(
    engagement_id: str,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    max_nodes: int = 500,
    seed_finding_id: Optional[str] = None,
    hops: int = 2,
    format: str = "force-graph",
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    service: ChainService = Depends(get_chain_service),
) -> SubgraphResponse:
    severities = set(severity.split(",")) if severity else None
    statuses = set(status.split(",")) if status else None

    result = await service.subgraph_for_engagement(
        db,
        user_id=user.id,
        engagement_id=engagement_id,
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

- [ ] **Step 3: Add the relation curation endpoint**

```python
@router.patch("/relations/{relation_id}")
async def update_relation(
    relation_id: str,
    body: RelationStatusUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    service: ChainService = Depends(get_chain_service),
):
    valid_statuses = {"user_confirmed", "user_rejected"}
    if body.status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"status must be one of: {', '.join(valid_statuses)}",
        )

    result = await service.update_relation_status(
        db, user_id=user.id, relation_id=relation_id, new_status=body.status,
    )
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="relation not found")
    return result
```

- [ ] **Step 4: Verify the app starts**

Run: `cd packages/web/backend && python -c "from app.main import app; print('OK')"`
Expected: `OK`

- [ ] **Step 5: Commit**

```bash
git add packages/web/backend/app/routes/chain.py
git commit -m "feat(chain): add subgraph and relation curation endpoints"
```

---

## Task 5: Backend — Subgraph endpoint tests

**Files:**
- Create: `packages/web/backend/tests/test_chain_subgraph.py`

- [ ] **Step 1: Write subgraph endpoint tests**

Create `packages/web/backend/tests/test_chain_subgraph.py`:

```python
"""Subgraph endpoint tests (Phase 3C.2)."""

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


async def _seed_engagement(user_id, eng_id):
    async with test_session_factory() as session:
        session.add(Engagement(
            id=eng_id, user_id=user_id, name="Test", target="10.0.0.0/24",
            type="pentest", created_at=NOW, updated_at=NOW,
        ))
        await session.commit()


async def _seed_finding(user_id, eng_id, finding_id, severity="high", phase=None):
    async with test_session_factory() as session:
        session.add(Finding(
            id=finding_id, user_id=user_id, engagement_id=eng_id,
            tool="nmap", severity=severity, title=f"Finding {finding_id}",
            phase=phase, created_at=NOW,
        ))
        await session.commit()


async def _seed_relation(user_id, src_id, tgt_id, rel_id, status="auto_confirmed", weight=0.8):
    async with test_session_factory() as session:
        session.add(ChainFindingRelation(
            id=rel_id, user_id=user_id, source_finding_id=src_id,
            target_finding_id=tgt_id, weight=weight, status=status,
            symmetric=False, created_at=NOW, updated_at=NOW,
        ))
        await session.commit()


@pytest.mark.asyncio
async def test_subgraph_empty_engagement(auth_client):
    """Engagement with no findings returns empty graph."""
    user_id = await _get_user_id(auth_client)
    await _seed_engagement(user_id, "eng-empty")

    resp = await auth_client.get("/api/chain/subgraph?engagement_id=eng-empty")
    assert resp.status_code == 200
    data = resp.json()
    assert data["graph"]["nodes"] == []
    assert data["graph"]["links"] == []
    assert data["meta"]["total_findings"] == 0
    assert data["meta"]["rendered_findings"] == 0


@pytest.mark.asyncio
async def test_subgraph_returns_nodes_and_links(auth_client):
    """Seeded findings and relations appear in subgraph response."""
    user_id = await _get_user_id(auth_client)
    await _seed_engagement(user_id, "eng-sub")
    await _seed_finding(user_id, "eng-sub", "f-1", severity="critical")
    await _seed_finding(user_id, "eng-sub", "f-2", severity="high")
    await _seed_relation(user_id, "f-1", "f-2", "rel-1")

    resp = await auth_client.get("/api/chain/subgraph?engagement_id=eng-sub")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["graph"]["nodes"]) == 2
    assert len(data["graph"]["links"]) == 1
    link = data["graph"]["links"][0]
    assert link["id"] == "rel-1"
    assert link["source"] == "f-1"
    assert link["target"] == "f-2"
    assert "drift" in link


@pytest.mark.asyncio
async def test_subgraph_severity_filter(auth_client):
    """Severity filter excludes non-matching findings."""
    user_id = await _get_user_id(auth_client)
    await _seed_engagement(user_id, "eng-sev")
    await _seed_finding(user_id, "eng-sev", "f-crit", severity="critical")
    await _seed_finding(user_id, "eng-sev", "f-low", severity="low")

    resp = await auth_client.get("/api/chain/subgraph?engagement_id=eng-sev&severity=critical")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["graph"]["nodes"]) == 1
    assert data["graph"]["nodes"][0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_subgraph_status_filter(auth_client):
    """Status filter excludes non-matching relations."""
    user_id = await _get_user_id(auth_client)
    await _seed_engagement(user_id, "eng-stat")
    await _seed_finding(user_id, "eng-stat", "f-a")
    await _seed_finding(user_id, "eng-stat", "f-b")
    await _seed_relation(user_id, "f-a", "f-b", "rel-conf", status="auto_confirmed")
    await _seed_relation(user_id, "f-b", "f-a", "rel-cand", status="candidate")

    # Only auto_confirmed
    resp = await auth_client.get(
        "/api/chain/subgraph?engagement_id=eng-stat&status=auto_confirmed"
    )
    data = resp.json()
    assert len(data["graph"]["links"]) == 1
    assert data["graph"]["links"][0]["status"] == "auto_confirmed"


@pytest.mark.asyncio
async def test_subgraph_max_nodes_cap(auth_client):
    """max_nodes caps the number of returned findings."""
    user_id = await _get_user_id(auth_client)
    await _seed_engagement(user_id, "eng-cap")
    for i in range(10):
        await _seed_finding(user_id, "eng-cap", f"f-cap-{i}")

    resp = await auth_client.get("/api/chain/subgraph?engagement_id=eng-cap&max_nodes=3")
    data = resp.json()
    assert len(data["graph"]["nodes"]) == 3
    assert data["meta"]["total_findings"] == 10
    assert data["meta"]["filtered"] is True


@pytest.mark.asyncio
async def test_subgraph_unauthenticated(client):
    """Unauthenticated request returns 401."""
    resp = await client.get("/api/chain/subgraph?engagement_id=eng-x")
    assert resp.status_code == 401
```

- [ ] **Step 2: Run the tests**

Run: `cd packages/web/backend && python -m pytest tests/test_chain_subgraph.py -v`
Expected: all tests PASS

- [ ] **Step 3: Commit**

```bash
git add packages/web/backend/tests/test_chain_subgraph.py
git commit -m "test(chain): subgraph endpoint tests — filters, cap, auth"
```

---

## Task 6: Backend — Curation endpoint tests

**Files:**
- Create: `packages/web/backend/tests/test_chain_curation.py`

- [ ] **Step 1: Write curation endpoint tests**

Create `packages/web/backend/tests/test_chain_curation.py`:

```python
"""Relation curation (PATCH) endpoint tests (Phase 3C.2)."""

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


async def _seed_with_relation(user_id, rel_id="rel-cur", status="candidate"):
    async with test_session_factory() as session:
        session.add(Engagement(
            id="eng-cur", user_id=user_id, name="Test", target="10.0.0.1",
            type="pentest", created_at=NOW, updated_at=NOW,
        ))
        await session.flush()
        session.add(Finding(
            id="f-cur-1", user_id=user_id, engagement_id="eng-cur",
            tool="nmap", severity="high", title="Finding 1", created_at=NOW,
        ))
        session.add(Finding(
            id="f-cur-2", user_id=user_id, engagement_id="eng-cur",
            tool="nuclei", severity="medium", title="Finding 2", created_at=NOW,
        ))
        await session.flush()
        session.add(ChainFindingRelation(
            id=rel_id, user_id=user_id, source_finding_id="f-cur-1",
            target_finding_id="f-cur-2", weight=0.75, status=status,
            symmetric=False, reasons_json=b'[{"rule":"shared_strong_entity","weight_contribution":0.5,"idf_factor":null,"details":{}}]',
            created_at=NOW, updated_at=NOW,
        ))
        await session.commit()


@pytest.mark.asyncio
async def test_confirm_candidate(auth_client):
    """Confirming a candidate relation succeeds."""
    user_id = await _get_user_id(auth_client)
    await _seed_with_relation(user_id, "rel-c1", status="candidate")

    resp = await auth_client.patch(
        "/api/chain/relations/rel-c1",
        json={"status": "user_confirmed"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "user_confirmed"


@pytest.mark.asyncio
async def test_reject_candidate(auth_client):
    """Rejecting a candidate relation succeeds."""
    user_id = await _get_user_id(auth_client)
    await _seed_with_relation(user_id, "rel-c2", status="candidate")

    resp = await auth_client.patch(
        "/api/chain/relations/rel-c2",
        json={"status": "user_rejected"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "user_rejected"


@pytest.mark.asyncio
async def test_toggle_confirmed_to_rejected(auth_client):
    """User can change from confirmed to rejected."""
    user_id = await _get_user_id(auth_client)
    await _seed_with_relation(user_id, "rel-c3", status="user_confirmed")

    resp = await auth_client.patch(
        "/api/chain/relations/rel-c3",
        json={"status": "user_rejected"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "user_rejected"


@pytest.mark.asyncio
async def test_invalid_status_returns_422(auth_client):
    """Setting auto_confirmed via PATCH returns 422."""
    user_id = await _get_user_id(auth_client)
    await _seed_with_relation(user_id, "rel-c4")

    resp = await auth_client.patch(
        "/api/chain/relations/rel-c4",
        json={"status": "auto_confirmed"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_nonexistent_relation_returns_404(auth_client):
    """Patching a nonexistent relation returns 404."""
    resp = await auth_client.patch(
        "/api/chain/relations/rel-does-not-exist",
        json={"status": "user_confirmed"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_confirm_snapshots_reasons(auth_client):
    """Confirming snapshots reasons_json into confirmed_at_reasons_json."""
    user_id = await _get_user_id(auth_client)
    await _seed_with_relation(user_id, "rel-c5", status="candidate")

    await auth_client.patch(
        "/api/chain/relations/rel-c5",
        json={"status": "user_confirmed"},
    )

    # Verify in DB
    async with test_session_factory() as session:
        from sqlalchemy import select
        result = await session.execute(
            select(ChainFindingRelation).where(ChainFindingRelation.id == "rel-c5")
        )
        rel = result.scalar_one()
        assert rel.confirmed_at_reasons_json is not None
        assert rel.confirmed_at_reasons_json == rel.reasons_json


@pytest.mark.asyncio
async def test_unauthenticated_returns_401(client):
    """Unauthenticated curation request returns 401."""
    resp = await client.patch(
        "/api/chain/relations/rel-x",
        json={"status": "user_confirmed"},
    )
    assert resp.status_code == 401
```

- [ ] **Step 2: Run the tests**

Run: `cd packages/web/backend && python -m pytest tests/test_chain_curation.py -v`
Expected: all tests PASS

- [ ] **Step 3: Commit**

```bash
git add packages/web/backend/tests/test_chain_curation.py
git commit -m "test(chain): curation endpoint tests — transitions, validation, auth"
```

---

## Task 7: Frontend — Install `force-graph` and add route

**Files:**
- Modify: `packages/web/frontend/package.json` (via npm)
- Modify: `packages/web/frontend/src/router/index.ts`
- Modify: `packages/web/frontend/src/views/EngagementDetailView.vue`

- [ ] **Step 1: Install force-graph**

Run: `cd packages/web/frontend && npm install force-graph`

- [ ] **Step 2: Add the chain route to router**

In `packages/web/frontend/src/router/index.ts`, add after the `finding-detail` route:

```typescript
    { path: '/engagements/:id/chain', name: 'engagement-chain', component: () => import('@/views/ChainGraphView.vue') },
```

- [ ] **Step 3: Add "View Attack Chain" button to EngagementDetailView**

In `packages/web/frontend/src/views/EngagementDetailView.vue`, add a button next to the existing Delete button in the header:

Find the `<Button label="Delete"` block and add before it:

```vue
      <div class="flex gap-2">
        <Button
          label="Attack Chain"
          icon="pi pi-share-alt"
          outlined
          @click="router.push(`/engagements/${engId}/chain`)"
        />
        <Button
          label="Delete"
          ...existing props...
        />
      </div>
```

- [ ] **Step 4: Commit**

```bash
git add packages/web/frontend/package.json packages/web/frontend/package-lock.json
git add packages/web/frontend/src/router/index.ts
git add packages/web/frontend/src/views/EngagementDetailView.vue
git commit -m "feat(frontend): install force-graph, add chain route and nav button"
```

---

## Task 8: Frontend — `ChainFilterToolbar.vue`

**Files:**
- Create: `packages/web/frontend/src/components/ChainFilterToolbar.vue`

- [ ] **Step 1: Create the filter toolbar component**

Create `packages/web/frontend/src/components/ChainFilterToolbar.vue`:

```vue
<script setup lang="ts">
import { ref, watch } from 'vue'
import SelectButton from 'primevue/selectbutton'
import Button from 'primevue/button'

const emit = defineEmits<{
  (e: 'filter-change', filters: { severities: string[]; statuses: string[] }): void
}>()

const severityOptions = ['critical', 'high', 'medium', 'low', 'info']
const statusOptions = [
  { label: 'Confirmed', value: 'auto_confirmed,user_confirmed' },
  { label: 'Candidate', value: 'candidate' },
  { label: 'Rejected', value: 'rejected,user_rejected' },
]

const selectedSeverities = ref([...severityOptions])
const selectedStatuses = ref(['auto_confirmed,user_confirmed', 'candidate'])

function emitFilters() {
  const statuses = selectedStatuses.value.flatMap(s => s.split(','))
  emit('filter-change', {
    severities: selectedSeverities.value,
    statuses,
  })
}

watch([selectedSeverities, selectedStatuses], emitFilters, { deep: true })

function reset() {
  selectedSeverities.value = [...severityOptions]
  selectedStatuses.value = ['auto_confirmed,user_confirmed', 'candidate']
}
</script>

<template>
  <div class="flex items-center gap-3 flex-wrap">
    <SelectButton
      v-model="selectedSeverities"
      :options="severityOptions"
      multiple
      :allow-empty="false"
    />
    <span class="text-surface-400">|</span>
    <SelectButton
      v-model="selectedStatuses"
      :options="statusOptions"
      option-label="label"
      option-value="value"
      multiple
      :allow-empty="false"
    />
    <Button icon="pi pi-refresh" text rounded size="small" @click="reset" v-tooltip="'Reset filters'" />
  </div>
</template>
```

- [ ] **Step 2: Commit**

```bash
git add packages/web/frontend/src/components/ChainFilterToolbar.vue
git commit -m "feat(frontend): ChainFilterToolbar — severity and status toggles"
```

---

## Task 9: Frontend — `ChainLegend.vue`

**Files:**
- Create: `packages/web/frontend/src/components/ChainLegend.vue`

- [ ] **Step 1: Create the legend component**

Create `packages/web/frontend/src/components/ChainLegend.vue`:

```vue
<script setup lang="ts">
defineProps<{
  renderedCount: number
  totalCount: number
}>()

const severities = [
  { label: 'Critical', color: '#e74c3c' },
  { label: 'High', color: '#e67e22' },
  { label: 'Medium', color: '#f1c40f' },
  { label: 'Low', color: '#3498db' },
  { label: 'Info', color: '#95a5a6' },
]
</script>

<template>
  <div class="flex items-center justify-between px-4 py-2 border-t border-surface-200 dark:border-surface-700 text-sm">
    <div class="flex items-center gap-4">
      <div v-for="s in severities" :key="s.label" class="flex items-center gap-1">
        <span class="inline-block w-3 h-3 rounded-full" :style="{ backgroundColor: s.color }" />
        <span>{{ s.label }}</span>
      </div>
      <span class="text-surface-400 mx-1">|</span>
      <span>── Confirmed</span>
      <span>╌╌ Candidate</span>
    </div>
    <div class="text-surface-500">
      Showing {{ renderedCount }} of {{ totalCount }}
    </div>
  </div>
</template>
```

- [ ] **Step 2: Commit**

```bash
git add packages/web/frontend/src/components/ChainLegend.vue
git commit -m "feat(frontend): ChainLegend — severity colors, edge styles, node count"
```

---

## Task 10: Frontend — `ChainEmptyState.vue`

**Files:**
- Create: `packages/web/frontend/src/components/ChainEmptyState.vue`

- [ ] **Step 1: Create the empty state component**

Create `packages/web/frontend/src/components/ChainEmptyState.vue`:

```vue
<script setup lang="ts">
import { ref } from 'vue'
import Button from 'primevue/button'
import ProgressBar from 'primevue/progressbar'
import { useToast } from 'primevue/usetoast'

const props = defineProps<{ engagementId: string }>()
const emit = defineEmits<{ (e: 'rebuild-complete'): void }>()
const toast = useToast()

const rebuilding = ref(false)
const pollTimer = ref<ReturnType<typeof setInterval> | null>(null)

async function startRebuild() {
  rebuilding.value = true
  try {
    const resp = await fetch('/api/chain/rebuild', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ engagement_id: props.engagementId }),
    })
    if (!resp.ok) throw new Error('Failed to start rebuild')
    const { run_id } = await resp.json()
    pollStatus(run_id)
  } catch {
    rebuilding.value = false
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to start chain analysis', life: 5000 })
  }
}

function pollStatus(runId: string) {
  pollTimer.value = setInterval(async () => {
    try {
      const resp = await fetch(`/api/chain/runs/${runId}`, { credentials: 'include' })
      if (!resp.ok) return
      const run = await resp.json()
      if (run.status === 'done' || run.status === 'completed') {
        clearInterval(pollTimer.value!)
        pollTimer.value = null
        rebuilding.value = false
        emit('rebuild-complete')
      } else if (run.status === 'failed' || run.status === 'error') {
        clearInterval(pollTimer.value!)
        pollTimer.value = null
        rebuilding.value = false
        toast.add({ severity: 'error', summary: 'Analysis Failed', detail: run.error || 'Unknown error', life: 5000 })
      }
    } catch {
      // Silently retry on network error
    }
  }, 2000)
}
</script>

<template>
  <div class="flex flex-col items-center justify-center h-full gap-4">
    <i class="pi pi-share-alt text-6xl text-surface-300" />
    <h2 class="text-xl font-semibold text-surface-500">No attack chain data yet</h2>
    <p class="text-surface-400">Run chain analysis to extract relationships between findings.</p>
    <Button
      v-if="!rebuilding"
      label="Run Chain Analysis"
      icon="pi pi-play"
      @click="startRebuild"
    />
    <div v-else class="w-64">
      <ProgressBar mode="indeterminate" />
      <p class="text-sm text-surface-400 text-center mt-2">Analyzing findings…</p>
    </div>
  </div>
</template>
```

- [ ] **Step 2: Commit**

```bash
git add packages/web/frontend/src/components/ChainEmptyState.vue
git commit -m "feat(frontend): ChainEmptyState — rebuild trigger with progress polling"
```

---

## Task 11: Frontend — `ChainDetailPanel.vue`

**Files:**
- Create: `packages/web/frontend/src/components/ChainDetailPanel.vue`

- [ ] **Step 1: Create the detail panel component**

Create `packages/web/frontend/src/components/ChainDetailPanel.vue`:

```vue
<script setup lang="ts">
import { computed } from 'vue'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import SeverityBadge from '@/components/SeverityBadge.vue'

interface GraphNode {
  id: string
  name: string
  severity: string
  tool: string
  phase: string | null
  neighborCount?: number
}

interface GraphLink {
  id: string
  source: string | { id: string }
  target: string | { id: string }
  value: number
  status: string
  drift: boolean
  reasons: string[]
  relation_type: string | null
  rationale: string | null
}

const props = defineProps<{
  selectedNode: GraphNode | null
  selectedLink: GraphLink | null
  nodes: GraphNode[]
}>()

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'confirm', linkId: string): void
  (e: 'reject', linkId: string): void
  (e: 'expand', nodeId: string): void
}>()

const isOpen = computed(() => props.selectedNode !== null || props.selectedLink !== null)

// Resolve link source/target to node objects for display
function findNode(ref: string | { id: string }): GraphNode | undefined {
  const id = typeof ref === 'string' ? ref : ref.id
  return props.nodes.find(n => n.id === id)
}

const sourceNode = computed(() => props.selectedLink ? findNode(props.selectedLink.source) : null)
const targetNode = computed(() => props.selectedLink ? findNode(props.selectedLink.target) : null)

const statusLabel: Record<string, string> = {
  auto_confirmed: 'Auto Confirmed',
  user_confirmed: 'Confirmed',
  candidate: 'Candidate',
  rejected: 'Rejected',
  user_rejected: 'Rejected',
}

const statusSeverity: Record<string, string> = {
  auto_confirmed: 'success',
  user_confirmed: 'success',
  candidate: 'warn',
  rejected: 'danger',
  user_rejected: 'danger',
}
</script>

<template>
  <div
    v-if="isOpen"
    class="w-80 border-l border-surface-200 dark:border-surface-700 overflow-y-auto p-4 flex flex-col gap-4"
  >
    <div class="flex justify-between items-center">
      <h3 class="font-semibold text-lg">
        {{ selectedNode ? 'Finding' : 'Relationship' }}
      </h3>
      <Button icon="pi pi-times" text rounded size="small" @click="emit('close')" />
    </div>

    <!-- Node details -->
    <template v-if="selectedNode">
      <div class="flex flex-col gap-2">
        <p class="font-medium">{{ selectedNode.name }}</p>
        <div class="flex items-center gap-2">
          <SeverityBadge :severity="selectedNode.severity" />
          <span class="text-sm text-surface-500">{{ selectedNode.tool }}</span>
        </div>
        <div v-if="selectedNode.phase" class="text-sm">
          <span class="text-surface-400">Phase:</span> {{ selectedNode.phase }}
        </div>
      </div>
      <Button
        :label="`Expand ${selectedNode.neighborCount ?? '?'} Neighbors`"
        icon="pi pi-arrows-alt"
        outlined
        size="small"
        @click="emit('expand', selectedNode.id)"
      />
    </template>

    <!-- Link details -->
    <template v-if="selectedLink">
      <div class="flex flex-col gap-2">
        <div class="text-sm">
          <span class="font-medium">{{ sourceNode?.name ?? '?' }}</span>
          <span class="text-surface-400 mx-1">→</span>
          <span class="font-medium">{{ targetNode?.name ?? '?' }}</span>
        </div>

        <div class="flex items-center gap-2">
          <Tag
            :value="statusLabel[selectedLink.status] ?? selectedLink.status"
            :severity="statusSeverity[selectedLink.status] ?? 'secondary'"
          />
          <span class="text-sm text-surface-500">Weight: {{ selectedLink.value.toFixed(2) }}</span>
        </div>

        <!-- Drift warning -->
        <div v-if="selectedLink.drift" class="flex items-center gap-2 p-2 bg-yellow-50 dark:bg-yellow-900/20 rounded text-sm">
          <i class="pi pi-exclamation-triangle text-yellow-500" />
          <span>Reasoning changed since you confirmed this edge.</span>
        </div>

        <!-- Reasons -->
        <div>
          <p class="text-sm font-medium text-surface-400 mb-1">Rules fired:</p>
          <ul class="text-sm flex flex-col gap-1">
            <li v-for="reason in selectedLink.reasons" :key="reason" class="flex items-center gap-1">
              <i class="pi pi-check-circle text-surface-400 text-xs" />
              {{ reason }}
            </li>
          </ul>
        </div>

        <!-- LLM rationale -->
        <div v-if="selectedLink.rationale">
          <p class="text-sm font-medium text-surface-400 mb-1">LLM rationale:</p>
          <p class="text-sm bg-surface-50 dark:bg-surface-800 p-2 rounded">{{ selectedLink.rationale }}</p>
        </div>

        <!-- Relation type -->
        <div v-if="selectedLink.relation_type" class="text-sm">
          <span class="text-surface-400">Type:</span> {{ selectedLink.relation_type }}
        </div>
      </div>

      <!-- Curation buttons -->
      <div class="flex gap-2 mt-2">
        <Button
          label="Confirm"
          icon="pi pi-check"
          severity="success"
          size="small"
          :disabled="selectedLink.status === 'user_confirmed'"
          @click="emit('confirm', selectedLink.id)"
        />
        <Button
          label="Reject"
          icon="pi pi-times"
          severity="danger"
          size="small"
          outlined
          :disabled="selectedLink.status === 'user_rejected'"
          @click="emit('reject', selectedLink.id)"
        />
      </div>
    </template>
  </div>
</template>
```

- [ ] **Step 2: Commit**

```bash
git add packages/web/frontend/src/components/ChainDetailPanel.vue
git commit -m "feat(frontend): ChainDetailPanel — node/edge details with curation buttons"
```

---

## Task 12: Frontend — `ForceGraphCanvas.vue`

**Files:**
- Create: `packages/web/frontend/src/components/ForceGraphCanvas.vue`

This is the core rendering component wrapping the `force-graph` library.

- [ ] **Step 1: Create the force-graph wrapper component**

Create `packages/web/frontend/src/components/ForceGraphCanvas.vue`:

```vue
<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, nextTick } from 'vue'
import ForceGraph from 'force-graph'

interface GraphNode {
  id: string
  name: string
  severity: string
  tool: string
  phase: string | null
  x?: number
  y?: number
  fx?: number | null
  fy?: number | null
  neighborCount?: number
}

interface GraphLink {
  id: string
  source: string | GraphNode
  target: string | GraphNode
  value: number
  status: string
  drift: boolean
  reasons: string[]
  relation_type: string | null
  rationale: string | null
}

interface GraphData {
  nodes: GraphNode[]
  links: GraphLink[]
}

const props = defineProps<{
  data: GraphData
  selectedNodeId: string | null
  selectedLinkId: string | null
}>()

const emit = defineEmits<{
  (e: 'node-click', node: GraphNode): void
  (e: 'link-click', link: GraphLink): void
  (e: 'background-click'): void
}>()

const container = ref<HTMLDivElement | null>(null)
let graph: any = null

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#e74c3c',
  high: '#e67e22',
  medium: '#f1c40f',
  low: '#3498db',
  info: '#95a5a6',
}

const MITRE_ABBREVS: Record<string, string> = {
  'reconnaissance': 'RE',
  'resource-development': 'RD',
  'initial-access': 'IA',
  'execution': 'EX',
  'persistence': 'PE',
  'privilege-escalation': 'PR',
  'defense-evasion': 'DE',
  'credential-access': 'CA',
  'discovery': 'DI',
  'lateral-movement': 'LM',
  'collection': 'CO',
  'command-and-control': 'C2',
  'exfiltration': 'EF',
  'impact': 'IM',
}

function getNodeId(ref: string | GraphNode): string {
  return typeof ref === 'string' ? ref : ref.id
}

function initGraph() {
  if (!container.value) return

  graph = ForceGraph()(container.value)
    .graphData(props.data)
    .nodeId('id')
    .linkSource('source')
    .linkTarget('target')
    .nodeCanvasObject((node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const n = node as GraphNode
      const links = props.data.links
      const connCount = links.filter(l => getNodeId(l.source) === n.id || getNodeId(l.target) === n.id).length
      const radius = Math.min(4 + connCount * 0.8, 12)
      const color = SEVERITY_COLORS[n.severity] || '#95a5a6'
      const isSelected = n.id === props.selectedNodeId

      // Circle
      ctx.beginPath()
      ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI)
      ctx.fillStyle = color
      ctx.fill()

      // Selection ring
      if (isSelected) {
        ctx.strokeStyle = '#ffffff'
        ctx.lineWidth = 2 / globalScale
        ctx.stroke()
        ctx.strokeStyle = color
        ctx.lineWidth = 1 / globalScale
        ctx.stroke()
      }

      // Label (visible at medium+ zoom)
      if (globalScale > 1.5) {
        const label = n.name.length > 30 ? n.name.slice(0, 27) + '…' : n.name
        ctx.font = `${10 / globalScale}px sans-serif`
        ctx.textAlign = 'center'
        ctx.textBaseline = 'top'
        ctx.fillStyle = '#666'
        ctx.fillText(label, node.x, node.y + radius + 2 / globalScale)
      }

      // MITRE phase pill (visible at medium+ zoom)
      if (n.phase && globalScale > 2) {
        const abbrev = MITRE_ABBREVS[n.phase] || n.phase.slice(0, 2).toUpperCase()
        const pillX = node.x + radius
        const pillY = node.y - radius
        ctx.font = `bold ${7 / globalScale}px sans-serif`
        const textWidth = ctx.measureText(abbrev).width
        const padding = 2 / globalScale

        ctx.fillStyle = 'rgba(0,0,0,0.6)'
        ctx.beginPath()
        ctx.roundRect(pillX - padding, pillY - 4 / globalScale - padding, textWidth + padding * 2, 8 / globalScale + padding * 2, 2 / globalScale)
        ctx.fill()

        ctx.fillStyle = '#fff'
        ctx.textAlign = 'left'
        ctx.textBaseline = 'middle'
        ctx.fillText(abbrev, pillX, pillY)
      }
    })
    .nodePointerAreaPaint((node: any, color: string, ctx: CanvasRenderingContext2D) => {
      const connCount = props.data.links.filter(l => getNodeId(l.source) === node.id || getNodeId(l.target) === node.id).length
      const radius = Math.min(4 + connCount * 0.8, 12)
      ctx.beginPath()
      ctx.arc(node.x, node.y, radius + 2, 0, 2 * Math.PI)
      ctx.fillStyle = color
      ctx.fill()
    })
    .linkCanvasObject((link: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
      const l = link as GraphLink
      const src = link.source
      const tgt = link.target
      if (!src.x || !tgt.x) return

      const isSelected = l.id === props.selectedLinkId

      ctx.beginPath()
      ctx.moveTo(src.x, src.y)
      ctx.lineTo(tgt.x, tgt.y)

      // Style by status
      const isConfirmed = l.status === 'auto_confirmed' || l.status === 'user_confirmed'
      const isCandidate = l.status === 'candidate'
      const isRejected = l.status === 'rejected' || l.status === 'user_rejected'

      if (isRejected) {
        ctx.strokeStyle = 'rgba(231, 76, 60, 0.4)'
        ctx.setLineDash([4 / globalScale, 4 / globalScale])
        ctx.lineWidth = (isSelected ? 2 : 0.5) / globalScale
      } else if (isCandidate) {
        ctx.strokeStyle = `rgba(100, 100, 100, ${0.3 + l.value * 0.3})`
        ctx.setLineDash([4 / globalScale, 4 / globalScale])
        ctx.lineWidth = (isSelected ? 2 : 1) / globalScale
      } else {
        const opacity = l.status === 'user_confirmed' ? 1 : 0.4 + l.value * 0.6
        ctx.strokeStyle = `rgba(80, 80, 80, ${opacity})`
        ctx.setLineDash([])
        ctx.lineWidth = (isSelected ? 2.5 : l.status === 'user_confirmed' ? 1.5 : 1) / globalScale
      }

      ctx.stroke()
      ctx.setLineDash([])

      // Arrowhead
      const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x)
      const arrowLen = 6 / globalScale
      const connCount = props.data.links.filter(lk => getNodeId(lk.source) === getNodeId(l.target) || getNodeId(lk.target) === getNodeId(l.target)).length
      const tgtRadius = Math.min(4 + connCount * 0.8, 12)
      const endX = tgt.x - Math.cos(angle) * tgtRadius
      const endY = tgt.y - Math.sin(angle) * tgtRadius
      ctx.beginPath()
      ctx.moveTo(endX, endY)
      ctx.lineTo(endX - arrowLen * Math.cos(angle - Math.PI / 6), endY - arrowLen * Math.sin(angle - Math.PI / 6))
      ctx.lineTo(endX - arrowLen * Math.cos(angle + Math.PI / 6), endY - arrowLen * Math.sin(angle + Math.PI / 6))
      ctx.closePath()
      ctx.fillStyle = ctx.strokeStyle
      ctx.fill()

      // Drift badge
      if (l.drift) {
        const midX = (src.x + tgt.x) / 2
        const midY = (src.y + tgt.y) / 2
        ctx.font = `${10 / globalScale}px sans-serif`
        ctx.fillStyle = '#f59e0b'
        ctx.textAlign = 'center'
        ctx.textBaseline = 'middle'
        ctx.fillText('▲', midX, midY)
      }
    })
    .linkPointerAreaPaint((link: any, color: string, ctx: CanvasRenderingContext2D) => {
      const src = link.source
      const tgt = link.target
      if (!src.x || !tgt.x) return
      ctx.beginPath()
      ctx.moveTo(src.x, src.y)
      ctx.lineTo(tgt.x, tgt.y)
      ctx.lineWidth = 8
      ctx.strokeStyle = color
      ctx.stroke()
    })
    .onNodeClick((node: any) => emit('node-click', node))
    .onLinkClick((link: any) => emit('link-click', link))
    .onBackgroundClick(() => emit('background-click'))
    .cooldownTicks(100)
    .warmupTicks(50)

  // Zoom to fit after initial layout
  setTimeout(() => graph?.zoomToFit(400, 50), 500)
}

function updateData(newData: GraphData) {
  if (!graph) return

  // Preserve positions of existing nodes
  const oldNodes = graph.graphData().nodes as GraphNode[]
  const posMap = new Map<string, { x: number; y: number }>()
  for (const n of oldNodes) {
    if (n.x !== undefined && n.y !== undefined) {
      posMap.set(n.id, { x: n.x, y: n.y })
    }
  }

  for (const n of newData.nodes) {
    const pos = posMap.get(n.id)
    if (pos) {
      n.x = pos.x
      n.y = pos.y
      n.fx = pos.x
      n.fy = pos.y
      // Unpin after short delay to let simulation settle
      setTimeout(() => {
        n.fx = null
        n.fy = null
      }, 1000)
    }
  }

  graph.graphData(newData)
}

watch(() => props.data, (newData) => {
  if (graph) {
    updateData(newData)
  }
}, { deep: true })

onMounted(() => {
  nextTick(() => initGraph())
})

onUnmounted(() => {
  if (graph) {
    graph._destructor?.()
    graph = null
  }
})

function resize() {
  if (graph && container.value) {
    graph.width(container.value.clientWidth)
    graph.height(container.value.clientHeight)
  }
}

defineExpose({ resize })
</script>

<template>
  <div ref="container" class="w-full h-full" />
</template>
```

- [ ] **Step 2: Commit**

```bash
git add packages/web/frontend/src/components/ForceGraphCanvas.vue
git commit -m "feat(frontend): ForceGraphCanvas — force-graph wrapper with custom rendering"
```

---

## Task 13: Frontend — `ChainGraphView.vue` (page component)

**Files:**
- Create: `packages/web/frontend/src/views/ChainGraphView.vue`

This is the top-level page component that ties everything together.

- [ ] **Step 1: Create the page component**

Create `packages/web/frontend/src/views/ChainGraphView.vue`:

```vue
<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useQuery, useMutation, useQueryClient } from '@tanstack/vue-query'
import Button from 'primevue/button'
import ProgressSpinner from 'primevue/progressspinner'
import { useToast } from 'primevue/usetoast'

import ForceGraphCanvas from '@/components/ForceGraphCanvas.vue'
import ChainDetailPanel from '@/components/ChainDetailPanel.vue'
import ChainFilterToolbar from '@/components/ChainFilterToolbar.vue'
import ChainLegend from '@/components/ChainLegend.vue'
import ChainEmptyState from '@/components/ChainEmptyState.vue'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const queryClient = useQueryClient()

const engId = route.params.id as string

// Filter state
const filters = ref({ severities: [] as string[], statuses: [] as string[] })

function onFilterChange(f: { severities: string[]; statuses: string[] }) {
  filters.value = f
}

// Build query params
const queryParams = computed(() => {
  const params = new URLSearchParams({ engagement_id: engId, max_nodes: '500' })
  if (filters.value.severities.length > 0 && filters.value.severities.length < 5) {
    params.set('severity', filters.value.severities.join(','))
  }
  if (filters.value.statuses.length > 0) {
    params.set('status', filters.value.statuses.join(','))
  }
  return params.toString()
})

// Fetch subgraph
const { data: subgraphData, isLoading, refetch } = useQuery({
  queryKey: ['chain-subgraph', engId, queryParams],
  queryFn: () =>
    fetch(`/api/chain/subgraph?${queryParams.value}`, { credentials: 'include' })
      .then(r => {
        if (!r.ok) throw new Error('Failed to fetch subgraph')
        return r.json()
      }),
})

const graphData = computed(() => subgraphData.value?.graph ?? { nodes: [], links: [] })
const meta = computed(() => subgraphData.value?.meta ?? { total_findings: 0, rendered_findings: 0, filtered: false, generation: 0 })
const isEmpty = computed(() => !isLoading.value && meta.value.total_findings === 0)
const hasNoRelations = computed(() => !isLoading.value && meta.value.total_findings > 0 && graphData.value.links.length === 0 && graphData.value.nodes.length === 0)

// Selection state
const selectedNode = ref<any>(null)
const selectedLink = ref<any>(null)

function onNodeClick(node: any) {
  selectedLink.value = null
  selectedNode.value = {
    ...node,
    neighborCount: graphData.value.links.filter(
      (l: any) => {
        const srcId = typeof l.source === 'string' ? l.source : l.source.id
        const tgtId = typeof l.target === 'string' ? l.target : l.target.id
        return srcId === node.id || tgtId === node.id
      }
    ).length,
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

// Curation mutation
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
    // Optimistic update: update the link in local graph data
    const link = graphData.value.links.find((l: any) => l.id === variables.relationId)
    if (link) {
      link.status = variables.status
      if (variables.status === 'user_confirmed') {
        link.drift = false
      }
    }
    if (selectedLink.value?.id === variables.relationId) {
      selectedLink.value = { ...selectedLink.value, status: variables.status }
    }
    toast.add({ severity: 'success', summary: 'Updated', detail: `Edge ${variables.status === 'user_confirmed' ? 'confirmed' : 'rejected'}`, life: 2000 })
  },
  onError: () => {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to update edge', life: 3000 })
  },
})

function onConfirm(linkId: string) {
  curateMutation.mutate({ relationId: linkId, status: 'user_confirmed' })
}

function onReject(linkId: string) {
  curateMutation.mutate({ relationId: linkId, status: 'user_rejected' })
}

// Neighborhood expansion
async function onExpand(nodeId: string) {
  try {
    const params = new URLSearchParams({
      engagement_id: engId,
      seed_finding_id: nodeId,
      hops: '2',
      max_nodes: '500',
    })
    if (filters.value.severities.length > 0 && filters.value.severities.length < 5) {
      params.set('severity', filters.value.severities.join(','))
    }
    if (filters.value.statuses.length > 0) {
      params.set('status', filters.value.statuses.join(','))
    }
    const resp = await fetch(`/api/chain/subgraph?${params}`, { credentials: 'include' })
    if (!resp.ok) throw new Error('Failed to expand')
    const expansion = await resp.json()

    // Merge into existing graph data
    const existingNodeIds = new Set(graphData.value.nodes.map((n: any) => n.id))
    const existingLinkIds = new Set(graphData.value.links.map((l: any) => l.id))

    for (const node of expansion.graph.nodes) {
      if (!existingNodeIds.has(node.id)) {
        graphData.value.nodes.push(node)
      }
    }
    for (const link of expansion.graph.links) {
      if (!existingLinkIds.has(link.id)) {
        graphData.value.links.push(link)
      }
    }

    toast.add({ severity: 'info', summary: 'Expanded', detail: `Added ${expansion.graph.nodes.length} nodes`, life: 2000 })
  } catch {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to expand neighborhood', life: 3000 })
  }
}

function onRebuildComplete() {
  refetch()
}

// Engagement name for header
const { data: engagement } = useQuery({
  queryKey: ['engagement', engId],
  queryFn: () =>
    fetch(`/api/v1/engagements/${engId}`, { credentials: 'include' }).then(r => r.json()),
})
</script>

<template>
  <div class="flex flex-col h-screen">
    <!-- Toolbar -->
    <div class="flex items-center gap-3 p-3 border-b border-surface-200 dark:border-surface-700">
      <Button icon="pi pi-arrow-left" text rounded @click="router.push(`/engagements/${engId}`)" />
      <h1 class="text-lg font-bold">{{ engagement?.name ?? 'Attack Chain' }}</h1>
      <div class="flex-1">
        <ChainFilterToolbar @filter-change="onFilterChange" />
      </div>
    </div>

    <!-- Main content -->
    <div v-if="isLoading" class="flex-1 flex items-center justify-center">
      <ProgressSpinner />
    </div>

    <template v-else-if="isEmpty || hasNoRelations">
      <ChainEmptyState :engagement-id="engId" @rebuild-complete="onRebuildComplete" />
    </template>

    <template v-else>
      <div class="flex flex-1 overflow-hidden">
        <ForceGraphCanvas
          :data="graphData"
          :selected-node-id="selectedNode?.id ?? null"
          :selected-link-id="selectedLink?.id ?? null"
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
          @expand="onExpand"
        />
      </div>
    </template>

    <!-- Legend -->
    <ChainLegend
      :rendered-count="meta.rendered_findings"
      :total-count="meta.total_findings"
    />
  </div>
</template>
```

- [ ] **Step 2: Verify the build compiles**

Run: `cd packages/web/frontend && npx vue-tsc --noEmit`
Expected: no type errors (or only pre-existing ones)

- [ ] **Step 3: Commit**

```bash
git add packages/web/frontend/src/views/ChainGraphView.vue
git commit -m "feat(frontend): ChainGraphView — page component with data fetching, curation, expansion"
```

---

## Task 14: Manual browser verification

**Files:** none (verification only)

- [ ] **Step 1: Start the backend dev server**

Run: `cd packages/web/backend && uvicorn app.main:app --reload --port 8000`

- [ ] **Step 2: Start the frontend dev server**

Run: `cd packages/web/frontend && npm run dev`

- [ ] **Step 3: Verify the flow**

1. Login at `http://localhost:5173/login`
2. Navigate to an engagement → click "Attack Chain" button
3. If no chain data: verify empty state appears with "Run Chain Analysis" button
4. If chain data exists: verify the force-graph renders with nodes and edges
5. Click a node → verify detail panel opens with finding info and "Expand Neighbors" button
6. Click an edge → verify detail panel shows reasons, rationale, confirm/reject buttons
7. Click Confirm/Reject → verify edge style updates optimistically
8. Toggle severity/status filters → verify graph re-renders with filtered data
9. Verify legend bar shows correct node count

- [ ] **Step 4: Fix any issues found during verification**

- [ ] **Step 5: Final commit with any fixes**

```bash
git add -A
git commit -m "fix(chain-viz): address issues found during browser verification"
```

---

## Task 15: Run full test suite

**Files:** none (verification only)

- [ ] **Step 1: Run all backend tests**

Run: `cd packages/web/backend && python -m pytest tests/ -v`
Expected: all tests PASS, including new `test_chain_subgraph.py` and `test_chain_curation.py`

- [ ] **Step 2: Run frontend type check**

Run: `cd packages/web/frontend && npx vue-tsc --noEmit`
Expected: no new type errors

- [ ] **Step 3: Commit if any test fixes were needed**

```bash
git add -A
git commit -m "fix: address test suite issues from 3C.2 integration"
```
