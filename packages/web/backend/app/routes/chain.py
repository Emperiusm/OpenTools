"""Chain data layer API routes."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.dependencies import get_db, get_current_user, chain_task_registry_dep
from app.models import User
from app.services.chain_rebuild_worker import run_rebuild_shared
from app.services.chain_service import (
    ChainPathResultDTO,
    ChainQueryPathRequest,
    ChainService,
)
from app.services.chain_tasks import ChainTaskRegistry


def _get_session_factory():
    """Return the async session factory for use by background tasks.

    Background tasks must NOT reuse the request-scoped session — it will be
    closed by the time the task coroutine runs. This factory creates fresh
    sessions that support ``async with session_factory() as session: ...``
    usage.
    """
    return async_session_factory

router = APIRouter(prefix="/api/chain", tags=["chain"])


class EntityResponse(BaseModel):
    id: str
    type: str
    canonical_value: str
    mention_count: int
    first_seen_at: datetime
    last_seen_at: datetime


class RelationResponse(BaseModel):
    id: str
    source_finding_id: str
    target_finding_id: str
    weight: float
    status: str
    symmetric: bool


class PathRequest(BaseModel):
    from_finding_id: str
    to_finding_id: str
    k: int = 5
    max_hops: int = 6
    include_candidates: bool = False


class PathResponse(BaseModel):
    paths: list[dict]
    total: int


class RebuildRequest(BaseModel):
    engagement_id: Optional[str] = None


class RebuildResponse(BaseModel):
    run_id: str
    status: str


class RunStatusResponse(BaseModel):
    run_id: str
    status: str
    started_at: datetime
    finished_at: Optional[datetime]
    findings_processed: int
    relations_created: int
    error: Optional[str]


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


def get_chain_service() -> ChainService:
    return ChainService()


@router.get("/entities", response_model=list[EntityResponse])
async def list_entities(
    type_: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    service: ChainService = Depends(get_chain_service),
) -> list[EntityResponse]:
    entities = await service.list_entities(
        db, user_id=user.id, type_=type_, limit=limit, offset=offset,
    )
    return [
        EntityResponse(
            id=e["id"],
            type=e["type"],
            canonical_value=e["canonical_value"],
            mention_count=e["mention_count"],
            first_seen_at=e["first_seen_at"],
            last_seen_at=e["last_seen_at"],
        )
        for e in entities
    ]


@router.get("/entities/{entity_id}", response_model=EntityResponse)
async def get_entity(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    service: ChainService = Depends(get_chain_service),
) -> EntityResponse:
    entity = await service.get_entity(db, user_id=user.id, entity_id=entity_id)
    if entity is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="entity not found")
    return EntityResponse(
        id=entity["id"],
        type=entity["type"],
        canonical_value=entity["canonical_value"],
        mention_count=entity["mention_count"],
        first_seen_at=entity["first_seen_at"],
        last_seen_at=entity["last_seen_at"],
    )


@router.get("/findings/{finding_id}/relations", response_model=list[RelationResponse])
async def relations_for_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    service: ChainService = Depends(get_chain_service),
) -> list[RelationResponse]:
    relations = await service.relations_for_finding(
        db, user_id=user.id, finding_id=finding_id,
    )
    return [
        RelationResponse(
            id=r["id"],
            source_finding_id=r["source_finding_id"],
            target_finding_id=r["target_finding_id"],
            weight=r["weight"],
            status=r["status"],
            symmetric=r["symmetric"],
        )
        for r in relations
    ]


@router.post("/path", response_model=PathResponse)
async def query_path(
    request: PathRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    service: ChainService = Depends(get_chain_service),
) -> PathResponse:
    req = ChainQueryPathRequest(
        from_finding_id=request.from_finding_id,
        to_finding_id=request.to_finding_id,
        k=request.k,
        max_hops=request.max_hops,
        include_candidates=request.include_candidates,
    )
    results = await service.k_shortest_paths(db, user_id=user.id, request=req)
    return PathResponse(
        paths=[
            {
                "nodes": p.nodes,
                "edges": p.edges,
                "total_cost": p.total_cost,
                "length": p.length,
            }
            for p in results
        ],
        total=len(results),
    )


@router.post("/rebuild", response_model=RebuildResponse, status_code=status.HTTP_202_ACCEPTED)
async def rebuild_chain(
    request: RebuildRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    service: ChainService = Depends(get_chain_service),
    registry: ChainTaskRegistry = Depends(chain_task_registry_dep),
) -> RebuildResponse:
    """Start a background rebuild task via the shared pipeline.

    Creates a ChainLinkerRun row in pending state (through the
    ``PostgresChainStore.start_linker_run`` protocol method), launches
    an ``asyncio.Task`` through the ChainTaskRegistry, and returns
    the run_id immediately. The task updates the row as it
    progresses: pending -> running -> done/failed.

    The background worker uses the shared CLI
    :class:`ExtractionPipeline` + :class:`LinkerEngine` instead of the
    old web-specific subset, so all 6 default linker rules (not just
    shared-strong-entity) are applied.
    """
    run = await service.create_linker_run_pending(
        db, user_id=user.id, engagement_id=request.engagement_id,
    )

    # Launch the background task. The factory passed must open NEW sessions —
    # the request-scoped session will be closed by the time the task actually runs.
    session_factory = _get_session_factory()

    registry.start(
        run["id"],
        run_rebuild_shared(
            session_factory=session_factory,
            run_id=run["id"],
            user_id=user.id,
            engagement_id=request.engagement_id,
        ),
    )

    return RebuildResponse(
        run_id=run["id"], status=run.get("status_text") or "pending"
    )


@router.get("/runs/{run_id}", response_model=RunStatusResponse)
async def get_run_status(
    run_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
    service: ChainService = Depends(get_chain_service),
) -> RunStatusResponse:
    run = await service.get_linker_run(db, user_id=user.id, run_id=run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run not found")
    return RunStatusResponse(
        run_id=run["id"],
        status=run.get("status_text") or "unknown",
        started_at=run["started_at"],
        finished_at=run.get("finished_at"),
        findings_processed=run["findings_processed"],
        relations_created=run["relations_created"],
        error=run.get("error"),
    )


@router.get("/subgraph", response_model=SubgraphResponse)
async def get_subgraph(
    engagement_id: str,
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
