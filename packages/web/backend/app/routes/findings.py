"""Finding API routes."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db, get_current_user
from app.models import User
from app.services.finding_service import FindingService

router = APIRouter(prefix="/api/v1", tags=["findings"])


class FindingCreate(BaseModel):
    tool: str
    title: str
    severity: str
    cwe: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    description: Optional[str] = None
    evidence: Optional[str] = None


class FindingStatusUpdate(BaseModel):
    status: str


class BulkFPRequest(BaseModel):
    finding_ids: list[str]


class BulkStatusRequest(BaseModel):
    finding_ids: list[str]
    status: str


@router.get("/engagements/{engagement_id}/findings")
async def list_findings(
    engagement_id: str,
    cursor: Optional[str] = None,
    limit: int = 50,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    phase: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = FindingService(db, user)
    items, next_cursor = await service.list(
        engagement_id, cursor, limit, severity, status, phase
    )
    return {"items": items, "next_cursor": next_cursor, "has_more": next_cursor is not None}


@router.post("/engagements/{engagement_id}/findings", status_code=201)
async def create_finding(
    engagement_id: str,
    body: FindingCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = FindingService(db, user)
    finding = await service.create(
        engagement_id=engagement_id,
        tool=body.tool,
        title=body.title,
        severity=body.severity,
        cwe=body.cwe,
        file_path=body.file_path,
        line_start=body.line_start,
        description=body.description,
        evidence=body.evidence,
    )
    return finding


@router.get("/findings/search")
async def search_findings(
    q: str,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = FindingService(db, user)
    results = await service.search(q, limit)
    return {"items": results, "count": len(results)}


@router.patch("/findings/bulk/false-positive")
async def bulk_flag_false_positive(
    body: BulkFPRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = FindingService(db, user)
    count = await service.bulk_flag_fp(body.finding_ids)
    return {"updated": count}


@router.patch("/findings/bulk/status")
async def bulk_update_status(
    body: BulkStatusRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = FindingService(db, user)
    count = await service.bulk_update_status(body.finding_ids, body.status)
    return {"updated": count}


@router.get("/findings/{finding_id}")
async def get_finding(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = FindingService(db, user)
    finding = await service.get(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: str,
    body: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = FindingService(db, user)
    finding = await service.update_status(finding_id, body.status)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.patch("/findings/{finding_id}/false-positive")
async def flag_false_positive(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = FindingService(db, user)
    finding = await service.flag_false_positive(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding
