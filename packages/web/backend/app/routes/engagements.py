"""Engagement API routes."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db, get_current_user
from app.models import User
from app.services.engagement_service import EngagementService

router = APIRouter(prefix="/api/v1/engagements", tags=["engagements"])


class EngagementCreate(BaseModel):
    name: str
    target: str
    type: str
    scope: Optional[str] = None


class EngagementUpdate(BaseModel):
    name: Optional[str] = None
    target: Optional[str] = None
    type: Optional[str] = None
    scope: Optional[str] = None


class EngagementStatusUpdate(BaseModel):
    status: str


@router.get("")
async def list_engagements(
    cursor: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = EngagementService(db, user)
    items, next_cursor = await service.list(cursor, limit)
    return {"items": items, "next_cursor": next_cursor, "has_more": next_cursor is not None}


@router.post("", status_code=201)
async def create_engagement(
    body: EngagementCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = EngagementService(db, user)
    engagement = await service.create(
        name=body.name, target=body.target, type=body.type, scope=body.scope
    )
    return engagement


@router.get("/{engagement_id}")
async def get_engagement(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = EngagementService(db, user)
    summary = await service.get_summary(engagement_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return summary


@router.patch("/{engagement_id}")
async def update_engagement(
    engagement_id: str,
    body: EngagementUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = EngagementService(db, user)
    engagement = await service.update(
        engagement_id, **body.model_dump(exclude_unset=True)
    )
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return engagement


@router.delete("/{engagement_id}", status_code=204)
async def delete_engagement(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = EngagementService(db, user)
    deleted = await service.delete(engagement_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return None


@router.patch("/{engagement_id}/status")
async def update_engagement_status(
    engagement_id: str,
    body: EngagementStatusUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = EngagementService(db, user)
    engagement = await service.update(engagement_id, status=body.status)
    if not engagement:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return engagement
