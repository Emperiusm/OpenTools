"""IOC API routes."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db, get_current_user
from app.models import User
from app.services.ioc_service import IOCService

router = APIRouter(prefix="/api/v1", tags=["iocs"])


class IOCCreate(BaseModel):
    ioc_type: str
    value: str
    context: Optional[str] = None


@router.get("/engagements/{engagement_id}/iocs")
async def list_iocs(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = IOCService(db, user)
    items = await service.list(engagement_id)
    return {"items": items}


@router.post("/engagements/{engagement_id}/iocs", status_code=201)
async def create_ioc(
    engagement_id: str,
    body: IOCCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = IOCService(db, user)
    ioc = await service.create(
        engagement_id=engagement_id,
        ioc_type=body.ioc_type,
        value=body.value,
        context=body.context,
    )
    return ioc


@router.get("/iocs/search")
async def search_iocs(
    q: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = IOCService(db, user)
    items = await service.search(q)
    return {"items": items, "count": len(items)}
