"""IOC correlation and trending API endpoints."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db, get_current_user
from app.models import User
from app.services.correlation_service import CorrelationService

router = APIRouter(prefix="/api/v1", tags=["correlation"])


@router.get("/iocs/correlate")
async def correlate_ioc(
    value: str = Query(..., description="IOC value to correlate"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Find all engagements containing this IOC."""
    service = CorrelationService(db, user)
    return await service.correlate(value)


@router.get("/engagements/{engagement_id}/correlations")
async def correlate_engagement(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Find IOCs in this engagement that also appear in other engagements."""
    service = CorrelationService(db, user)
    return await service.correlate_engagement(engagement_id)


@router.get("/iocs/trending")
async def trending_iocs(
    limit: int = Query(10, ge=1, le=100),
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Top N most-seen IOCs in the last N days."""
    service = CorrelationService(db, user)
    return await service.hot_iocs(limit, days)


@router.get("/iocs/{ioc_type}/{ioc_value}/timeline")
async def ioc_timeline(
    ioc_type: str,
    ioc_value: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """IOC lifecycle + monthly frequency."""
    service = CorrelationService(db, user)
    lifecycle = await service.lifecycle(ioc_type, ioc_value)
    frequency = await service.frequency(ioc_type, ioc_value)
    return {"lifecycle": lifecycle, "frequency": frequency}


@router.get("/iocs/{ioc_type}/{ioc_value}/enrichment")
async def get_enrichment(
    ioc_type: str,
    ioc_value: str,
    refresh: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get cached enrichment (or fetch fresh if refresh=true)."""
    from opentools.correlation.enrichment import get_providers
    from opentools.correlation.enrichment.manager import EnrichmentManager
    manager = EnrichmentManager(get_providers())
    results = await manager.enrich_single(ioc_type, ioc_value, force_refresh=refresh)
    return {
        "enrichments": [r.model_dump() for r in results],
        "aggregated_risk_score": EnrichmentManager.aggregate_risk_score(results, ioc_type),
    }


@router.post("/iocs/{ioc_type}/{ioc_value}/enrich")
async def force_enrich(
    ioc_type: str,
    ioc_value: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Force fresh enrichment from all providers."""
    from opentools.correlation.enrichment import get_providers
    from opentools.correlation.enrichment.manager import EnrichmentManager
    manager = EnrichmentManager(get_providers())
    results = await manager.enrich_single(ioc_type, ioc_value, force_refresh=True)
    return {
        "enrichments": [r.model_dump() for r in results],
        "aggregated_risk_score": EnrichmentManager.aggregate_risk_score(results, ioc_type),
    }


@router.get("/iocs/common")
async def common_iocs(
    engagements: str = Query(..., description="Comma-separated engagement IDs"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Find IOCs shared between specific engagements."""
    eng_ids = [e.strip() for e in engagements.split(",")]
    service = CorrelationService(db, user)
    # Use the correlate method for each engagement and intersect
    results = []
    for eng_id in eng_ids:
        correlations = await service.correlate_engagement(eng_id)
        for c in correlations:
            if all(e["id"] in eng_ids for e in c.engagements):
                if not any(r.ioc_value == c.ioc_value for r in results):
                    results.append(c)
    return results
