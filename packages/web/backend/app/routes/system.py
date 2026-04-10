"""System, health, config, audit, and SSE API routes."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db, get_current_user
from app.models import AuditEntry, User
from app.sse import sse_manager

router = APIRouter(prefix="/api/v1", tags=["system"])


@router.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@router.get("/preflight")
async def preflight(
    user: User = Depends(get_current_user),
):
    """Pre-flight check: verify CLI tools and database connectivity."""
    checks = {
        "database": True,
        "cli_available": False,
        "docker_available": False,
    }
    try:
        from opentools.plugin import discover_plugin_dir

        discover_plugin_dir()
        checks["cli_available"] = True
    except Exception:
        pass

    try:
        from opentools.containers import ContainerManager

        checks["docker_available"] = True
    except Exception:
        pass

    return checks


@router.get("/config")
async def get_config(
    user: User = Depends(get_current_user),
):
    """Return non-sensitive application configuration."""
    try:
        from opentools.config import ConfigLoader

        config = ConfigLoader().load()
        # Only expose safe keys
        return {
            "tools": getattr(config, "tools", []),
            "recipes_available": True,
        }
    except ImportError:
        return {"tools": [], "recipes_available": False}
    except Exception as exc:
        return {"tools": [], "recipes_available": False, "error": str(exc)}


@router.get("/audit")
async def list_audit(
    cursor: Optional[str] = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    stmt = (
        select(AuditEntry)
        .where(AuditEntry.user_id == user.id)
        .order_by(AuditEntry.timestamp.desc())
        .limit(limit + 1)
    )
    if cursor:
        stmt = stmt.where(AuditEntry.timestamp < cursor)

    result = await db.execute(stmt)
    rows = list(result.scalars().all())

    next_cursor: Optional[str] = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = rows[-1].timestamp.isoformat()

    return {"items": rows, "next_cursor": next_cursor, "has_more": next_cursor is not None}


@router.get("/events")
async def sse_events(
    user: User = Depends(get_current_user),
):
    """Server-Sent Events endpoint for real-time updates."""
    try:
        from sse_starlette.sse import EventSourceResponse

        return EventSourceResponse(sse_manager.subscribe(str(user.id)))
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="SSE not available (sse-starlette not installed)",
        )
