# packages/web/backend/app/routes/scans.py
"""Scan API routes — CRUD, control, and streaming endpoints.

Follows the existing router pattern in app/routes/.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.dependencies import get_current_user
from app.models import User

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

# ---------------------------------------------------------------------------
# Singleton store — one SQLite connection for the process lifetime
# ---------------------------------------------------------------------------

_scan_store: "SqliteScanStore | None" = None
_scan_store_lock = asyncio.Lock()


async def _get_scan_store():
    """Lazy singleton — one SqliteScanStore for the process lifetime."""
    global _scan_store
    if _scan_store is not None:
        return _scan_store
    async with _scan_store_lock:
        if _scan_store is not None:
            return _scan_store
        from pathlib import Path
        from opentools.scanner.store import SqliteScanStore
        db_path = Path.home() / ".opentools" / "scans.db"
        if not db_path.exists():
            return None
        store = SqliteScanStore(db_path)
        await store.initialize()
        _scan_store = store
        return store


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ScanCreateRequest(BaseModel):
    target: str
    engagement_id: str
    profile: Optional[str] = None
    mode: str = "auto"
    concurrency: int = 8
    timeout: Optional[int] = None


class ScanResponse(BaseModel):
    id: str
    engagement_id: str
    target: str
    target_type: str
    profile: Optional[str] = None
    mode: str
    status: str
    tools_planned: list[str] = []
    finding_count: int = 0
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class ScanListResponse(BaseModel):
    items: list[ScanResponse]
    total: int


class TaskResponse(BaseModel):
    id: str
    name: str
    tool: str
    task_type: str
    status: str
    priority: int
    depends_on: list[str] = []
    duration_ms: Optional[int] = None


class FindingResponse(BaseModel):
    id: str
    canonical_title: str
    severity_consensus: str
    tools: list[str] = []
    confidence_score: float
    location_fingerprint: str
    suppressed: bool = False


class ProfileResponse(BaseModel):
    id: str
    name: str
    description: str
    target_types: list[str]


class ControlResponse(BaseModel):
    scan_id: str
    status: str
    message: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/profiles", response_model=list[ProfileResponse])
async def list_profiles(
    user: User = Depends(get_current_user),
):
    """List available scan profiles."""
    from opentools.scanner.profiles import PROFILE_REGISTRY

    return [
        ProfileResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            target_types=[t.value for t in p.target_types],
        )
        for p in PROFILE_REGISTRY.values()
    ]


@router.post("", status_code=201)
async def create_scan(
    body: ScanCreateRequest,
    user: User = Depends(get_current_user),
):
    """Create and start a scan.

    Plans the scan based on target detection and profile, persists it,
    and returns the scan record. Execution is started in the background.
    """
    from opentools.scanner.api import ScanAPI
    from opentools.scanner.models import ScanConfig, ScanMode

    api = ScanAPI()
    try:
        scan_mode = ScanMode(body.mode)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid mode: {body.mode}")

    config = ScanConfig(
        max_concurrent_tasks=body.concurrency,
        max_duration_seconds=body.timeout,
    )

    try:
        scan, tasks = await api.plan(
            target=body.target,
            engagement_id=body.engagement_id,
            profile_name=body.profile,
            mode=scan_mode,
            config=config,
        )
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return ScanResponse(
        id=scan.id,
        engagement_id=scan.engagement_id,
        target=scan.target,
        target_type=scan.target_type.value,
        profile=scan.profile,
        mode=scan.mode.value,
        status=scan.status.value,
        tools_planned=scan.tools_planned,
        finding_count=scan.finding_count,
        created_at=scan.created_at.isoformat(),
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
    )


@router.get("")
async def list_scans(
    engagement_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: User = Depends(get_current_user),
):
    """List scans, optionally filtered by engagement."""
    store = await _get_scan_store()
    if store is None:
        return ScanListResponse(items=[], total=0)

    scans = await store.list_scans(engagement_id=engagement_id)
    scans.sort(key=lambda s: s.created_at, reverse=True)
    scans = scans[:limit]

    items = [
        ScanResponse(
            id=s.id,
            engagement_id=s.engagement_id,
            target=s.target,
            target_type=s.target_type.value,
            profile=s.profile,
            mode=s.mode.value,
            status=s.status.value,
            tools_planned=s.tools_planned,
            finding_count=s.finding_count,
            created_at=s.created_at.isoformat(),
            started_at=s.started_at.isoformat() if s.started_at else None,
            completed_at=s.completed_at.isoformat() if s.completed_at else None,
        )
        for s in scans
    ]
    return ScanListResponse(items=items, total=len(items))


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    user: User = Depends(get_current_user),
):
    """Get scan detail."""
    store = await _get_scan_store()
    if store is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = await store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanResponse(
        id=scan.id,
        engagement_id=scan.engagement_id,
        target=scan.target,
        target_type=scan.target_type.value,
        profile=scan.profile,
        mode=scan.mode.value,
        status=scan.status.value,
        tools_planned=scan.tools_planned,
        finding_count=scan.finding_count,
        created_at=scan.created_at.isoformat(),
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
    )


@router.get("/{scan_id}/tasks")
async def get_scan_tasks(
    scan_id: str,
    user: User = Depends(get_current_user),
):
    """Get task DAG with status for a scan."""
    store = await _get_scan_store()
    if store is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = await store.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    tasks = await store.get_scan_tasks(scan_id)
    return {
        "scan_id": scan_id,
        "tasks": [
            TaskResponse(
                id=t.id,
                name=t.name,
                tool=t.tool,
                task_type=t.task_type.value,
                status=t.status.value,
                priority=t.priority,
                depends_on=t.depends_on,
                duration_ms=t.duration_ms,
            ).model_dump()
            for t in tasks
        ],
        "total": len(tasks),
    }


@router.get("/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = Query(None),
    user: User = Depends(get_current_user),
):
    """Get deduplicated findings for a scan."""
    store = await _get_scan_store()
    if store is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = await store.get_scan_findings(scan_id)
    if severity:
        findings = [f for f in findings if f.severity_consensus == severity]

    return {
        "scan_id": scan_id,
        "findings": [
            FindingResponse(
                id=f.id,
                canonical_title=f.canonical_title,
                severity_consensus=f.severity_consensus,
                tools=f.tools,
                confidence_score=f.confidence_score,
                location_fingerprint=f.location_fingerprint,
                suppressed=f.suppressed,
            ).model_dump()
            for f in findings
        ],
        "total": len(findings),
    }


# ---------------------------------------------------------------------------
# Control endpoints
# ---------------------------------------------------------------------------


@router.post("/{scan_id}/pause")
async def pause_scan(
    scan_id: str,
    user: User = Depends(get_current_user),
):
    """Pause a running scan."""
    from opentools.scanner.api import ScanAPI

    api = ScanAPI()
    try:
        await api.pause(scan_id)
        return ControlResponse(scan_id=scan_id, status="paused", message="Scan paused")
    except KeyError:
        raise HTTPException(status_code=404, detail="No active scan with this ID")


@router.post("/{scan_id}/resume")
async def resume_scan(
    scan_id: str,
    user: User = Depends(get_current_user),
):
    """Resume a paused scan."""
    from opentools.scanner.api import ScanAPI

    api = ScanAPI()
    try:
        await api.resume(scan_id)
        return ControlResponse(scan_id=scan_id, status="resumed", message="Scan resumed")
    except KeyError:
        raise HTTPException(status_code=404, detail="No active scan with this ID")


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    reason: str = Query("user requested"),
    user: User = Depends(get_current_user),
):
    """Cancel a running scan."""
    from opentools.scanner.api import ScanAPI

    api = ScanAPI()
    try:
        await api.cancel(scan_id, reason)
        return ControlResponse(
            scan_id=scan_id, status="cancelled",
            message=f"Scan cancelled: {reason}",
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="No active scan with this ID")


# ---------------------------------------------------------------------------
# SSE streaming
# ---------------------------------------------------------------------------


@router.get("/{scan_id}/stream")
async def stream_scan_events(
    scan_id: str,
    request: Request,
    last_event_id: Optional[str] = Query(None, alias="Last-Event-ID"),
    user: User = Depends(get_current_user),
):
    """SSE event stream for scan progress.

    Supports reconnection via Last-Event-ID header — events are replayed
    from the persisted event store.
    """
    async def event_generator():
        store = await _get_scan_store()
        if store is None:
            yield f"event: error\ndata: {json.dumps({'detail': 'Scan store not available'})}\n\n"
            return

        # Determine starting sequence
        last_seq = 0
        if last_event_id:
            try:
                last_seq = int(last_event_id)
            except ValueError:
                pass

        poll_interval = 0.5
        while True:
            if await request.is_disconnected():
                break

            events = await store.get_events_after(scan_id, last_seq)
            if events:
                poll_interval = 0.5  # reset to aggressive on activity
            else:
                poll_interval = min(poll_interval * 1.5, 5.0)  # back off when idle

            for event in events:
                data = event.model_dump_json()
                yield f"id: {event.sequence}\nevent: {event.type.value}\ndata: {data}\n\n"
                last_seq = event.sequence

            # Check if scan is finished
            scan = await store.get_scan(scan_id)
            if scan and scan.status.value in ("completed", "failed", "cancelled"):
                yield f"event: scan_finished\ndata: {json.dumps({'status': scan.status.value})}\n\n"
                break

            await asyncio.sleep(poll_interval)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
