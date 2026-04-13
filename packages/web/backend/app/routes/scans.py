# packages/web/backend/app/routes/scans.py
"""Scan API routes — CRUD, control, and streaming endpoints.

Follows the existing router pattern in app/routes/.
Uses PostgreSQL via AsyncSession + ScanService (user-scoped).
"""

from __future__ import annotations

import asyncio
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db
from app.models import ScanRecord, ScanTaskRecord, User
from app.services.scan_service import ScanService

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


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
# Helpers
# ---------------------------------------------------------------------------


def _scan_record_to_response(rec: ScanRecord) -> ScanResponse:
    """Convert a ScanRecord ORM object to a ScanResponse."""
    return ScanResponse(
        id=rec.id,
        engagement_id=rec.engagement_id,
        target=rec.target,
        target_type=rec.target_type,
        profile=rec.profile,
        mode=rec.mode,
        status=rec.status,
        tools_planned=ScanService.parse_json_list(rec.tools_planned),
        finding_count=rec.finding_count,
        created_at=rec.created_at.isoformat(),
        started_at=rec.started_at.isoformat() if rec.started_at else None,
        completed_at=rec.completed_at.isoformat() if rec.completed_at else None,
    )


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
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Create and start a scan.

    Plans the scan based on target detection and profile, persists it
    to PostgreSQL, and returns the scan record. Execution is started in
    the background.
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

    # Persist to PostgreSQL via the service
    svc = ScanService(session, user)
    scan_record = ScanRecord(
        id=scan.id,
        engagement_id=scan.engagement_id,
        target=scan.target,
        target_type=scan.target_type.value,
        resolved_path=getattr(scan, "resolved_path", None),
        target_metadata=json.dumps(getattr(scan, "target_metadata", {})),
        profile=scan.profile,
        profile_snapshot=json.dumps(getattr(scan, "profile_snapshot", {})),
        mode=scan.mode.value,
        status=scan.status.value,
        config=json.dumps(config.model_dump()) if config else None,
        tools_planned=json.dumps(scan.tools_planned),
        tools_completed=json.dumps(getattr(scan, "tools_completed", [])),
        tools_failed=json.dumps(getattr(scan, "tools_failed", [])),
        finding_count=scan.finding_count,
        estimated_duration_seconds=getattr(scan, "estimated_duration_seconds", None),
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )
    await svc.persist_scan(scan_record)

    # Persist tasks
    task_records = [
        ScanTaskRecord(
            id=t.id,
            scan_id=scan.id,
            name=t.name,
            tool=t.tool,
            task_type=t.task_type.value,
            command=getattr(t, "command", None),
            mcp_server=getattr(t, "mcp_server", None),
            mcp_tool=getattr(t, "mcp_tool", None),
            mcp_args=json.dumps(getattr(t, "mcp_args", None)) if getattr(t, "mcp_args", None) else None,
            depends_on=json.dumps(t.depends_on),
            reactive_edges=json.dumps(getattr(t, "reactive_edges", [])),
            status=t.status.value,
            priority=t.priority,
            tier=getattr(t, "tier", "normal") if isinstance(getattr(t, "tier", "normal"), str) else getattr(t, "tier", "normal").value,
            resource_group=getattr(t, "resource_group", None),
            retry_policy=json.dumps(getattr(t, "retry_policy", None)) if getattr(t, "retry_policy", None) else None,
            cache_key=getattr(t, "cache_key", None),
            parser=getattr(t, "parser", None),
            tool_version=getattr(t, "tool_version", None),
            started_at=getattr(t, "started_at", None),
            completed_at=getattr(t, "completed_at", None),
        )
        for t in tasks
    ]
    await svc.persist_tasks(task_records)

    return _scan_record_to_response(scan_record)


@router.get("")
async def list_scans(
    engagement_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List scans, optionally filtered by engagement."""
    svc = ScanService(session, user)
    scans = await svc.list_scans(engagement_id=engagement_id, limit=limit)
    items = [_scan_record_to_response(s) for s in scans]
    return ScanListResponse(items=items, total=len(items))


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get scan detail."""
    svc = ScanService(session, user)
    rec = await svc.get_scan(scan_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _scan_record_to_response(rec)


@router.get("/{scan_id}/tasks")
async def get_scan_tasks(
    scan_id: str,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get task DAG with status for a scan."""
    svc = ScanService(session, user)
    scan = await svc.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    tasks = await svc.get_scan_tasks(scan_id)
    return {
        "scan_id": scan_id,
        "tasks": [
            TaskResponse(
                id=t.id,
                name=t.name,
                tool=t.tool,
                task_type=t.task_type,
                status=t.status,
                priority=t.priority,
                depends_on=ScanService.parse_json_list(t.depends_on),
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
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get deduplicated findings for a scan."""
    svc = ScanService(session, user)
    findings = await svc.get_scan_findings(scan_id, severity=severity)

    return {
        "scan_id": scan_id,
        "findings": [
            FindingResponse(
                id=f["id"],
                canonical_title=f["canonical_title"],
                severity_consensus=f["severity_consensus"],
                tools=f["tools"],
                confidence_score=f["confidence_score"],
                location_fingerprint=f["location_fingerprint"],
                suppressed=f["suppressed"],
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
    from opentools.scanner.api import _active_scans

    if scan_id not in _active_scans:
        raise HTTPException(status_code=404, detail="No active scan with this ID")
    entry = _active_scans[scan_id]
    engine = entry.get("engine")
    if engine is not None:
        await engine.pause()
    return ControlResponse(scan_id=scan_id, status="paused", message="Scan paused")


@router.post("/{scan_id}/resume")
async def resume_scan(
    scan_id: str,
    user: User = Depends(get_current_user),
):
    """Resume a paused scan."""
    from opentools.scanner.api import _active_scans

    if scan_id not in _active_scans:
        raise HTTPException(status_code=404, detail="No active scan with this ID")
    entry = _active_scans[scan_id]
    engine = entry.get("engine")
    if engine is not None:
        await engine.resume()
    return ControlResponse(scan_id=scan_id, status="resumed", message="Scan resumed")


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    reason: str = Query("user requested"),
    user: User = Depends(get_current_user),
):
    """Cancel a running scan."""
    from opentools.scanner.api import _active_scans

    if scan_id not in _active_scans:
        raise HTTPException(status_code=404, detail="No active scan with this ID")
    entry = _active_scans[scan_id]
    cancel_token = entry.get("cancel")
    if cancel_token is not None:
        await cancel_token.cancel(reason)
    return ControlResponse(
        scan_id=scan_id, status="cancelled",
        message=f"Scan cancelled: {reason}",
    )


# ---------------------------------------------------------------------------
# Approval gate endpoints
# ---------------------------------------------------------------------------


class GateResponse(BaseModel):
    ticket_id: str
    task_id: str
    tool: str
    command: str | None = None
    description: str
    status: str
    expires_at: str | None = None

class GateDecisionResponse(BaseModel):
    ticket_id: str
    decision: str

class GateRejectRequest(BaseModel):
    reason: str = "operator rejected"


@router.get("/{scan_id}/gates")
async def list_pending_gates(
    scan_id: str,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List tasks awaiting operator approval."""
    svc = ScanService(session, user)
    scan = await svc.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    tasks = await svc.get_scan_tasks(scan_id)
    gates = []
    for t in tasks:
        if t.status == "awaiting_approval" and t.approval_ticket_id:
            gates.append(GateResponse(
                ticket_id=t.approval_ticket_id,
                task_id=t.id, tool=t.tool, command=t.command,
                description="",
                status=t.status,
                expires_at=t.approval_expires_at.isoformat() if t.approval_expires_at else None,
            ))
    return {"scan_id": scan_id, "gates": gates}


@router.post("/{scan_id}/gates/{ticket_id}/approve")
async def approve_gate(
    scan_id: str, ticket_id: str,
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Approve a pending gate. Write-before-signal."""
    svc = ScanService(session, user)
    scan = await svc.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    task_record = await svc.get_task_by_ticket(scan_id, ticket_id)
    if task_record is None:
        raise HTTPException(status_code=404, detail="Gate ticket not found")
    if task_record.status != "awaiting_approval":
        raise HTTPException(status_code=409, detail=f"Gate already resolved: {task_record.status}")

    # 1. PERSIST FIRST (source of truth)
    await svc.update_task_approval_status(task_record.id, "approved")
    await session.commit()

    # 2. Signal event (best-effort tripwire)
    from opentools.scanner.api import _active_scans
    entry = _active_scans.get(scan_id, {})
    registry = entry.get("approval_registry")
    if registry is not None:
        registry.signal(ticket_id)

    return GateDecisionResponse(ticket_id=ticket_id, decision="approved")


@router.post("/{scan_id}/gates/{ticket_id}/reject")
async def reject_gate(
    scan_id: str, ticket_id: str,
    body: GateRejectRequest = GateRejectRequest(),
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Reject a pending gate. Write-before-signal."""
    svc = ScanService(session, user)
    scan = await svc.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    task_record = await svc.get_task_by_ticket(scan_id, ticket_id)
    if task_record is None:
        raise HTTPException(status_code=404, detail="Gate ticket not found")
    if task_record.status != "awaiting_approval":
        raise HTTPException(status_code=409, detail=f"Gate already resolved: {task_record.status}")

    await svc.update_task_approval_status(task_record.id, "rejected")
    await session.commit()

    from opentools.scanner.api import _active_scans
    entry = _active_scans.get(scan_id, {})
    registry = entry.get("approval_registry")
    if registry is not None:
        registry.signal(ticket_id)

    return GateDecisionResponse(ticket_id=ticket_id, decision="rejected")


# ---------------------------------------------------------------------------
# SSE streaming
# ---------------------------------------------------------------------------


@router.get("/{scan_id}/stream")
async def stream_scan_events(
    scan_id: str,
    request: Request,
    last_event_id: Optional[str] = Query(None, alias="Last-Event-ID"),
    session: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """SSE event stream for scan progress.

    Supports reconnection via Last-Event-ID header — events are replayed
    from the persisted PostgreSQL event store.
    """
    async def event_generator():
        svc = ScanService(session, user)

        # Verify scan belongs to user
        scan = await svc.get_scan(scan_id)
        if scan is None:
            yield f"event: error\ndata: {json.dumps({'detail': 'Scan not found'})}\n\n"
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

            events = await svc.get_scan_events_after(scan_id, last_seq)
            if events:
                poll_interval = 0.5  # reset to aggressive on activity
            else:
                poll_interval = min(poll_interval * 1.5, 5.0)  # back off when idle

            for event in events:
                data = json.dumps({
                    "id": event.id,
                    "scan_id": event.scan_id,
                    "type": event.type,
                    "sequence": event.sequence,
                    "timestamp": event.timestamp.isoformat(),
                    "task_id": event.task_id,
                    "data": json.loads(event.data) if event.data else {},
                    "tasks_total": event.tasks_total,
                    "tasks_completed": event.tasks_completed,
                    "tasks_running": event.tasks_running,
                    "findings_total": event.findings_total,
                    "elapsed_seconds": event.elapsed_seconds,
                    "estimated_remaining_seconds": event.estimated_remaining_seconds,
                })
                yield f"id: {event.sequence}\nevent: {event.type}\ndata: {data}\n\n"
                last_seq = event.sequence

            # Check if scan is finished
            scan = await svc.get_scan(scan_id)
            if scan and scan.status in ("completed", "failed", "cancelled"):
                yield f"event: scan_finished\ndata: {json.dumps({'status': scan.status})}\n\n"
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
