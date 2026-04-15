# packages/web/backend/app/routes/scans.py
"""Scan API routes — CRUD, control, and streaming endpoints.

Follows the existing router pattern in app/routes/.
Uses PostgreSQL via AsyncSession + ScanService (user-scoped).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.dependencies import get_current_user, get_db
from app.models import ScanRecord, ScanTaskRecord, User
from app.services.scan_service import ScanService

logger = logging.getLogger(__name__)

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
            reactive_edges=json.dumps([e.model_dump() if hasattr(e, "model_dump") else e for e in getattr(t, "reactive_edges", [])]),
            status=t.status.value,
            priority=t.priority,
            tier=getattr(t, "tier", "normal") if isinstance(getattr(t, "tier", "normal"), str) else getattr(t, "tier", "normal").value,
            resource_group=getattr(t, "resource_group", None),
            retry_policy=json.dumps(getattr(t, "retry_policy", None).model_dump() if hasattr(getattr(t, "retry_policy", None), "model_dump") else getattr(t, "retry_policy", None)) if getattr(t, "retry_policy", None) else None,
            cache_key=getattr(t, "cache_key", None),
            parser=getattr(t, "parser", None),
            tool_version=getattr(t, "tool_version", None),
            started_at=getattr(t, "started_at", None),
            completed_at=getattr(t, "completed_at", None),
        )
        for t in tasks
    ]
    await svc.persist_tasks(task_records)

    # Start execution in the background
    async def _run_scan():
        """Background task: execute scan and persist findings."""
        print(f"[SCAN] {scan.id}: background task started ({len(tasks)} tasks)", flush=True)
        try:
            # Register Docker executors for tool containers.
            # The ScanAPI.execute() only registers ShellExecutor by default.
            # We need to patch in DockerExecExecutor for each tool since
            # the web deployment runs tools in Docker containers.
            from opentools.scanner.executor.docker import DockerExecExecutor
            from opentools.scanner.models import TaskType

            _original_execute = api.execute

            # Tool name → Docker container name mapping.
            # Tools run in mcp-security-hub containers, accessed via docker exec.
            _TOOL_CONTAINERS = {
                "nmap": "nmap-mcp",
                "nuclei": "nuclei-mcp",
                "nikto": "nikto-mcp",
                "ffuf": "ffuf-mcp",
                "sqlmap": "sqlmap-mcp",
                "whatweb": "whatweb-mcp",
                "waybackurls": "waybackurls-mcp",
                "masscan": "masscan-mcp",
                "gitleaks": "gitleaks-mcp",
                "trivy": "trivy-mcp",
                "searchsploit": "searchsploit-mcp",
                "dnstwist": "dnstwist-mcp",
                "capa": "capa-mcp",
                "yara": "yara-mcp",
                "binwalk": "binwalk-mcp",
            }

            # Auto-start required tool containers
            needed_containers = set()
            for task in tasks:
                container = _TOOL_CONTAINERS.get(task.tool)
                if container:
                    needed_containers.add(container)

            if needed_containers:
                import subprocess
                for cname in needed_containers:
                    try:
                        # Check if container exists and is running
                        check = subprocess.run(
                            ["docker", "inspect", "-f", "{{.State.Running}}", cname],
                            capture_output=True, text=True, timeout=5,
                        )
                        if check.returncode != 0:
                            logger.warning("Container %s does not exist, skipping", cname)
                            continue
                        if check.stdout.strip() == "true":
                            continue  # already running

                        # Start the container
                        logger.info("Auto-starting container %s", cname)
                        subprocess.run(
                            ["docker", "start", cname],
                            capture_output=True, timeout=30,
                        )
                    except Exception as exc:
                        logger.warning("Failed to start container %s: %s", cname, exc)

                # Wait for containers to be ready (poll until running, max 30s)
                import asyncio as _aio
                for attempt in range(15):
                    all_ready = True
                    for cname in needed_containers:
                        try:
                            check = subprocess.run(
                                ["docker", "inspect", "-f", "{{.State.Running}}", cname],
                                capture_output=True, text=True, timeout=5,
                            )
                            if check.stdout.strip() != "true":
                                all_ready = False
                                break
                        except Exception:
                            all_ready = False
                            break
                    if all_ready:
                        logger.info("All %d containers ready after %ds", len(needed_containers), attempt * 2)
                        break
                    await _aio.sleep(2)
                else:
                    logger.warning("Some containers may not be ready after 30s, proceeding anyway")

            # Clear dependencies so all tools run in parallel.
            for task in tasks:
                task.depends_on = []

            # Fix tool commands for container versions.
            # The planner generates commands for specific CLI versions
            # but container builds may have different flags.
            target_url = scan.target
            target_host = target_url.replace("https://", "").replace("http://", "").split("/")[0]
            for task in tasks:
                if task.tool == "nuclei":
                    # v3 uses -jsonl not -json
                    task.command = f"nuclei -u {target_url} -jsonl"
                elif task.tool == "whatweb":
                    # --log-json=- has pipe issues in containers, use --log-json=/tmp/out.json
                    task.command = f"sh -c 'whatweb --color=never --log-json=/tmp/out.json {target_url} >/dev/null 2>&1; cat /tmp/out.json'"
                elif task.tool == "nikto":
                    task.command = f"sh -c 'nikto -h {target_url} -Format json -output /tmp/nikto.json 2>/dev/null; cat /tmp/nikto.json'"
                elif task.tool == "sqlmap":
                    task.command = f"python /opt/sqlmap/sqlmap.py -u {target_url} --batch --forms --crawl=2 --output-dir=/tmp/sqlmap"
                elif task.tool == "ffuf":
                    # Use SecLists common wordlist, copy into container first
                    task.command = f"sh -c 'ffuf -u {target_url}/FUZZ -w /tmp/common.txt -o - -of json -mc 200,301,302,403 2>/dev/null || true'"
                elif task.tool == "waybackurls":
                    task.command = f"sh -c 'echo {target_host} | waybackurls'"

            # Copy wordlist into ffuf container if needed
            if any(t.tool == "ffuf" for t in tasks):
                import subprocess
                wordlist = "/app/packages/plugin/wordlists/common.txt"
                if not os.path.exists(wordlist):
                    # Try SecLists on host
                    seclists = os.environ.get("SECLISTS_PATH", "/opt/SecLists")
                    alt = os.path.join(seclists, "Discovery/Web-Content/common.txt")
                    if os.path.exists(alt):
                        wordlist = alt
                try:
                    subprocess.run(["docker", "cp", wordlist, "ffuf-mcp:/tmp/common.txt"], capture_output=True, timeout=10)
                except Exception:
                    pass

            # Rewrite task commands to go through docker exec
            for task in tasks:
                if getattr(task, "_skip_docker_exec", False):
                    print(f"[SCAN] {scan.id}: {task.tool} uses custom docker command", flush=True)
                    continue
                container = _TOOL_CONTAINERS.get(task.tool)
                if container and task.command and not task.command.startswith("docker "):
                    task.command = f"docker exec {container} {task.command}"
                    print(f"[SCAN] {scan.id}: rewritten {task.tool} -> docker exec {container}", flush=True)

            print(f"[SCAN] {scan.id}: starting execution with {len(tasks)} tasks", flush=True)

            async def _execute_with_docker(s, t, **kw):
                """Wrapper that registers docker executors before running."""
                from opentools.scanner.engine import ScanEngine
                from opentools.scanner.approval import ApprovalRegistry
                from opentools.scanner.cancellation import CancellationToken
                from opentools.shared.progress import EventBus
                from opentools.shared.resource_pool import AdaptiveResourcePool

                cancel = CancellationToken()
                event_bus = EventBus()
                max_concurrent = 8
                if s.config and s.config.max_concurrent_tasks:
                    max_concurrent = s.config.max_concurrent_tasks
                pool = AdaptiveResourcePool(
                    global_limit=max_concurrent,
                    group_limits={"approval_gate": 9999},
                )

                # Register both shell and docker executors
                executors = {}
                try:
                    from opentools.scanner.executor.shell import ShellExecutor
                    executors[TaskType.SHELL] = ShellExecutor(default_timeout=600)
                except Exception:
                    pass

                # For docker_exec tasks, create a executor that passes through
                # the command directly (the command already includes 'docker exec <container>')
                executors[TaskType.DOCKER_EXEC] = ShellExecutor(default_timeout=600)

                engine = ScanEngine(
                    scan=s,
                    resource_pool=pool,
                    executors=executors,
                    event_bus=event_bus,
                    cancellation=cancel,
                )
                approval_registry = ApprovalRegistry()
                engine.set_approval_registry(approval_registry)

                from opentools.scanner.api import _active_scans
                _active_scans[s.id] = {
                    "scan": s,
                    "cancel": cancel,
                    "engine": engine,
                    "approval_registry": approval_registry,
                }

                try:
                    engine.load_tasks(t)
                    print(f"[SCAN] {s.id}: engine loaded {len(t)} tasks, ready: {engine.ready_task_ids()}", flush=True)
                    print(f"[SCAN] {s.id}: executors: {list(executors.keys())}", flush=True)
                    for tt in t:
                        print(f"[SCAN] {s.id}: task {tt.tool} type={tt.task_type} cmd={(tt.command or '')[:80]}", flush=True)
                    await engine.run()
                    print(f"[SCAN] {s.id}: engine finished, status={engine.scan.status}", flush=True)
                    return engine.scan
                except Exception as exc:
                    print(f"[SCAN ERROR] {s.id}: engine error: {exc}", flush=True)
                    import traceback; traceback.print_exc()
                    from opentools.scanner.models import ScanStatus
                    s.status = ScanStatus.FAILED
                    return s
                finally:
                    _active_scans.pop(s.id, None)

            result = await _execute_with_docker(scan, tasks)

            # Update scan + task statuses in DB and create findings
            async with async_session_factory() as bg_session:
                bg_svc = ScanService(bg_session, user)

                # Update individual task records from engine state
                for task_obj in tasks:
                    try:
                        from sqlalchemy import update
                        await bg_session.execute(
                            update(ScanTaskRecord).where(
                                ScanTaskRecord.id == task_obj.id
                            ).values(
                                status=task_obj.status.value if hasattr(task_obj.status, "value") else str(task_obj.status),
                                exit_code=getattr(task_obj, "exit_code", None),
                                duration_ms=getattr(task_obj, "duration_ms", None),
                            )
                        )
                    except Exception as exc:
                        print(f"[SCAN] task update failed for {task_obj.id}: {exc}", flush=True)

                # Parse tool output into findings via the full parsing pipeline
                from opentools.scanner.parsing.router import ParserRouter
                from opentools.scanner.parsing.parsers.nmap import NmapParser
                from opentools.scanner.parsing.parsers.generic_json import GenericJsonParser
                from datetime import datetime, timezone
                import uuid as _uuid

                # Build parser router with all available parsers
                parser_router = ParserRouter()
                parser_router.register(NmapParser())
                parser_router.register(GenericJsonParser())

                # Register dedicated parsers if available
                for parser_mod_name, parser_class_name in [
                    ("semgrep", "SemgrepParser"),
                    ("trivy", "TrivyParser"),
                    ("gitleaks", "GitleaksParser"),
                ]:
                    try:
                        mod = __import__(
                            f"opentools.scanner.parsing.parsers.{parser_mod_name}",
                            fromlist=[parser_class_name],
                        )
                        parser_cls = getattr(mod, parser_class_name)
                        parser_router.register(parser_cls())
                    except Exception:
                        pass

                # Map tool names to parser names
                _TOOL_TO_PARSER = {
                    "nmap": "nmap",
                    "semgrep": "semgrep",
                    "trivy": "trivy",
                    "gitleaks": "gitleaks",
                }

                def _parse_jsonl(data: bytes, scan_id: str, task_id: str, tool: str):
                    """Parse JSONL (one JSON object per line) output — used by nuclei, httpx, etc."""
                    import orjson
                    findings = []
                    for line in data.split(b"\n"):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = orjson.loads(line)
                        except Exception:
                            continue
                        if not isinstance(obj, dict):
                            continue
                        title = (
                            obj.get("info", {}).get("name")  # nuclei format
                            or obj.get("template-id")
                            or obj.get("title")
                            or obj.get("name")
                            or "Finding"
                        )
                        sev = (
                            obj.get("info", {}).get("severity")  # nuclei
                            or obj.get("severity")
                            or "info"
                        )
                        desc = (
                            obj.get("info", {}).get("description")
                            or obj.get("description")
                            or obj.get("matcher-name", "")
                        )
                        matched = obj.get("matched-at") or obj.get("host") or obj.get("url") or ""
                        evidence = obj.get("extracted-results", obj.get("matcher-name", ""))
                        if isinstance(evidence, list):
                            evidence = "; ".join(str(e) for e in evidence)
                        findings.append({
                            "title": str(title),
                            "severity": str(sev),
                            "description": f"{desc}\n\nMatched: {matched}" if matched else str(desc),
                            "evidence": str(evidence),
                            "url": str(matched),
                        })
                    return findings

                def _parse_text(data: bytes, tool: str):
                    """Last-resort: extract findings from plain text output."""
                    text = data.decode("utf-8", errors="replace")
                    findings = []
                    for line in text.strip().split("\n"):
                        line = line.strip()
                        if not line or len(line) < 10:
                            continue
                        # Skip banner/header lines
                        if line.startswith(("#", "//", "---", "===", "[*]", "[INF]")):
                            continue
                        findings.append({
                            "title": f"{tool}: {line[:120]}",
                            "severity": "info",
                            "description": line,
                            "evidence": line,
                        })
                    return findings[:50]  # cap at 50 per tool

                finding_count = 0
                for task_obj in tasks:
                    stdout = getattr(task_obj, "stdout", "") or ""
                    stderr = getattr(task_obj, "stderr", "") or ""
                    print(f"[SCAN] {scan.id}: task {task_obj.tool} status={task_obj.status} exit={getattr(task_obj, 'exit_code', '?')} stdout={len(stdout)}b stderr={len(stderr)}b", flush=True)
                    if not stdout:
                        continue

                    # Select parser: tool-specific → generic_json fallback
                    parser_name = _TOOL_TO_PARSER.get(task_obj.tool)
                    parser = None
                    if parser_name:
                        parser = parser_router.get(parser_name)
                    if parser is None:
                        parser = parser_router.get("generic_json")
                    if parser is None:
                        print(f"[SCAN] {scan.id}: no parser available for {task_obj.tool}", flush=True)
                        continue

                    data = stdout.encode()
                    parsed_findings = []

                    # Try parsers in order: dedicated → generic_json → JSONL → text
                    if parser and parser.validate(data):
                        try:
                            for rf in parser.parse(data, scan.id, task_obj.id):
                                parsed_findings.append({
                                    "title": rf.title,
                                    "severity": rf.raw_severity,
                                    "description": rf.description or "",
                                    "evidence": rf.evidence or "",
                                    "file_path": rf.file_path,
                                    "cwe": rf.cwe,
                                })
                        except Exception as exc:
                            print(f"[SCAN] {scan.id}: {parser.name} parse error: {exc}", flush=True)

                    if not parsed_findings:
                        # Try JSONL (nuclei, httpx, etc.)
                        parsed_findings = _parse_jsonl(data, scan.id, task_obj.id, task_obj.tool)

                    if not parsed_findings:
                        # Try generic JSON
                        gj = parser_router.get("generic_json")
                        if gj and gj.validate(data):
                            try:
                                for rf in gj.parse(data, scan.id, task_obj.id):
                                    parsed_findings.append({
                                        "title": rf.title,
                                        "severity": rf.raw_severity,
                                        "description": rf.description or "",
                                        "evidence": rf.evidence or "",
                                        "file_path": rf.file_path,
                                        "cwe": rf.cwe,
                                    })
                            except Exception:
                                pass

                    if not parsed_findings:
                        # Last resort: text parsing
                        parsed_findings = _parse_text(data, task_obj.tool)

                    print(f"[SCAN] {scan.id}: {task_obj.tool} → {len(parsed_findings)} findings", flush=True)

                    severity_map = {
                        "critical": "critical", "high": "high",
                        "medium": "medium", "low": "low",
                        "info": "info", "informational": "info",
                        "warning": "medium", "error": "high",
                    }

                    for pf in parsed_findings:
                        from app.models import Finding as WebFinding
                        severity = severity_map.get(str(pf.get("severity", "info")).lower(), "info")
                        finding_id = f"fnd-{_uuid.uuid4().hex[:12]}"
                        finding = WebFinding(
                            id=finding_id,
                            engagement_id=scan.engagement_id,
                            user_id=user.id,
                            tool=task_obj.tool,
                            title=str(pf.get("title", f"{task_obj.tool} finding"))[:500],
                            description=str(pf.get("description", ""))[:5000],
                            severity=severity,
                            status="open",
                            evidence=str(pf.get("evidence", ""))[:5000],
                            file_path=pf.get("file_path"),
                            cwe=pf.get("cwe"),
                            created_at=datetime.now(timezone.utc),
                        )
                        bg_session.add(finding)
                        finding_count += 1

                # Update scan record
                scan_rec = await bg_svc.get_scan(scan.id)
                if scan_rec:
                    scan_rec.status = result.status.value
                    scan_rec.completed_at = result.completed_at
                    scan_rec.finding_count = finding_count
                    scan_rec.tools_completed = json.dumps(
                        getattr(result, "tools_completed", [])
                    )
                    scan_rec.tools_failed = json.dumps(
                        getattr(result, "tools_failed", [])
                    )

                await bg_session.commit()
                print(f"[SCAN] {scan.id}: persisted {finding_count} findings, updated {len(tasks)} tasks", flush=True)
        except Exception as exc:
            logger.error("Scan %s failed: %s", scan.id, exc, exc_info=True)
            try:
                async with async_session_factory() as bg_session:
                    bg_svc = ScanService(bg_session, user)
                    scan_rec = await bg_svc.get_scan(scan.id)
                    if scan_rec:
                        scan_rec.status = "failed"
                        await bg_session.commit()
            except Exception:
                pass
        finally:
            # Containers are left running for subsequent scans.
            # Users can stop them manually via the Containers page.
            pass

    task = asyncio.create_task(_run_scan())
    task.add_done_callback(lambda t: logger.error("Scan task error: %s", t.exception()) if t.exception() else None)

    return _scan_record_to_response(scan_record)


@router.post("/upload")
async def upload_scan_target(
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
):
    """Upload a file for scanning. Returns the workspace path to use as scan target."""
    workspace = os.environ.get("OPENTOOLS_WORKSPACE", "/workspace")

    # Create user-scoped directory
    user_dir = os.path.join(workspace, str(user.id))
    os.makedirs(user_dir, exist_ok=True)

    # Sanitize filename
    safe_name = os.path.basename(file.filename or "upload")
    # Remove any path traversal attempts
    safe_name = safe_name.replace("..", "").replace("/", "").replace("\\", "")
    if not safe_name:
        safe_name = "upload"

    dest = os.path.join(user_dir, safe_name)

    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)

    return {"path": dest, "filename": safe_name, "size": os.path.getsize(dest)}


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

    # Overlay live engine state if scan is actively running
    from opentools.scanner.api import _active_scans
    active = _active_scans.get(scan_id)
    live_tasks = {}
    if active:
        engine = active.get("engine")
        if engine:
            for tid, st in engine.tasks.items():
                live_tasks[tid] = {
                    "status": st.status.value if hasattr(st.status, "value") else str(st.status),
                    "duration_ms": getattr(st, "duration_ms", None),
                    "exit_code": getattr(st, "exit_code", None),
                }

    return {
        "scan_id": scan_id,
        "tasks": [
            TaskResponse(
                id=t.id,
                name=t.name,
                tool=t.tool,
                task_type=t.task_type,
                status=live_tasks.get(t.id, {}).get("status", t.status),
                priority=t.priority,
                depends_on=ScanService.parse_json_list(t.depends_on),
                duration_ms=live_tasks.get(t.id, {}).get("duration_ms", t.duration_ms),
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
