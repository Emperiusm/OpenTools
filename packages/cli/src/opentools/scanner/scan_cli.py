"""CLI command surface for the scan subcommand group.

Provides `opentools scan` with subcommands:
- plan       — show what would run without executing
- profiles   — list available scan profiles
- run        — plan and execute a scan
- status     — show scan status
- history    — list past scans
- findings   — show findings from a scan
- cancel     — cancel a running scan
"""

from __future__ import annotations

import asyncio
import functools
import json as json_mod
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(name="scan", help="Security scan orchestration")
console = Console(stderr=True)
out = Console()


def _async_command(coro_fn):
    """Wrap async function for Typer (which does not support async natively)."""
    @functools.wraps(coro_fn)
    def _wrapper(*args, **kwargs):
        return asyncio.run(coro_fn(*args, **kwargs))
    return _wrapper


def _get_scan_store_path() -> Path:
    """Return the default scan store database path."""
    db_dir = Path.home() / ".opentools"
    db_dir.mkdir(parents=True, exist_ok=True)
    return db_dir / "scans.db"


async def _get_store():
    """Create and initialize a SqliteScanStore."""
    from opentools.scanner.store import SqliteScanStore

    store = SqliteScanStore(_get_scan_store_path())
    await store.initialize()
    return store


# ---------------------------------------------------------------------------
# scan profiles
# ---------------------------------------------------------------------------


@app.command("profiles")
def scan_profiles(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List available scan profiles."""
    from opentools.scanner.profiles import list_builtin_profiles, load_builtin_profile

    profile_names = list_builtin_profiles()
    profiles = []
    for name in profile_names:
        try:
            p = load_builtin_profile(name)
            profiles.append(p)
        except Exception:
            pass

    if json_output:
        data = []
        for p in profiles:
            data.append({
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "target_types": [t.value for t in p.target_types],
            })
        out.print(json_mod.dumps(data, indent=2))
    else:
        table = Table(title="Scan Profiles")
        table.add_column("ID")
        table.add_column("Name")
        table.add_column("Target Types")
        table.add_column("Description")
        for p in profiles:
            types = ", ".join(t.value for t in p.target_types)
            table.add_row(p.id, p.name, types, p.description)
        out.print(table)


# ---------------------------------------------------------------------------
# scan plan
# ---------------------------------------------------------------------------


@app.command("plan")
@_async_command
async def scan_plan(
    target: str = typer.Argument(..., help="Target to scan (path, URL, IP, image)"),
    engagement: str = typer.Option("ephemeral", "--engagement", "-e", help="Engagement ID"),
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="Profile name"),
    mode: str = typer.Option("auto", "--mode", "-m", help="Scan mode: auto or assisted"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show what a scan would do without executing."""
    from opentools.scanner.api import ScanAPI
    from opentools.scanner.models import ScanMode

    api = ScanAPI()
    try:
        scan_mode = ScanMode(mode)
    except ValueError:
        console.print(f"[red]Error:[/red] Invalid mode: {mode!r}. Use 'auto' or 'assisted'.")
        raise typer.Exit(1)

    try:
        scan, tasks = await api.plan(
            target=target,
            engagement_id=engagement,
            profile_name=profile,
            mode=scan_mode,
        )
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    if json_output:
        data = {
            "scan": json_mod.loads(scan.model_dump_json()),
            "tasks": [json_mod.loads(t.model_dump_json()) for t in tasks],
            "task_count": len(tasks),
        }
        out.print(json_mod.dumps(data, indent=2))
    else:
        out.print("[bold]Scan Plan[/bold]")
        out.print(f"  Target: {scan.target}")
        out.print(f"  Type: {scan.target_type.value}")
        out.print(f"  Profile: {scan.profile or 'auto'}")
        out.print(f"  Mode: {scan.mode.value}")
        out.print(f"  Tasks: {len(tasks)}")
        out.print()

        if tasks:
            table = Table(title="Planned Tasks")
            table.add_column("#", justify="right")
            table.add_column("Tool")
            table.add_column("Name")
            table.add_column("Type")
            table.add_column("Priority", justify="right")
            table.add_column("Tier")
            table.add_column("Dependencies")
            for i, t in enumerate(tasks, 1):
                deps = ", ".join(t.depends_on) if t.depends_on else "-"
                table.add_row(
                    str(i), t.tool, t.name,
                    t.task_type.value, str(t.priority),
                    t.tier.value, deps,
                )
            out.print(table)
        else:
            out.print("No tasks planned.")


# ---------------------------------------------------------------------------
# scan run
# ---------------------------------------------------------------------------


@app.command("run")
@_async_command
async def scan_run(
    target: str = typer.Argument(..., help="Target to scan (path, URL, IP, image)"),
    engagement: str = typer.Option("ephemeral", "--engagement", "-e", help="Engagement ID"),
    profile: Optional[str] = typer.Option(None, "--profile", "-p", help="Profile name"),
    mode: str = typer.Option("auto", "--mode", "-m", help="Scan mode: auto or assisted"),
    concurrency: int = typer.Option(8, "--concurrency", "-c", help="Max concurrent tasks"),
    timeout: Optional[int] = typer.Option(None, "--timeout", help="Scan timeout in seconds"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Plan and execute a security scan."""
    from opentools.scanner.api import ScanAPI
    from opentools.scanner.models import ScanConfig, ScanMode

    api = ScanAPI()
    try:
        scan_mode = ScanMode(mode)
    except ValueError:
        console.print(f"[red]Error:[/red] Invalid mode: {mode!r}. Use 'auto' or 'assisted'.")
        raise typer.Exit(1)

    config = ScanConfig(
        max_concurrent_tasks=concurrency,
        max_duration_seconds=timeout,
    )

    try:
        scan, tasks = await api.plan(
            target=target,
            engagement_id=engagement,
            profile_name=profile,
            mode=scan_mode,
            config=config,
        )
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1)

    console.print(
        f"[bold]Starting scan[/bold] {scan.id} "
        f"({len(tasks)} tasks, profile={scan.profile or 'auto'})"
    )

    # Execute
    store = await _get_store()
    try:
        await store.save_scan(scan)
        for t in tasks:
            await store.save_task(t)

        result = await api.execute(scan, tasks, store=store)

        # Populate finding_count from the pipeline-persisted deduplicated
        # findings. The engine updates scan summary fields but has no way to
        # know how many findings the pipeline emitted — that lives in the store.
        try:
            scan_findings = await store.get_scan_findings(result.id)
            result.finding_count = len(scan_findings)
        except Exception:
            pass

        # Persist the final scan state (status, tools_completed, finding_count).
        # The in-memory scan is updated by the engine, but the DB row still
        # reflects the initial "pending" save unless we write the terminal
        # state back through the store.
        await store.save_scan(result)

        # Persist terminal task state (status, exit_code, stdout, stderr, duration_ms).
        # Tasks are mutated in memory by the engine but never re-saved, so the
        # initial "pending" rows would otherwise remain stale after completion.
        for t in tasks:
            await store.save_task(t)

        if json_output:
            out.print(result.model_dump_json(indent=2))
        else:
            status_color = {
                "completed": "green",
                "failed": "red",
                "cancelled": "yellow",
            }.get(result.status.value, "white")
            out.print(
                f"\n[bold]Scan {result.id}[/bold] "
                f"[{status_color}]{result.status.value}[/{status_color}]"
            )
            out.print(f"  Target: {result.target}")
            out.print(f"  Profile: {result.profile or 'auto'}")
            out.print(f"  Findings: {result.finding_count}")
    finally:
        await store.close()


# ---------------------------------------------------------------------------
# scan status
# ---------------------------------------------------------------------------


@app.command("status")
@_async_command
async def scan_status(
    scan_id: str = typer.Argument(..., help="Scan ID"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show the status of a scan."""
    store = await _get_store()
    try:
        scan = await store.get_scan(scan_id)
        if scan is None:
            console.print(f"[red]Error:[/red] Scan '{scan_id}' not found")
            raise typer.Exit(1)

        if json_output:
            out.print(scan.model_dump_json(indent=2))
        else:
            status_color = {
                "pending": "dim",
                "running": "cyan",
                "paused": "yellow",
                "completed": "green",
                "failed": "red",
                "cancelled": "yellow",
            }.get(scan.status.value, "white")

            out.print(f"[bold]Scan {scan.id}[/bold]")
            out.print(f"  Status: [{status_color}]{scan.status.value}[/{status_color}]")
            out.print(f"  Target: {scan.target}")
            out.print(f"  Type: {scan.target_type.value}")
            out.print(f"  Profile: {scan.profile or 'auto'}")
            out.print(f"  Mode: {scan.mode.value}")
            out.print(f"  Findings: {scan.finding_count}")
            if scan.started_at:
                out.print(f"  Started: {scan.started_at.isoformat()}")
            if scan.completed_at:
                out.print(f"  Completed: {scan.completed_at.isoformat()}")

            # Show tasks summary
            tasks = await store.get_scan_tasks(scan_id)
            if tasks:
                from collections import Counter
                status_counts = Counter(t.status.value for t in tasks)
                out.print(f"  Tasks: {len(tasks)} total — " + ", ".join(
                    f"{v} {k}" for k, v in status_counts.items()
                ))
    finally:
        await store.close()


# ---------------------------------------------------------------------------
# scan history
# ---------------------------------------------------------------------------


@app.command("history")
@_async_command
async def scan_history(
    engagement: Optional[str] = typer.Option(None, "--engagement", "-e", help="Filter by engagement"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max number of scans"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List past scans."""
    store = await _get_store()
    try:
        scans = await store.list_scans(engagement_id=engagement)
        # Sort by created_at descending
        scans.sort(key=lambda s: s.created_at, reverse=True)
        scans = scans[:limit]

        if json_output:
            data = [json_mod.loads(s.model_dump_json()) for s in scans]
            out.print(json_mod.dumps(data, indent=2))
        else:
            if not scans:
                out.print("No scans found.")
                return

            table = Table(title="Scan History")
            table.add_column("ID", max_width=16)
            table.add_column("Status")
            table.add_column("Target", max_width=30)
            table.add_column("Profile")
            table.add_column("Findings", justify="right")
            table.add_column("Created")

            for s in scans:
                status_color = {
                    "completed": "green", "failed": "red",
                    "running": "cyan", "cancelled": "yellow",
                }.get(s.status.value, "white")
                table.add_row(
                    s.id[:16],
                    f"[{status_color}]{s.status.value}[/{status_color}]",
                    s.target[:30],
                    s.profile or "auto",
                    str(s.finding_count),
                    s.created_at.strftime("%Y-%m-%d %H:%M"),
                )
            out.print(table)
    finally:
        await store.close()


# ---------------------------------------------------------------------------
# scan findings
# ---------------------------------------------------------------------------


@app.command("findings")
@_async_command
async def scan_findings(
    scan_id: str = typer.Argument(..., help="Scan ID"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show findings from a scan."""
    store = await _get_store()
    try:
        scan = await store.get_scan(scan_id)
        if scan is None:
            console.print(f"[red]Error:[/red] Scan '{scan_id}' not found")
            raise typer.Exit(1)

        findings = await store.get_scan_findings(scan_id)

        if severity:
            findings = [f for f in findings if f.severity_consensus == severity]

        if json_output:
            data = [json_mod.loads(f.model_dump_json()) for f in findings]
            out.print(json_mod.dumps(data, indent=2))
        else:
            if not findings:
                out.print("No findings found.")
                return

            table = Table(title=f"Findings for scan {scan_id[:16]}")
            table.add_column("ID", max_width=10)
            table.add_column("Severity")
            table.add_column("Title")
            table.add_column("Tools")
            table.add_column("Confidence", justify="right")
            table.add_column("Location", max_width=30)

            for f in findings:
                sev_color = {
                    "critical": "red", "high": "red",
                    "medium": "yellow", "low": "cyan", "info": "dim",
                }.get(f.severity_consensus, "white")
                table.add_row(
                    f.id[:10],
                    f"[{sev_color}]{f.severity_consensus}[/{sev_color}]",
                    f.canonical_title,
                    ", ".join(f.tools),
                    f"{f.confidence_score:.2f}",
                    f.location_fingerprint[:30],
                )
            out.print(table)
    finally:
        await store.close()


# ---------------------------------------------------------------------------
# scan cancel
# ---------------------------------------------------------------------------


@app.command("cancel")
@_async_command
async def scan_cancel(
    scan_id: str = typer.Argument(..., help="Scan ID to cancel"),
    reason: str = typer.Option("user requested", "--reason", "-r", help="Cancellation reason"),
):
    """Cancel a running scan."""
    from opentools.scanner.api import ScanAPI

    api = ScanAPI()
    try:
        await api.cancel(scan_id, reason)
        out.print(f"[green]Cancelled scan[/green] {scan_id}")
    except KeyError:
        console.print(f"[red]Error:[/red] No active scan with ID '{scan_id}'")
        raise typer.Exit(1)
