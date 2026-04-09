"""Typer CLI entry point for the OpenTools security toolkit."""

from __future__ import annotations

import json as json_mod
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from opentools import __version__

# ---------------------------------------------------------------------------
# App and sub-apps
# ---------------------------------------------------------------------------

app = typer.Typer(name="opentools", help="Security toolkit CLI")
console = Console(stderr=True)
out = Console()

engagement_app = typer.Typer(name="engagement", help="Engagement lifecycle")
findings_app = typer.Typer(name="findings", help="Finding management")
iocs_app = typer.Typer(name="iocs", help="IOC management")
timeline_app = typer.Typer(name="timeline", help="Timeline management")
containers_app = typer.Typer(name="containers", help="Docker container management")
recipe_app = typer.Typer(name="recipe", help="Recipe execution")
report_app = typer.Typer(name="report", help="Report generation")
audit_app = typer.Typer(name="audit", help="Audit trail")
config_app = typer.Typer(name="config", help="Configuration")

app.add_typer(engagement_app)
app.add_typer(findings_app)
app.add_typer(iocs_app)
app.add_typer(timeline_app)
app.add_typer(containers_app)
app.add_typer(recipe_app)
app.add_typer(report_app)
app.add_typer(audit_app)
app.add_typer(config_app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_store():
    """Get or create the engagement store."""
    from opentools.plugin import discover_plugin_dir
    from opentools.engagement.store import EngagementStore

    plugin_dir = discover_plugin_dir()
    db_path = plugin_dir.parent.parent / "engagements" / "opentools.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return EngagementStore(db_path=db_path)


def _get_config():
    """Get plugin dir and config."""
    from opentools.plugin import discover_plugin_dir
    from opentools.config import ConfigLoader

    plugin_dir = discover_plugin_dir()
    config = ConfigLoader(plugin_dir).load()
    return plugin_dir, config


def _error(msg: str) -> None:
    """Print error to stderr and exit."""
    console.print(f"[red]Error:[/red] {msg}")
    raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Top-level commands
# ---------------------------------------------------------------------------


@app.command()
def version():
    """Print the OpenTools version."""
    out.print(f"opentools {__version__}")


@app.command()
def setup():
    """Run preflight checks and print a report."""
    try:
        _plugin_dir, config = _get_config()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    from opentools.preflight import PreflightRunner

    runner = PreflightRunner(config)
    report = runner.check_all()

    table = Table(title="Preflight Report")
    table.add_column("Tool")
    table.add_column("Category")
    table.add_column("Status")
    table.add_column("Message")
    for t in report.tools:
        color = "green" if t.status.value in ("available", "running") else "red"
        table.add_row(t.name, t.category, f"[{color}]{t.status.value}[/{color}]", t.message)
    out.print(table)
    out.print(f"\nTotal: {report.summary.total}  Available: {report.summary.available}  Missing: {report.summary.missing}")


@app.command()
def preflight(
    skill: Optional[str] = typer.Option(None, "--skill", help="Check tools for a specific skill"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    fix: bool = typer.Option(False, "--fix", help="Attempt to fix issues"),
):
    """Run preflight health checks."""
    try:
        _plugin_dir, config = _get_config()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    from opentools.preflight import PreflightRunner

    runner = PreflightRunner(config)
    if skill:
        report = runner.check_skill(skill)
    else:
        report = runner.check_all()

    if json_output:
        out.print(report.model_dump_json(indent=2))
    else:
        table = Table(title=f"Preflight: {skill or 'all'}")
        table.add_column("Tool")
        table.add_column("Status")
        table.add_column("Message")
        for t in report.tools:
            color = "green" if t.status.value in ("available", "running") else "red"
            table.add_row(t.name, f"[{color}]{t.status.value}[/{color}]", t.message)
        out.print(table)


# ---------------------------------------------------------------------------
# Engagement commands
# ---------------------------------------------------------------------------


@engagement_app.command("create")
def engagement_create(
    name: str = typer.Argument(..., help="Engagement name"),
    target: str = typer.Option(..., "--target", "-t", help="Target scope"),
    eng_type: str = typer.Option("pentest", "--type", "-T", help="Engagement type"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Create a new engagement."""
    from opentools.models import Engagement, EngagementType, EngagementStatus

    try:
        store = _get_store()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    now = datetime.now(timezone.utc)
    engagement = Engagement(
        id=str(uuid.uuid4()),
        name=name,
        target=target,
        type=EngagementType(eng_type),
        status=EngagementStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )
    store.create(engagement)

    if json_output:
        out.print(engagement.model_dump_json(indent=2))
    else:
        out.print(f"[green]Created engagement:[/green] {engagement.name} ({engagement.id})")


@engagement_app.command("list")
def engagement_list(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List all engagements."""
    try:
        store = _get_store()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    engagements = store.list_all()

    if json_output:
        out.print(json_mod.dumps([e.model_dump(mode="json") for e in engagements], indent=2))
    else:
        if not engagements:
            out.print("No engagements found.")
            return
        table = Table(title="Engagements")
        table.add_column("ID", max_width=8)
        table.add_column("Name")
        table.add_column("Target")
        table.add_column("Type")
        table.add_column("Status")
        for e in engagements:
            table.add_row(e.id[:8], e.name, e.target, e.type.value, e.status.value)
        out.print(table)


@engagement_app.command("show")
def engagement_show(
    name: str = typer.Argument(..., help="Engagement name or ID"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show engagement summary."""
    try:
        store = _get_store()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    # Find by name or ID
    engagements = store.list_all()
    match = None
    for e in engagements:
        if e.name == name or e.id == name or e.id.startswith(name):
            match = e
            break
    if not match:
        _error(f"Engagement not found: {name}")

    summary = store.get_summary(match.id)
    if json_output:
        out.print(summary.model_dump_json(indent=2))
    else:
        out.print(f"[bold]{summary.engagement.name}[/bold] ({summary.engagement.id})")
        out.print(f"  Target: {summary.engagement.target}")
        out.print(f"  Type: {summary.engagement.type.value}")
        out.print(f"  Status: {summary.engagement.status.value}")
        out.print(f"  Findings: {sum(summary.finding_counts.values())}")
        out.print(f"  IOCs: {sum(summary.ioc_counts_by_type.values())}")
        out.print(f"  Artifacts: {summary.artifact_count}")
        out.print(f"  Timeline events: {summary.timeline_event_count}")


@engagement_app.command("export")
def engagement_export(
    name: str = typer.Argument(..., help="Engagement name or ID"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
):
    """Export engagement to JSON."""
    from opentools.engagement.export import export_engagement

    try:
        store = _get_store()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    engagements = store.list_all()
    match = None
    for e in engagements:
        if e.name == name or e.id == name or e.id.startswith(name):
            match = e
            break
    if not match:
        _error(f"Engagement not found: {name}")

    output_path = Path(output) if output else Path(f"{match.name}-export.json")
    result = export_engagement(store, match.id, output_path)
    out.print(f"[green]Exported to:[/green] {result}")


# ---------------------------------------------------------------------------
# Findings commands
# ---------------------------------------------------------------------------


@findings_app.command("list")
def findings_list(
    engagement: str = typer.Argument(..., help="Engagement name or ID"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List findings for an engagement."""
    from opentools.models import Severity, FindingStatus

    try:
        store = _get_store()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    # Resolve engagement
    engagements = store.list_all()
    match = None
    for e in engagements:
        if e.name == engagement or e.id == engagement or e.id.startswith(engagement):
            match = e
            break
    if not match:
        _error(f"Engagement not found: {engagement}")

    sev = Severity(severity) if severity else None
    stat = FindingStatus(status) if status else None
    findings = store.get_findings(match.id, severity=sev, status=stat)

    if json_output:
        out.print(json_mod.dumps([f.model_dump(mode="json") for f in findings], indent=2))
    else:
        if not findings:
            out.print("No findings found.")
            return
        table = Table(title=f"Findings for {match.name}")
        table.add_column("ID", max_width=8)
        table.add_column("Severity")
        table.add_column("Tool")
        table.add_column("Title")
        table.add_column("Status")
        for f in findings:
            sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}.get(f.severity.value, "white")
            table.add_row(f.id[:8], f"[{sev_color}]{f.severity.value}[/{sev_color}]", f.tool, f.title, f.status.value)
        out.print(table)


@findings_app.command("add")
def findings_add(
    engagement: str = typer.Argument(..., help="Engagement name or ID"),
    tool: str = typer.Option(..., "--tool", help="Tool that found this"),
    title: str = typer.Option(..., "--title", help="Finding title"),
    severity: str = typer.Option("medium", "--severity", "-s", help="Severity level"),
    description: Optional[str] = typer.Option(None, "--description", "-d", help="Description"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Add a finding to an engagement."""
    from opentools.models import Finding, Severity

    try:
        store = _get_store()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    engagements = store.list_all()
    match = None
    for e in engagements:
        if e.name == engagement or e.id == engagement or e.id.startswith(engagement):
            match = e
            break
    if not match:
        _error(f"Engagement not found: {engagement}")

    now = datetime.now(timezone.utc)
    finding = Finding(
        id=str(uuid.uuid4()),
        engagement_id=match.id,
        tool=tool,
        severity=Severity(severity),
        title=title,
        description=description,
        created_at=now,
    )
    store.add_finding(finding)

    if json_output:
        out.print(finding.model_dump_json(indent=2))
    else:
        out.print(f"[green]Added finding:[/green] {finding.title} ({finding.id})")


@findings_app.command("search")
def findings_search(
    query: str = typer.Argument(..., help="Search query (FTS)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Search findings across all engagements (full-text search)."""
    try:
        store = _get_store()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    findings = store.search_findings(query)

    if json_output:
        out.print(json_mod.dumps([f.model_dump(mode="json") for f in findings], indent=2))
    else:
        if not findings:
            out.print("No findings matched the search query.")
            return
        table = Table(title=f"Search: {query}")
        table.add_column("ID", max_width=8)
        table.add_column("Severity")
        table.add_column("Tool")
        table.add_column("Title")
        for f in findings:
            table.add_row(f.id[:8], f.severity.value, f.tool, f.title)
        out.print(table)


@findings_app.command("export")
def findings_export(
    engagement: str = typer.Argument(..., help="Engagement name or ID"),
    fmt: str = typer.Option("json", "--format", "-f", help="Export format: sarif, csv, json"),
):
    """Export findings in SARIF, CSV, or JSON format."""
    from opentools.findings import export_sarif, export_csv, export_json

    try:
        store = _get_store()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    engagements = store.list_all()
    match = None
    for e in engagements:
        if e.name == engagement or e.id == engagement or e.id.startswith(engagement):
            match = e
            break
    if not match:
        _error(f"Engagement not found: {engagement}")

    findings = store.get_findings(match.id)

    if fmt == "sarif":
        out.print(json_mod.dumps(export_sarif(findings), indent=2))
    elif fmt == "csv":
        out.print(export_csv(findings))
    else:
        out.print(export_json(findings))


# ---------------------------------------------------------------------------
# Containers commands
# ---------------------------------------------------------------------------


@containers_app.command("status")
def containers_status(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show container status."""
    try:
        _plugin_dir, config = _get_config()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    from opentools.containers import ContainerManager

    mgr = ContainerManager(config)
    statuses = mgr.status()

    if json_output:
        out.print(json_mod.dumps([s.model_dump(mode="json") for s in statuses], indent=2))
    else:
        if not statuses:
            out.print("No containers found.")
            return
        table = Table(title="Container Status")
        table.add_column("Name")
        table.add_column("State")
        table.add_column("Health")
        table.add_column("Profiles")
        for s in statuses:
            state_color = "green" if s.state == "running" else "red"
            table.add_row(s.name, f"[{state_color}]{s.state}[/{state_color}]", s.health or "-", ", ".join(s.profile))
        out.print(table)


@containers_app.command("start")
def containers_start(
    names: list[str] = typer.Argument(..., help="Container names to start"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Start containers by name."""
    try:
        _plugin_dir, config = _get_config()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    from opentools.containers import ContainerManager

    mgr = ContainerManager(config)
    result = mgr.start(names)

    if json_output:
        out.print(result.model_dump_json(indent=2))
    else:
        if result.success:
            out.print(f"[green]Started:[/green] {', '.join(result.started)}")
        else:
            out.print(f"[red]Failed to start containers.[/red]")
            for name, err in result.errors.items():
                out.print(f"  {name}: {err}")


# ---------------------------------------------------------------------------
# Recipe commands
# ---------------------------------------------------------------------------


@recipe_app.command("list")
def recipe_list(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List available recipes."""
    try:
        _plugin_dir, config = _get_config()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    from opentools.recipes import RecipeRunner

    recipes_path = _plugin_dir / "recipes.json"
    runner = RecipeRunner(config, recipes_path)
    recipes = runner.list_recipes()

    if json_output:
        out.print(json_mod.dumps([r.model_dump(mode="json") for r in recipes], indent=2))
    else:
        if not recipes:
            out.print("No recipes found.")
            return
        table = Table(title="Recipes")
        table.add_column("ID")
        table.add_column("Name")
        table.add_column("Description")
        table.add_column("Steps")
        for r in recipes:
            table.add_row(r.id, r.name, r.description, str(len(r.steps)))
        out.print(table)


@recipe_app.command("run")
def recipe_run(
    recipe_id: str = typer.Argument(..., help="Recipe ID"),
    target: str = typer.Option(..., "--target", "-t", help="Target for the recipe"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be executed"),
    engagement_name: Optional[str] = typer.Option(None, "--engagement", "-e", help="Engagement name or ID"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Run a recipe."""
    import asyncio

    try:
        _plugin_dir, config = _get_config()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    from opentools.recipes import RecipeRunner

    recipes_path = _plugin_dir / "recipes.json"
    runner = RecipeRunner(config, recipes_path)

    variables = {"target": target}
    result = asyncio.run(runner.run(recipe_id, variables, dry_run=dry_run))

    if json_output:
        out.print(result.model_dump_json(indent=2))
    else:
        out.print(f"Recipe: {result.recipe_name} ({result.recipe_id})")
        out.print(f"Status: {result.status}")
        for step in result.steps:
            icon = "[green]OK[/green]" if step.status == "success" else f"[yellow]{step.status}[/yellow]"
            out.print(f"  {icon} {step.step_name}")
            if step.stdout:
                out.print(f"       {step.stdout[:200]}")


# ---------------------------------------------------------------------------
# Report commands
# ---------------------------------------------------------------------------


@report_app.command("generate")
def report_generate(
    engagement: str = typer.Argument(..., help="Engagement name or ID"),
    template: str = typer.Option(..., "--template", "-t", help="Template name"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
):
    """Generate a report from an engagement."""
    try:
        _plugin_dir, config = _get_config()
        store = _get_store()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    from opentools.reports import ReportGenerator

    engagements = store.list_all()
    match = None
    for e in engagements:
        if e.name == engagement or e.id == engagement or e.id.startswith(engagement):
            match = e
            break
    if not match:
        _error(f"Engagement not found: {engagement}")

    template_dir = _plugin_dir / "templates"
    gen = ReportGenerator(template_dir, store)
    output_path = Path(output) if output else None

    try:
        rendered = gen.generate(match.id, template, output_path=output_path)
    except Exception as exc:
        _error(f"Report generation failed: {exc}")

    if output_path:
        out.print(f"[green]Report written to:[/green] {output_path}")
    else:
        out.print(rendered)


@report_app.command("templates")
def report_templates(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """List available report templates."""
    try:
        _plugin_dir, config = _get_config()
        store = _get_store()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    from opentools.reports import ReportGenerator

    template_dir = _plugin_dir / "templates"
    gen = ReportGenerator(template_dir, store)
    templates = gen.list_templates()

    if json_output:
        out.print(json_mod.dumps(templates, indent=2))
    else:
        if not templates:
            out.print("No templates found.")
            return
        out.print("[bold]Available templates:[/bold]")
        for t in templates:
            out.print(f"  - {t}")


# ---------------------------------------------------------------------------
# Config commands
# ---------------------------------------------------------------------------


@config_app.command("show")
def config_show(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show resolved configuration."""
    try:
        _plugin_dir, config = _get_config()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    if json_output:
        out.print(config.model_dump_json(indent=2))
    else:
        out.print(f"[bold]Plugin dir:[/bold] {_plugin_dir}")
        out.print(f"[bold]CLI tools:[/bold] {len(config.cli_tools)}")
        for name in config.cli_tools:
            out.print(f"  - {name}")
        out.print(f"[bold]MCP servers:[/bold] {len(config.mcp_servers)}")
        for name in config.mcp_servers:
            out.print(f"  - {name}")
        out.print(f"[bold]Containers:[/bold] {len(config.containers)}")
        for name in config.containers:
            out.print(f"  - {name}")


@config_app.command("validate")
def config_validate(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Validate configuration YAML files."""
    try:
        _plugin_dir, config = _get_config()
    except FileNotFoundError as exc:
        if json_output:
            out.print(json_mod.dumps({"valid": False, "error": str(exc)}))
        else:
            _error(str(exc))
        return
    except Exception as exc:
        if json_output:
            out.print(json_mod.dumps({"valid": False, "error": str(exc)}))
        else:
            _error(str(exc))
        return

    issues: list[str] = []
    if not config.cli_tools and not config.mcp_servers and not config.containers:
        issues.append("No tools, servers, or containers configured")

    if json_output:
        out.print(json_mod.dumps({"valid": not issues, "issues": issues}))
    else:
        if issues:
            out.print("[yellow]Validation issues:[/yellow]")
            for issue in issues:
                out.print(f"  - {issue}")
        else:
            out.print("[green]Configuration is valid.[/green]")


# ---------------------------------------------------------------------------
# Audit commands
# ---------------------------------------------------------------------------


@audit_app.command("list")
def audit_list(
    engagement: Optional[str] = typer.Option(None, "--engagement", "-e", help="Filter by engagement"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show audit trail."""
    try:
        store = _get_store()
    except (FileNotFoundError, Exception) as exc:
        _error(str(exc))

    entries = store.get_audit_log(engagement_id=engagement)

    if json_output:
        out.print(json_mod.dumps([e.model_dump(mode="json") for e in entries], indent=2))
    else:
        if not entries:
            out.print("No audit entries found.")
            return
        table = Table(title="Audit Trail")
        table.add_column("Timestamp")
        table.add_column("Command")
        table.add_column("Result")
        table.add_column("Details")
        for e in entries:
            table.add_row(str(e.timestamp), e.command, e.result, e.details or "-")
        out.print(table)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
