"""Typer sub-app for ``opentools plugin`` commands."""

from __future__ import annotations

import json as json_mod
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

plugin_app = typer.Typer(name="plugin", help="Plugin marketplace")
console = Console(stderr=True)
out = Console()


def _opentools_home() -> Path:
    """Return ~/.opentools, creating if needed."""
    home = Path.home() / ".opentools"
    home.mkdir(exist_ok=True)
    (home / "plugins").mkdir(exist_ok=True)
    (home / "staging").mkdir(exist_ok=True)
    (home / "cache").mkdir(exist_ok=True)
    (home / "registry-cache").mkdir(exist_ok=True)
    return home


def _error(msg: str, hint: str = "") -> None:
    """Print error and exit."""
    console.print(f"[red]Error:[/red] {msg}")
    if hint:
        console.print(f"[dim]Hint:[/dim] {hint}")
    raise typer.Exit(1)


# --- Core commands: list, search, info, install, uninstall, update ---

@plugin_app.command("list")
def plugin_list(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    check_updates: bool = typer.Option(False, "--check-updates"),
    verify: bool = typer.Option(False, "--verify"),
    domain: Optional[str] = typer.Option(None, "--domain"),
):
    """List installed plugins."""
    from opentools_plugin_core.index import PluginIndex

    home = _opentools_home()
    idx = PluginIndex(home / "plugins.db")
    plugins = idx.list_all()

    if json_output:
        out.print(json_mod.dumps([p.model_dump(mode="json") for p in plugins], indent=2))
        return

    if not plugins:
        out.print("No plugins installed.")
        return

    table = Table(title="Installed Plugins")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Registry")
    table.add_column("Mode")
    table.add_column("Verified")
    for p in plugins:
        v_icon = "[green]yes[/green]" if p.signature_verified else "[yellow]no[/yellow]"
        table.add_row(p.name, p.version, p.registry, p.mode.value, v_icon)
    out.print(table)


@plugin_app.command("search")
def plugin_search(
    query: str = typer.Argument(..., help="Search query"),
    domain: Optional[str] = typer.Option(None, "--domain"),
    registry_name: Optional[str] = typer.Option(None, "--registry"),
    refresh: bool = typer.Option(False, "--refresh"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Search the plugin registry."""
    from opentools_plugin_core.registry import RegistryClient
    from opentools_plugin_core.errors import RegistryError

    home = _opentools_home()
    client = RegistryClient(cache_dir=home / "registry-cache")
    try:
        results = client.search(query, domain=domain)
    except RegistryError as e:
        _error(e.message, hint=e.hint)
        return

    if json_output:
        out.print(json_mod.dumps([r.model_dump(mode="json") for r in results], indent=2))
        return

    if not results:
        out.print(f"No plugins found matching '{query}'.")
        return

    table = Table(title=f"Search: {query}")
    table.add_column("Name")
    table.add_column("Description")
    table.add_column("Version")
    table.add_column("Domain")
    table.add_column("Trust")
    for r in results:
        table.add_row(r.name, r.description[:50], r.latest_version, r.domain, r.trust_tier)
    out.print(table)


@plugin_app.command("info")
def plugin_info(
    name: str = typer.Argument(..., help="Plugin name"),
    version: Optional[str] = typer.Option(None, "--version"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Show plugin details."""
    from opentools_plugin_core.registry import RegistryClient
    from opentools_plugin_core.errors import RegistryError

    home = _opentools_home()
    client = RegistryClient(cache_dir=home / "registry-cache")
    try:
        entry = client.lookup(name)
    except RegistryError as e:
        _error(e.message, hint=e.hint)
        return

    if entry is None:
        _error(f"Plugin '{name}' not found", hint=f"opentools plugin search {name}")
        return

    if json_output:
        out.print(entry.model_dump_json(indent=2))
        return

    out.print(f"[bold]{entry.name}[/bold] v{entry.latest_version}")
    out.print(f"  {entry.description}")
    out.print(f"  Domain: {entry.domain}")
    out.print(f"  Author: {entry.author}")
    out.print(f"  Trust: {entry.trust_tier}")
    out.print(f"  Tags: {', '.join(entry.tags)}")
    out.print(f"  Repo: {entry.repo}")


@plugin_app.command("install")
def plugin_install(
    names: list[str] = typer.Argument(..., help="Plugin name(s)"),
    yes: bool = typer.Option(False, "--yes", "-y"),
    registry_name: Optional[str] = typer.Option(None, "--registry"),
    pre: bool = typer.Option(False, "--pre"),
    pull: bool = typer.Option(False, "--pull"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Install plugin(s) from the registry."""
    out.print(f"[bold]Installing:[/bold] {', '.join(names)}")
    out.print("[yellow]Full install pipeline not yet wired to registry fetch + git clone.[/yellow]")


@plugin_app.command("uninstall")
def plugin_uninstall(
    name: str = typer.Argument(..., help="Plugin name"),
    yes: bool = typer.Option(False, "--yes", "-y"),
    keep_images: bool = typer.Option(False, "--keep-images"),
    purge: bool = typer.Option(False, "--purge"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Uninstall a plugin."""
    import shutil
    from opentools_plugin_core.index import PluginIndex

    home = _opentools_home()
    idx = PluginIndex(home / "plugins.db")
    plugin = idx.get(name)
    if plugin is None:
        _error(f"Plugin '{name}' is not installed", hint="opentools plugin list")
        return

    if not yes:
        confirm = typer.confirm(f"Uninstall {name} v{plugin.version}?")
        if not confirm:
            out.print("Cancelled.")
            raise typer.Exit(0)

    plugin_dir = home / "plugins" / name
    if plugin_dir.exists():
        shutil.rmtree(plugin_dir)
    idx.unregister(name)

    if json_output:
        out.print(json_mod.dumps({"uninstalled": name, "version": plugin.version}))
    else:
        out.print(f"[green]Uninstalled:[/green] {name} v{plugin.version}")


@plugin_app.command("update")
def plugin_update(
    names: list[str] = typer.Argument(None, help="Plugin name(s)"),
    yes: bool = typer.Option(False, "--yes", "-y"),
    pre: bool = typer.Option(False, "--pre"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Update plugin(s) to latest version."""
    out.print("[yellow]Update flow not yet fully wired.[/yellow]")


# --- Lifecycle commands: up, down, logs, exec, pull, setup, verify ---

@plugin_app.command("up")
def plugin_up(
    name: str = typer.Argument(..., help="Plugin name"),
    pull_images: bool = typer.Option(False, "--pull"),
):
    """Start plugin containers."""
    out.print(f"[yellow]Starting containers for {name}...[/yellow]")


@plugin_app.command("down")
def plugin_down(name: str = typer.Argument(..., help="Plugin name")):
    """Stop plugin containers."""
    out.print(f"[yellow]Stopping containers for {name}...[/yellow]")


@plugin_app.command("logs")
def plugin_logs(
    name: str = typer.Argument(..., help="Plugin name"),
    tail: int = typer.Option(50, "--tail"),
):
    """View plugin container logs."""
    out.print(f"[yellow]Logs for {name} (not yet wired).[/yellow]")


@plugin_app.command("exec")
def plugin_exec(
    name: str = typer.Argument(..., help="Plugin name"),
    container: str = typer.Argument(..., help="Container name"),
    command: list[str] = typer.Argument(..., help="Command"),
):
    """Exec into a plugin container."""
    out.print(f"[yellow]Exec into {container} of {name} (not yet wired).[/yellow]")


@plugin_app.command("pull")
def plugin_pull(
    name: str = typer.Argument(None, help="Plugin name"),
    all_plugins: bool = typer.Option(False, "--all"),
):
    """Pull container images for a plugin."""
    out.print("[yellow]Pull not yet wired.[/yellow]")


@plugin_app.command("setup")
def plugin_setup(name: str = typer.Argument(..., help="Plugin name")):
    """Re-run container setup for a plugin."""
    out.print(f"[yellow]Setup for {name} (not yet wired).[/yellow]")


@plugin_app.command("verify")
def plugin_verify(
    name: str = typer.Argument(..., help="Plugin name"),
    accept: bool = typer.Option(False, "--accept"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Check file integrity for an installed plugin."""
    import hashlib
    from opentools_plugin_core.index import PluginIndex
    from opentools_plugin_core.installer import read_active_version

    home = _opentools_home()
    idx = PluginIndex(home / "plugins.db")
    plugin = idx.get(name)

    if plugin is None:
        _error(f"Plugin '{name}' not installed", hint="opentools plugin list")
        return

    plugin_dir = home / "plugins" / name
    active = read_active_version(plugin_dir)
    if not active:
        _error(f"No active version for '{name}'")
        return

    records = idx.get_integrity(name)
    if not records and not accept:
        out.print(f"[yellow]No integrity records for {name}. Run with --accept to record.[/yellow]")
        return

    if accept:
        version_dir = plugin_dir / active
        count = 0
        for f in version_dir.rglob("*"):
            if f.is_file():
                sha = hashlib.sha256(f.read_bytes()).hexdigest()
                rel = str(f.relative_to(version_dir))
                idx.record_integrity(name, rel, sha)
                count += 1
        out.print(f"[green]Recorded {count} file hashes for {name}.[/green]")
        return

    version_dir = plugin_dir / active
    failures = []
    for rec in records:
        fpath = version_dir / rec.file_path
        if not fpath.exists():
            failures.append((rec.file_path, "missing"))
        else:
            actual = hashlib.sha256(fpath.read_bytes()).hexdigest()
            if actual != rec.sha256:
                failures.append((rec.file_path, "modified"))

    if json_output:
        out.print(json_mod.dumps({"plugin": name, "version": active, "verified": len(failures) == 0, "failures": failures}))
    elif failures:
        out.print(f"[red]Integrity check FAILED for {name}:[/red]")
        for path, reason in failures:
            out.print(f"  {reason}: {path}")
    else:
        out.print(f"[green]Integrity OK for {name} ({len(records)} files).[/green]")


# --- Authoring commands: init, link, unlink, validate ---

@plugin_app.command("init")
def plugin_init(name: str = typer.Argument(..., help="Plugin name")):
    """Scaffold a new plugin project."""
    target = Path.cwd() / name
    target.mkdir(exist_ok=True)

    manifest = {
        "name": name,
        "version": "0.1.0",
        "description": f"{name} plugin for OpenTools",
        "author": {"name": "Your Name"},
        "license": "MIT",
        "min_opentools_version": "0.3.0",
        "tags": [],
        "domain": "pentest",
        "provides": {"skills": [], "recipes": [], "containers": []},
    }

    from ruamel.yaml import YAML
    yaml = YAML()
    yaml.default_flow_style = False
    with (target / "opentools-plugin.yaml").open("w") as f:
        yaml.dump(manifest, f)

    (target / "skills").mkdir(exist_ok=True)
    (target / "recipes").mkdir(exist_ok=True)
    (target / "containers").mkdir(exist_ok=True)
    (target / "README.md").write_text(f"# {name}\n\nAn OpenTools plugin.\n")

    out.print(f"[green]Scaffolded plugin:[/green] {name}")
    out.print(f"  Directory: {target}")


@plugin_app.command("link")
def plugin_link(path: str = typer.Argument(".", help="Path to local plugin")):
    """Symlink a local plugin for development."""
    out.print(f"[yellow]Link {path} (not yet wired).[/yellow]")


@plugin_app.command("unlink")
def plugin_unlink(name: str = typer.Argument(..., help="Plugin name")):
    """Remove a development symlink."""
    out.print(f"[yellow]Unlink {name} (not yet wired).[/yellow]")


@plugin_app.command("validate")
def plugin_validate(
    path: str = typer.Argument(".", help="Path to plugin directory"),
    strict: bool = typer.Option(False, "--strict"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Validate a local plugin (author tool)."""
    from ruamel.yaml import YAML
    from opentools_plugin_core.models import PluginManifest
    from pydantic import ValidationError

    plugin_path = Path(path)
    manifest_file = plugin_path / "opentools-plugin.yaml"

    if not manifest_file.exists():
        _error(f"No opentools-plugin.yaml in {plugin_path}")
        return

    yaml = YAML()
    with manifest_file.open("r") as f:
        raw = yaml.load(f)

    issues: list[dict] = []
    try:
        manifest = PluginManifest(**raw)
    except ValidationError as e:
        for err in e.errors():
            issues.append({"severity": "error", "field": ".".join(str(l) for l in err["loc"]), "message": err["msg"]})

    if not issues:
        for skill in (raw.get("provides", {}).get("skills", []) or []):
            sp = plugin_path / skill.get("path", "")
            if not sp.exists():
                issues.append({"severity": "error", "field": "provides.skills", "message": f"File not found: {sp}"})

    if json_output:
        out.print(json_mod.dumps({"valid": len(issues) == 0, "issues": issues}, indent=2))
    elif issues:
        out.print(f"[red]Validation issues in {path}:[/red]")
        for i in issues:
            color = "red" if i["severity"] == "error" else "yellow"
            out.print(f"  [{color}]{i['severity']}[/{color}] {i['field']}: {i['message']}")
        if strict:
            raise typer.Exit(1)
    else:
        out.print(f"[green]Plugin at {path} is valid.[/green]")


# --- Team commands: freeze, sync, export, import, rollback, prune ---

@plugin_app.command("freeze")
def plugin_freeze(json_output: bool = typer.Option(False, "--json")):
    """Generate a lockfile from current installed state."""
    from datetime import datetime, timezone
    from opentools_plugin_core.index import PluginIndex
    from opentools_plugin_core.models import Lockfile, LockfileEntry
    from opentools_plugin_core import __version__

    home = _opentools_home()
    idx = PluginIndex(home / "plugins.db")
    plugins = idx.list_all()

    entries = {}
    for p in plugins:
        entries[p.name] = LockfileEntry(
            version=p.version, registry=p.registry, repo=p.repo,
            ref=f"v{p.version}", sha256="",
        )

    lockfile = Lockfile(
        generated_at=datetime.now(timezone.utc).isoformat(),
        opentools_version=__version__,
        plugins=entries,
    )

    if json_output:
        out.print(lockfile.model_dump_json(indent=2))
    else:
        from ruamel.yaml import YAML
        import io
        yaml = YAML()
        yaml.default_flow_style = False
        buf = io.StringIO()
        yaml.dump(lockfile.model_dump(mode="json"), buf)
        out.print(buf.getvalue())


@plugin_app.command("sync")
def plugin_sync(
    lockfile: Optional[str] = typer.Option(None, "--lockfile"),
    plugin_set: Optional[str] = typer.Option(None, "--set"),
    freeze_path: Optional[str] = typer.Option(None, "--freeze"),
    yes: bool = typer.Option(False, "--yes", "-y"),
):
    """Sync to a lockfile or plugin set."""
    out.print("[yellow]Sync (not yet wired).[/yellow]")


@plugin_app.command("export")
def plugin_export(
    name: str = typer.Argument(..., help="Plugin name"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
):
    """Export a plugin to a .otp archive."""
    out.print(f"[yellow]Export {name} (not yet wired).[/yellow]")


@plugin_app.command("import")
def plugin_import_cmd(
    archive: str = typer.Argument(..., help="Path to .otp archive"),
    yes: bool = typer.Option(False, "--yes", "-y"),
):
    """Install a plugin from a .otp archive."""
    out.print(f"[yellow]Import {archive} (not yet wired).[/yellow]")


@plugin_app.command("rollback")
def plugin_rollback(
    name: str = typer.Argument(..., help="Plugin name"),
    version: Optional[str] = typer.Option(None, "--version"),
    yes: bool = typer.Option(False, "--yes", "-y"),
):
    """Roll back a plugin to a previous version."""
    from opentools_plugin_core.updater import get_available_versions, get_active_version, rollback

    home = _opentools_home()
    plugin_dir = home / "plugins" / name
    if not plugin_dir.exists():
        _error(f"Plugin '{name}' not installed", hint="opentools plugin list")
        return

    active = get_active_version(plugin_dir)
    versions = get_available_versions(plugin_dir)

    if not version:
        others = [v for v in versions if v != active]
        if not others:
            _error("No previous version to roll back to")
            return
        version = others[-1]

    out.print(f"Rolling back {name} from {active} to {version}")
    rollback(plugin_dir, version)
    out.print(f"[green]Rolled back to {version}[/green]")


@plugin_app.command("prune")
def plugin_prune(
    name: Optional[str] = typer.Argument(None, help="Plugin name"),
    keep: int = typer.Option(1, "--keep"),
    yes: bool = typer.Option(False, "--yes", "-y"),
):
    """Delete old version directories."""
    from opentools_plugin_core.updater import prune_old_versions

    home = _opentools_home()
    plugins_dir = home / "plugins"

    if name:
        dirs = [plugins_dir / name]
    else:
        dirs = [d for d in plugins_dir.iterdir() if d.is_dir()] if plugins_dir.exists() else []

    total_removed = 0
    for d in dirs:
        if not (d / ".active").exists():
            continue
        removed = prune_old_versions(d, keep=keep)
        total_removed += len(removed)
        if removed:
            out.print(f"  {d.name}: removed {', '.join(removed)}")

    out.print(f"[green]Pruned {total_removed} old version(s).[/green]")
