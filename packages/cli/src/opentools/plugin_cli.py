"""Typer sub-app for ``opentools plugin`` commands."""

from __future__ import annotations

import hashlib
import json as json_mod
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
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


def _is_local_path(name: str) -> bool:
    """Return True if name looks like a filesystem path rather than a registry name."""
    return (
        name.startswith("./")
        or name.startswith("../")
        or name.startswith("/")
        or name.startswith("~")
        or (len(name) >= 2 and name[1] == ":" and name[0].isalpha())
    )


def _load_manifest(src: Path):
    """Parse opentools-plugin.yaml from src, return (raw_dict, PluginManifest)."""
    from ruamel.yaml import YAML
    from opentools_plugin_core.models import PluginManifest

    manifest_file = src / "opentools-plugin.yaml"
    if not manifest_file.exists():
        _error(
            f"No opentools-plugin.yaml in {src}",
            hint="Run 'opentools plugin init <name>' to scaffold a new plugin.",
        )
    yaml = YAML()
    with manifest_file.open("r", encoding="utf-8") as f:
        raw = yaml.load(f)
    manifest = PluginManifest(**raw)
    return raw, manifest


def _compose_path(home: Path, name: str, version: str) -> Path:
    return home / "plugins" / name / version / "compose" / "docker-compose.yaml"


def _get_active_compose_path(home: Path, name: str):
    """Return (compose_path, version) or call _error if plugin/compose not found."""
    from opentools_plugin_core.installer import read_active_version

    plugin_dir = home / "plugins" / name
    if not plugin_dir.exists():
        _error(f"Plugin '{name}' is not installed", hint="opentools plugin list")

    active = read_active_version(plugin_dir)
    if not active:
        _error(f"No active version for plugin '{name}'")

    compose = _compose_path(home, name, active)
    if not compose.exists():
        _error(
            f"Plugin '{name}' has no compose file (no containers defined).",
            hint="This plugin does not manage Docker containers.",
        )
    return compose, active


def _do_install(src: Path, home: Path, yes: bool) -> None:
    """Core install pipeline: stage -> validate -> prompt -> promote -> register."""
    from opentools_plugin_core.index import PluginIndex
    from opentools_plugin_core.installer import (
        stage_plugin,
        promote_plugin,
        cleanup_staging,
    )
    from opentools_plugin_core.compose import generate_compose
    from opentools_plugin_core.resolver import detect_conflicts
    from opentools_plugin_core.models import InstalledPlugin, InstallMode
    from opentools_plugin_core.errors import PluginInstallError

    idx = PluginIndex(home / "plugins.db")
    _, manifest = _load_manifest(src)
    name = manifest.name
    version = manifest.version

    # Conflict check against installed plugins
    installed_provides: dict[str, dict[str, str]] = {}
    for p in idx.list_all():
        p_dir = home / "plugins" / p.name
        p_manifest_file = p_dir / p.version / "manifest.yaml"
        if p_manifest_file.exists():
            from ruamel.yaml import YAML
            yaml = YAML()
            with p_manifest_file.open("r") as f:
                p_raw = yaml.load(f) or {}
            p_provides = p_raw.get("provides", {})
            for cat in ("containers", "skills", "recipes"):
                for item in (p_provides.get(cat) or []):
                    item_name = item.get("name") or item.get("path") if isinstance(item, dict) else str(item)
                    if item_name:
                        installed_provides.setdefault(cat, {})[item_name] = p.name

    new_provides: dict[str, list[str]] = {}
    for container in manifest.provides.containers:
        new_provides.setdefault("containers", []).append(container.name)
    for skill in manifest.provides.skills:
        new_provides.setdefault("skills", []).append(skill.path)
    for recipe in manifest.provides.recipes:
        new_provides.setdefault("recipes", []).append(recipe.path)

    conflicts = detect_conflicts(name, new_provides, installed_provides)
    if conflicts:
        out.print("[red]Conflict detected:[/red]")
        for c in conflicts:
            out.print(f"  {c}")
        _error("Install aborted due to conflicts.")

    # Audit summary
    out.print(f"\n[bold]Plugin:[/bold] {name} v{version}")
    out.print(f"  Skills:     {len(manifest.provides.skills)}")
    out.print(f"  Recipes:    {len(manifest.provides.recipes)}")
    out.print(f"  Containers: {len(manifest.provides.containers)}")
    if manifest.sandbox.capabilities:
        out.print(f"  Capabilities: {', '.join(manifest.sandbox.capabilities)}")
    if manifest.sandbox.egress:
        out.print(f"  [yellow]Egress to: {', '.join(manifest.sandbox.egress_domains) or 'any'}[/yellow]")

    if not yes:
        confirmed = typer.confirm(f"\nInstall {name} v{version}?")
        if not confirmed:
            out.print("Cancelled.")
            raise typer.Exit(0)

    staged: Optional[Path] = None
    try:
        staged = stage_plugin(src, home)

        # Generate compose if containers exist
        if manifest.provides.containers:
            compose_data = generate_compose(manifest)
            if compose_data:
                from ruamel.yaml import YAML
                compose_dir = staged / "compose"
                compose_dir.mkdir(exist_ok=True)
                yaml2 = YAML()
                yaml2.default_flow_style = False
                with (compose_dir / "docker-compose.yaml").open("w") as f:
                    yaml2.dump(compose_data, f)

        # Record integrity hashes for staged files
        for fpath in staged.rglob("*"):
            if fpath.is_file():
                sha = hashlib.sha256(fpath.read_bytes()).hexdigest()
                rel = str(fpath.relative_to(staged))
                idx.record_integrity(name, rel, sha)

        promote_plugin(staged, home, name, version)
        staged = None  # ownership transferred

    except PluginInstallError as e:
        if staged:
            cleanup_staging(staged)
        _error(e.message, hint=e.hint)
        return
    except Exception as e:
        if staged:
            cleanup_staging(staged)
        _error(str(e))
        return

    idx.register(InstalledPlugin(
        name=name,
        version=version,
        repo="",
        registry="local",
        installed_at=datetime.now(timezone.utc).isoformat(),
        signature_verified=False,
        mode=InstallMode.REGISTRY,
    ))

    out.print(f"[green]Installed:[/green] {name} v{version}")


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
    names: list[str] = typer.Argument(..., help="Plugin name(s) or local path(s)"),
    yes: bool = typer.Option(False, "--yes", "-y"),
    registry_name: Optional[str] = typer.Option(None, "--registry"),
    pre: bool = typer.Option(False, "--pre"),
    pull: bool = typer.Option(False, "--pull"),
    json_output: bool = typer.Option(False, "--json"),
):
    """Install plugin(s) from a local path or the registry."""
    from opentools_plugin_core.registry import RegistryClient
    from opentools_plugin_core.errors import RegistryError

    home = _opentools_home()

    for name in names:
        if _is_local_path(name):
            src = Path(name).expanduser().resolve()
            if not src.exists():
                _error(f"Path does not exist: {src}")
            _do_install(src, home, yes)
        else:
            client = RegistryClient(cache_dir=home / "registry-cache")
            try:
                entry = client.lookup(name)
            except RegistryError:
                entry = None

            if entry is None:
                out.print(
                    "[yellow]Registry-based install requires a populated catalog — "
                    "use `opentools plugin install <path>` with a local directory for now.[/yellow]"
                )
                raise typer.Exit(1)

            latest_ver = getattr(entry, "latest_version", None)
            clone_ref = f"v{latest_ver}" if latest_ver else "main"

            with tempfile.TemporaryDirectory() as tmp_dir:
                clone_result = subprocess.run(
                    ["git", "clone", "--depth", "1", "--branch", clone_ref, entry.repo, tmp_dir],
                    capture_output=True,
                    text=True,
                )
                if clone_result.returncode != 0:
                    clone_result = subprocess.run(
                        ["git", "clone", "--depth", "1", entry.repo, tmp_dir],
                        capture_output=True,
                        text=True,
                    )
                if clone_result.returncode != 0:
                    _error(
                        f"Failed to clone {entry.repo}: {clone_result.stderr.strip()}",
                        hint="Check the repository URL and your network connection.",
                    )
                _do_install(Path(tmp_dir), home, yes)


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
    from opentools_plugin_core.index import PluginIndex
    from opentools_plugin_core.installer import read_active_version

    home = _opentools_home()
    idx = PluginIndex(home / "plugins.db")

    targets = list(names) if names else [p.name for p in idx.list_all()]
    if not targets:
        out.print("No plugins installed.")
        return

    for name in targets:
        plugin = idx.get(name)
        if plugin is None:
            out.print(f"[yellow]Plugin '{name}' is not installed — skipping.[/yellow]")
            continue

        plugin_dir = home / "plugins" / name

        if not plugin.repo:
            out.print(
                f"[yellow]{name}: no source repo recorded — cannot auto-update. "
                "Re-install manually with a local path.[/yellow]"
            )
            continue

        out.print(f"Updating [bold]{name}[/bold] (current: v{plugin.version})...")
        with tempfile.TemporaryDirectory() as tmp_dir:
            clone_result = subprocess.run(
                ["git", "clone", "--depth", "1", plugin.repo, tmp_dir],
                capture_output=True,
                text=True,
            )
            if clone_result.returncode != 0:
                out.print(f"[red]Failed to clone {plugin.repo}:[/red] {clone_result.stderr.strip()}")
                continue

            src = Path(tmp_dir)
            try:
                from ruamel.yaml import YAML
                yaml = YAML()
                with (src / "opentools-plugin.yaml").open("r") as f:
                    raw = yaml.load(f)
                new_version = raw.get("version", "")
            except Exception:
                new_version = ""

            if new_version and new_version == plugin.version:
                out.print(f"[green]{name}:[/green] already at latest ({plugin.version})")
                continue

            # Stop containers before update
            active = read_active_version(plugin_dir)
            if active:
                compose = _compose_path(home, name, active)
                if compose.exists():
                    subprocess.run(
                        ["docker", "compose", "-f", str(compose), "down"],
                        capture_output=True,
                    )

            _do_install(src, home, yes)

            if new_version:
                idx.update_version(name, new_version)

            # Restart containers
            new_active = read_active_version(plugin_dir)
            if new_active:
                new_compose = _compose_path(home, name, new_active)
                if new_compose.exists():
                    subprocess.run(
                        ["docker", "compose", "-f", str(new_compose), "up", "-d"],
                        capture_output=True,
                    )

        out.print(f"[green]Updated:[/green] {name} {plugin.version} -> {new_version or 'latest'}")


# --- Lifecycle commands: up, down, logs, exec, pull, setup, verify ---

@plugin_app.command("up")
def plugin_up(
    name: str = typer.Argument(..., help="Plugin name"),
    pull_images: bool = typer.Option(False, "--pull"),
):
    """Start plugin containers."""
    home = _opentools_home()
    compose, version = _get_active_compose_path(home, name)
    cmd = ["docker", "compose", "-f", str(compose), "up", "-d"]
    if pull_images:
        cmd.append("--pull=always")
    out.print(f"Starting containers for [bold]{name}[/bold] v{version}...")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise typer.Exit(result.returncode)


@plugin_app.command("down")
def plugin_down(name: str = typer.Argument(..., help="Plugin name")):
    """Stop plugin containers."""
    home = _opentools_home()
    compose, version = _get_active_compose_path(home, name)
    out.print(f"Stopping containers for [bold]{name}[/bold] v{version}...")
    result = subprocess.run(["docker", "compose", "-f", str(compose), "down"])
    if result.returncode != 0:
        raise typer.Exit(result.returncode)


@plugin_app.command("logs")
def plugin_logs(
    name: str = typer.Argument(..., help="Plugin name"),
    tail: int = typer.Option(50, "--tail"),
):
    """View plugin container logs."""
    home = _opentools_home()
    compose, _ = _get_active_compose_path(home, name)
    result = subprocess.run(
        ["docker", "compose", "-f", str(compose), "logs", "--tail", str(tail)]
    )
    if result.returncode != 0:
        raise typer.Exit(result.returncode)


@plugin_app.command("exec")
def plugin_exec(
    name: str = typer.Argument(..., help="Plugin name"),
    container: str = typer.Argument(..., help="Container name"),
    command: list[str] = typer.Argument(..., help="Command"),
):
    """Exec into a plugin container."""
    from opentools_plugin_core.enforcement import validate_command
    from opentools_plugin_core.installer import read_active_version

    home = _opentools_home()
    plugin_dir = home / "plugins" / name
    if not plugin_dir.exists():
        _error(f"Plugin '{name}' is not installed", hint="opentools plugin list")

    active = read_active_version(plugin_dir)
    if not active:
        _error(f"No active version for plugin '{name}'")

    allowed_containers: set[str] = set()
    manifest_file = plugin_dir / active / "manifest.yaml"
    if manifest_file.exists():
        from ruamel.yaml import YAML
        yaml = YAML()
        with manifest_file.open("r") as f:
            raw = yaml.load(f) or {}
        for c in (raw.get("provides", {}).get("containers") or []):
            if isinstance(c, dict) and c.get("name"):
                allowed_containers.add(c["name"])

    full_cmd = "docker exec " + container + " " + " ".join(command)
    violations = validate_command(full_cmd, allowed_containers)
    if violations:
        for v in violations:
            console.print(f"[red]Violation:[/red] {v.message}")
            if v.detail:
                console.print(f"  [dim]{v.detail}[/dim]")
        _error("Command blocked by sandbox policy.")

    result = subprocess.run(["docker", "exec", container, *command])
    if result.returncode != 0:
        raise typer.Exit(result.returncode)


@plugin_app.command("pull")
def plugin_pull(
    name: str = typer.Argument(None, help="Plugin name"),
    all_plugins: bool = typer.Option(False, "--all"),
):
    """Pull container images for a plugin."""
    from opentools_plugin_core.index import PluginIndex

    home = _opentools_home()

    if all_plugins:
        idx = PluginIndex(home / "plugins.db")
        names = [p.name for p in idx.list_all()]
    elif name:
        names = [name]
    else:
        _error("Specify a plugin name or use --all")
        return

    for plugin_name in names:
        try:
            compose_path, _ = _get_active_compose_path(home, plugin_name)
        except SystemExit:
            out.print(f"[dim]{plugin_name}: no compose file — skipping.[/dim]")
            continue

        out.print(f"Pulling images for [bold]{plugin_name}[/bold]...")
        result = subprocess.run(["docker", "compose", "-f", str(compose_path), "pull"])
        if result.returncode != 0:
            out.print(f"[red]Pull failed for {plugin_name}[/red]")


@plugin_app.command("setup")
def plugin_setup(name: str = typer.Argument(..., help="Plugin name")):
    """Re-run container setup for a plugin (regenerate compose file)."""
    from opentools_plugin_core.index import PluginIndex
    from opentools_plugin_core.installer import read_active_version
    from opentools_plugin_core.compose import generate_compose
    from opentools_plugin_core.models import PluginManifest

    home = _opentools_home()
    idx = PluginIndex(home / "plugins.db")
    plugin = idx.get(name)
    if plugin is None:
        _error(f"Plugin '{name}' is not installed", hint="opentools plugin list")

    plugin_dir = home / "plugins" / name
    active = read_active_version(plugin_dir)
    if not active:
        _error(f"No active version for plugin '{name}'")

    version_dir = plugin_dir / active
    manifest_file = version_dir / "manifest.yaml"
    if not manifest_file.exists():
        _error(f"Manifest not found for {name} v{active}")

    from ruamel.yaml import YAML
    yaml = YAML()
    with manifest_file.open("r") as f:
        raw = yaml.load(f)
    manifest = PluginManifest(**raw)

    if not manifest.provides.containers:
        out.print(f"[yellow]{name} has no containers — nothing to set up.[/yellow]")
        return

    compose_data = generate_compose(manifest)
    if not compose_data:
        out.print(f"[yellow]{name}: compose generation returned nothing.[/yellow]")
        return

    compose_dir = version_dir / "compose"
    compose_dir.mkdir(exist_ok=True)
    compose_file = compose_dir / "docker-compose.yaml"
    yaml2 = YAML()
    yaml2.default_flow_style = False
    with compose_file.open("w") as f:
        yaml2.dump(compose_data, f)

    out.print(f"[green]Compose file regenerated for {name} v{active}:[/green] {compose_file}")


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
    from opentools_plugin_core.index import PluginIndex
    from opentools_plugin_core.models import InstalledPlugin, InstallMode

    home = _opentools_home()
    src = Path(path).expanduser().resolve()
    if not src.exists():
        _error(f"Path does not exist: {src}")

    _, manifest = _load_manifest(src)
    name = manifest.name
    version = manifest.version

    plugin_dir = home / "plugins" / name
    version_dir = plugin_dir / version
    plugin_dir.mkdir(parents=True, exist_ok=True)

    if version_dir.exists() or version_dir.is_symlink():
        if version_dir.is_symlink():
            version_dir.unlink()
        else:
            shutil.rmtree(version_dir)

    # Prefer symlink on non-Windows; fall back to copytree
    link_created = False
    if sys.platform != "win32":
        try:
            os.symlink(src, version_dir)
            link_created = True
        except OSError:
            pass

    if not link_created:
        shutil.copytree(str(src), str(version_dir))

    # Write .active pointer atomically
    active_file = plugin_dir / ".active"
    tmp_active = active_file.with_suffix(".tmp")
    tmp_active.write_text(version)
    os.replace(str(tmp_active), str(active_file))

    idx = PluginIndex(home / "plugins.db")
    idx.register(InstalledPlugin(
        name=name,
        version=version,
        repo=str(src),
        registry="local",
        installed_at=datetime.now(timezone.utc).isoformat(),
        signature_verified=False,
        mode=InstallMode.LINKED,
    ))

    link_type = "symlinked" if link_created else "copied (Windows fallback)"
    out.print(f"[green]Linked:[/green] {name} v{version} ({link_type})")
    out.print(f"  Source: {src}")
    out.print(f"  Active: {version_dir}")


@plugin_app.command("unlink")
def plugin_unlink(name: str = typer.Argument(..., help="Plugin name")):
    """Remove a development symlink."""
    from opentools_plugin_core.index import PluginIndex

    home = _opentools_home()
    idx = PluginIndex(home / "plugins.db")
    plugin = idx.get(name)

    if plugin is None:
        _error(f"Plugin '{name}' is not installed", hint="opentools plugin list")
        return

    if plugin.mode.value != "linked":
        _error(
            f"Plugin '{name}' is installed in mode '{plugin.mode.value}', not 'linked'.",
            hint="Use 'opentools plugin uninstall' to remove non-linked plugins.",
        )
        return

    plugin_dir = home / "plugins" / name
    if plugin_dir.exists():
        shutil.rmtree(plugin_dir)
    idx.unregister(name)

    out.print(f"[green]Unlinked:[/green] {name} v{plugin.version}")


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
    from opentools_plugin_core.index import PluginIndex

    if lockfile and plugin_set:
        _error("Specify --lockfile or --set, not both.")

    if not lockfile and not plugin_set:
        _error("Specify --lockfile <path> or --set <path>.")

    home = _opentools_home()
    idx = PluginIndex(home / "plugins.db")
    installed = {p.name: p for p in idx.list_all()}

    if lockfile:
        from ruamel.yaml import YAML
        from opentools_plugin_core.models import Lockfile

        lf_path = Path(lockfile)
        if not lf_path.exists():
            _error(f"Lockfile not found: {lockfile}")

        yaml = YAML()
        with lf_path.open("r") as f:
            raw = yaml.load(f)
        lf = Lockfile(**raw)

        for plugin_name, entry in lf.plugins.items():
            current = installed.get(plugin_name)
            if current is None or current.version != entry.version:
                out.print(f"  Installing {plugin_name} v{entry.version}...")
                if entry.repo:
                    with tempfile.TemporaryDirectory() as tmp_dir:
                        ref = entry.ref or f"v{entry.version}"
                        result = subprocess.run(
                            ["git", "clone", "--depth", "1", "--branch", ref, entry.repo, tmp_dir],
                            capture_output=True,
                            text=True,
                        )
                        if result.returncode != 0:
                            result = subprocess.run(
                                ["git", "clone", "--depth", "1", entry.repo, tmp_dir],
                                capture_output=True,
                                text=True,
                            )
                        if result.returncode != 0:
                            out.print(f"  [red]Failed to clone {entry.repo}[/red]")
                            continue
                        _do_install(Path(tmp_dir), home, yes=True)
                else:
                    out.print(f"  [yellow]{plugin_name}: no repo URL in lockfile — skipping.[/yellow]")

        for installed_name in list(installed.keys()):
            if installed_name not in lf.plugins:
                do_remove = yes or typer.confirm(
                    f"Plugin '{installed_name}' not in lockfile. Uninstall?"
                )
                if do_remove:
                    plugin_dir = home / "plugins" / installed_name
                    if plugin_dir.exists():
                        shutil.rmtree(plugin_dir)
                    idx.unregister(installed_name)
                    out.print(f"  [yellow]Removed {installed_name}[/yellow]")

    elif plugin_set:
        from ruamel.yaml import YAML
        from opentools_plugin_core.models import PluginSet

        ps_path = Path(plugin_set)
        if not ps_path.exists():
            _error(f"Plugin set file not found: {plugin_set}")

        yaml = YAML()
        with ps_path.open("r") as f:
            raw = yaml.load(f)
        pset = PluginSet(**raw)

        for plugin_name, version_spec in pset.plugins.items():
            current = installed.get(plugin_name)
            target_version = version_spec if version_spec not in ("latest", "*") else None
            if current is not None and (target_version is None or current.version == target_version):
                out.print(f"  [dim]{plugin_name}: already up to date ({current.version})[/dim]")
                continue
            out.print(
                f"  {plugin_name} ({version_spec}): no registry source — skipping. "
                "Use local path install."
            )

    if freeze_path:
        from opentools_plugin_core.models import Lockfile, LockfileEntry
        from opentools_plugin_core import __version__

        refreshed = {p.name: p for p in idx.list_all()}
        entries = {}
        for p in refreshed.values():
            entries[p.name] = LockfileEntry(
                version=p.version, registry=p.registry, repo=p.repo,
                ref=f"v{p.version}", sha256="",
            )
        lf_out = Lockfile(
            generated_at=datetime.now(timezone.utc).isoformat(),
            opentools_version=__version__,
            plugins=entries,
        )
        from ruamel.yaml import YAML
        import io
        yaml3 = YAML()
        yaml3.default_flow_style = False
        with open(freeze_path, "w") as f:
            yaml3.dump(lf_out.model_dump(mode="json"), f)
        out.print(f"[green]Lockfile written:[/green] {freeze_path}")

    out.print("[green]Sync complete.[/green]")


@plugin_app.command("export")
def plugin_export(
    name: str = typer.Argument(..., help="Plugin name"),
    output: Optional[str] = typer.Option(None, "--output", "-o"),
):
    """Export a plugin to a .otp archive."""
    from opentools_plugin_core.index import PluginIndex
    from opentools_plugin_core.installer import read_active_version

    home = _opentools_home()
    idx = PluginIndex(home / "plugins.db")
    plugin = idx.get(name)
    if plugin is None:
        _error(f"Plugin '{name}' is not installed", hint="opentools plugin list")
        return

    plugin_dir = home / "plugins" / name
    active = read_active_version(plugin_dir)
    if not active:
        _error(f"No active version for plugin '{name}'")
        return

    version_dir = plugin_dir / active

    if output:
        archive_path = Path(output)
    else:
        exports_dir = home / "exports"
        exports_dir.mkdir(exist_ok=True)
        archive_path = exports_dir / f"{name}-{active}.otp"

    with tarfile.open(str(archive_path), "w:gz") as tar:
        tar.add(str(version_dir), arcname=f"{name}-{active}")

    out.print(f"[green]Exported:[/green] {name} v{active} -> {archive_path}")


@plugin_app.command("import")
def plugin_import_cmd(
    archive: str = typer.Argument(..., help="Path to .otp archive"),
    yes: bool = typer.Option(False, "--yes", "-y"),
):
    """Install a plugin from a .otp archive."""
    archive_path = Path(archive)
    if not archive_path.exists():
        _error(f"Archive not found: {archive}")
        return

    home = _opentools_home()

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        try:
            with tarfile.open(str(archive_path), "r:gz") as tar:
                tar.extractall(str(tmp))
        except tarfile.TarError as e:
            _error(f"Failed to extract archive: {e}")
            return

        subdirs = [d for d in tmp.iterdir() if d.is_dir()]
        if not subdirs:
            _error("Archive contains no directories")
            return
        src = subdirs[0]

        # manifest.yaml is the name used inside .otp archives (from promote_plugin)
        manifest_yaml = src / "manifest.yaml"
        plugin_yaml = src / "opentools-plugin.yaml"
        if manifest_yaml.exists() and not plugin_yaml.exists():
            shutil.copy2(str(manifest_yaml), str(plugin_yaml))

        if not plugin_yaml.exists():
            _error("No manifest found in archive (expected opentools-plugin.yaml or manifest.yaml)")
            return

        _do_install(src, home, yes)

    out.print(f"[green]Imported:[/green] {archive_path.name}")


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
