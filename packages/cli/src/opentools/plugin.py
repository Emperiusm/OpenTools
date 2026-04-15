"""Plugin directory discovery."""

import os
from pathlib import Path


def discover_plugin_dir(cli_package_root: Path | None = None) -> Path:
    """Find the plugin directory containing config/, skills/, etc.

    Resolution order:
    1. OPENTOOLS_PLUGIN_DIR environment variable
    2. ../plugin/ relative to cli_package_root (or this file's grandparent)
    3. Raise FileNotFoundError
    """
    env_path = os.environ.get("OPENTOOLS_PLUGIN_DIR")
    if env_path:
        plugin_dir = Path(env_path)
        if not plugin_dir.is_dir():
            raise FileNotFoundError(
                f"OPENTOOLS_PLUGIN_DIR points to '{plugin_dir}' which does not exist."
            )
        return plugin_dir

    if cli_package_root is None:
        cli_package_root = Path(__file__).resolve().parent.parent.parent.parent

    relative = cli_package_root.parent / "plugin"
    if relative.is_dir():
        return relative

    raise FileNotFoundError(
        "Plugin directory not found. Set OPENTOOLS_PLUGIN_DIR or run from the OpenTools repo."
    )


def _marketplace_plugin_dirs() -> list[Path]:
    """Scan ~/.opentools/plugins/ for active plugin version directories."""
    marketplace = Path.home() / ".opentools" / "plugins"
    if not marketplace.is_dir():
        return []

    dirs: list[Path] = []
    for plugin_dir in marketplace.iterdir():
        if not plugin_dir.is_dir():
            continue
        active_file = plugin_dir / ".active"
        if active_file.exists():
            version = active_file.read_text(encoding="utf-8").strip()
            version_dir = plugin_dir / version
            if version_dir.is_dir():
                dirs.append(version_dir)
    return dirs


def skill_search_paths() -> list[Path]:
    """Return search paths for skills: built-in + marketplace."""
    paths: list[Path] = []

    try:
        plugin_dir = discover_plugin_dir()
        paths.append(plugin_dir / "skills")
    except FileNotFoundError:
        pass

    for version_dir in _marketplace_plugin_dirs():
        skills_dir = version_dir / "skills"
        if skills_dir.is_dir():
            paths.append(skills_dir)

    marketplace = Path.home() / ".opentools" / "plugins"
    if marketplace.is_dir():
        paths.append(marketplace)

    return paths


def recipe_search_paths() -> list[Path]:
    """Return search paths for recipes: built-in + marketplace."""
    paths: list[Path] = []

    try:
        plugin_dir = discover_plugin_dir()
        paths.append(plugin_dir)
    except FileNotFoundError:
        pass

    for version_dir in _marketplace_plugin_dirs():
        recipes_dir = version_dir / "recipes"
        if recipes_dir.is_dir():
            paths.append(recipes_dir)

    marketplace = Path.home() / ".opentools" / "plugins"
    if marketplace.is_dir():
        paths.append(marketplace)

    return paths
