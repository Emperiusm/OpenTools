"""Plugin update, rollback, and version management."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from opentools_plugin_core.errors import PluginError


def get_available_versions(plugin_dir: Path) -> list[str]:
    versions = []
    for child in plugin_dir.iterdir():
        if child.is_dir() and child.name != ".active" and not child.name.startswith("."):
            versions.append(child.name)
    versions.sort()
    return versions


def get_active_version(plugin_dir: Path) -> str | None:
    active = plugin_dir / ".active"
    if not active.exists():
        return None
    return active.read_text(encoding="utf-8").strip()


def rollback(plugin_dir: Path, target_version: str) -> None:
    target_dir = plugin_dir / target_version
    if not target_dir.is_dir():
        raise PluginError(
            f"Version {target_version} not installed",
            hint=f"Available: {', '.join(get_available_versions(plugin_dir))}",
        )
    active_file = plugin_dir / ".active"
    tmp_active = active_file.with_suffix(".tmp")
    tmp_active.write_text(target_version)
    os.replace(str(tmp_active), str(active_file))


def prune_old_versions(plugin_dir: Path, keep: int = 1) -> list[str]:
    active = get_active_version(plugin_dir)
    versions = get_available_versions(plugin_dir)
    if active and active in versions:
        versions.remove(active)
    to_remove = versions[:-keep] if keep > 0 and len(versions) > keep else []
    removed: list[str] = []
    for ver in to_remove:
        ver_dir = plugin_dir / ver
        if ver_dir.is_dir():
            shutil.rmtree(ver_dir)
            removed.append(ver)
    return removed
