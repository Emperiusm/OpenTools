"""Transactional install pipeline: stage, promote, cleanup."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional

from opentools_plugin_core.errors import PluginInstallError


def stage_plugin(source_dir: Path, opentools_home: Path) -> Path:
    from ruamel.yaml import YAML
    yaml = YAML()
    manifest_path = source_dir / "opentools-plugin.yaml"
    if not manifest_path.exists():
        raise PluginInstallError(
            "No opentools-plugin.yaml found",
            hint=f"Ensure {source_dir} contains an opentools-plugin.yaml",
        )
    with manifest_path.open("r", encoding="utf-8") as f:
        manifest_data = yaml.load(f)
    name = manifest_data["name"]
    version = manifest_data["version"]
    staging = opentools_home / "staging" / name / version
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    shutil.copy2(manifest_path, staging / "manifest.yaml")
    for subdir in ("skills", "recipes", "containers"):
        src = source_dir / subdir
        if src.is_dir():
            shutil.copytree(src, staging / subdir)
    for extra in ("CHANGELOG.md", "README.md"):
        src = source_dir / extra
        if src.exists():
            shutil.copy2(src, staging / extra)
    return staging


def promote_plugin(staged_dir: Path, opentools_home: Path, name: str, version: str) -> Path:
    final_dir = opentools_home / "plugins" / name / version
    final_dir.parent.mkdir(parents=True, exist_ok=True)
    if final_dir.exists():
        shutil.rmtree(final_dir)
    shutil.move(str(staged_dir), str(final_dir))
    active_file = opentools_home / "plugins" / name / ".active"
    tmp_active = active_file.with_suffix(".tmp")
    tmp_active.write_text(version)
    os.replace(str(tmp_active), str(active_file))
    staging_parent = opentools_home / "staging" / name
    if staging_parent.exists() and not any(staging_parent.iterdir()):
        staging_parent.rmdir()
    return final_dir


def cleanup_staging(staged_dir: Path) -> None:
    if staged_dir.exists():
        shutil.rmtree(staged_dir)
    parent = staged_dir.parent
    if parent.exists() and not any(parent.iterdir()):
        parent.rmdir()


def cleanup_stale_staging(opentools_home: Path) -> int:
    staging = opentools_home / "staging"
    if not staging.exists():
        return 0
    count = 0
    for child in staging.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
            count += 1
    return count


def read_active_version(plugin_dir: Path) -> Optional[str]:
    active = plugin_dir / ".active"
    if not active.exists():
        return None
    return active.read_text(encoding="utf-8").strip()
