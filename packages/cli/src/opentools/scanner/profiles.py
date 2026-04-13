# packages/cli/src/opentools/scanner/profiles.py
"""Scan profile models, YAML loading, and built-in profile registry.

Profiles define which tools run against which target types, organized
into phases with dependency and concurrency control.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field

from opentools.scanner.models import (
    ExecutionTier,
    RetryPolicy,
    ScanConfig,
    TargetType,
    TaskIsolation,
    TaskType,
)


# ---------------------------------------------------------------------------
# Profile data models
# ---------------------------------------------------------------------------


class ReactiveEdgeTemplate(BaseModel):
    """Template for reactive edges defined at the profile level.

    At plan time, the ScanPlanner instantiates these into concrete
    ``ReactiveEdge`` instances attached to specific task IDs.
    """

    evaluator: str
    trigger_tool: str  # tool name or "*" for any
    condition: Optional[str] = None
    max_spawns: int = 20
    max_spawns_per_trigger: int = 5
    cooldown_seconds: float = 0
    budget_group: Optional[str] = None
    min_upstream_confidence: float = 0.5


class ProfileTool(BaseModel):
    """A tool entry within a profile phase."""

    tool: str
    task_type: TaskType
    command_template: Optional[str] = None
    mcp_server: Optional[str] = None
    mcp_tool: Optional[str] = None
    mcp_args_template: Optional[dict] = None
    parser: Optional[str] = None
    priority: int = 50
    tier: ExecutionTier = ExecutionTier.NORMAL
    resource_group: Optional[str] = None
    retry_policy: Optional[RetryPolicy] = None
    cache_key_template: Optional[str] = None
    optional: bool = False
    condition: Optional[str] = None
    isolation: TaskIsolation = TaskIsolation.NONE
    preferred_output_format: Optional[str] = None
    reactive_edges: Optional[list[ReactiveEdgeTemplate]] = None


class ProfilePhase(BaseModel):
    """A phase within a scan profile — a group of tools that can run together."""

    name: str
    tools: list[ProfileTool]
    parallel: bool = True


class ScanProfile(BaseModel):
    """A scan profile defines what tools to run for a given target type."""

    id: str
    name: str
    description: str
    target_types: list[TargetType]
    extends: Optional[str] = None
    add_tools: list[ProfileTool] = Field(default_factory=list)
    remove_tools: list[str] = Field(default_factory=list)
    phases: list[ProfilePhase] = Field(default_factory=list)
    reactive_edges: list[ReactiveEdgeTemplate] = Field(default_factory=list)
    default_config: Optional[ScanConfig] = None
    override_config: Optional[ScanConfig] = None


# ---------------------------------------------------------------------------
# Default profile mapping
# ---------------------------------------------------------------------------

DEFAULT_PROFILES: dict[TargetType, str] = {
    TargetType.SOURCE_CODE: "source-full",
    TargetType.URL: "web-full",
    TargetType.BINARY: "binary-triage",
    TargetType.DOCKER_IMAGE: "container-audit",
    TargetType.APK: "apk-analysis",
    TargetType.NETWORK: "network-recon",
}


# ---------------------------------------------------------------------------
# Profile loading
# ---------------------------------------------------------------------------

_PROFILES_DIR = Path(__file__).parent / "profiles"

_profile_cache: dict[str, ScanProfile] = {}


def list_builtin_profiles() -> list[str]:
    """Return names of all built-in profiles (without .yaml extension)."""
    if not _PROFILES_DIR.exists():
        return []
    return sorted(
        p.stem.replace("_", "-")
        for p in _PROFILES_DIR.glob("*.yaml")
    )


def load_builtin_profile(name: str) -> ScanProfile:
    """Load a built-in profile by name, caching the parsed result.

    Args:
        name: Profile name (e.g. "source-quick"). Hyphens are converted
            to underscores for filename lookup.

    Returns:
        Parsed ScanProfile (cached after first load).

    Raises:
        FileNotFoundError: If the profile YAML does not exist.
    """
    cached = _profile_cache.get(name)
    if cached is not None:
        return cached

    filename = name.replace("-", "_") + ".yaml"
    filepath = _PROFILES_DIR / filename
    if not filepath.exists():
        raise FileNotFoundError(
            f"Built-in profile '{name}' not found at {filepath}"
        )
    profile = load_profile_yaml(filepath.read_text(encoding="utf-8"))
    _profile_cache[name] = profile
    return profile


def load_profile_yaml(yaml_content: str) -> ScanProfile:
    """Parse a YAML string into a ScanProfile.

    Args:
        yaml_content: Raw YAML string.

    Returns:
        Validated ScanProfile.
    """
    data = yaml.safe_load(yaml_content)
    return ScanProfile.model_validate(data)
