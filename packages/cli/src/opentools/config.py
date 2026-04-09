"""Configuration loader for the OpenTools CLI toolkit.

Reads tools.yaml, mcp-servers.yaml, and profiles.yaml from the plugin's
config/ directory, resolves ${VAR:-default} environment variable patterns,
and returns a populated ToolkitConfig.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from opentools.models import ToolConfig, ToolkitConfig

# Regex matches ${VAR:-default} or ${VAR}
_ENV_VAR_RE = re.compile(r"\$\{([^}:]+)(?::-((?:[^}]|\}(?!\}))*))?\}")


def resolve_env_vars(value: str) -> str:
    """Replace ``${VAR:-default}`` patterns with environment values.

    Rules:
    - If *VAR* is set in the environment → use the env value.
    - If *VAR* is not set but a default is provided → use the default.
    - If *VAR* is not set and no default exists → leave the token as-is.
    """

    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        default = match.group(2)  # None when no ``:-`` clause is present
        env_val = os.environ.get(var_name)
        if env_val is not None:
            return env_val
        if default is not None:
            return default
        # No env value and no default — keep the original token unchanged.
        return match.group(0)

    return _ENV_VAR_RE.sub(_replace, value)


def _resolve_dict(d: dict) -> dict:
    """Recursively resolve env var patterns in all string values of *d*."""
    result: dict = {}
    for key, value in d.items():
        if isinstance(value, str):
            result[key] = resolve_env_vars(value)
        elif isinstance(value, dict):
            result[key] = _resolve_dict(value)
        elif isinstance(value, list):
            result[key] = [
                resolve_env_vars(item) if isinstance(item, str) else item
                for item in value
            ]
        else:
            result[key] = value
    return result


class ConfigLoader:
    """Loads and parses the three YAML configuration files.

    Parameters
    ----------
    plugin_dir:
        Root directory of the plugin package.  The YAML files are expected
        under ``<plugin_dir>/config/``.
    """

    def __init__(self, plugin_dir: Path) -> None:
        self._plugin_dir = Path(plugin_dir)
        self._yaml = YAML()
        self._yaml.preserve_quotes = True

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self) -> ToolkitConfig:
        """Load all three YAML files and return a :class:`ToolkitConfig`."""
        tools_raw = self._load_yaml("tools.yaml")
        mcp_raw = self._load_yaml("mcp-servers.yaml")
        _profiles_raw = self._load_yaml("profiles.yaml")  # loaded for validation

        # Resolve env vars throughout each document
        tools_data: dict = _resolve_dict(dict(tools_raw))
        mcp_data: dict = _resolve_dict(dict(mcp_raw))

        # ── CLI tools ────────────────────────────────────────────────────
        cli_tools: dict[str, ToolConfig] = {}
        for name, spec in (tools_data.get("cli_tools") or {}).items():
            if not isinstance(spec, dict):
                continue
            cli_tools[name] = ToolConfig(
                name=name,
                type="cli_tool",
                path_or_command=spec.get("path", ""),
                profiles=_as_list(spec.get("used_by", [])),
                env_required=_as_list(spec.get("env_required", [])),
            )

        # ── Docker containers ─────────────────────────────────────────────
        containers: dict[str, Any] = {}
        for name, spec in (tools_data.get("containers") or {}).items():
            if not isinstance(spec, dict):
                continue
            containers[name] = ToolConfig(
                name=name,
                type="docker_container",
                path_or_command=name,
                profiles=_as_list(spec.get("profile", [])),
                env_required=_as_list(spec.get("env_required", [])),
            )

        # ── MCP servers ───────────────────────────────────────────────────
        mcp_servers: dict[str, Any] = {}
        for name, spec in (mcp_data.get("servers") or {}).items():
            if not isinstance(spec, dict):
                continue
            # Prefer explicit command; fall back to URL for HTTP transports.
            path_or_command = spec.get("command") or spec.get("url") or name
            mcp_servers[name] = ToolConfig(
                name=name,
                type="mcp_server",
                path_or_command=path_or_command,
                health_check=spec.get("health_check"),
                env_required=_as_list(spec.get("env_required", [])),
            )

        # ── docker_hub path ───────────────────────────────────────────────
        docker_hub_raw: str | None = tools_data.get("docker_hub")
        docker_hub_path = Path(docker_hub_raw) if docker_hub_raw else None

        # ── api_keys list → dict[str, bool] (is the key set?) ───────────
        api_keys: dict[str, bool] = {
            key: bool(os.environ.get(key))
            for key in (tools_data.get("api_keys") or [])
            if isinstance(key, str)
        }

        return ToolkitConfig(
            mcp_servers=mcp_servers,
            containers=containers,
            cli_tools=cli_tools,
            docker_hub_path=docker_hub_path,
            plugin_dir=self._plugin_dir,
            api_keys=api_keys,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_yaml(self, filename: str) -> dict:
        """Load a single YAML file from the config/ sub-directory."""
        path = self._plugin_dir / "config" / filename
        if not path.exists():
            raise FileNotFoundError(
                f"Required config file not found: {path}"
            )
        with path.open("r", encoding="utf-8") as fh:
            data = self._yaml.load(fh)
        return data or {}


# ---------------------------------------------------------------------------
# Internal utilities
# ---------------------------------------------------------------------------


def _as_list(value: Any) -> list[str]:
    """Normalise a scalar, list, or None into a list of strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]
