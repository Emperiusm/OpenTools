"""Preflight health checks for tool availability."""

import shutil
import subprocess
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

from opentools.models import (
    ToolConfig, ToolkitConfig, ToolStatus,
    ToolCheckResult, PreflightSummary, PreflightReport,
)

# Skill → required/optional MCP servers and tools (from mcp-servers.yaml skill_dependencies)
SKILL_DEPENDENCIES: dict[str, dict[str, list[str]]] = {
    "pentest": {
        "required": ["codebadger", "semgrep-mcp"],
        "optional": ["nmap-mcp", "cyberchef", "wazuh-mcp", "elasticsearch-mcp", "deobfuscate-mcp"],
    },
    "reverse-engineering": {
        "required": ["ghydramcp"],
        "optional": ["arkana", "codebadger", "cyberchef", "deobfuscate-mcp"],
    },
    "hardware-re": {
        "required": [],
        "optional": ["ghydramcp", "arkana", "codebadger", "cyberchef"],
    },
    "forensics": {
        "required": [],
        "optional": ["wazuh-mcp", "elasticsearch-mcp", "cyberchef", "arkana"],
    },
    "cloud-security": {
        "required": [],
        "optional": ["codebadger", "semgrep-mcp"],
    },
    "mobile": {
        "required": [],
        "optional": ["ghydramcp", "arkana", "codebadger", "deobfuscate-mcp"],
    },
}


class PreflightRunner:
    """Run health checks against configured tools."""

    def __init__(self, config: ToolkitConfig) -> None:
        self._config = config
        self._docker_available: bool | None = None

    def check_all(self) -> PreflightReport:
        """Check all tools across all categories."""
        results: list[ToolCheckResult] = []
        self._check_docker()

        for name, tool in self._config.mcp_servers.items():
            results.append(self._check_tool(name, tool, "mcp_server"))
        for name, tool in self._config.containers.items():
            results.append(self._check_tool(name, tool, "docker_container"))
        for name, tool in self._config.cli_tools.items():
            results.append(self._check_tool(name, tool, "cli_tool"))

        # API keys
        for key_name, is_set in self._config.api_keys.items():
            status = ToolStatus.AVAILABLE if is_set else ToolStatus.NOT_CONFIGURED
            results.append(ToolCheckResult(
                name=key_name, category="api_key", status=status,
                message="Set" if is_set else "Not set",
            ))

        return self._build_report(results)

    def check_skill(self, skill_name: str) -> PreflightReport:
        """Check only tools relevant to a specific skill."""
        deps = SKILL_DEPENDENCIES.get(skill_name)
        if deps is None:
            return self._build_report([], skill=skill_name)

        relevant = set(deps.get("required", [])) | set(deps.get("optional", []))
        results: list[ToolCheckResult] = []
        self._check_docker()

        for name, tool in self._config.mcp_servers.items():
            if name in relevant:
                r = self._check_tool(name, tool, "mcp_server")
                r.required_by = [skill_name]
                results.append(r)

        return self._build_report(results, skill=skill_name)

    def check_tool(self, tool_name: str) -> ToolCheckResult:
        """Check a single tool by name."""
        self._check_docker()
        for registry in (self._config.mcp_servers, self._config.containers, self._config.cli_tools):
            if tool_name in registry:
                tool = registry[tool_name]
                return self._check_tool(tool_name, tool, tool.type)
        return ToolCheckResult(
            name=tool_name, category="unknown",
            status=ToolStatus.MISSING, message=f"Tool '{tool_name}' not found in config",
        )

    def _check_docker(self) -> None:
        """Check if Docker binary and daemon are available."""
        if self._docker_available is not None:
            return
        if not shutil.which("docker"):
            self._docker_available = False
            return
        try:
            result = subprocess.run(
                ["docker", "info"], capture_output=True, timeout=10,
            )
            self._docker_available = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self._docker_available = False

    def _check_tool(self, name: str, tool: ToolConfig, category: str) -> ToolCheckResult:
        """Check a single tool's availability."""
        start = time.monotonic()

        if category == "mcp_server":
            status, message = self._check_mcp_server(tool)
        elif category == "docker_container":
            status, message = self._check_container(name)
        elif category == "cli_tool":
            status, message = self._check_cli_tool(tool)
        else:
            status, message = ToolStatus.ERROR, f"Unknown category: {category}"

        elapsed_ms = int((time.monotonic() - start) * 1000)
        return ToolCheckResult(
            name=name, category=category, status=status,
            message=message, health_check_ms=elapsed_ms,
        )

    def _check_mcp_server(self, tool: ToolConfig) -> tuple[ToolStatus, str]:
        """Check MCP server by transport type."""
        cmd = tool.path_or_command
        health = tool.health_check

        # HTTP health endpoint
        if health and (health.startswith("http://") or health.startswith("https://")):
            try:
                urllib.request.urlopen(health, timeout=3)
                return ToolStatus.RUNNING, "OK"
            except (urllib.error.URLError, OSError):
                return ToolStatus.STOPPED, "Health check failed"

        # Docker-based stdio (check image exists)
        if cmd and "docker" in cmd.lower():
            if not self._docker_available:
                return ToolStatus.STOPPED, "Docker not available"
            # Try to find image name from command
            return ToolStatus.AVAILABLE, "Docker image configured"

        # Local process — check executable exists
        if cmd:
            parts = cmd.split()
            exe = parts[0] if parts else cmd
            if Path(exe).exists() or shutil.which(exe):
                return ToolStatus.AVAILABLE, "Executable found"
            return ToolStatus.MISSING, f"Executable not found: {exe}"

        return ToolStatus.MISSING, "No command configured"

    def _check_container(self, name: str) -> tuple[ToolStatus, str]:
        """Check Docker container status."""
        if not self._docker_available:
            return ToolStatus.STOPPED, "Docker not available"
        # In a real implementation, we'd parse docker compose ps --format json
        # For now, we check if docker is available (container management is in containers.py)
        return ToolStatus.AVAILABLE, "Docker available (use 'opentools containers status' for details)"

    def _check_cli_tool(self, tool: ToolConfig) -> tuple[ToolStatus, str]:
        """Check CLI tool availability."""
        cmd = tool.path_or_command
        if not cmd:
            return ToolStatus.MISSING, "No path configured"

        path = Path(cmd)
        if path.is_absolute() and path.exists():
            return ToolStatus.AVAILABLE, f"Found at {cmd}"

        which_result = shutil.which(cmd)
        if which_result:
            return ToolStatus.AVAILABLE, f"Found on PATH: {which_result}"

        return ToolStatus.MISSING, f"Not found: {cmd}"

    def _build_report(
        self, tools: list[ToolCheckResult], skill: str | None = None,
    ) -> PreflightReport:
        """Build a PreflightReport from check results."""
        available = sum(1 for t in tools if t.status in (ToolStatus.AVAILABLE, ToolStatus.RUNNING))
        missing = sum(1 for t in tools if t.status in (ToolStatus.MISSING, ToolStatus.STOPPED, ToolStatus.NOT_CONFIGURED))
        errors = sum(1 for t in tools if t.status == ToolStatus.ERROR)

        # Compute skill availability
        fully = []
        partially = []
        unavailable = []
        for sname, deps in SKILL_DEPENDENCIES.items():
            required = deps.get("required", [])
            tool_names = {t.name for t in tools}
            required_available = all(
                any(t.name == r and t.status in (ToolStatus.AVAILABLE, ToolStatus.RUNNING) for t in tools)
                for r in required
                if r in tool_names
            )
            if not required:
                required_available = True

            optional_count = sum(
                1 for o in deps.get("optional", [])
                if any(t.name == o and t.status in (ToolStatus.AVAILABLE, ToolStatus.RUNNING) for t in tools)
            )
            total_optional = len([o for o in deps.get("optional", []) if o in tool_names])

            if required_available and optional_count == total_optional and total_optional > 0:
                fully.append(sname)
            elif required_available:
                partially.append(sname)
            else:
                unavailable.append(sname)

        return PreflightReport(
            timestamp=datetime.now(timezone.utc),
            platform=_detect_platform(),
            docker_available=self._docker_available or False,
            skill=skill,
            tools=tools,
            summary=PreflightSummary(
                total=len(tools),
                available=available,
                missing=missing,
                errors=errors,
                skills_fully_available=fully,
                skills_partially_available=partially,
                skills_unavailable=unavailable,
            ),
        )


def _detect_platform() -> str:
    """Detect the current platform."""
    import sys
    return sys.platform
