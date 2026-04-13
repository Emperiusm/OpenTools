# packages/cli/src/opentools/scanner/reactive.py
"""Builtin reactive edge evaluators.

Each evaluator is a callable that takes (task, output, edge) and returns
a list of new ScanTask objects to inject into the DAG.

Evaluators codify common security workflows:
- Open ports → vulnerability scanning
- Framework detection → framework-specific rules
- Packing detected → unpacking + re-analysis
- High severity finding → targeted deep analysis
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Callable

from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.models import (
    ExecutionTier,
    ReactiveEdge,
    ScanTask,
    TaskType,
)


# Type alias for edge evaluator callable
EdgeEvaluator = Callable[[ScanTask, TaskOutput, ReactiveEdge], list[ScanTask]]


def _make_spawned_task(
    scan_id: str,
    spawned_by: str,
    tool: str,
    name: str,
    task_type: TaskType,
    command: str | None = None,
    mcp_server: str | None = None,
    mcp_tool: str | None = None,
    mcp_args: dict | None = None,
    priority: int = 50,
    tier: ExecutionTier = ExecutionTier.NORMAL,
    depends_on: list[str] | None = None,
    spawned_reason: str | None = None,
) -> ScanTask:
    """Helper to create a spawned task with proper provenance."""
    return ScanTask(
        id=f"spawned-{uuid.uuid4().hex[:12]}",
        scan_id=scan_id,
        name=name,
        tool=tool,
        task_type=task_type,
        command=command,
        mcp_server=mcp_server,
        mcp_tool=mcp_tool,
        mcp_args=mcp_args,
        priority=priority,
        tier=tier,
        depends_on=depends_on or [spawned_by],
        spawned_by=spawned_by,
        spawned_reason=spawned_reason,
    )


# ---------------------------------------------------------------------------
# Builtin evaluators
# ---------------------------------------------------------------------------


class OpenPortsToVulnScan:
    """Spawn vulnerability scans for open ports discovered by nmap/masscan.

    - HTTP ports (80, 443, 8080, 8443, etc.) → nuclei + nikto
    - Database ports (3306, 5432, 1433, etc.) → noted but no automatic sqlmap
    """

    # Ports that indicate HTTP services
    _HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9443}
    _HTTP_SERVICES = {"http", "https", "http-proxy", "http-alt"}

    def __call__(
        self, task: ScanTask, output: TaskOutput, edge: ReactiveEdge
    ) -> list[ScanTask]:
        if output.exit_code != 0:
            return []

        open_ports = self._parse_open_ports(output.stdout)
        if not open_ports:
            return []

        new_tasks: list[ScanTask] = []

        # Find HTTP services
        http_targets: list[str] = []
        host = self._extract_host(output.stdout)
        for port, service in open_ports:
            if port in self._HTTP_PORTS or service in self._HTTP_SERVICES:
                scheme = "https" if port in {443, 8443, 9443} or "ssl" in service or "https" in service else "http"
                if host:
                    http_targets.append(f"{scheme}://{host}:{port}")
                else:
                    # No host extractable; use a placeholder so tasks are still spawned
                    http_targets.append(f"{scheme}://{{target}}:{port}")

        # Spawn nuclei for HTTP targets
        for target_url in http_targets:
            safe_name = target_url.split("://", 1)[1].replace(":", "-").replace("{", "").replace("}", "")
            new_tasks.append(
                _make_spawned_task(
                    scan_id=task.scan_id,
                    spawned_by=task.id,
                    tool="nuclei",
                    name=f"nuclei-{safe_name}",
                    task_type=TaskType.SHELL,
                    command=f"nuclei -u {target_url} -json",
                    priority=35,
                    tier=ExecutionTier.NORMAL,
                    spawned_reason=f"HTTP service discovered on port(s) by {task.tool}",
                )
            )

        # Spawn nikto for first HTTP target (to avoid excessive scanning)
        if http_targets:
            new_tasks.append(
                _make_spawned_task(
                    scan_id=task.scan_id,
                    spawned_by=task.id,
                    tool="nikto",
                    name=f"nikto-reactive",
                    task_type=TaskType.SHELL,
                    command=f"nikto -h {http_targets[0]} -Format json",
                    priority=45,
                    tier=ExecutionTier.NORMAL,
                    spawned_reason=f"HTTP service discovered by {task.tool}",
                )
            )

        return new_tasks

    def _parse_open_ports(self, stdout: str) -> list[tuple[int, str]]:
        """Parse nmap/masscan output for open ports."""
        ports: list[tuple[int, str]] = []
        # nmap format: "80/tcp   open  http"
        for match in re.finditer(
            r"(\d+)/(?:tcp|udp)\s+open\s+(\S+)", stdout
        ):
            port = int(match.group(1))
            service = match.group(2)
            ports.append((port, service))
        return ports

    def _extract_host(self, stdout: str) -> str | None:
        """Extract scanned host from nmap output."""
        # "Nmap scan report for hostname (1.2.3.4)"
        match = re.search(r"Nmap scan report for [\w\.\-]+ \(([\d\.]+)\)", stdout)
        if match:
            return match.group(1)
        # "Nmap scan report for 1.2.3.4"
        match = re.search(r"Nmap scan report for ([\d\.]+)", stdout)
        if match:
            return match.group(1)
        return None


class WebFrameworkToRuleset:
    """Add framework-specific scanning when whatweb detects a framework.

    Detects: WordPress, Django, Flask, React, Angular, Laravel, Rails,
    Spring Boot, Express, Next.js.
    """

    _FRAMEWORK_TEMPLATES: dict[str, dict[str, Any]] = {
        "WordPress": {
            "tool": "nuclei",
            "command": "nuclei -u {target} -t wordpress/ -json",
            "name": "nuclei-wordpress",
        },
        "Django": {
            "tool": "semgrep",
            "command": "semgrep --config p/django --json {target}",
            "name": "semgrep-django",
        },
        "Laravel": {
            "tool": "nuclei",
            "command": "nuclei -u {target} -t laravel/ -json",
            "name": "nuclei-laravel",
        },
        "Ruby on Rails": {
            "tool": "nuclei",
            "command": "nuclei -u {target} -t rails/ -json",
            "name": "nuclei-rails",
        },
    }

    def __call__(
        self, task: ScanTask, output: TaskOutput, edge: ReactiveEdge
    ) -> list[ScanTask]:
        if output.exit_code != 0:
            return []

        frameworks = self._detect_frameworks(output.stdout)
        if not frameworks:
            return []

        new_tasks: list[ScanTask] = []
        for framework in frameworks:
            template = self._FRAMEWORK_TEMPLATES.get(framework)
            if template is None:
                continue
            new_tasks.append(
                _make_spawned_task(
                    scan_id=task.scan_id,
                    spawned_by=task.id,
                    tool=template["tool"],
                    name=template["name"],
                    task_type=TaskType.SHELL,
                    command=template["command"],
                    priority=35,
                    spawned_reason=f"{framework} detected by {task.tool}",
                )
            )

        return new_tasks

    def _detect_frameworks(self, stdout: str) -> list[str]:
        """Parse whatweb JSON output for frameworks."""
        frameworks: list[str] = []
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                for entry in data:
                    plugins = entry.get("plugins", {})
                    for framework_name in self._FRAMEWORK_TEMPLATES:
                        if framework_name in plugins:
                            frameworks.append(framework_name)
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass
        return frameworks


class PackingDetectedToUnpack:
    """Spawn unpacking when Arkana detects a packed binary.

    Supports UPX, Themida, and generic unpacking approaches.
    """

    def __call__(
        self, task: ScanTask, output: TaskOutput, edge: ReactiveEdge
    ) -> list[ScanTask]:
        if output.exit_code != 0:
            return []

        packed, packer = self._check_packing(output.stdout)
        if not packed:
            return []

        new_tasks: list[ScanTask] = []

        if packer and packer.lower() == "upx":
            new_tasks.append(
                _make_spawned_task(
                    scan_id=task.scan_id,
                    spawned_by=task.id,
                    tool="arkana-upx-unpack",
                    name="arkana-upx-unpack",
                    task_type=TaskType.MCP_CALL,
                    mcp_server="arkana",
                    mcp_tool="auto_unpack_pe",
                    mcp_args={"file_path": "{target}"},
                    priority=15,
                    tier=ExecutionTier.NORMAL,
                    spawned_reason=f"UPX packing detected by {task.tool}",
                )
            )
        else:
            new_tasks.append(
                _make_spawned_task(
                    scan_id=task.scan_id,
                    spawned_by=task.id,
                    tool="arkana-generic-unpack",
                    name="arkana-generic-unpack",
                    task_type=TaskType.MCP_CALL,
                    mcp_server="arkana",
                    mcp_tool="try_all_unpackers",
                    mcp_args={"file_path": "{target}"},
                    priority=15,
                    tier=ExecutionTier.HEAVY,
                    spawned_reason=f"Packing detected ({packer or 'unknown'}) by {task.tool}",
                )
            )

        return new_tasks

    def _check_packing(self, stdout: str) -> tuple[bool, str | None]:
        """Parse Arkana packing detection output."""
        try:
            data = json.loads(stdout)
            packed = data.get("packed", False)
            packer = data.get("packer")
            return packed, packer
        except (json.JSONDecodeError, TypeError):
            return False, None


class HighSeverityToDeepDive:
    """Spawn targeted deep analysis when critical/high findings are discovered.

    Looks for high-severity markers in common tool output formats:
    - semgrep: results[].extra.severity == "ERROR"
    - nuclei: results with severity "critical" or "high"
    - General: any output containing "CRITICAL" or "HIGH" severity markers
    """

    _HIGH_SEVERITY_PATTERNS = re.compile(
        r'"severity"\s*:\s*"(critical|high|error)"', re.IGNORECASE
    )

    def __call__(
        self, task: ScanTask, output: TaskOutput, edge: ReactiveEdge
    ) -> list[ScanTask]:
        if output.exit_code != 0:
            return []

        if not self._has_high_severity(output.stdout):
            return []

        new_tasks: list[ScanTask] = []

        # Spawn a deeper analysis with the same tool using more aggressive configs
        if task.tool == "semgrep":
            new_tasks.append(
                _make_spawned_task(
                    scan_id=task.scan_id,
                    spawned_by=task.id,
                    tool="semgrep-deep",
                    name="semgrep-deep-dive",
                    task_type=TaskType.SHELL,
                    command="semgrep --config p/security-audit --config p/owasp-top-ten --json {target}",
                    priority=25,
                    tier=ExecutionTier.HEAVY,
                    spawned_reason=f"High severity finding discovered by {task.tool}",
                )
            )
        elif task.tool == "nuclei":
            new_tasks.append(
                _make_spawned_task(
                    scan_id=task.scan_id,
                    spawned_by=task.id,
                    tool="nuclei-deep",
                    name="nuclei-deep-dive",
                    task_type=TaskType.SHELL,
                    command="nuclei -u {target} -severity critical,high -t cves/ -json",
                    priority=25,
                    tier=ExecutionTier.HEAVY,
                    spawned_reason=f"High severity finding discovered by {task.tool}",
                )
            )

        return new_tasks

    def _has_high_severity(self, stdout: str) -> bool:
        """Check if output contains high-severity indicators."""
        return bool(self._HIGH_SEVERITY_PATTERNS.search(stdout))


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def get_builtin_evaluators() -> dict[str, EdgeEvaluator]:
    """Return a mapping of evaluator names to callable evaluators."""
    return {
        "builtin:open_ports_to_vuln_scan": OpenPortsToVulnScan(),
        "builtin:web_framework_to_ruleset": WebFrameworkToRuleset(),
        "builtin:packing_detected_to_unpack": PackingDetectedToUnpack(),
        "builtin:high_severity_to_deep_dive": HighSeverityToDeepDive(),
    }
