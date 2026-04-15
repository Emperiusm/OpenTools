"""Docker container lifecycle management via docker compose."""

import json
import subprocess
import time
from pathlib import Path
from typing import Optional

from opentools.models import ToolkitConfig, ContainerStatus, ContainerResult


class ContainerManager:
    """Manage Docker containers for security tools."""

    def __init__(self, config: ToolkitConfig) -> None:
        self._config = config
        self._hub_path = config.docker_hub_path

    def start(
        self, names: list[str], wait: bool = True, timeout: int = 30,
    ) -> ContainerResult:
        """Start specific containers by name."""
        if not self._hub_path:
            return ContainerResult(success=False, failed=names, errors={"all": "docker_hub_path not configured"})

        result = self._compose_run(["up", "-d"] + names)
        if result.returncode != 0:
            return ContainerResult(
                success=False, failed=names,
                errors={"compose": result.stderr.decode(errors="replace").strip()},
            )

        if wait:
            started, failed = self._wait_for_ready(names, timeout)
            return ContainerResult(success=not failed, started=started, failed=failed)

        return ContainerResult(success=True, started=names)

    def start_profile(
        self, profile: str, wait: bool = True, timeout: int = 30,
    ) -> ContainerResult:
        """Start all containers for a docker compose profile."""
        if not self._hub_path:
            return ContainerResult(success=False, errors={"all": "docker_hub_path not configured"})

        result = self._compose_run(["--profile", profile, "up", "-d"])
        if result.returncode != 0:
            return ContainerResult(
                success=False,
                errors={"compose": result.stderr.decode(errors="replace").strip()},
            )
        return ContainerResult(success=True)

    def stop(self, names: list[str]) -> ContainerResult:
        """Stop specific containers."""
        if not self._hub_path:
            return ContainerResult(success=False, errors={"all": "docker_hub_path not configured"})
        result = self._compose_run(["stop"] + names)
        success = result.returncode == 0
        return ContainerResult(success=success, started=[] if success else names)

    def stop_all(self) -> ContainerResult:
        """Stop all toolkit containers."""
        if not self._hub_path:
            return ContainerResult(success=False, errors={"all": "docker_hub_path not configured"})
        result = self._compose_run(["down"])
        return ContainerResult(success=result.returncode == 0)

    def restart(self, names: list[str]) -> ContainerResult:
        """Restart specific containers."""
        if not self._hub_path:
            return ContainerResult(success=False, errors={"all": "docker_hub_path not configured"})
        result = self._compose_run(["restart"] + names)
        return ContainerResult(success=result.returncode == 0, started=names if result.returncode == 0 else [])

    def status(self) -> list[ContainerStatus]:
        """Get status of all containers via docker compose ps."""
        if not self._hub_path:
            return []
        result = self._compose_run(["ps", "--format", "json"])
        if result.returncode != 0:
            return []

        containers = []
        stdout = result.stdout.decode(errors="replace").strip()
        if not stdout:
            return []

        # docker compose ps --format json outputs one JSON object per line
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                containers.append(ContainerStatus(
                    name=data.get("Name", data.get("Service", "")),
                    state=data.get("State", "unknown"),
                    health=data.get("Health", None),
                    profile=self._get_profiles(data.get("Name", data.get("Service", ""))),
                    exit_code=data.get("ExitCode"),
                ))
            except json.JSONDecodeError:
                continue
        return containers

    def logs(self, name: str, tail: int = 50) -> str:
        """Get recent logs for a container."""
        if not self._hub_path:
            return ""
        result = self._compose_run(["logs", "--tail", str(tail), name])
        return result.stdout.decode(errors="replace")

    def _compose_run(self, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """Run a docker compose command."""
        cmd = ["docker", "compose"] + args
        return subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            cwd=str(self._hub_path) if self._hub_path else None,
        )

    def _wait_for_ready(self, names: list[str], timeout: int) -> tuple[list[str], list[str]]:
        """Poll until containers are running or timeout."""
        deadline = time.monotonic() + timeout
        started: list[str] = []
        pending = set(names)

        while pending and time.monotonic() < deadline:
            statuses = self.status()
            status_map = {s.name: s.state for s in statuses}
            for name in list(pending):
                if status_map.get(name) == "running":
                    started.append(name)
                    pending.discard(name)
            if pending:
                time.sleep(1)

        return started, list(pending)

    def _get_profiles(self, container_name: str) -> list[str]:
        """Look up profiles for a container from config."""
        tool = self._config.containers.get(container_name)
        if tool:
            return tool.profiles
        return []


def get_plugin_container_statuses() -> list[ContainerStatus]:
    """Get status of all plugin containers across installed plugins."""
    from opentools.plugin import _marketplace_plugin_dirs

    statuses: list[ContainerStatus] = []
    for version_dir in _marketplace_plugin_dirs():
        compose_dir = version_dir / "compose"
        if not compose_dir.is_dir():
            continue

        compose_file = compose_dir / "docker-compose.yaml"
        if not compose_file.exists():
            compose_file = compose_dir / "docker-compose.yml"
        if not compose_file.exists():
            continue

        try:
            result = subprocess.run(
                ["docker", "compose", "-f", str(compose_file), "ps", "--format", "json"],
                capture_output=True, timeout=10,
                cwd=str(compose_dir),
            )
            if result.returncode != 0:
                continue

            stdout = result.stdout.decode(errors="replace").strip()
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    statuses.append(ContainerStatus(
                        name=data.get("Name", data.get("Service", "")),
                        state=data.get("State", "unknown"),
                        health=data.get("Health"),
                        profile=["plugin"],
                    ))
                except json.JSONDecodeError:
                    continue
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    return statuses
