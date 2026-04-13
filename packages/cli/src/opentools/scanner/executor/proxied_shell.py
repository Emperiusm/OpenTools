"""ProxiedShellExecutor — optionally routes tool traffic through ephemeral proxy."""
from __future__ import annotations
import shlex
from typing import Callable
from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.infra.provider import CloudNodeProvider
from opentools.scanner.infra.proxy import ephemeral_proxy
from opentools.scanner.models import ScanTask, TaskIsolation
from opentools.shared.subprocess import run_streaming

class ProxiedShellExecutor:
    """Shell executor with optional ephemeral proxy routing.
    Tasks with isolation == NETWORK_ISOLATED are routed through proxy.
    All others run as plain subprocesses."""

    def __init__(
        self, provider: CloudNodeProvider | None,
        ssh_key: str = "", ssh_key_path: str = "~/.ssh/id_ed25519",
        default_timeout: int = 300, base_socks_port: int = 10800,
        _skip_tunnel: bool = False,
    ) -> None:
        self._provider = provider
        self._ssh_key = ssh_key
        self._ssh_key_path = ssh_key_path
        self._default_timeout = default_timeout
        self._base_socks_port = base_socks_port
        self._port_counter = 0
        self._skip_tunnel = _skip_tunnel

    def _next_socks_port(self) -> int:
        port = self._base_socks_port + self._port_counter
        self._port_counter += 1
        return port

    async def execute(self, task: ScanTask, on_output: Callable[[bytes], None], cancellation: CancellationToken) -> TaskOutput:
        if task.command is None:
            raise ValueError(f"Task {task.id} has no command")
        needs_proxy = self._provider is not None and task.isolation == TaskIsolation.NETWORK_ISOLATED
        if not needs_proxy:
            return await self._run_direct(task, on_output, cancellation)
        return await self._run_proxied(task, on_output, cancellation)

    async def _run_direct(self, task, on_output, cancellation) -> TaskOutput:
        args = shlex.split(task.command)
        result = await run_streaming(args=args, on_output=on_output, timeout=self._default_timeout, cancellation=cancellation)
        return TaskOutput(exit_code=result.exit_code, stdout=result.stdout, stderr=result.stderr, duration_ms=result.duration_ms)

    async def _run_proxied(self, task, on_output, cancellation) -> TaskOutput:
        socks_port = self._next_socks_port()
        async with ephemeral_proxy(
            provider=self._provider, region="nyc3", ssh_key=self._ssh_key,
            ssh_key_path=self._ssh_key_path, local_socks_port=socks_port,
            scan_id=task.scan_id, _skip_tunnel=self._skip_tunnel,
        ) as proxy:
            args = shlex.split(task.command)
            result = await run_streaming(args=args, on_output=on_output, timeout=self._default_timeout, cancellation=cancellation, env=proxy.env)
        return TaskOutput(exit_code=result.exit_code, stdout=result.stdout, stderr=result.stderr, duration_ms=result.duration_ms)
