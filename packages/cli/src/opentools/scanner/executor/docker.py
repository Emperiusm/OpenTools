"""DockerExecExecutor — execute commands inside a Docker container."""

from __future__ import annotations

import shlex
from typing import Callable

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.models import ScanTask
from opentools.shared.subprocess import run_streaming


class DockerExecExecutor:
    """Execute commands inside a running Docker container via `docker exec`."""

    def __init__(
        self,
        container_id: str,
        default_timeout: int = 300,
    ) -> None:
        self._container_id = container_id
        self._default_timeout = default_timeout

    async def execute(
        self,
        task: ScanTask,
        on_output: Callable[[bytes], None],
        cancellation: CancellationToken,
    ) -> TaskOutput:
        if task.command is None:
            raise ValueError(f"Task {task.id} has no command")

        cmd_parts = shlex.split(task.command)
        args = ["docker", "exec", self._container_id] + cmd_parts

        result = await run_streaming(
            args=args,
            on_output=on_output,
            timeout=self._default_timeout,
            cancellation=cancellation,
        )

        return TaskOutput(
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_ms=result.duration_ms,
        )
