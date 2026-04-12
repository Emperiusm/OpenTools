"""ShellExecutor — subprocess-based task execution with streaming."""

from __future__ import annotations

import shlex
from typing import Callable

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.models import ScanTask
from opentools.shared.subprocess import run_streaming


class ShellExecutor:
    """Execute shell commands via async subprocess with streaming output."""

    def __init__(self, default_timeout: int = 300) -> None:
        self._default_timeout = default_timeout

    async def execute(
        self,
        task: ScanTask,
        on_output: Callable[[bytes], None],
        cancellation: CancellationToken,
    ) -> TaskOutput:
        if task.command is None:
            raise ValueError(f"Task {task.id} has no command")

        args = shlex.split(task.command)

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
