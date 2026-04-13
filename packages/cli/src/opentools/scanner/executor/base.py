"""TaskExecutor protocol and TaskOutput model."""

from __future__ import annotations

from typing import Callable, Protocol, runtime_checkable

from pydantic import BaseModel

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.models import ScanTask


class TaskOutput(BaseModel):
    """Result of executing a single scan task."""

    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    cached: bool = False


@runtime_checkable
class TaskExecutor(Protocol):
    """Protocol for task executors (shell, docker, MCP)."""

    async def execute(
        self,
        task: ScanTask,
        on_output: Callable[[bytes], None],
        cancellation: CancellationToken,
    ) -> TaskOutput: ...
