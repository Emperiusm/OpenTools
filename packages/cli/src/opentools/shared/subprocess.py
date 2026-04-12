"""Async subprocess execution with streaming output, timeout, and cancellation."""

from __future__ import annotations

import asyncio
import time
from typing import Callable

from pydantic import BaseModel


class SubprocessResult(BaseModel):
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    timed_out: bool = False
    cancelled: bool = False


async def run_streaming(
    args: list[str],
    on_output: Callable[[bytes], None],
    timeout: int = 300,
    cancellation: object | None = None,  # CancellationToken
) -> SubprocessResult:
    """Spawn an async subprocess and stream its stdout in 4096-byte chunks.

    Args:
        args: Command and arguments to execute.
        on_output: Callback invoked with each stdout chunk as raw bytes.
        timeout: Maximum wall-clock seconds to allow; kills process on expiry.
        cancellation: Optional CancellationToken; kills process when signalled.

    Returns:
        SubprocessResult with exit_code, stdout, stderr, duration_ms, and
        timed_out / cancelled flags.
    """
    start_ns = time.monotonic_ns()

    # --- spawn ---------------------------------------------------------------
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        elapsed_ms = (time.monotonic_ns() - start_ns) // 1_000_000
        return SubprocessResult(
            exit_code=-1,
            stderr=str(exc),
            duration_ms=elapsed_ms,
        )

    # --- reader coroutines ---------------------------------------------------

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []

    async def _read_stdout() -> None:
        assert proc.stdout is not None
        while True:
            chunk = await proc.stdout.read(4096)
            if not chunk:
                break
            stdout_chunks.append(chunk)
            on_output(chunk)

    async def _read_stderr() -> None:
        assert proc.stderr is not None
        data = await proc.stderr.read()
        if data:
            stderr_chunks.append(data)

    # --- build task set ------------------------------------------------------

    stdout_task = asyncio.ensure_future(_read_stdout())
    stderr_task = asyncio.ensure_future(_read_stderr())

    pending: set[asyncio.Task] = {stdout_task, stderr_task}

    cancel_task: asyncio.Task | None = None
    if cancellation is not None:
        cancel_task = asyncio.ensure_future(cancellation.wait_for_cancellation())
        pending.add(cancel_task)

    # --- wait -----------------------------------------------------------------

    timed_out = False
    cancelled = False

    try:
        done, still_pending = await asyncio.wait(pending, timeout=timeout)

        if cancel_task is not None and cancel_task in done:
            # Cancellation was signalled first.
            cancelled = True
        elif stdout_task not in done or stderr_task not in done:
            # Timeout expired before both readers finished.
            timed_out = True

    finally:
        # Kill the process regardless of the outcome path.
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()

        # Cancel every remaining asyncio task to avoid resource leaks.
        for task in (stdout_task, stderr_task, cancel_task):
            if task is not None and not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

    elapsed_ms = (time.monotonic_ns() - start_ns) // 1_000_000

    stdout_text = b"".join(stdout_chunks).decode(errors="replace")
    stderr_text = b"".join(stderr_chunks).decode(errors="replace")

    return SubprocessResult(
        exit_code=proc.returncode,
        stdout=stdout_text,
        stderr=stderr_text,
        duration_ms=elapsed_ms,
        timed_out=timed_out,
        cancelled=cancelled,
    )
