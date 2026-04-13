"""Async subprocess execution with streaming output, timeout, and cancellation.

Design notes — pipe safety
--------------------------
Both stdout and stderr are drained concurrently in 4 KiB chunks.  This is
critical: if only one pipe is read, the OS pipe buffer on the *other* pipe
(typically 64 KiB on Linux, 4 KiB on some Windows configs) can fill up,
causing the child process to block on ``write(2)`` and effectively deadlock.

Stderr is capped at ``_MAX_STDERR_BYTES`` (4 MiB) to prevent a misbehaving
tool from consuming unbounded memory with warning spam.  Excess stderr is
silently discarded.

Stdout is accumulated into a ``bytearray`` and streamed through ``on_output``
in chunks.  For very large tool outputs (>100 MB), callers should consider
writing to a temp file via ``on_output`` rather than relying on the returned
``stdout`` string — see ``SubprocessResult.stdout_len`` to detect this.
"""

from __future__ import annotations

import asyncio
import time
from typing import Callable

from pydantic import BaseModel

# Cap stderr accumulation to prevent runaway memory from noisy tools.
_MAX_STDERR_BYTES = 4 * 1024 * 1024  # 4 MiB
_CHUNK_SIZE = 4096


class SubprocessResult(BaseModel):
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    stdout_len: int = 0
    duration_ms: int = 0
    timed_out: bool = False
    cancelled: bool = False


async def run_streaming(
    args: list[str],
    on_output: Callable[[bytes], None],
    timeout: int = 300,
    cancellation: object | None = None,  # CancellationToken
    env: dict[str, str] | None = None,
) -> SubprocessResult:
    """Spawn an async subprocess and stream its stdout in 4 KiB chunks.

    Both stdout and stderr are drained concurrently to prevent OS pipe
    buffer deadlocks.  Stderr is capped at 4 MiB.

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
            env=env,
        )
    except FileNotFoundError as exc:
        elapsed_ms = (time.monotonic_ns() - start_ns) // 1_000_000
        return SubprocessResult(
            exit_code=-1,
            stderr=str(exc),
            duration_ms=elapsed_ms,
        )

    # --- reader coroutines ---------------------------------------------------
    # Both pipes are read in chunked loops to keep the OS buffers drained.
    # This prevents the classic deadlock where one full pipe blocks the child
    # while we're waiting on the other.

    stdout_buf = bytearray()
    stderr_buf = bytearray()

    async def _read_stdout() -> None:
        assert proc.stdout is not None
        while True:
            chunk = await proc.stdout.read(_CHUNK_SIZE)
            if not chunk:
                break
            stdout_buf.extend(chunk)
            on_output(chunk)

    async def _read_stderr() -> None:
        assert proc.stderr is not None
        while True:
            chunk = await proc.stderr.read(_CHUNK_SIZE)
            if not chunk:
                break
            # Cap stderr to prevent unbounded memory growth from noisy tools.
            remaining = _MAX_STDERR_BYTES - len(stderr_buf)
            if remaining > 0:
                stderr_buf.extend(chunk[:remaining])

    # --- build task set ------------------------------------------------------

    stdout_task = asyncio.ensure_future(_read_stdout())
    stderr_task = asyncio.ensure_future(_read_stderr())

    # --- wait -----------------------------------------------------------------

    timed_out = False
    cancelled = False

    # Background watchdog: if cancellation fires, kill the process immediately
    # so that the I/O reader tasks unblock and asyncio.wait can return.
    cancel_task: asyncio.Task | None = None

    async def _cancellation_watchdog() -> None:
        nonlocal cancelled
        assert cancellation is not None
        await cancellation.wait_for_cancellation()
        cancelled = True
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass

    if cancellation is not None:
        cancel_task = asyncio.ensure_future(_cancellation_watchdog())

    try:
        # Only wait for I/O tasks; the watchdog runs independently and kills
        # the process when cancelled, which unblocks the I/O tasks.
        done, _still_pending = await asyncio.wait(
            {stdout_task, stderr_task}, timeout=timeout
        )

        if stdout_task not in done or stderr_task not in done:
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

    stdout_text = stdout_buf.decode(errors="replace")
    stderr_text = stderr_buf.decode(errors="replace")

    return SubprocessResult(
        exit_code=proc.returncode,
        stdout=stdout_text,
        stderr=stderr_text,
        stdout_len=len(stdout_buf),
        duration_ms=elapsed_ms,
        timed_out=timed_out,
        cancelled=cancelled,
    )
