"""Tests for ShellExecutor."""

import asyncio

import pytest

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.base import TaskExecutor, TaskOutput
from opentools.scanner.executor.shell import ShellExecutor
from opentools.scanner.models import ScanTask, TaskType


def _make_task(command: str, task_id: str = "t1") -> ScanTask:
    return ScanTask(
        id=task_id,
        scan_id="scan1",
        name="test-task",
        tool="test",
        task_type=TaskType.SHELL,
        command=command,
    )


class TestShellExecutor:
    @pytest.mark.asyncio
    async def test_implements_protocol(self):
        executor = ShellExecutor()
        assert isinstance(executor, TaskExecutor)

    @pytest.mark.asyncio
    async def test_echo_command(self):
        executor = ShellExecutor()
        task = _make_task("echo hello")
        chunks: list[bytes] = []
        cancel = CancellationToken()

        result = await executor.execute(task, chunks.append, cancel)

        assert result.exit_code == 0
        assert "hello" in result.stdout
        assert result.duration_ms >= 0
        assert result.cached is False
        assert len(chunks) > 0

    @pytest.mark.asyncio
    async def test_failing_command(self):
        executor = ShellExecutor()
        task = _make_task("python -c \"import sys; sys.exit(42)\"")
        cancel = CancellationToken()

        result = await executor.execute(task, lambda _: None, cancel)

        assert result.exit_code == 42

    @pytest.mark.asyncio
    async def test_stderr_captured(self):
        executor = ShellExecutor()
        task = _make_task("python -c \"import sys; sys.stderr.write('err\\n')\"")
        cancel = CancellationToken()

        result = await executor.execute(task, lambda _: None, cancel)

        assert "err" in result.stderr

    @pytest.mark.asyncio
    async def test_cancellation(self):
        executor = ShellExecutor()
        task = _make_task("python -c \"import time; time.sleep(30)\"")
        cancel = CancellationToken()

        async def cancel_soon():
            await asyncio.sleep(0.2)
            await cancel.cancel("test cancel")

        asyncio.ensure_future(cancel_soon())
        result = await executor.execute(task, lambda _: None, cancel)

        assert result.exit_code is not None  # process was killed
        assert result.duration_ms < 5000  # didn't wait full 30s

    @pytest.mark.asyncio
    async def test_timeout(self):
        executor = ShellExecutor(default_timeout=1)
        task = _make_task("python -c \"import time; time.sleep(30)\"")
        cancel = CancellationToken()

        result = await executor.execute(task, lambda _: None, cancel)

        assert result.duration_ms < 5000

    @pytest.mark.asyncio
    async def test_missing_command_binary(self):
        executor = ShellExecutor()
        task = _make_task("nonexistent_binary_xyz123")
        cancel = CancellationToken()

        result = await executor.execute(task, lambda _: None, cancel)

        assert result.exit_code == -1

    @pytest.mark.asyncio
    async def test_streaming_output_chunks(self):
        executor = ShellExecutor()
        cmd = "python -c \"import sys; sys.stdout.write('line1\\n'); sys.stdout.flush(); sys.stdout.write('line2\\n'); sys.stdout.flush()\""
        task = _make_task(cmd)
        chunks: list[bytes] = []
        cancel = CancellationToken()

        result = await executor.execute(task, chunks.append, cancel)

        assert result.exit_code == 0
        combined = b"".join(chunks).decode()
        assert "line1" in combined
        assert "line2" in combined

    @pytest.mark.asyncio
    async def test_no_command_raises(self):
        executor = ShellExecutor()
        task = _make_task("echo hi")
        task = task.model_copy(update={"command": None})
        cancel = CancellationToken()

        with pytest.raises(ValueError, match="command"):
            await executor.execute(task, lambda _: None, cancel)
