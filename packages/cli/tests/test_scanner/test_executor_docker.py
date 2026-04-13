"""Tests for DockerExecExecutor.

Uses mock subprocess to avoid requiring Docker in CI.
"""

from unittest.mock import AsyncMock, patch

import pytest

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.base import TaskExecutor, TaskOutput
from opentools.scanner.executor.docker import DockerExecExecutor
from opentools.scanner.models import ScanTask, TaskType
from opentools.shared.subprocess import SubprocessResult


def _make_docker_task(
    command: str,
    task_id: str = "t1",
) -> ScanTask:
    return ScanTask(
        id=task_id,
        scan_id="scan1",
        name="docker-task",
        tool="test",
        task_type=TaskType.DOCKER_EXEC,
        command=command,
    )


class TestDockerExecExecutor:
    @pytest.mark.asyncio
    async def test_implements_protocol(self):
        executor = DockerExecExecutor(container_id="ctr1")
        assert isinstance(executor, TaskExecutor)

    @pytest.mark.asyncio
    async def test_successful_exec(self):
        executor = DockerExecExecutor(container_id="ctr1")
        task = _make_docker_task("semgrep --json .")
        cancel = CancellationToken()

        mock_result = SubprocessResult(
            exit_code=0,
            stdout='{"results": []}',
            stderr="",
            duration_ms=200,
        )

        with patch(
            "opentools.scanner.executor.docker.run_streaming",
            new_callable=AsyncMock,
            return_value=mock_result,
        ) as mock_run:
            result = await executor.execute(task, lambda _: None, cancel)

            call_args = mock_run.call_args
            args_list = call_args.kwargs.get("args") or call_args[0][0]
            assert args_list[0] == "docker"
            assert args_list[1] == "exec"
            assert "ctr1" in args_list
            assert "semgrep" in args_list
            assert "--json" in args_list

        assert result.exit_code == 0
        assert result.stdout == '{"results": []}'

    @pytest.mark.asyncio
    async def test_failed_exec(self):
        executor = DockerExecExecutor(container_id="ctr1")
        task = _make_docker_task("failing-tool")
        cancel = CancellationToken()

        mock_result = SubprocessResult(
            exit_code=1, stdout="", stderr="tool not found", duration_ms=50
        )

        with patch(
            "opentools.scanner.executor.docker.run_streaming",
            new_callable=AsyncMock,
            return_value=mock_result,
        ):
            result = await executor.execute(task, lambda _: None, cancel)

        assert result.exit_code == 1
        assert "tool not found" in result.stderr

    @pytest.mark.asyncio
    async def test_no_command_raises(self):
        executor = DockerExecExecutor(container_id="ctr1")
        task = _make_docker_task("echo hi")
        task = task.model_copy(update={"command": None})
        cancel = CancellationToken()

        with pytest.raises(ValueError, match="command"):
            await executor.execute(task, lambda _: None, cancel)

    @pytest.mark.asyncio
    async def test_passes_cancellation(self):
        executor = DockerExecExecutor(container_id="ctr1")
        task = _make_docker_task("long-running")
        cancel = CancellationToken()

        mock_result = SubprocessResult(
            exit_code=-9, stdout="", stderr="", duration_ms=100, cancelled=True
        )

        with patch(
            "opentools.scanner.executor.docker.run_streaming",
            new_callable=AsyncMock,
            return_value=mock_result,
        ) as mock_run:
            await executor.execute(task, lambda _: None, cancel)

            call_kwargs = mock_run.call_args.kwargs
            assert call_kwargs.get("cancellation") is cancel

    @pytest.mark.asyncio
    async def test_streaming_callback_forwarded(self):
        executor = DockerExecExecutor(container_id="ctr1")
        task = _make_docker_task("scan-tool")
        cancel = CancellationToken()
        chunks: list[bytes] = []

        mock_result = SubprocessResult(exit_code=0, stdout="data", duration_ms=10)

        with patch(
            "opentools.scanner.executor.docker.run_streaming",
            new_callable=AsyncMock,
            return_value=mock_result,
        ) as mock_run:
            await executor.execute(task, chunks.append, cancel)

            call_kwargs = mock_run.call_args.kwargs
            assert call_kwargs.get("on_output") is not None
