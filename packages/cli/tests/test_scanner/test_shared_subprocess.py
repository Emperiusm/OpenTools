"""Tests for the shared async subprocess module."""

from __future__ import annotations

import sys
import asyncio

import pytest

from opentools.shared.subprocess import run_streaming, SubprocessResult
from opentools.scanner.cancellation import CancellationToken


# ===========================================================================
# Task 8: Shared Subprocess tests
# ===========================================================================


class TestSubprocessResult:
    """Sanity-check the SubprocessResult model defaults."""

    def test_defaults(self):
        result = SubprocessResult()
        assert result.exit_code is None
        assert result.stdout == ""
        assert result.stderr == ""
        assert result.duration_ms == 0
        assert result.timed_out is False
        assert result.cancelled is False


class TestRunStreaming:
    @pytest.mark.asyncio
    async def test_successful_command(self):
        """A simple print command exits 0 and captures stdout."""
        chunks: list[bytes] = []
        result = await run_streaming(
            [sys.executable, "-c", "print('hello')"],
            on_output=chunks.append,
        )
        assert result.exit_code == 0
        assert "hello" in result.stdout
        assert result.timed_out is False
        assert result.cancelled is False
        assert result.duration_ms > 0

    @pytest.mark.asyncio
    async def test_failed_command(self):
        """A command that exits non-zero is captured correctly."""
        result = await run_streaming(
            [sys.executable, "-c", "import sys; sys.exit(1)"],
            on_output=lambda _: None,
        )
        assert result.exit_code == 1
        assert result.timed_out is False
        assert result.cancelled is False

    @pytest.mark.asyncio
    async def test_streaming_output(self):
        """on_output callback receives chunks; reassembled content matches stdout."""
        chunks: list[bytes] = []
        result = await run_streaming(
            [sys.executable, "-c", "print('chunk_test')"],
            on_output=chunks.append,
        )
        reassembled = b"".join(chunks).decode(errors="replace")
        assert "chunk_test" in reassembled
        assert "chunk_test" in result.stdout

    @pytest.mark.asyncio
    async def test_timeout(self):
        """A long-running process is killed and timed_out=True is returned."""
        result = await run_streaming(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            on_output=lambda _: None,
            timeout=1,
        )
        assert result.timed_out is True
        assert result.cancelled is False

    @pytest.mark.asyncio
    async def test_cancellation(self):
        """Cancelling the token kills the process and returns cancelled=True."""
        token = CancellationToken()

        async def _cancel_after_delay() -> None:
            await asyncio.sleep(0.1)
            await token.cancel("test cancel")

        cancel_task = asyncio.create_task(_cancel_after_delay())
        result = await run_streaming(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            on_output=lambda _: None,
            timeout=30,
            cancellation=token,
        )
        await cancel_task  # ensure clean teardown

        assert result.cancelled is True
        assert result.timed_out is False

    @pytest.mark.asyncio
    async def test_stderr_capture(self):
        """Output written to stderr is captured in result.stderr."""
        result = await run_streaming(
            [
                sys.executable,
                "-c",
                "import sys; sys.stderr.write('error_output\\n')",
            ],
            on_output=lambda _: None,
        )
        assert "error_output" in result.stderr
        assert result.exit_code == 0


class TestRunStreamingEnv:
    """Tests for environment variable passing to subprocess."""

    @pytest.mark.asyncio
    async def test_env_vars_passed_to_subprocess(self):
        """Custom env dict is forwarded to the subprocess."""
        result = await run_streaming(
            [sys.executable, "-c", "import os; print(os.environ.get('OT_TEST_PROXY', 'NOT_SET'))"],
            on_output=lambda _: None,
            env={"OT_TEST_PROXY": "socks5://127.0.0.1:1080"},
        )
        assert "socks5://127.0.0.1:1080" in result.stdout
        assert result.exit_code == 0

    @pytest.mark.asyncio
    async def test_env_none_inherits_parent(self):
        """env=None (default) inherits parent process environment."""
        result = await run_streaming(
            [sys.executable, "-c", "import os; print(os.environ.get('PATH', 'NOT_SET'))"],
            on_output=lambda _: None,
            env=None,
        )
        assert "NOT_SET" not in result.stdout
        assert result.exit_code == 0
