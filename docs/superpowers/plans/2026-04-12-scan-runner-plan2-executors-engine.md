# Scan Runner Plan 2: Executors + Engine

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the task execution layer (executor protocol + three executor implementations) and the ScanEngine DAG executor that schedules, dispatches, retries, caches, and evaluates reactive edges.

**Architecture:** Bottom-up — executor protocol and TaskOutput model first, then each executor (shell, docker, MCP), then OutputBuffer for backpressure, then the ScanEngine scheduling loop and its supporting methods. Integration tests use mock executors returning canned output to verify engine orchestration without real tools.

**Tech Stack:** Python 3.12, Pydantic v2, asyncio, pytest + pytest-asyncio

**Spec Reference:** `docs/superpowers/specs/2026-04-12-scan-runner-design.md` sections 2.2-2.9

**Decomposition Note:** This is Plan 2 of 5. Plan 1 (foundation) is complete on `feature/scan-runner-plan1`. Plans 3-5 (planner/profiles, parsing pipeline, surfaces) build on this.

**Branch:** `feature/scan-runner-plan2` (branch from `feature/scan-runner-plan1`)

---

## File Map

### New Files

| File | Responsibility |
|------|---------------|
| `packages/cli/src/opentools/scanner/executor/base.py` | `TaskExecutor` protocol + `TaskOutput` model |
| `packages/cli/src/opentools/scanner/executor/shell.py` | `ShellExecutor` — wraps `shared.subprocess.run_streaming()` |
| `packages/cli/src/opentools/scanner/executor/docker.py` | `DockerExecExecutor` — wraps `docker exec` with streaming |
| `packages/cli/src/opentools/scanner/executor/mcp.py` | `McpExecutor` — MCP client with stdio + HTTP transports |
| `packages/cli/src/opentools/scanner/output_buffer.py` | `OutputBuffer` — backpressure with disk spillover at 10 MB |
| `packages/cli/src/opentools/scanner/engine.py` | `ScanEngine` — DAG executor (schedule loop, dispatch, edges, pause/resume, cancel) |
| `packages/cli/tests/test_scanner/test_executor_base.py` | Tests for protocol + TaskOutput |
| `packages/cli/tests/test_scanner/test_executor_shell.py` | Tests for ShellExecutor |
| `packages/cli/tests/test_scanner/test_executor_docker.py` | Tests for DockerExecExecutor |
| `packages/cli/tests/test_scanner/test_executor_mcp.py` | Tests for McpExecutor |
| `packages/cli/tests/test_scanner/test_output_buffer.py` | Tests for OutputBuffer |
| `packages/cli/tests/test_scanner/test_engine.py` | Integration tests for ScanEngine with mock executors |

### Modified Files

| File | Change |
|------|--------|
| `packages/cli/src/opentools/scanner/executor/__init__.py` | Re-export `TaskExecutor`, `TaskOutput` |

---

### Task 1: TaskExecutor Protocol + TaskOutput Model

**Files:**
- Create: `packages/cli/src/opentools/scanner/executor/base.py`
- Modify: `packages/cli/src/opentools/scanner/executor/__init__.py`
- Test: `packages/cli/tests/test_scanner/test_executor_base.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_executor_base.py
"""Tests for TaskExecutor protocol and TaskOutput model."""

from opentools.scanner.executor.base import TaskExecutor, TaskOutput


class TestTaskOutput:
    def test_defaults(self):
        output = TaskOutput()
        assert output.exit_code is None
        assert output.stdout == ""
        assert output.stderr == ""
        assert output.duration_ms == 0
        assert output.cached is False

    def test_success_output(self):
        output = TaskOutput(exit_code=0, stdout="result", duration_ms=150)
        assert output.exit_code == 0
        assert output.stdout == "result"
        assert output.duration_ms == 150

    def test_failure_output(self):
        output = TaskOutput(exit_code=1, stderr="error msg", duration_ms=50)
        assert output.exit_code == 1
        assert output.stderr == "error msg"

    def test_cached_output(self):
        output = TaskOutput(exit_code=0, stdout="cached", cached=True, duration_ms=0)
        assert output.cached is True

    def test_serialization_round_trip(self):
        output = TaskOutput(exit_code=0, stdout="hello", stderr="warn", duration_ms=99)
        restored = TaskOutput.model_validate_json(output.model_dump_json())
        assert restored == output


class TestTaskExecutorProtocol:
    def test_protocol_structural_subtyping(self):
        """A class with the right method signature satisfies the protocol."""

        class FakeExecutor:
            async def execute(self, task, on_output, cancellation):
                return TaskOutput(exit_code=0)

        assert isinstance(FakeExecutor(), TaskExecutor)

    def test_non_conforming_class_rejected(self):
        """A class missing the execute method does not satisfy the protocol."""

        class NotAnExecutor:
            pass

        assert not isinstance(NotAnExecutor(), TaskExecutor)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_executor_base.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'opentools.scanner.executor.base'`

- [ ] **Step 3: Implement TaskExecutor protocol and TaskOutput model**

```python
# packages/cli/src/opentools/scanner/executor/base.py
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
```

- [ ] **Step 4: Update executor __init__.py with re-exports**

```python
# packages/cli/src/opentools/scanner/executor/__init__.py
"""Task executor package."""

from opentools.scanner.executor.base import TaskExecutor, TaskOutput

__all__ = ["TaskExecutor", "TaskOutput"]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_executor_base.py -v`
Expected: All 6 tests PASS

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/scanner/executor/base.py \
       packages/cli/src/opentools/scanner/executor/__init__.py \
       packages/cli/tests/test_scanner/test_executor_base.py
git commit -m "feat(scanner): TaskExecutor protocol + TaskOutput model"
```

---

### Task 2: ShellExecutor

**Files:**
- Create: `packages/cli/src/opentools/scanner/executor/shell.py`
- Test: `packages/cli/tests/test_scanner/test_executor_shell.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_executor_shell.py
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
    async def test_missing_command(self):
        executor = ShellExecutor()
        task = _make_task("nonexistent_binary_xyz123")
        cancel = CancellationToken()

        result = await executor.execute(task, lambda _: None, cancel)

        assert result.exit_code == -1

    @pytest.mark.asyncio
    async def test_streaming_output_chunks(self):
        """Output callback receives data as the process produces it."""
        executor = ShellExecutor()
        # Print two lines with a flush between
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
        task = _make_task.__wrapped__("echo hi") if hasattr(_make_task, "__wrapped__") else _make_task("echo hi")
        task = task.model_copy(update={"command": None})
        cancel = CancellationToken()

        with pytest.raises(ValueError, match="command"):
            await executor.execute(task, lambda _: None, cancel)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_executor_shell.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'opentools.scanner.executor.shell'`

- [ ] **Step 3: Implement ShellExecutor**

```python
# packages/cli/src/opentools/scanner/executor/shell.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_executor_shell.py -v`
Expected: All 8 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/executor/shell.py \
       packages/cli/tests/test_scanner/test_executor_shell.py
git commit -m "feat(scanner): ShellExecutor — subprocess with streaming"
```

---

### Task 3: DockerExecExecutor

**Files:**
- Create: `packages/cli/src/opentools/scanner/executor/docker.py`
- Test: `packages/cli/tests/test_scanner/test_executor_docker.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_executor_docker.py
"""Tests for DockerExecExecutor.

Uses mock subprocess to avoid requiring Docker in CI.
"""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.base import TaskExecutor, TaskOutput
from opentools.scanner.executor.docker import DockerExecExecutor
from opentools.scanner.models import ScanTask, TaskType
from opentools.shared.subprocess import SubprocessResult


def _make_docker_task(
    command: str,
    container: str = "scanner-container",
    task_id: str = "t1",
) -> ScanTask:
    return ScanTask(
        id=task_id,
        scan_id="scan1",
        name="docker-task",
        tool="test",
        task_type=TaskType.DOCKER_EXEC,
        command=command,
        # Container ID stored in task metadata via tool_args pattern:
        # the executor reads from a dedicated field we add
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

            # Verify docker exec command was constructed correctly
            call_args = mock_run.call_args
            args_list = call_args.kwargs.get("args") or call_args[1].get("args") or call_args[0][0]
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
            exit_code=1,
            stdout="",
            stderr="tool not found",
            duration_ms=50,
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
            exit_code=-9,
            stdout="",
            stderr="",
            duration_ms=100,
            cancelled=True,
        )

        with patch(
            "opentools.scanner.executor.docker.run_streaming",
            new_callable=AsyncMock,
            return_value=mock_result,
        ) as mock_run:
            result = await executor.execute(task, lambda _: None, cancel)

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
            # The on_output callback should be passed through
            assert call_kwargs.get("on_output") is not None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_executor_docker.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'opentools.scanner.executor.docker'`

- [ ] **Step 3: Implement DockerExecExecutor**

```python
# packages/cli/src/opentools/scanner/executor/docker.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_executor_docker.py -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/executor/docker.py \
       packages/cli/tests/test_scanner/test_executor_docker.py
git commit -m "feat(scanner): DockerExecExecutor — docker exec with streaming"
```

---

### Task 4: McpExecutor — Connection Management + Tool Discovery

**Files:**
- Create: `packages/cli/src/opentools/scanner/executor/mcp.py`
- Test: `packages/cli/tests/test_scanner/test_executor_mcp.py`

This is the largest executor. We build it in two tasks: Task 4 covers connection lifecycle + tool discovery; Task 5 covers `execute()` and resilience.

- [ ] **Step 1: Write the failing tests for connection management**

```python
# packages/cli/tests/test_scanner/test_executor_mcp.py
"""Tests for McpExecutor."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.base import TaskExecutor, TaskOutput
from opentools.scanner.executor.mcp import McpExecutor, McpConnection


class TestMcpConnection:
    @pytest.mark.asyncio
    async def test_lazy_connection_not_connected_initially(self):
        conn = McpConnection(server_name="test-server", transport="stdio", command=["echo"])
        assert conn.is_connected is False

    @pytest.mark.asyncio
    async def test_connect_and_disconnect(self):
        conn = McpConnection(server_name="test-server", transport="stdio", command=["echo"])

        with patch.object(conn, "_start_stdio", new_callable=AsyncMock):
            with patch.object(conn, "_discover_tools", new_callable=AsyncMock, return_value={"scan": {}}):
                await conn.connect()
                assert conn.is_connected is True
                assert conn.available_tools == {"scan": {}}

                await conn.disconnect()
                assert conn.is_connected is False

    @pytest.mark.asyncio
    async def test_tool_list_cached(self):
        conn = McpConnection(server_name="test-server", transport="stdio", command=["echo"])

        with patch.object(conn, "_start_stdio", new_callable=AsyncMock):
            with patch.object(
                conn, "_discover_tools", new_callable=AsyncMock, return_value={"tool_a": {}, "tool_b": {}}
            ) as mock_discover:
                await conn.connect()
                _ = conn.available_tools
                _ = conn.available_tools
                # _discover_tools called only once during connect
                mock_discover.assert_called_once()

    @pytest.mark.asyncio
    async def test_has_tool(self):
        conn = McpConnection(server_name="test-server", transport="stdio", command=["echo"])

        with patch.object(conn, "_start_stdio", new_callable=AsyncMock):
            with patch.object(
                conn, "_discover_tools", new_callable=AsyncMock, return_value={"scan": {}, "analyze": {}}
            ):
                await conn.connect()
                assert conn.has_tool("scan") is True
                assert conn.has_tool("nonexistent") is False


class TestMcpExecutor:
    @pytest.mark.asyncio
    async def test_implements_protocol(self):
        executor = McpExecutor()
        assert isinstance(executor, TaskExecutor)

    @pytest.mark.asyncio
    async def test_register_server(self):
        executor = McpExecutor()
        executor.register_server(
            server_name="codebadger",
            transport="http",
            url="http://localhost:4242",
        )
        assert "codebadger" in executor.servers

    @pytest.mark.asyncio
    async def test_register_stdio_server(self):
        executor = McpExecutor()
        executor.register_server(
            server_name="custom-server",
            transport="stdio",
            command=["python", "-m", "custom_server"],
        )
        assert "custom-server" in executor.servers
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_executor_mcp.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'opentools.scanner.executor.mcp'`

- [ ] **Step 3: Implement McpConnection and McpExecutor skeleton**

```python
# packages/cli/src/opentools/scanner/executor/mcp.py
"""McpExecutor — MCP client with stdio + HTTP transports, connection pool, tool discovery."""

from __future__ import annotations

import asyncio
import time
from typing import Any, Callable

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.models import ScanTask


class McpConnection:
    """Single MCP server connection with lazy connect and tool discovery."""

    def __init__(
        self,
        server_name: str,
        transport: str,  # "stdio" or "http"
        command: list[str] | None = None,  # for stdio
        url: str | None = None,  # for http
        max_reconnect_attempts: int = 3,
    ) -> None:
        self.server_name = server_name
        self._transport = transport
        self._command = command
        self._url = url
        self._max_reconnect_attempts = max_reconnect_attempts
        self._connected = False
        self._tools: dict[str, Any] | None = None
        self._process: asyncio.subprocess.Process | None = None

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def available_tools(self) -> dict[str, Any]:
        if self._tools is None:
            return {}
        return self._tools

    def has_tool(self, tool_name: str) -> bool:
        return tool_name in self.available_tools

    async def connect(self) -> None:
        """Establish connection and discover tools."""
        if self._connected:
            return
        if self._transport == "stdio":
            await self._start_stdio()
        elif self._transport == "http":
            await self._start_http()
        self._tools = await self._discover_tools()
        self._connected = True

    async def disconnect(self) -> None:
        """Clean shutdown of the connection."""
        if self._process is not None:
            try:
                self._process.terminate()
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except (ProcessLookupError, asyncio.TimeoutError):
                if self._process.returncode is None:
                    self._process.kill()
        self._process = None
        self._connected = False
        self._tools = None

    async def call_tool(self, tool_name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        """Invoke a tool on this MCP server. Returns the tool result."""
        if not self._connected:
            await self.connect()
        if not self.has_tool(tool_name):
            raise ValueError(
                f"Tool '{tool_name}' not found on server '{self.server_name}'. "
                f"Available: {list(self.available_tools.keys())}"
            )
        return await self._invoke_tool(tool_name, args or {})

    async def _start_stdio(self) -> None:
        """Start a stdio-based MCP server process."""
        if self._command is None:
            raise ValueError(f"No command configured for stdio server '{self.server_name}'")
        self._process = await asyncio.create_subprocess_exec(
            *self._command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def _start_http(self) -> None:
        """Initialize HTTP transport to an MCP server."""
        if self._url is None:
            raise ValueError(f"No URL configured for HTTP server '{self.server_name}'")
        # HTTP connections are stateless — just validate the URL is set.
        # Actual HTTP calls happen in _invoke_tool.

    async def _discover_tools(self) -> dict[str, Any]:
        """Call tools/list to discover available tools. Returns {name: schema}."""
        # Stub: in production this sends JSON-RPC tools/list.
        # For now returns empty dict; real implementation in Plan 5
        # when we integrate with actual MCP servers.
        return {}

    async def _invoke_tool(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Send JSON-RPC tool invocation. Returns result dict."""
        # Stub: will be backed by actual JSON-RPC in later plans.
        return {"content": [{"type": "text", "text": ""}]}


class McpExecutor:
    """Execute MCP tool calls with connection pooling and lazy connections."""

    def __init__(self) -> None:
        self._connections: dict[str, McpConnection] = {}

    @property
    def servers(self) -> dict[str, McpConnection]:
        return dict(self._connections)

    def register_server(
        self,
        server_name: str,
        transport: str,
        command: list[str] | None = None,
        url: str | None = None,
        max_reconnect_attempts: int = 3,
    ) -> None:
        """Register an MCP server for lazy connection."""
        self._connections[server_name] = McpConnection(
            server_name=server_name,
            transport=transport,
            command=command,
            url=url,
            max_reconnect_attempts=max_reconnect_attempts,
        )

    async def execute(
        self,
        task: ScanTask,
        on_output: Callable[[bytes], None],
        cancellation: CancellationToken,
    ) -> TaskOutput:
        """Execute an MCP tool call task."""
        if task.mcp_server is None:
            raise ValueError(f"Task {task.id} has no mcp_server")
        if task.mcp_tool is None:
            raise ValueError(f"Task {task.id} has no mcp_tool")

        conn = self._connections.get(task.mcp_server)
        if conn is None:
            raise ValueError(
                f"MCP server '{task.mcp_server}' not registered. "
                f"Registered: {list(self._connections.keys())}"
            )

        start_ns = time.monotonic_ns()

        if cancellation.is_cancelled:
            return TaskOutput(exit_code=-1, stderr="Cancelled before execution")

        try:
            # Lazy connect on first use
            if not conn.is_connected:
                await conn.connect()

            result = await conn.call_tool(task.mcp_tool, task.mcp_args)

            # Extract text content from MCP result
            stdout = ""
            if isinstance(result, dict):
                content = result.get("content", [])
                if isinstance(content, list):
                    text_parts = [
                        item.get("text", "")
                        for item in content
                        if isinstance(item, dict) and item.get("type") == "text"
                    ]
                    stdout = "\n".join(text_parts)

            stdout_bytes = stdout.encode()
            on_output(stdout_bytes)

            elapsed_ms = (time.monotonic_ns() - start_ns) // 1_000_000
            return TaskOutput(exit_code=0, stdout=stdout, duration_ms=elapsed_ms)

        except Exception as exc:
            elapsed_ms = (time.monotonic_ns() - start_ns) // 1_000_000
            return TaskOutput(exit_code=-1, stderr=str(exc), duration_ms=elapsed_ms)

    async def close_all(self) -> None:
        """Disconnect all MCP servers."""
        for conn in self._connections.values():
            await conn.disconnect()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_executor_mcp.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/executor/mcp.py \
       packages/cli/tests/test_scanner/test_executor_mcp.py
git commit -m "feat(scanner): McpExecutor — MCP client with connection pool and tool discovery"
```

---

### Task 5: McpExecutor — Execute, Resilience, Close

**Files:**
- Modify: `packages/cli/tests/test_scanner/test_executor_mcp.py`

- [ ] **Step 1: Add tests for execute and resilience**

Append to `packages/cli/tests/test_scanner/test_executor_mcp.py`:

```python
from opentools.scanner.models import TaskType


def _make_mcp_task(
    server: str = "codebadger",
    tool: str = "scan",
    args: dict | None = None,
    task_id: str = "t1",
) -> ScanTask:
    return ScanTask(
        id=task_id,
        scan_id="scan1",
        name="mcp-task",
        tool=server,
        task_type=TaskType.MCP_CALL,
        mcp_server=server,
        mcp_tool=tool,
        mcp_args=args,
    )


class TestMcpExecutorExecute:
    @pytest.mark.asyncio
    async def test_successful_tool_call(self):
        executor = McpExecutor()
        executor.register_server("codebadger", transport="http", url="http://localhost:4242")

        conn = executor.servers["codebadger"]
        with patch.object(conn, "_start_http", new_callable=AsyncMock):
            with patch.object(
                conn, "_discover_tools", new_callable=AsyncMock, return_value={"scan": {}}
            ):
                with patch.object(
                    conn,
                    "_invoke_tool",
                    new_callable=AsyncMock,
                    return_value={"content": [{"type": "text", "text": '{"findings": []}'}]},
                ):
                    # Need to get the actual connection from the executor's internal dict
                    executor._connections["codebadger"] = conn
                    task = _make_mcp_task()
                    cancel = CancellationToken()
                    chunks: list[bytes] = []

                    result = await executor.execute(task, chunks.append, cancel)

                    assert result.exit_code == 0
                    assert '{"findings": []}' in result.stdout
                    assert len(chunks) > 0

    @pytest.mark.asyncio
    async def test_missing_server_raises(self):
        executor = McpExecutor()
        task = _make_mcp_task(server="nonexistent")
        cancel = CancellationToken()

        with pytest.raises(ValueError, match="not registered"):
            await executor.execute(task, lambda _: None, cancel)

    @pytest.mark.asyncio
    async def test_missing_mcp_server_field_raises(self):
        executor = McpExecutor()
        task = _make_mcp_task()
        task = task.model_copy(update={"mcp_server": None})
        cancel = CancellationToken()

        with pytest.raises(ValueError, match="mcp_server"):
            await executor.execute(task, lambda _: None, cancel)

    @pytest.mark.asyncio
    async def test_missing_mcp_tool_field_raises(self):
        executor = McpExecutor()
        task = _make_mcp_task()
        task = task.model_copy(update={"mcp_tool": None})
        cancel = CancellationToken()

        with pytest.raises(ValueError, match="mcp_tool"):
            await executor.execute(task, lambda _: None, cancel)

    @pytest.mark.asyncio
    async def test_cancelled_before_execution(self):
        executor = McpExecutor()
        executor.register_server("codebadger", transport="http", url="http://localhost:4242")

        task = _make_mcp_task()
        cancel = CancellationToken()
        await cancel.cancel("pre-cancelled")

        result = await executor.execute(task, lambda _: None, cancel)

        assert result.exit_code == -1
        assert "Cancelled" in result.stderr

    @pytest.mark.asyncio
    async def test_tool_call_error_returns_failure(self):
        executor = McpExecutor()
        executor.register_server("codebadger", transport="http", url="http://localhost:4242")

        conn = executor.servers["codebadger"]
        with patch.object(conn, "_start_http", new_callable=AsyncMock):
            with patch.object(
                conn, "_discover_tools", new_callable=AsyncMock, return_value={"scan": {}}
            ):
                with patch.object(
                    conn,
                    "_invoke_tool",
                    new_callable=AsyncMock,
                    side_effect=ConnectionError("server down"),
                ):
                    executor._connections["codebadger"] = conn
                    task = _make_mcp_task()
                    cancel = CancellationToken()

                    result = await executor.execute(task, lambda _: None, cancel)

                    assert result.exit_code == -1
                    assert "server down" in result.stderr

    @pytest.mark.asyncio
    async def test_close_all_disconnects(self):
        executor = McpExecutor()
        executor.register_server("s1", transport="stdio", command=["echo"])
        executor.register_server("s2", transport="http", url="http://localhost:1234")

        # Mark both as connected
        for conn in executor._connections.values():
            conn._connected = True

        await executor.close_all()

        for conn in executor._connections.values():
            assert conn.is_connected is False
```

- [ ] **Step 2: Run tests to verify new tests fail (old tests still pass)**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_executor_mcp.py -v`
Expected: New tests in `TestMcpExecutorExecute` FAIL (import of `ScanTask` / `_make_mcp_task` issues if any), old tests PASS

- [ ] **Step 3: Fix any import issues, run all tests**

The implementation from Task 4 Step 3 already includes the `execute()` method. Verify all tests pass.

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_executor_mcp.py -v`
Expected: All 14 tests PASS

- [ ] **Step 4: Commit**

```bash
git add packages/cli/tests/test_scanner/test_executor_mcp.py
git commit -m "test(scanner): McpExecutor execute, resilience, and close tests"
```

---

### Task 6: OutputBuffer — Backpressure with Disk Spillover

**Files:**
- Create: `packages/cli/src/opentools/scanner/output_buffer.py`
- Test: `packages/cli/tests/test_scanner/test_output_buffer.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_output_buffer.py
"""Tests for OutputBuffer — backpressure with disk spillover."""

import tempfile
from pathlib import Path

import pytest

from opentools.scanner.output_buffer import OutputBuffer


class TestOutputBuffer:
    def test_small_output_stays_in_memory(self):
        buf = OutputBuffer(memory_limit=1024)
        buf.write(b"hello world")
        assert buf.size == 11
        assert buf.spilled is False
        assert buf.read() == b"hello world"

    def test_multiple_writes(self):
        buf = OutputBuffer(memory_limit=1024)
        buf.write(b"aaa")
        buf.write(b"bbb")
        assert buf.size == 6
        assert buf.read() == b"aaabbb"

    def test_spills_to_disk_above_memory_limit(self):
        buf = OutputBuffer(memory_limit=10)
        buf.write(b"12345")
        buf.write(b"67890")
        assert buf.spilled is False  # exactly at limit

        buf.write(b"X")  # exceeds limit
        assert buf.spilled is True
        assert buf.size == 11
        assert buf.read() == b"1234567890X"

    def test_read_after_spill(self):
        buf = OutputBuffer(memory_limit=5)
        buf.write(b"abcde")
        buf.write(b"fghij")
        data = buf.read()
        assert data == b"abcdefghij"

    def test_cleanup_removes_temp_file(self):
        buf = OutputBuffer(memory_limit=5)
        buf.write(b"abcdefghij")  # triggers spill
        assert buf.spilled is True
        spill_path = buf._spill_path
        assert spill_path is not None
        assert Path(spill_path).exists()

        buf.cleanup()
        assert not Path(spill_path).exists()

    def test_cleanup_no_spill_is_noop(self):
        buf = OutputBuffer(memory_limit=1024)
        buf.write(b"small")
        buf.cleanup()  # should not raise

    def test_empty_buffer(self):
        buf = OutputBuffer()
        assert buf.size == 0
        assert buf.read() == b""
        assert buf.spilled is False

    def test_as_callback(self):
        """OutputBuffer.write can be used directly as an on_output callback."""
        buf = OutputBuffer(memory_limit=1024)
        callback = buf.write
        callback(b"chunk1")
        callback(b"chunk2")
        assert buf.read() == b"chunk1chunk2"

    def test_disk_spill_limit_raises(self):
        """Writing beyond disk_spill_limit raises an error."""
        buf = OutputBuffer(memory_limit=5, disk_spill_limit=20)
        buf.write(b"123456")  # spills to disk (6 > 5)
        buf.write(b"1234567890")  # 16 total, still ok
        with pytest.raises(OverflowError, match="spill limit"):
            buf.write(b"123456")  # 22 > 20, exceeds disk limit

    def test_context_manager(self):
        with OutputBuffer(memory_limit=5) as buf:
            buf.write(b"abcdefghij")
            assert buf.spilled is True
            spill_path = buf._spill_path
        # After exiting context, temp file should be cleaned up
        if spill_path:
            assert not Path(spill_path).exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_output_buffer.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'opentools.scanner.output_buffer'`

- [ ] **Step 3: Implement OutputBuffer**

```python
# packages/cli/src/opentools/scanner/output_buffer.py
"""OutputBuffer — backpressure buffer with disk spillover."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Self


class OutputBuffer:
    """Buffer for streaming tool output with automatic disk spillover.

    Accumulates output in memory up to ``memory_limit`` bytes. Once exceeded,
    all data (existing + new) is flushed to a temporary file on disk. Reads
    always return the complete accumulated output.

    The ``disk_spill_limit`` caps total size on disk. Exceeding it raises
    ``OverflowError`` so the caller can abort the tool.
    """

    def __init__(
        self,
        memory_limit: int = 10 * 1024 * 1024,  # 10 MB
        disk_spill_limit: int = 500 * 1024 * 1024,  # 500 MB
    ) -> None:
        self._memory_limit = memory_limit
        self._disk_spill_limit = disk_spill_limit
        self._chunks: list[bytes] = []
        self._memory_size = 0
        self._spill_path: str | None = None
        self._spill_file = None
        self._total_size = 0

    @property
    def size(self) -> int:
        return self._total_size

    @property
    def spilled(self) -> bool:
        return self._spill_path is not None

    def write(self, data: bytes) -> None:
        """Append data to the buffer. Spills to disk if memory limit exceeded."""
        self._total_size += len(data)

        if self._spill_path is not None:
            # Already spilled — write directly to disk
            if self._total_size > self._disk_spill_limit:
                raise OverflowError(
                    f"Output exceeds disk spill limit "
                    f"({self._total_size} > {self._disk_spill_limit})"
                )
            assert self._spill_file is not None
            self._spill_file.write(data)
            self._spill_file.flush()
            return

        self._chunks.append(data)
        self._memory_size += len(data)

        if self._memory_size > self._memory_limit:
            self._spill_to_disk()

    def read(self) -> bytes:
        """Return all accumulated output."""
        if self._spill_path is not None:
            return Path(self._spill_path).read_bytes()
        return b"".join(self._chunks)

    def cleanup(self) -> None:
        """Remove temporary spill file if one was created."""
        if self._spill_file is not None:
            try:
                self._spill_file.close()
            except Exception:
                pass
            self._spill_file = None
        if self._spill_path is not None:
            try:
                os.unlink(self._spill_path)
            except FileNotFoundError:
                pass
            self._spill_path = None

    def _spill_to_disk(self) -> None:
        """Flush in-memory chunks to a temporary file."""
        fd, path = tempfile.mkstemp(prefix="opentools_output_", suffix=".buf")
        self._spill_path = path
        self._spill_file = os.fdopen(fd, "wb")
        # Write all existing chunks
        for chunk in self._chunks:
            self._spill_file.write(chunk)
        self._spill_file.flush()
        self._chunks.clear()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc) -> None:
        self.cleanup()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_output_buffer.py -v`
Expected: All 10 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/output_buffer.py \
       packages/cli/tests/test_scanner/test_output_buffer.py
git commit -m "feat(scanner): OutputBuffer — backpressure with disk spillover"
```

---

### Task 7: ScanEngine — Core Data Structures and Initialization

**Files:**
- Create: `packages/cli/src/opentools/scanner/engine.py`
- Test: `packages/cli/tests/test_scanner/test_engine.py`

We build the engine incrementally across Tasks 7-11. Task 7 covers: construction, task graph loading, readiness tracking, and the `_ready_tasks()` method.

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_engine.py
"""Tests for ScanEngine — DAG executor."""

import asyncio
from datetime import datetime, timezone
from typing import Callable
from unittest.mock import AsyncMock

import pytest

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.engine import ScanEngine
from opentools.scanner.executor.base import TaskExecutor, TaskOutput
from opentools.scanner.models import (
    Scan,
    ScanConfig,
    ScanStatus,
    ScanTask,
    TaskStatus,
    TaskType,
    TargetType,
)
from opentools.shared.progress import EventBus
from opentools.shared.resource_pool import AdaptiveResourcePool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class MockExecutor:
    """Mock executor that returns configurable results."""

    def __init__(self, results: dict[str, TaskOutput] | None = None):
        self._results = results or {}
        self._default = TaskOutput(exit_code=0, stdout="ok", duration_ms=10)
        self.executed: list[str] = []

    async def execute(
        self,
        task: ScanTask,
        on_output: Callable[[bytes], None],
        cancellation: CancellationToken,
    ) -> TaskOutput:
        self.executed.append(task.id)
        on_output(b"mock output")
        return self._results.get(task.id, self._default)


def _make_scan(scan_id: str = "scan1") -> Scan:
    return Scan(
        id=scan_id,
        engagement_id="eng1",
        target="/tmp/test",
        target_type=TargetType.SOURCE_CODE,
        status=ScanStatus.PENDING,
        created_at=datetime.now(timezone.utc),
    )


def _make_task(
    task_id: str,
    scan_id: str = "scan1",
    depends_on: list[str] | None = None,
    priority: int = 50,
    task_type: TaskType = TaskType.SHELL,
    command: str = "echo test",
) -> ScanTask:
    return ScanTask(
        id=task_id,
        scan_id=scan_id,
        name=f"task-{task_id}",
        tool="test-tool",
        task_type=task_type,
        command=command,
        depends_on=depends_on or [],
        priority=priority,
    )


def _make_engine(
    tasks: list[ScanTask] | None = None,
    executor: MockExecutor | None = None,
    scan: Scan | None = None,
) -> ScanEngine:
    pool = AdaptiveResourcePool(global_limit=4)
    mock_exec = executor or MockExecutor()
    executors = {
        TaskType.SHELL: mock_exec,
        TaskType.DOCKER_EXEC: mock_exec,
        TaskType.MCP_CALL: mock_exec,
    }
    event_bus = EventBus()
    cancel = CancellationToken()
    engine_scan = scan or _make_scan()

    engine = ScanEngine(
        scan=engine_scan,
        resource_pool=pool,
        executors=executors,
        event_bus=event_bus,
        cancellation=cancel,
    )

    if tasks:
        engine.load_tasks(tasks)

    return engine


# ---------------------------------------------------------------------------
# Tests — Initialization and readiness
# ---------------------------------------------------------------------------


class TestEngineInit:
    def test_construction(self):
        engine = _make_engine()
        assert engine.scan.id == "scan1"

    def test_load_tasks(self):
        tasks = [_make_task("a"), _make_task("b")]
        engine = _make_engine(tasks=tasks)
        assert len(engine.tasks) == 2

    def test_ready_tasks_no_deps(self):
        tasks = [_make_task("a"), _make_task("b")]
        engine = _make_engine(tasks=tasks)
        ready = engine.ready_task_ids()
        assert ready == {"a", "b"}

    def test_ready_tasks_with_deps(self):
        tasks = [
            _make_task("a"),
            _make_task("b", depends_on=["a"]),
            _make_task("c", depends_on=["a", "b"]),
        ]
        engine = _make_engine(tasks=tasks)
        ready = engine.ready_task_ids()
        assert ready == {"a"}

    def test_blocked_tasks_excluded(self):
        tasks = [
            _make_task("a"),
            _make_task("b", depends_on=["a"]),
        ]
        engine = _make_engine(tasks=tasks)
        ready = engine.ready_task_ids()
        assert "b" not in ready

    def test_load_tasks_validates_no_missing_deps(self):
        """Tasks referencing non-existent dependencies should raise."""
        tasks = [_make_task("a", depends_on=["nonexistent"])]
        engine = _make_engine()
        with pytest.raises(ValueError, match="nonexistent"):
            engine.load_tasks(tasks)

    def test_ready_set_priority_order(self):
        """ready_tasks_by_priority returns tasks sorted by priority (lowest number first)."""
        tasks = [
            _make_task("low", priority=90),
            _make_task("high", priority=10),
            _make_task("mid", priority=50),
        ]
        engine = _make_engine(tasks=tasks)
        ordered = engine.ready_tasks_by_priority()
        assert [t.id for t in ordered] == ["high", "mid", "low"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine.py::TestEngineInit -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'opentools.scanner.engine'`

- [ ] **Step 3: Implement ScanEngine core structure**

```python
# packages/cli/src/opentools/scanner/engine.py
"""ScanEngine — DAG-based task executor for security scans."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.base import TaskExecutor, TaskOutput
from opentools.scanner.models import (
    Scan,
    ScanStatus,
    ScanTask,
    TaskStatus,
    TaskType,
)
from opentools.shared.progress import EventBus
from opentools.shared.resource_pool import AdaptiveResourcePool


class ScanEngine:
    """DAG-based scan task executor.

    Maintains the task graph, schedules ready tasks respecting priority and
    concurrency (via AdaptiveResourcePool), dispatches to the appropriate
    executor, evaluates reactive edges on completion, and supports
    pause/resume/cancellation.
    """

    def __init__(
        self,
        scan: Scan,
        resource_pool: AdaptiveResourcePool,
        executors: dict[TaskType, TaskExecutor],
        event_bus: EventBus,
        cancellation: CancellationToken,
    ) -> None:
        self.scan = scan
        self._pool = resource_pool
        self._executors = executors
        self._event_bus = event_bus
        self._cancellation = cancellation

        # Task graph
        self._tasks: dict[str, ScanTask] = {}
        self._dependents: dict[str, set[str]] = defaultdict(set)  # task_id → set of dependent task IDs
        self._completed: set[str] = set()
        self._failed: set[str] = set()
        self._running: set[str] = set()
        self._skipped: set[str] = set()

        # Pause state
        self._paused = False

    @property
    def tasks(self) -> dict[str, ScanTask]:
        return dict(self._tasks)

    def load_tasks(self, tasks: list[ScanTask]) -> None:
        """Load tasks into the graph and build dependency index.

        Raises ValueError if any task references a dependency not in the graph.
        """
        task_ids = {t.id for t in tasks}
        for t in tasks:
            for dep in t.depends_on:
                if dep not in task_ids and dep not in self._tasks:
                    raise ValueError(
                        f"Task '{t.id}' depends on '{dep}' which is not in the task graph"
                    )

        for t in tasks:
            self._tasks[t.id] = t
            for dep in t.depends_on:
                self._dependents[dep].add(t.id)

    def ready_task_ids(self) -> set[str]:
        """Return IDs of tasks whose dependencies are all satisfied."""
        ready = set()
        terminal = self._completed | self._skipped
        non_ready = self._running | terminal | self._failed
        for task_id, task in self._tasks.items():
            if task_id in non_ready:
                continue
            if all(dep in terminal for dep in task.depends_on):
                ready.add(task_id)
        return ready

    def ready_tasks_by_priority(self) -> list[ScanTask]:
        """Return ready tasks sorted by priority (lowest number = highest priority)."""
        ready_ids = self.ready_task_ids()
        tasks = [self._tasks[tid] for tid in ready_ids]
        tasks.sort(key=lambda t: t.priority)
        return tasks
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine.py::TestEngineInit -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/engine.py \
       packages/cli/tests/test_scanner/test_engine.py
git commit -m "feat(scanner): ScanEngine — core graph structure and readiness tracking"
```

---

### Task 8: ScanEngine — Task Dispatch and Completion

**Files:**
- Modify: `packages/cli/src/opentools/scanner/engine.py`
- Modify: `packages/cli/tests/test_scanner/test_engine.py`

- [ ] **Step 1: Write the failing tests**

Append to `packages/cli/tests/test_scanner/test_engine.py`:

```python
class TestEngineDispatch:
    @pytest.mark.asyncio
    async def test_execute_single_task(self):
        mock_exec = MockExecutor()
        tasks = [_make_task("a")]
        engine = _make_engine(tasks=tasks, executor=mock_exec)

        await engine.run()

        assert "a" in mock_exec.executed
        assert engine._tasks["a"].status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_execute_linear_chain(self):
        """Tasks a → b → c execute in dependency order."""
        mock_exec = MockExecutor()
        tasks = [
            _make_task("a"),
            _make_task("b", depends_on=["a"]),
            _make_task("c", depends_on=["b"]),
        ]
        engine = _make_engine(tasks=tasks, executor=mock_exec)

        await engine.run()

        assert mock_exec.executed == ["a", "b", "c"]

    @pytest.mark.asyncio
    async def test_execute_parallel_tasks(self):
        """Independent tasks can execute concurrently."""
        mock_exec = MockExecutor()
        tasks = [
            _make_task("a"),
            _make_task("b"),
            _make_task("c"),
        ]
        engine = _make_engine(tasks=tasks, executor=mock_exec)

        await engine.run()

        assert set(mock_exec.executed) == {"a", "b", "c"}

    @pytest.mark.asyncio
    async def test_diamond_dependency(self):
        """Diamond: a → (b, c) → d."""
        mock_exec = MockExecutor()
        tasks = [
            _make_task("a"),
            _make_task("b", depends_on=["a"]),
            _make_task("c", depends_on=["a"]),
            _make_task("d", depends_on=["b", "c"]),
        ]
        engine = _make_engine(tasks=tasks, executor=mock_exec)

        await engine.run()

        assert set(mock_exec.executed) == {"a", "b", "c", "d"}
        # d must come after both b and c
        d_idx = mock_exec.executed.index("d")
        b_idx = mock_exec.executed.index("b")
        c_idx = mock_exec.executed.index("c")
        assert d_idx > b_idx
        assert d_idx > c_idx

    @pytest.mark.asyncio
    async def test_failed_task_blocks_dependents(self):
        """A failed task causes dependents to be skipped."""
        mock_exec = MockExecutor(
            results={"a": TaskOutput(exit_code=1, stderr="boom", duration_ms=5)}
        )
        tasks = [
            _make_task("a"),
            _make_task("b", depends_on=["a"]),
        ]
        engine = _make_engine(tasks=tasks, executor=mock_exec)

        await engine.run()

        assert "a" in mock_exec.executed
        assert "b" not in mock_exec.executed
        assert engine._tasks["b"].status == TaskStatus.SKIPPED

    @pytest.mark.asyncio
    async def test_scan_status_transitions(self):
        """Scan status should transition PENDING → RUNNING → COMPLETED."""
        tasks = [_make_task("a")]
        engine = _make_engine(tasks=tasks)

        assert engine.scan.status == ScanStatus.PENDING
        await engine.run()
        assert engine.scan.status == ScanStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_all_tasks_fail_scan_fails(self):
        """If all tasks fail, scan status is FAILED."""
        mock_exec = MockExecutor(
            results={"a": TaskOutput(exit_code=1, stderr="fail", duration_ms=5)}
        )
        tasks = [_make_task("a")]
        engine = _make_engine(tasks=tasks, executor=mock_exec)

        await engine.run()

        assert engine.scan.status == ScanStatus.FAILED

    @pytest.mark.asyncio
    async def test_executor_selection_by_task_type(self):
        """Engine dispatches to the correct executor based on task_type."""
        shell_exec = MockExecutor()
        docker_exec = MockExecutor()
        mcp_exec = MockExecutor()

        pool = AdaptiveResourcePool(global_limit=4)
        executors = {
            TaskType.SHELL: shell_exec,
            TaskType.DOCKER_EXEC: docker_exec,
            TaskType.MCP_CALL: mcp_exec,
        }
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors=executors,
            event_bus=EventBus(),
            cancellation=CancellationToken(),
        )
        engine.load_tasks([
            _make_task("s", task_type=TaskType.SHELL),
            _make_task("d", task_type=TaskType.DOCKER_EXEC, command="echo docker"),
            _make_task("m", task_type=TaskType.MCP_CALL, command="echo mcp"),
        ])

        await engine.run()

        assert "s" in shell_exec.executed
        assert "d" in docker_exec.executed
        assert "m" in mcp_exec.executed
```

- [ ] **Step 2: Run tests to verify new tests fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine.py::TestEngineDispatch -v`
Expected: FAIL — `ScanEngine` has no `run()` method yet

- [ ] **Step 3: Implement run() and _execute_task()**

Add to `packages/cli/src/opentools/scanner/engine.py`:

```python
    async def run(self) -> None:
        """Execute the full task DAG."""
        self.scan = self.scan.model_copy(update={"status": ScanStatus.RUNNING})
        await self._schedule_loop()
        self._finalize()

    async def _schedule_loop(self) -> None:
        """Main scheduling loop: dispatch ready tasks, wait for completion."""
        in_flight: dict[str, asyncio.Task] = {}

        while True:
            if self._cancellation.is_cancelled:
                # Cancel all in-flight tasks
                for task in in_flight.values():
                    task.cancel()
                break

            if self._paused:
                await asyncio.sleep(0.05)
                continue

            # Find ready tasks not yet dispatched
            ready = self.ready_tasks_by_priority()
            for scan_task in ready:
                if scan_task.id in in_flight:
                    continue
                executor = self._executors.get(scan_task.task_type)
                if executor is None:
                    self._mark_failed(scan_task.id, f"No executor for {scan_task.task_type}")
                    continue
                self._running.add(scan_task.id)
                scan_task = scan_task.model_copy(update={"status": TaskStatus.RUNNING})
                self._tasks[scan_task.id] = scan_task
                coro = self._execute_task(scan_task, executor)
                in_flight[scan_task.id] = asyncio.ensure_future(coro)

            if not in_flight:
                # No tasks running and no ready tasks → done
                break

            # Wait for at least one task to complete
            done, _ = await asyncio.wait(
                in_flight.values(),
                return_when=asyncio.FIRST_COMPLETED,
            )

            for completed_future in done:
                # Find which task ID this future belongs to
                task_id = None
                for tid, fut in in_flight.items():
                    if fut is completed_future:
                        task_id = tid
                        break
                if task_id is None:
                    continue

                del in_flight[task_id]
                self._running.discard(task_id)

                try:
                    output: TaskOutput = completed_future.result()
                except Exception as exc:
                    self._mark_failed(task_id, str(exc))
                    self._skip_dependents(task_id)
                    continue

                if output.exit_code is not None and output.exit_code != 0:
                    self._mark_failed(task_id, output.stderr or f"exit code {output.exit_code}")
                    self._skip_dependents(task_id)
                else:
                    self._mark_completed(task_id, output)

    async def _execute_task(
        self, task: ScanTask, executor: TaskExecutor
    ) -> TaskOutput:
        """Acquire resource, dispatch to executor, release resource."""
        resource_group = task.resource_group or task.task_type.value
        await self._pool.acquire(task.id, task.priority, resource_group)
        try:
            output = await executor.execute(
                task, lambda _chunk: None, self._cancellation
            )
            return output
        finally:
            self._pool.release(resource_group)

    def _mark_completed(self, task_id: str, output: TaskOutput) -> None:
        task = self._tasks[task_id]
        self._tasks[task_id] = task.model_copy(
            update={
                "status": TaskStatus.COMPLETED,
                "exit_code": output.exit_code,
                "stdout": output.stdout,
                "stderr": output.stderr,
                "duration_ms": output.duration_ms,
            }
        )
        self._completed.add(task_id)

    def _mark_failed(self, task_id: str, reason: str) -> None:
        task = self._tasks[task_id]
        self._tasks[task_id] = task.model_copy(
            update={"status": TaskStatus.FAILED, "stderr": reason}
        )
        self._failed.add(task_id)

    def _skip_dependents(self, failed_task_id: str) -> None:
        """Recursively skip all downstream tasks of a failed task."""
        to_skip = list(self._dependents.get(failed_task_id, set()))
        while to_skip:
            dep_id = to_skip.pop()
            if dep_id in self._skipped or dep_id in self._completed:
                continue
            self._tasks[dep_id] = self._tasks[dep_id].model_copy(
                update={"status": TaskStatus.SKIPPED}
            )
            self._skipped.add(dep_id)
            to_skip.extend(self._dependents.get(dep_id, set()))

    def _finalize(self) -> None:
        """Set final scan status based on task outcomes."""
        if self._cancellation.is_cancelled:
            self.scan = self.scan.model_copy(update={"status": ScanStatus.CANCELLED})
        elif self._completed:
            self.scan = self.scan.model_copy(update={"status": ScanStatus.COMPLETED})
        else:
            self.scan = self.scan.model_copy(update={"status": ScanStatus.FAILED})
```

Also add `import asyncio` at the top of `engine.py`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine.py -v`
Expected: All 15 tests PASS (7 init + 8 dispatch)

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/engine.py \
       packages/cli/tests/test_scanner/test_engine.py
git commit -m "feat(scanner): ScanEngine — task dispatch, dependency resolution, status tracking"
```

---

### Task 9: ScanEngine — Cancellation + Pause/Resume

**Files:**
- Modify: `packages/cli/src/opentools/scanner/engine.py`
- Modify: `packages/cli/tests/test_scanner/test_engine.py`

- [ ] **Step 1: Write the failing tests**

Append to `packages/cli/tests/test_scanner/test_engine.py`:

```python
class TestEngineCancellation:
    @pytest.mark.asyncio
    async def test_cancel_stops_execution(self):
        """Cancelling mid-scan prevents remaining tasks from executing."""
        call_count = 0

        class SlowExecutor:
            executed: list[str] = []

            async def execute(self, task, on_output, cancellation):
                nonlocal call_count
                call_count += 1
                self.executed.append(task.id)
                if task.id == "a":
                    # Simulate work, then cancel during task a
                    await cancellation.cancel("user requested")
                return TaskOutput(exit_code=0, stdout="ok", duration_ms=10)

        slow_exec = SlowExecutor()
        tasks = [
            _make_task("a"),
            _make_task("b", depends_on=["a"]),
        ]
        pool = AdaptiveResourcePool(global_limit=4)
        cancel = CancellationToken()
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors={TaskType.SHELL: slow_exec},
            event_bus=EventBus(),
            cancellation=cancel,
        )
        engine.load_tasks(tasks)

        await engine.run()

        assert engine.scan.status == ScanStatus.CANCELLED
        assert "b" not in slow_exec.executed

    @pytest.mark.asyncio
    async def test_external_cancel(self):
        """External cancellation via the token stops the engine."""

        class HangingExecutor:
            executed: list[str] = []

            async def execute(self, task, on_output, cancellation):
                self.executed.append(task.id)
                # Simulate a long-running task
                await asyncio.sleep(10)
                return TaskOutput(exit_code=0, duration_ms=10000)

        hanging = HangingExecutor()
        tasks = [_make_task("a"), _make_task("b")]
        cancel = CancellationToken()
        pool = AdaptiveResourcePool(global_limit=4)
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors={TaskType.SHELL: hanging},
            event_bus=EventBus(),
            cancellation=cancel,
        )
        engine.load_tasks(tasks)

        async def cancel_soon():
            await asyncio.sleep(0.1)
            await cancel.cancel("timeout")

        asyncio.ensure_future(cancel_soon())
        await engine.run()

        assert engine.scan.status == ScanStatus.CANCELLED


class TestEnginePauseResume:
    @pytest.mark.asyncio
    async def test_pause_prevents_new_dispatches(self):
        executed_order: list[str] = []

        class TrackingExecutor:
            async def execute(self, task, on_output, cancellation):
                executed_order.append(task.id)
                return TaskOutput(exit_code=0, duration_ms=10)

        tasks = [_make_task("a"), _make_task("b", depends_on=["a"])]
        cancel = CancellationToken()
        pool = AdaptiveResourcePool(global_limit=4)
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors={TaskType.SHELL: TrackingExecutor()},
            event_bus=EventBus(),
            cancellation=cancel,
        )
        engine.load_tasks(tasks)

        # Pause the engine before running
        await engine.pause()
        assert engine.is_paused is True

        # Start run in background — it should be paused
        run_task = asyncio.ensure_future(engine.run())

        # Wait briefly — b should not have executed
        await asyncio.sleep(0.15)

        # Resume and let it complete
        await engine.resume()
        assert engine.is_paused is False

        await asyncio.wait_for(run_task, timeout=5)
        assert set(executed_order) == {"a", "b"}

    @pytest.mark.asyncio
    async def test_pause_sets_scan_status(self):
        tasks = [_make_task("a")]
        engine = _make_engine(tasks=tasks)

        await engine.pause()
        assert engine.scan.status == ScanStatus.PAUSED

        await engine.resume()
        assert engine.scan.status == ScanStatus.RUNNING
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine.py::TestEngineCancellation tests/test_scanner/test_engine.py::TestEnginePauseResume -v`
Expected: FAIL — `ScanEngine` has no `pause()`, `resume()`, or `is_paused` yet

- [ ] **Step 3: Implement pause/resume and is_paused**

Add to `ScanEngine` in `packages/cli/src/opentools/scanner/engine.py`:

```python
    @property
    def is_paused(self) -> bool:
        return self._paused

    async def pause(self) -> None:
        """Stop scheduling new tasks. In-flight tasks run to completion."""
        self._paused = True
        self.scan = self.scan.model_copy(update={"status": ScanStatus.PAUSED})

    async def resume(self) -> None:
        """Resume scheduling from where we left off."""
        self._paused = False
        self.scan = self.scan.model_copy(update={"status": ScanStatus.RUNNING})
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine.py -v`
Expected: All 19 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/engine.py \
       packages/cli/tests/test_scanner/test_engine.py
git commit -m "feat(scanner): ScanEngine — cancellation propagation + pause/resume"
```

---

### Task 10: ScanEngine — Retry Logic

**Files:**
- Modify: `packages/cli/src/opentools/scanner/engine.py`
- Modify: `packages/cli/tests/test_scanner/test_engine.py`

- [ ] **Step 1: Write the failing tests**

Append to `packages/cli/tests/test_scanner/test_engine.py`:

```python
from opentools.scanner.models import RetryPolicy


class TestEngineRetry:
    @pytest.mark.asyncio
    async def test_retry_on_failure(self):
        """Task with retry policy retries on matching failure."""
        attempt = 0

        class RetryingExecutor:
            executed: list[str] = []

            async def execute(self, task, on_output, cancellation):
                nonlocal attempt
                attempt += 1
                self.executed.append(task.id)
                if attempt < 2:
                    raise ConnectionError("connection_error: server refused")
                return TaskOutput(exit_code=0, stdout="success", duration_ms=10)

        task = _make_task("a")
        task = task.model_copy(
            update={
                "retry_policy": RetryPolicy(
                    max_retries=2,
                    backoff_seconds=0.01,
                    retry_on=["connection_error"],
                )
            }
        )

        cancel = CancellationToken()
        pool = AdaptiveResourcePool(global_limit=4)
        retrying_exec = RetryingExecutor()
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors={TaskType.SHELL: retrying_exec},
            event_bus=EventBus(),
            cancellation=cancel,
        )
        engine.load_tasks([task])

        await engine.run()

        assert engine._tasks["a"].status == TaskStatus.COMPLETED
        assert attempt == 2

    @pytest.mark.asyncio
    async def test_retry_exhausted_fails(self):
        """Task fails after exhausting retries."""

        class AlwaysFailExecutor:
            executed: list[str] = []

            async def execute(self, task, on_output, cancellation):
                self.executed.append(task.id)
                raise ConnectionError("connection_error: always fails")

        task = _make_task("a")
        task = task.model_copy(
            update={
                "retry_policy": RetryPolicy(
                    max_retries=1,
                    backoff_seconds=0.01,
                    retry_on=["connection_error"],
                )
            }
        )

        cancel = CancellationToken()
        pool = AdaptiveResourcePool(global_limit=4)
        fail_exec = AlwaysFailExecutor()
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors={TaskType.SHELL: fail_exec},
            event_bus=EventBus(),
            cancellation=cancel,
        )
        engine.load_tasks([task])

        await engine.run()

        assert engine._tasks["a"].status == TaskStatus.FAILED

    @pytest.mark.asyncio
    async def test_no_retry_on_non_matching_error(self):
        """Non-retryable errors propagate immediately."""
        attempt = 0

        class NonRetryableExecutor:
            executed: list[str] = []

            async def execute(self, task, on_output, cancellation):
                nonlocal attempt
                attempt += 1
                self.executed.append(task.id)
                raise RuntimeError("unexpected crash")

        task = _make_task("a")
        task = task.model_copy(
            update={
                "retry_policy": RetryPolicy(
                    max_retries=3,
                    backoff_seconds=0.01,
                    retry_on=["connection_error"],
                )
            }
        )

        cancel = CancellationToken()
        pool = AdaptiveResourcePool(global_limit=4)
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors={TaskType.SHELL: NonRetryableExecutor()},
            event_bus=EventBus(),
            cancellation=cancel,
        )
        engine.load_tasks([task])

        await engine.run()

        assert attempt == 1  # No retries — error didn't match
        assert engine._tasks["a"].status == TaskStatus.FAILED
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine.py::TestEngineRetry -v`
Expected: FAIL — `_execute_task` doesn't handle retry yet

- [ ] **Step 3: Add retry logic to _execute_task**

Modify `_execute_task` in `packages/cli/src/opentools/scanner/engine.py`:

```python
    async def _execute_task(
        self, task: ScanTask, executor: TaskExecutor
    ) -> TaskOutput:
        """Acquire resource, dispatch to executor with retry, release resource."""
        resource_group = task.resource_group or task.task_type.value

        if task.retry_policy is not None:
            from opentools.shared.retry import execute_with_retry

            async def _attempt() -> TaskOutput:
                await self._pool.acquire(task.id, task.priority, resource_group)
                try:
                    return await executor.execute(
                        task, lambda _chunk: None, self._cancellation
                    )
                finally:
                    self._pool.release(resource_group)

            return await execute_with_retry(_attempt, task.retry_policy)
        else:
            await self._pool.acquire(task.id, task.priority, resource_group)
            try:
                return await executor.execute(
                    task, lambda _chunk: None, self._cancellation
                )
            finally:
                self._pool.release(resource_group)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine.py -v`
Expected: All 22 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/engine.py \
       packages/cli/tests/test_scanner/test_engine.py
git commit -m "feat(scanner): ScanEngine — retry logic via RetryPolicy"
```

---

### Task 11: ScanEngine — Reactive Edge Evaluation

**Files:**
- Modify: `packages/cli/src/opentools/scanner/engine.py`
- Modify: `packages/cli/tests/test_scanner/test_engine.py`

- [ ] **Step 1: Write the failing tests**

Append to `packages/cli/tests/test_scanner/test_engine.py`:

```python
from opentools.scanner.models import ReactiveEdge


class TestEngineReactiveEdges:
    @pytest.mark.asyncio
    async def test_reactive_edge_spawns_task(self):
        """A reactive edge spawns a new task when the trigger task completes."""
        mock_exec = MockExecutor()
        spawned_task = _make_task("b", depends_on=[])
        edge = ReactiveEdge(
            id="edge1",
            trigger_task_id="a",
            evaluator="builtin:always_spawn",
            spawns=[spawned_task],
        )
        trigger = _make_task("a")
        trigger = trigger.model_copy(update={"reactive_edges": [edge]})

        engine = _make_engine(tasks=[trigger], executor=mock_exec)

        # Register a simple edge evaluator
        def always_spawn(task: ScanTask, output: TaskOutput, edge: ReactiveEdge) -> list[ScanTask]:
            return edge.spawns or []

        engine.register_edge_evaluator("builtin:always_spawn", always_spawn)

        await engine.run()

        assert "a" in mock_exec.executed
        assert "b" in mock_exec.executed
        assert engine._tasks["b"].status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_reactive_edge_respects_max_spawns(self):
        """Edge respects max_spawns cap."""
        mock_exec = MockExecutor()

        # Create edge that tries to spawn 5 tasks but cap is 2
        spawned = [_make_task(f"s{i}") for i in range(5)]
        edge = ReactiveEdge(
            id="edge1",
            trigger_task_id="a",
            evaluator="builtin:multi_spawn",
            spawns=spawned,
            max_spawns=2,
        )
        trigger = _make_task("a")
        trigger = trigger.model_copy(update={"reactive_edges": [edge]})

        engine = _make_engine(tasks=[trigger], executor=mock_exec)

        def multi_spawn(task, output, edge):
            return edge.spawns or []

        engine.register_edge_evaluator("builtin:multi_spawn", multi_spawn)

        await engine.run()

        # Only 2 spawned tasks should have been added (plus trigger "a")
        spawned_executed = [t for t in mock_exec.executed if t.startswith("s")]
        assert len(spawned_executed) == 2

    @pytest.mark.asyncio
    async def test_reactive_edge_condition_not_met(self):
        """Edge evaluator that returns empty list spawns nothing."""
        mock_exec = MockExecutor()
        edge = ReactiveEdge(
            id="edge1",
            trigger_task_id="a",
            evaluator="builtin:conditional",
            condition="exit_code == 42",
        )
        trigger = _make_task("a")
        trigger = trigger.model_copy(update={"reactive_edges": [edge]})

        engine = _make_engine(tasks=[trigger], executor=mock_exec)

        def conditional(task, output, edge):
            # Only spawn if condition matches
            if edge.condition == "exit_code == 42" and output.exit_code != 42:
                return []
            return [_make_task("b")]

        engine.register_edge_evaluator("builtin:conditional", conditional)

        await engine.run()

        assert "b" not in mock_exec.executed

    @pytest.mark.asyncio
    async def test_no_duplicate_spawns(self):
        """If a task ID already exists in the graph, don't spawn a duplicate."""
        mock_exec = MockExecutor()
        existing = _make_task("b")
        spawned = _make_task("b")  # same ID
        edge = ReactiveEdge(
            id="edge1",
            trigger_task_id="a",
            evaluator="builtin:dup_spawn",
            spawns=[spawned],
        )
        trigger = _make_task("a")
        trigger = trigger.model_copy(update={"reactive_edges": [edge]})

        engine = _make_engine(tasks=[trigger, existing], executor=mock_exec)

        def dup_spawn(task, output, edge):
            return edge.spawns or []

        engine.register_edge_evaluator("builtin:dup_spawn", dup_spawn)

        await engine.run()

        # "b" should only appear once in executed
        assert mock_exec.executed.count("b") == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine.py::TestEngineReactiveEdges -v`
Expected: FAIL — `register_edge_evaluator` doesn't exist

- [ ] **Step 3: Implement reactive edge evaluation**

Add to `ScanEngine.__init__` in `packages/cli/src/opentools/scanner/engine.py`:

```python
        # Edge evaluators: evaluator_name → callable(task, output, edge) → list[ScanTask]
        self._edge_evaluators: dict[str, Any] = {}
```

Add methods to `ScanEngine`:

```python
    def register_edge_evaluator(
        self,
        name: str,
        evaluator: Any,  # Callable[[ScanTask, TaskOutput, ReactiveEdge], list[ScanTask]]
    ) -> None:
        """Register a reactive edge evaluator."""
        self._edge_evaluators[name] = evaluator

    def _evaluate_edges(
        self, task: ScanTask, output: TaskOutput
    ) -> list[ScanTask]:
        """Evaluate reactive edges for a completed task, return new tasks to add."""
        new_tasks: list[ScanTask] = []

        for edge in task.reactive_edges:
            evaluator = self._edge_evaluators.get(edge.evaluator)
            if evaluator is None:
                continue

            spawned = evaluator(task, output, edge)
            if not spawned:
                continue

            # Enforce max_spawns cap
            remaining = edge.max_spawns - len(new_tasks)
            spawned = spawned[:max(0, remaining)]

            # Dedup: skip tasks whose ID already exists in the graph
            for s in spawned:
                if s.id not in self._tasks:
                    new_tasks.append(s)

        return new_tasks
```

Modify `_mark_completed` to call `_evaluate_edges` and inject spawned tasks:

```python
    def _mark_completed(self, task_id: str, output: TaskOutput) -> None:
        task = self._tasks[task_id]
        self._tasks[task_id] = task.model_copy(
            update={
                "status": TaskStatus.COMPLETED,
                "exit_code": output.exit_code,
                "stdout": output.stdout,
                "stderr": output.stderr,
                "duration_ms": output.duration_ms,
            }
        )
        self._completed.add(task_id)

        # Evaluate reactive edges
        new_tasks = self._evaluate_edges(task, output)
        if new_tasks:
            self._inject_tasks(new_tasks)

    def _inject_tasks(self, tasks: list[ScanTask]) -> None:
        """Add dynamically spawned tasks to the graph."""
        for t in tasks:
            if t.id in self._tasks:
                continue
            self._tasks[t.id] = t
            for dep in t.depends_on:
                self._dependents[dep].add(t.id)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine.py -v`
Expected: All 26 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/engine.py \
       packages/cli/tests/test_scanner/test_engine.py
git commit -m "feat(scanner): ScanEngine — reactive edge evaluation with budget caps and dedup"
```

---

### Task 12: ScanEngine — Cache Check Stub + Liveness Monitor Stub

**Files:**
- Modify: `packages/cli/src/opentools/scanner/engine.py`
- Modify: `packages/cli/tests/test_scanner/test_engine.py`

These are intentionally lightweight stubs. Full cache implementation is Plan 3+; liveness monitoring is a future enhancement. We add the hooks now so the engine's `_execute_task` flow has the right shape.

- [ ] **Step 1: Write the failing tests**

Append to `packages/cli/tests/test_scanner/test_engine.py`:

```python
class TestEngineCache:
    @pytest.mark.asyncio
    async def test_cached_task_skips_executor(self):
        """A task with a cache hit should not invoke the executor."""
        mock_exec = MockExecutor()
        task = _make_task("a")
        task = task.model_copy(update={"cache_key": "key-abc"})

        engine = _make_engine(tasks=[task], executor=mock_exec)

        cached_output = TaskOutput(exit_code=0, stdout="cached result", cached=True, duration_ms=0)
        engine.set_cache({
            "key-abc": cached_output,
        })

        await engine.run()

        assert "a" not in mock_exec.executed
        assert engine._tasks["a"].status == TaskStatus.COMPLETED
        assert engine._tasks["a"].cached is True

    @pytest.mark.asyncio
    async def test_cache_miss_executes_normally(self):
        """A task with a cache key but no cache entry executes normally."""
        mock_exec = MockExecutor()
        task = _make_task("a")
        task = task.model_copy(update={"cache_key": "key-miss"})

        engine = _make_engine(tasks=[task], executor=mock_exec)
        engine.set_cache({})

        await engine.run()

        assert "a" in mock_exec.executed
        assert engine._tasks["a"].status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_no_cache_key_executes_normally(self):
        """Tasks without a cache_key always execute."""
        mock_exec = MockExecutor()
        task = _make_task("a")
        assert task.cache_key is None

        engine = _make_engine(tasks=[task], executor=mock_exec)

        await engine.run()

        assert "a" in mock_exec.executed
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine.py::TestEngineCache -v`
Expected: FAIL — `set_cache` method doesn't exist

- [ ] **Step 3: Implement cache stub**

Add to `ScanEngine.__init__`:

```python
        # Cache: cache_key → TaskOutput (stub — real persistence in future plan)
        self._cache: dict[str, TaskOutput] = {}
```

Add method:

```python
    def set_cache(self, cache: dict[str, TaskOutput]) -> None:
        """Set the in-memory output cache (stub for real cache backend)."""
        self._cache = cache
```

Modify `_execute_task` to check cache first:

```python
    async def _execute_task(
        self, task: ScanTask, executor: TaskExecutor
    ) -> TaskOutput:
        """Check cache → acquire resource → dispatch to executor → release."""
        # Cache check
        if task.cache_key and task.cache_key in self._cache:
            return self._cache[task.cache_key]

        resource_group = task.resource_group or task.task_type.value

        if task.retry_policy is not None:
            from opentools.shared.retry import execute_with_retry

            async def _attempt() -> TaskOutput:
                await self._pool.acquire(task.id, task.priority, resource_group)
                try:
                    return await executor.execute(
                        task, lambda _chunk: None, self._cancellation
                    )
                finally:
                    self._pool.release(resource_group)

            output = await execute_with_retry(_attempt, task.retry_policy)
        else:
            await self._pool.acquire(task.id, task.priority, resource_group)
            try:
                output = await executor.execute(
                    task, lambda _chunk: None, self._cancellation
                )
            finally:
                self._pool.release(resource_group)

        # Populate cache on success
        if task.cache_key and output.exit_code == 0:
            self._cache[task.cache_key] = output.model_copy(update={"cached": True})

        return output
```

Update `_mark_completed` to set the `cached` field on the task model when a cached output was used:

```python
    def _mark_completed(self, task_id: str, output: TaskOutput) -> None:
        task = self._tasks[task_id]
        self._tasks[task_id] = task.model_copy(
            update={
                "status": TaskStatus.COMPLETED,
                "exit_code": output.exit_code,
                "stdout": output.stdout,
                "stderr": output.stderr,
                "duration_ms": output.duration_ms,
                "cached": output.cached,
            }
        )
        self._completed.add(task_id)

        # Evaluate reactive edges
        new_tasks = self._evaluate_edges(task, output)
        if new_tasks:
            self._inject_tasks(new_tasks)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine.py -v`
Expected: All 29 tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/engine.py \
       packages/cli/tests/test_scanner/test_engine.py
git commit -m "feat(scanner): ScanEngine — cache check stub + populate on success"
```

---

### Task 13: Full Integration Test — Complex DAG with Mixed Executors

**Files:**
- Modify: `packages/cli/tests/test_scanner/test_engine.py`

- [ ] **Step 1: Write the integration test**

Append to `packages/cli/tests/test_scanner/test_engine.py`:

```python
class TestEngineIntegration:
    @pytest.mark.asyncio
    async def test_complex_dag_with_reactive_edges_and_cache(self):
        """End-to-end: multi-phase DAG with caching, failure, reactive edges.

        Graph:
            preflight → (semgrep, gitleaks) → dedup_merge
            semgrep has a reactive edge that spawns nuclei if findings found
            gitleaks is cached

        Expected:
            1. preflight runs first
            2. semgrep and gitleaks become ready
            3. gitleaks hits cache — no executor call
            4. semgrep completes, reactive edge spawns nuclei
            5. dedup_merge waits for semgrep + gitleaks, then runs
            6. nuclei runs (no deps, spawned by edge)
        """
        execution_log: list[str] = []

        class LoggingExecutor:
            async def execute(self, task, on_output, cancellation):
                execution_log.append(task.id)
                on_output(f"output-{task.id}".encode())
                return TaskOutput(exit_code=0, stdout=f"output-{task.id}", duration_ms=10)

        logging_exec = LoggingExecutor()

        preflight = _make_task("preflight", priority=10)
        semgrep = _make_task("semgrep", depends_on=["preflight"], priority=30)
        gitleaks = _make_task("gitleaks", depends_on=["preflight"], priority=30)
        gitleaks = gitleaks.model_copy(update={"cache_key": "gitleaks-key"})
        dedup = _make_task("dedup_merge", depends_on=["semgrep", "gitleaks"], priority=50)

        # Reactive edge on semgrep: always spawn nuclei
        nuclei_task = _make_task("nuclei")
        edge = ReactiveEdge(
            id="edge-nuclei",
            trigger_task_id="semgrep",
            evaluator="builtin:findings_to_nuclei",
            spawns=[nuclei_task],
        )
        semgrep = semgrep.model_copy(update={"reactive_edges": [edge]})

        pool = AdaptiveResourcePool(global_limit=4)
        cancel = CancellationToken()
        engine = ScanEngine(
            scan=_make_scan(),
            resource_pool=pool,
            executors={
                TaskType.SHELL: logging_exec,
                TaskType.DOCKER_EXEC: logging_exec,
                TaskType.MCP_CALL: logging_exec,
            },
            event_bus=EventBus(),
            cancellation=cancel,
        )
        engine.load_tasks([preflight, semgrep, gitleaks, dedup])

        # Pre-populate cache for gitleaks
        engine.set_cache({
            "gitleaks-key": TaskOutput(
                exit_code=0, stdout="no leaks", cached=True, duration_ms=0
            ),
        })

        # Register edge evaluator
        def findings_to_nuclei(task, output, edge):
            return edge.spawns or []

        engine.register_edge_evaluator("builtin:findings_to_nuclei", findings_to_nuclei)

        await engine.run()

        # Assertions
        assert engine.scan.status == ScanStatus.COMPLETED

        # preflight ran first
        assert execution_log[0] == "preflight"

        # gitleaks was cached — NOT in execution log
        assert "gitleaks" not in execution_log

        # semgrep executed
        assert "semgrep" in execution_log

        # nuclei was spawned by reactive edge and executed
        assert "nuclei" in execution_log

        # dedup_merge ran after semgrep and gitleaks
        assert "dedup_merge" in execution_log
        dedup_idx = execution_log.index("dedup_merge")
        semgrep_idx = execution_log.index("semgrep")
        assert dedup_idx > semgrep_idx

        # gitleaks marked as cached
        assert engine._tasks["gitleaks"].cached is True

        # All tasks completed
        for tid in ["preflight", "semgrep", "gitleaks", "dedup_merge", "nuclei"]:
            assert engine._tasks[tid].status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_partial_failure_with_independent_branches(self):
        """One branch fails, the other succeeds. Scan still completes.

        Graph:
            root → (branch_a, branch_b)
            branch_a → dep_a (fails)
            branch_b → dep_b (succeeds)
        """
        mock_exec = MockExecutor(
            results={
                "branch_a": TaskOutput(exit_code=1, stderr="segfault", duration_ms=5),
            }
        )
        tasks = [
            _make_task("root"),
            _make_task("branch_a", depends_on=["root"]),
            _make_task("branch_b", depends_on=["root"]),
            _make_task("dep_a", depends_on=["branch_a"]),
            _make_task("dep_b", depends_on=["branch_b"]),
        ]
        engine = _make_engine(tasks=tasks, executor=mock_exec)

        await engine.run()

        assert engine.scan.status == ScanStatus.COMPLETED

        assert engine._tasks["root"].status == TaskStatus.COMPLETED
        assert engine._tasks["branch_a"].status == TaskStatus.FAILED
        assert engine._tasks["branch_b"].status == TaskStatus.COMPLETED
        assert engine._tasks["dep_a"].status == TaskStatus.SKIPPED
        assert engine._tasks["dep_b"].status == TaskStatus.COMPLETED
```

- [ ] **Step 2: Run the integration tests**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine.py::TestEngineIntegration -v`
Expected: All 2 tests PASS

- [ ] **Step 3: Run the full test suite to check for regressions**

Run: `cd packages/cli && python -m pytest tests/test_scanner/ -v`
Expected: All tests PASS (Plan 1's 115 tests + Plan 2's new tests)

- [ ] **Step 4: Commit**

```bash
git add packages/cli/tests/test_scanner/test_engine.py
git commit -m "test(scanner): ScanEngine integration tests — complex DAG, caching, edges, partial failure"
```

---

### Task 14: Update Executor __init__.py Re-exports + Final Verification

**Files:**
- Modify: `packages/cli/src/opentools/scanner/executor/__init__.py`

- [ ] **Step 1: Update __init__.py to re-export all executors**

```python
# packages/cli/src/opentools/scanner/executor/__init__.py
"""Task executor package."""

from opentools.scanner.executor.base import TaskExecutor, TaskOutput
from opentools.scanner.executor.docker import DockerExecExecutor
from opentools.scanner.executor.mcp import McpConnection, McpExecutor
from opentools.scanner.executor.shell import ShellExecutor

__all__ = [
    "DockerExecExecutor",
    "McpConnection",
    "McpExecutor",
    "ShellExecutor",
    "TaskExecutor",
    "TaskOutput",
]
```

- [ ] **Step 2: Run full test suite**

Run: `cd packages/cli && python -m pytest tests/test_scanner/ -v`
Expected: All tests PASS

- [ ] **Step 3: Commit**

```bash
git add packages/cli/src/opentools/scanner/executor/__init__.py
git commit -m "chore(scanner): executor package re-exports all executor types"
```

---

## Summary

| Task | What it builds | Approx tests |
|------|---------------|-------------|
| 1 | TaskExecutor protocol + TaskOutput model | 6 |
| 2 | ShellExecutor | 8 |
| 3 | DockerExecExecutor (mocked subprocess) | 6 |
| 4 | McpExecutor — connections + discovery | 7 |
| 5 | McpExecutor — execute + resilience | 7 |
| 6 | OutputBuffer (backpressure + disk spill) | 10 |
| 7 | ScanEngine — graph + readiness | 7 |
| 8 | ScanEngine — dispatch + completion | 8 |
| 9 | ScanEngine — cancel + pause/resume | 4 |
| 10 | ScanEngine — retry | 3 |
| 11 | ScanEngine — reactive edges | 4 |
| 12 | ScanEngine — cache stub | 3 |
| 13 | Integration tests (complex DAG) | 2 |
| 14 | Re-exports + final verification | 0 |
| **Total** | | **~75** |
