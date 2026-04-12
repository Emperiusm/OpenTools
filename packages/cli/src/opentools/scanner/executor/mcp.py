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

    async def _discover_tools(self) -> dict[str, Any]:
        """Call tools/list to discover available tools. Returns {name: schema}."""
        # Stub: real implementation sends JSON-RPC tools/list
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
            if not conn.is_connected:
                await conn.connect()

            result = await conn.call_tool(task.mcp_tool, task.mcp_args)

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
