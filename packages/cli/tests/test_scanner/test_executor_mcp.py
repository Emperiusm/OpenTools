"""Tests for McpExecutor."""

from unittest.mock import AsyncMock, patch

import pytest

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.base import TaskExecutor, TaskOutput
from opentools.scanner.executor.mcp import McpExecutor, McpConnection
from opentools.scanner.models import ScanTask, TaskType


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


class TestMcpExecutor:
    @pytest.mark.asyncio
    async def test_implements_protocol(self):
        executor = McpExecutor()
        assert isinstance(executor, TaskExecutor)

    @pytest.mark.asyncio
    async def test_register_server(self):
        executor = McpExecutor()
        executor.register_server(
            server_name="codebadger", transport="http", url="http://localhost:4242"
        )
        assert "codebadger" in executor.servers

    @pytest.mark.asyncio
    async def test_register_stdio_server(self):
        executor = McpExecutor()
        executor.register_server(
            server_name="custom-server", transport="stdio", command=["python", "-m", "custom_server"]
        )
        assert "custom-server" in executor.servers


class TestMcpExecutorExecute:
    @pytest.mark.asyncio
    async def test_successful_tool_call(self):
        executor = McpExecutor()
        executor.register_server("codebadger", transport="http", url="http://localhost:4242")

        conn = executor._connections["codebadger"]
        with patch.object(conn, "_start_http", new_callable=AsyncMock):
            with patch.object(conn, "_discover_tools", new_callable=AsyncMock, return_value={"scan": {}}):
                with patch.object(
                    conn, "_invoke_tool", new_callable=AsyncMock,
                    return_value={"content": [{"type": "text", "text": '{"findings": []}'}]},
                ):
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

        conn = executor._connections["codebadger"]
        with patch.object(conn, "_start_http", new_callable=AsyncMock):
            with patch.object(conn, "_discover_tools", new_callable=AsyncMock, return_value={"scan": {}}):
                with patch.object(
                    conn, "_invoke_tool", new_callable=AsyncMock,
                    side_effect=ConnectionError("server down"),
                ):
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

        for conn in executor._connections.values():
            conn._connected = True

        await executor.close_all()

        for conn in executor._connections.values():
            assert conn.is_connected is False
