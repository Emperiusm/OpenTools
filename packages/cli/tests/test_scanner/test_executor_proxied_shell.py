"""Tests for ProxiedShellExecutor."""
from __future__ import annotations

import pytest

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.proxied_shell import ProxiedShellExecutor
from opentools.scanner.infra.provider import CloudNodeProvider, ProvisioningError
from opentools.scanner.models import ScanTask, TaskIsolation, TaskType


# ---------------------------------------------------------------------------
# FakeProvider — identical to the one in test_infra_proxy.py
# ---------------------------------------------------------------------------


class FakeProvider(CloudNodeProvider):
    def __init__(
        self,
        ready_after_polls: int = 1,
        ip_address: str = "1.2.3.4",
        fail_create: bool = False,
        fail_destroy: bool = False,
    ) -> None:
        self.ready_after_polls = ready_after_polls
        self.ip_address = ip_address
        self.fail_create = fail_create
        self.fail_destroy = fail_destroy
        self.created_ids: list[str] = []
        self.destroyed_ids: list[str] = []
        self._poll_count = 0

    async def create_node(self, region: str, ssh_public_key: str, tags: list[str]) -> str:
        if self.fail_create:
            raise ProvisioningError("create failed")
        node_id = f"fake-{len(self.created_ids)}"
        self.created_ids.append(node_id)
        return node_id

    async def poll_status(self, provider_id: str) -> tuple[str, str | None]:
        self._poll_count += 1
        if self._poll_count >= self.ready_after_polls:
            return "active", self.ip_address
        return "creating", None

    async def destroy_node(self, provider_id: str) -> None:
        if self.fail_destroy:
            raise ProvisioningError("destroy failed")
        self.destroyed_ids.append(provider_id)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_task(
    command: str | None = "echo hello",
    isolation: TaskIsolation = TaskIsolation.NONE,
    task_id: str = "t1",
) -> ScanTask:
    return ScanTask(
        id=task_id,
        scan_id="scan1",
        name="test-task",
        tool="test",
        task_type=TaskType.SHELL,
        command=command,
        isolation=isolation,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestProxiedShellExecutor:
    @pytest.mark.asyncio
    async def test_non_proxied_task_runs_directly(self) -> None:
        """TaskIsolation.NONE runs directly without touching the provider."""
        provider = FakeProvider()
        executor = ProxiedShellExecutor(provider=provider, _skip_tunnel=True)
        task = _make_task(command="echo direct", isolation=TaskIsolation.NONE)
        cancel = CancellationToken()

        result = await executor.execute(task, lambda _: None, cancel)

        assert result.exit_code == 0
        assert "direct" in result.stdout
        # Provider was never called
        assert provider.created_ids == []
        assert provider.destroyed_ids == []

    @pytest.mark.asyncio
    async def test_no_provider_falls_through(self) -> None:
        """NETWORK_ISOLATED task with provider=None falls through to direct run."""
        executor = ProxiedShellExecutor(provider=None, _skip_tunnel=True)
        task = _make_task(command="echo fallthrough", isolation=TaskIsolation.NETWORK_ISOLATED)
        cancel = CancellationToken()

        result = await executor.execute(task, lambda _: None, cancel)

        assert result.exit_code == 0
        assert "fallthrough" in result.stdout

    @pytest.mark.asyncio
    async def test_proxied_task_provisions_and_destroys(self) -> None:
        """NETWORK_ISOLATED with a real provider provisions one node and destroys it."""
        provider = FakeProvider(ready_after_polls=1)
        executor = ProxiedShellExecutor(provider=provider, _skip_tunnel=True)
        task = _make_task(command="echo proxied", isolation=TaskIsolation.NETWORK_ISOLATED)
        cancel = CancellationToken()

        result = await executor.execute(task, lambda _: None, cancel)

        assert result.exit_code == 0
        # Node was provisioned and torn down
        assert len(provider.created_ids) == 1
        assert provider.created_ids == provider.destroyed_ids

    @pytest.mark.asyncio
    async def test_missing_command_raises(self) -> None:
        """ValueError is raised when task.command is None."""
        executor = ProxiedShellExecutor(provider=None)
        task = _make_task(command=None)
        cancel = CancellationToken()

        with pytest.raises(ValueError, match="command"):
            await executor.execute(task, lambda _: None, cancel)

    def test_socks_port_increments(self) -> None:
        """Each call to _next_socks_port increments from base_socks_port."""
        executor = ProxiedShellExecutor(provider=None, base_socks_port=10800)

        port1 = executor._next_socks_port()
        port2 = executor._next_socks_port()

        assert port1 == 10800
        assert port2 == 10801
