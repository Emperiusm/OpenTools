"""Tests for ephemeral_proxy context manager and ProxyEndpoint."""
from __future__ import annotations

import asyncio
import os

import pytest

from opentools.scanner.infra.provider import CloudNodeProvider, ProvisioningError
from opentools.scanner.infra.proxy import (
    ProxyEndpoint,
    _shielded_destroy,
    ephemeral_proxy,
)


# ---------------------------------------------------------------------------
# FakeProvider — in-memory, no real cloud calls
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
# TestProxyEndpoint
# ---------------------------------------------------------------------------


class TestProxyEndpoint:
    def test_env_includes_proxy_vars(self) -> None:
        """All 5 proxy env vars are set with socks5://127.0.0.1:PORT."""
        endpoint = ProxyEndpoint(host="1.2.3.4", socks_port=10800)
        env = endpoint.env
        expected_url = "socks5://127.0.0.1:10800"
        assert env["HTTP_PROXY"] == expected_url
        assert env["HTTPS_PROXY"] == expected_url
        assert env["http_proxy"] == expected_url
        assert env["https_proxy"] == expected_url
        assert env["ALL_PROXY"] == expected_url

    def test_env_inherits_parent_env(self) -> None:
        """PATH (or Path on Windows) is present from the parent environment."""
        endpoint = ProxyEndpoint(host="1.2.3.4", socks_port=10800)
        env = endpoint.env
        # On Windows the key may be 'Path'; check case-insensitively.
        lower_keys = {k.lower() for k in env}
        assert "path" in lower_keys


# ---------------------------------------------------------------------------
# TestShieldedDestroy
# ---------------------------------------------------------------------------


class TestShieldedDestroy:
    @pytest.mark.asyncio
    async def test_normal_destroy(self) -> None:
        """Happy path: provider.destroyed_ids contains the node after destroy."""
        provider = FakeProvider()
        node_id = "fake-0"
        provider.created_ids.append(node_id)

        await _shielded_destroy(provider, node_id)

        assert node_id in provider.destroyed_ids

    @pytest.mark.asyncio
    async def test_destroy_failure_does_not_raise(self) -> None:
        """A destroy failure is logged but does not propagate."""
        provider = FakeProvider(fail_destroy=True)
        # Should complete without raising even though destroy raises internally.
        await _shielded_destroy(provider, "fake-0")  # must not raise


# ---------------------------------------------------------------------------
# TestEphemeralProxyLifecycle
# ---------------------------------------------------------------------------


class TestEphemeralProxyLifecycle:
    @pytest.mark.asyncio
    async def test_provision_and_teardown(self) -> None:
        """Happy path: after __aexit__, exactly one node created and destroyed."""
        provider = FakeProvider(ready_after_polls=1)

        async with ephemeral_proxy(provider, _skip_tunnel=True) as endpoint:
            assert endpoint.host == "1.2.3.4"
            assert endpoint.socks_port == 10800

        assert len(provider.created_ids) == 1
        assert provider.created_ids == provider.destroyed_ids

    @pytest.mark.asyncio
    async def test_teardown_on_exception(self) -> None:
        """Body raises ValueError — node is still destroyed in finally block."""
        provider = FakeProvider(ready_after_polls=1)

        with pytest.raises(ValueError, match="body error"):
            async with ephemeral_proxy(provider, _skip_tunnel=True):
                raise ValueError("body error")

        assert len(provider.created_ids) == 1
        assert provider.destroyed_ids == provider.created_ids

    @pytest.mark.asyncio
    async def test_create_failure_no_destroy(self) -> None:
        """create_node raises ProvisioningError — destroy is never called."""
        provider = FakeProvider(fail_create=True)

        with pytest.raises(ProvisioningError, match="create failed"):
            async with ephemeral_proxy(provider, _skip_tunnel=True):
                pass  # pragma: no cover

        assert provider.created_ids == []
        assert provider.destroyed_ids == []
