"""Tests for CloudNodeProvider ABC, DigitalOceanProvider, and VultrProvider.

Uses httpx.MockTransport to avoid real network calls.
"""
from __future__ import annotations
import json

import httpx
import pytest

from opentools.scanner.infra.provider import (
    CloudNodeProvider,
    EphemeralNode,
    ProvisioningError,
    ProvisioningTimeout,
)
from opentools.scanner.infra.digitalocean import DigitalOceanProvider
from opentools.scanner.infra.vultr import VultrProvider


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_transport(responses: list[httpx.Response]) -> httpx.MockTransport:
    """Return a MockTransport that replays responses in order."""
    idx = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal idx
        resp = responses[idx]
        idx += 1
        return resp

    return httpx.MockTransport(handler)


def _json_response(data: dict, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code=status_code,
        headers={"Content-Type": "application/json"},
        content=json.dumps(data).encode(),
    )


def _empty_response(status_code: int) -> httpx.Response:
    return httpx.Response(status_code=status_code)


# ---------------------------------------------------------------------------
# EphemeralNode
# ---------------------------------------------------------------------------

class TestEphemeralNode:
    def test_construction_minimal(self):
        node = EphemeralNode(
            provider_id="123",
            ip_address="1.2.3.4",
            region="nyc3",
            ssh_key_fingerprint="aa:bb:cc",
        )
        assert node.provider_id == "123"
        assert node.ip_address == "1.2.3.4"
        assert node.tags == []
        assert node.metadata == {}

    def test_construction_full(self):
        node = EphemeralNode(
            provider_id="456",
            ip_address="5.6.7.8",
            region="lon1",
            ssh_key_fingerprint="dd:ee:ff",
            tags=["scan", "ot-proxy"],
            metadata={"scan_id": "s1"},
        )
        assert node.tags == ["scan", "ot-proxy"]
        assert node.metadata == {"scan_id": "s1"}


# ---------------------------------------------------------------------------
# CloudNodeProvider ABC
# ---------------------------------------------------------------------------

class TestCloudNodeProviderABC:
    def test_is_abstract(self):
        """Cannot instantiate CloudNodeProvider directly."""
        with pytest.raises(TypeError):
            CloudNodeProvider()  # type: ignore[abstract]

    def test_digitalocean_is_subclass(self):
        assert issubclass(DigitalOceanProvider, CloudNodeProvider)

    def test_vultr_is_subclass(self):
        assert issubclass(VultrProvider, CloudNodeProvider)


# ---------------------------------------------------------------------------
# DigitalOceanProvider
# ---------------------------------------------------------------------------

def _make_do_provider(responses: list[httpx.Response]) -> DigitalOceanProvider:
    transport = _make_transport(responses)
    client = httpx.AsyncClient(
        base_url="https://api.digitalocean.com/v2",
        transport=transport,
    )
    return DigitalOceanProvider(client=client)


class TestDigitalOceanProviderCreateNode:
    @pytest.mark.asyncio
    async def test_create_node_returns_id(self):
        payload = {"droplet": {"id": 99999, "status": "new"}}
        provider = _make_do_provider([_json_response(payload, 202)])
        node_id = await provider.create_node(
            region="nyc3",
            ssh_public_key="sha1:abc123",
            tags=["ot-proxy"],
        )
        assert node_id == "99999"

    @pytest.mark.asyncio
    async def test_create_node_payload_fields(self):
        """Verify region, size, image, ssh_keys, and tags are sent."""
        captured: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(req)
            return _json_response({"droplet": {"id": 1}}, 202)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(
            base_url="https://api.digitalocean.com/v2",
            transport=transport,
        )
        provider = DigitalOceanProvider(client=client)
        await provider.create_node(
            region="ams3",
            ssh_public_key="my-key-fingerprint",
            tags=["tag-a", "tag-b"],
        )

        assert len(captured) == 1
        body = json.loads(captured[0].content)
        assert body["region"] == "ams3"
        assert body["size"] == "s-1vcpu-512mb-10gb"
        assert body["image"] == "ubuntu-24-04-x64"
        assert body["ssh_keys"] == ["my-key-fingerprint"]
        assert body["tags"] == ["tag-a", "tag-b"]
        assert body["name"].startswith("ot-proxy-")

    @pytest.mark.asyncio
    async def test_create_node_name_is_unique(self):
        """Two calls should produce different node names."""
        names: list[str] = []

        def handler(req: httpx.Request) -> httpx.Response:
            body = json.loads(req.content)
            names.append(body["name"])
            return _json_response({"droplet": {"id": len(names)}}, 202)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(
            base_url="https://api.digitalocean.com/v2",
            transport=transport,
        )
        provider = DigitalOceanProvider(client=client)
        await provider.create_node("nyc3", "key", [])
        await provider.create_node("nyc3", "key", [])
        assert names[0] != names[1]


class TestDigitalOceanProviderPollStatus:
    @pytest.mark.asyncio
    async def test_poll_status_active_with_ip(self):
        payload = {
            "droplet": {
                "status": "active",
                "networks": {"v4": [{"type": "public", "ip_address": "10.0.0.1"}]},
            }
        }
        provider = _make_do_provider([_json_response(payload)])
        status, ip = await provider.poll_status("99999")
        assert status == "active"
        assert ip == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_poll_status_creating_no_ip(self):
        payload = {"droplet": {"status": "new", "networks": {}}}
        provider = _make_do_provider([_json_response(payload)])
        status, ip = await provider.poll_status("99999")
        assert status == "creating"
        assert ip is None

    @pytest.mark.asyncio
    async def test_poll_status_active_no_public_ip(self):
        """active status but only private network — IP should be None."""
        payload = {
            "droplet": {
                "status": "active",
                "networks": {
                    "v4": [{"type": "private", "ip_address": "10.10.0.5"}]
                },
            }
        }
        provider = _make_do_provider([_json_response(payload)])
        status, ip = await provider.poll_status("99999")
        assert status == "active"
        assert ip is None

    @pytest.mark.asyncio
    async def test_poll_status_off_status_maps_to_creating(self):
        payload = {"droplet": {"status": "off", "networks": {}}}
        provider = _make_do_provider([_json_response(payload)])
        status, ip = await provider.poll_status("99999")
        assert status == "creating"


class TestDigitalOceanProviderDestroyNode:
    @pytest.mark.asyncio
    async def test_destroy_node_204(self):
        provider = _make_do_provider([_empty_response(204)])
        # Should not raise
        await provider.destroy_node("99999")

    @pytest.mark.asyncio
    async def test_destroy_node_404_idempotent(self):
        provider = _make_do_provider([_empty_response(404)])
        # Should not raise — idempotent delete
        await provider.destroy_node("99999")

    @pytest.mark.asyncio
    async def test_destroy_node_500_raises(self):
        provider = _make_do_provider([_empty_response(500)])
        with pytest.raises(httpx.HTTPStatusError):
            await provider.destroy_node("99999")


class TestDigitalOceanWaitUntilReady:
    @pytest.mark.asyncio
    async def test_wait_until_ready_success_first_poll(self):
        payload = {
            "droplet": {
                "status": "active",
                "networks": {"v4": [{"type": "public", "ip_address": "1.2.3.4"}]},
            }
        }
        provider = _make_do_provider([_json_response(payload)])
        ip = await provider.wait_until_ready("99999", poll_interval=0, max_polls=5)
        assert ip == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_wait_until_ready_success_after_two_polls(self):
        creating = {"droplet": {"status": "new", "networks": {}}}
        active = {
            "droplet": {
                "status": "active",
                "networks": {"v4": [{"type": "public", "ip_address": "9.9.9.9"}]},
            }
        }
        provider = _make_do_provider(
            [_json_response(creating), _json_response(active)]
        )
        ip = await provider.wait_until_ready("99999", poll_interval=0, max_polls=5)
        assert ip == "9.9.9.9"

    @pytest.mark.asyncio
    async def test_wait_until_ready_timeout(self):
        creating = {"droplet": {"status": "new", "networks": {}}}
        # Always returns creating
        responses = [_json_response(creating)] * 3
        provider = _make_do_provider(responses)
        with pytest.raises(ProvisioningTimeout):
            await provider.wait_until_ready("99999", poll_interval=0, max_polls=3)

    @pytest.mark.asyncio
    async def test_wait_until_ready_error_state(self):
        """If poll_status returns 'error', ProvisioningError should be raised."""
        # We need a custom provider that returns error status
        class ErrorProvider(DigitalOceanProvider):
            async def poll_status(self, provider_id: str):
                return "error", None

        transport = httpx.MockTransport(lambda r: _empty_response(200))
        client = httpx.AsyncClient(
            base_url="https://api.digitalocean.com/v2",
            transport=transport,
        )
        provider = ErrorProvider(client=client)
        with pytest.raises(ProvisioningError, match="error state"):
            await provider.wait_until_ready("99999", poll_interval=0, max_polls=5)


# ---------------------------------------------------------------------------
# VultrProvider
# ---------------------------------------------------------------------------

def _make_vultr_provider(responses: list[httpx.Response]) -> VultrProvider:
    transport = _make_transport(responses)
    client = httpx.AsyncClient(
        base_url="https://api.vultr.com/v2",
        transport=transport,
    )
    return VultrProvider(client=client)


class TestVultrProviderCreateNode:
    @pytest.mark.asyncio
    async def test_create_node_returns_id(self):
        payload = {"instance": {"id": "vultr-uuid-1234"}}
        provider = _make_vultr_provider([_json_response(payload, 202)])
        node_id = await provider.create_node(
            region="ewr",
            ssh_public_key="ssh-key-uuid",
            tags=["ot-proxy"],
        )
        assert node_id == "vultr-uuid-1234"

    @pytest.mark.asyncio
    async def test_create_node_sshkey_id_is_present(self):
        """CRITICAL: sshkey_id must be sent as an array."""
        captured: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(req)
            return _json_response({"instance": {"id": "abc"}}, 202)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(
            base_url="https://api.vultr.com/v2",
            transport=transport,
        )
        provider = VultrProvider(client=client)
        await provider.create_node(
            region="ewr",
            ssh_public_key="my-vultr-ssh-key-uuid",
            tags=[],
        )

        body = json.loads(captured[0].content)
        assert "sshkey_id" in body, "sshkey_id must be present in Vultr payload"
        assert isinstance(body["sshkey_id"], list), "sshkey_id must be a list"
        assert body["sshkey_id"] == ["my-vultr-ssh-key-uuid"]

    @pytest.mark.asyncio
    async def test_create_node_payload_fields(self):
        captured: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(req)
            return _json_response({"instance": {"id": "xyz"}}, 202)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(
            base_url="https://api.vultr.com/v2",
            transport=transport,
        )
        provider = VultrProvider(client=client)
        await provider.create_node(
            region="sea",
            ssh_public_key="key-uuid",
            tags=["scan", "test"],
        )

        body = json.loads(captured[0].content)
        assert body["region"] == "sea"
        assert body["plan"] == "vc2-1c-0.5gb"
        assert body["os_id"] == 2284
        assert body["label"].startswith("ot-proxy-")
        assert body["tags"] == ["scan", "test"]
        assert body["backups"] == "disabled"
        assert body["activation_email"] is False

    @pytest.mark.asyncio
    async def test_create_node_name_is_unique(self):
        labels: list[str] = []

        def handler(req: httpx.Request) -> httpx.Response:
            body = json.loads(req.content)
            labels.append(body["label"])
            return _json_response({"instance": {"id": str(len(labels))}}, 202)

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(
            base_url="https://api.vultr.com/v2",
            transport=transport,
        )
        provider = VultrProvider(client=client)
        await provider.create_node("ewr", "key", [])
        await provider.create_node("ewr", "key", [])
        assert labels[0] != labels[1]


class TestVultrProviderPollStatus:
    @pytest.mark.asyncio
    async def test_poll_status_active_running_with_real_ip(self):
        payload = {
            "instance": {
                "status": "active",
                "power_status": "running",
                "main_ip": "45.76.1.2",
            }
        }
        provider = _make_vultr_provider([_json_response(payload)])
        status, ip = await provider.poll_status("vultr-id")
        assert status == "active"
        assert ip == "45.76.1.2"

    @pytest.mark.asyncio
    async def test_poll_status_zero_ip_treated_as_creating(self):
        """Vultr reports 'active' before IP assigned — 0.0.0.0 must map to creating."""
        payload = {
            "instance": {
                "status": "active",
                "power_status": "running",
                "main_ip": "0.0.0.0",
            }
        }
        provider = _make_vultr_provider([_json_response(payload)])
        status, ip = await provider.poll_status("vultr-id")
        assert status == "creating"
        assert ip is None

    @pytest.mark.asyncio
    async def test_poll_status_active_not_running(self):
        """active status but power_status != running — still creating."""
        payload = {
            "instance": {
                "status": "active",
                "power_status": "stopped",
                "main_ip": "45.76.1.2",
            }
        }
        provider = _make_vultr_provider([_json_response(payload)])
        status, ip = await provider.poll_status("vultr-id")
        assert status == "creating"
        assert ip is None

    @pytest.mark.asyncio
    async def test_poll_status_pending(self):
        payload = {
            "instance": {
                "status": "pending",
                "power_status": "stopped",
                "main_ip": "0.0.0.0",
            }
        }
        provider = _make_vultr_provider([_json_response(payload)])
        status, ip = await provider.poll_status("vultr-id")
        assert status == "creating"
        assert ip is None

    @pytest.mark.asyncio
    async def test_poll_status_missing_main_ip_defaults_to_zero(self):
        """If main_ip key is absent, the 0.0.0.0 default guard kicks in."""
        payload = {
            "instance": {
                "status": "active",
                "power_status": "running",
                # main_ip intentionally absent
            }
        }
        provider = _make_vultr_provider([_json_response(payload)])
        status, ip = await provider.poll_status("vultr-id")
        assert status == "creating"
        assert ip is None


class TestVultrProviderDestroyNode:
    @pytest.mark.asyncio
    async def test_destroy_node_204(self):
        provider = _make_vultr_provider([_empty_response(204)])
        await provider.destroy_node("vultr-id")

    @pytest.mark.asyncio
    async def test_destroy_node_404_idempotent(self):
        provider = _make_vultr_provider([_empty_response(404)])
        await provider.destroy_node("vultr-id")

    @pytest.mark.asyncio
    async def test_destroy_node_500_raises(self):
        provider = _make_vultr_provider([_empty_response(500)])
        with pytest.raises(httpx.HTTPStatusError):
            await provider.destroy_node("vultr-id")


class TestVultrProviderListNodesByTag:
    @pytest.mark.asyncio
    async def test_list_nodes_by_tag_returns_ids(self):
        payload = {
            "instances": [
                {"id": "id-a", "tag": "ot-proxy"},
                {"id": "id-b", "tag": "ot-proxy"},
            ]
        }
        provider = _make_vultr_provider([_json_response(payload)])
        ids = await provider.list_nodes_by_tag("ot-proxy")
        assert ids == ["id-a", "id-b"]

    @pytest.mark.asyncio
    async def test_list_nodes_by_tag_empty(self):
        payload = {"instances": []}
        provider = _make_vultr_provider([_json_response(payload)])
        ids = await provider.list_nodes_by_tag("ot-proxy")
        assert ids == []

    @pytest.mark.asyncio
    async def test_list_nodes_by_tag_sends_tag_param(self):
        captured: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            captured.append(req)
            return _json_response({"instances": []})

        transport = httpx.MockTransport(handler)
        client = httpx.AsyncClient(
            base_url="https://api.vultr.com/v2",
            transport=transport,
        )
        provider = VultrProvider(client=client)
        await provider.list_nodes_by_tag("my-tag")

        assert len(captured) == 1
        assert "tag=my-tag" in str(captured[0].url)


class TestVultrWaitUntilReady:
    @pytest.mark.asyncio
    async def test_wait_until_ready_success(self):
        active = {
            "instance": {
                "status": "active",
                "power_status": "running",
                "main_ip": "203.0.113.5",
            }
        }
        provider = _make_vultr_provider([_json_response(active)])
        ip = await provider.wait_until_ready("vultr-id", poll_interval=0, max_polls=5)
        assert ip == "203.0.113.5"

    @pytest.mark.asyncio
    async def test_wait_until_ready_skips_zero_ip_then_succeeds(self):
        zero_ip = {
            "instance": {
                "status": "active",
                "power_status": "running",
                "main_ip": "0.0.0.0",
            }
        }
        real_ip = {
            "instance": {
                "status": "active",
                "power_status": "running",
                "main_ip": "203.0.113.5",
            }
        }
        provider = _make_vultr_provider(
            [_json_response(zero_ip), _json_response(real_ip)]
        )
        ip = await provider.wait_until_ready("vultr-id", poll_interval=0, max_polls=5)
        assert ip == "203.0.113.5"

    @pytest.mark.asyncio
    async def test_wait_until_ready_timeout(self):
        creating = {
            "instance": {
                "status": "pending",
                "power_status": "stopped",
                "main_ip": "0.0.0.0",
            }
        }
        responses = [_json_response(creating)] * 3
        provider = _make_vultr_provider(responses)
        with pytest.raises(ProvisioningTimeout):
            await provider.wait_until_ready("vultr-id", poll_interval=0, max_polls=3)
