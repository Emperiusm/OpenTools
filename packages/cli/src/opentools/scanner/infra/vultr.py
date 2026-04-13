"""VultrProvider — ephemeral Vultr instance provisioning via REST API.

IMPORTANT: sshkey_id array is REQUIRED. Without it, SSH tunnel fails.
"""
from __future__ import annotations
import uuid

import httpx

from opentools.scanner.infra.provider import CloudNodeProvider


class VultrProvider(CloudNodeProvider):
    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    @classmethod
    def from_token(cls, api_token: str) -> VultrProvider:
        client = httpx.AsyncClient(
            base_url="https://api.vultr.com/v2",
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=30.0,
        )
        return cls(client=client)

    async def create_node(
        self,
        region: str,
        ssh_public_key: str,
        tags: list[str],
    ) -> str:
        """ssh_public_key must be a Vultr SSH key UUID (pre-registered)."""
        resp = await self._client.post(
            "/instances",
            json={
                "region": region,
                "plan": "vc2-1c-0.5gb",
                "os_id": 2284,  # Ubuntu 24.04 LTS
                "label": f"ot-proxy-{uuid.uuid4().hex[:8]}",
                "sshkey_id": [ssh_public_key],  # REQUIRED for tunnel auth
                "tags": tags,
                "backups": "disabled",
                "activation_email": False,
            },
        )
        resp.raise_for_status()
        return resp.json()["instance"]["id"]

    async def poll_status(self, provider_id: str) -> tuple[str, str | None]:
        resp = await self._client.get(f"/instances/{provider_id}")
        resp.raise_for_status()
        inst = resp.json()["instance"]
        # Vultr can report "active" before IP is assigned — guard against 0.0.0.0
        if (
            inst.get("status") == "active"
            and inst.get("power_status") == "running"
            and inst.get("main_ip", "0.0.0.0") != "0.0.0.0"
        ):
            return "active", inst["main_ip"]
        return "creating", None

    async def destroy_node(self, provider_id: str) -> None:
        resp = await self._client.delete(f"/instances/{provider_id}")
        if resp.status_code not in (204, 404):
            resp.raise_for_status()

    async def list_nodes_by_tag(self, tag: str) -> list[str]:
        """List instance IDs with given tag (for orphan sweeping)."""
        resp = await self._client.get("/instances", params={"tag": tag})
        resp.raise_for_status()
        return [inst["id"] for inst in resp.json().get("instances", [])]
