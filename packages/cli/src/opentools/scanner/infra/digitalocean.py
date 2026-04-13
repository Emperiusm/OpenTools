"""DigitalOcean CloudNodeProvider implementation."""
from __future__ import annotations
import uuid

import httpx

from opentools.scanner.infra.provider import CloudNodeProvider


class DigitalOceanProvider(CloudNodeProvider):
    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    @classmethod
    def from_token(cls, api_token: str) -> DigitalOceanProvider:
        client = httpx.AsyncClient(
            base_url="https://api.digitalocean.com/v2",
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
        resp = await self._client.post(
            "/droplets",
            json={
                "name": f"ot-proxy-{uuid.uuid4().hex[:8]}",
                "region": region,
                "size": "s-1vcpu-512mb-10gb",
                "image": "ubuntu-24-04-x64",
                "ssh_keys": [ssh_public_key],
                "tags": tags,
            },
        )
        resp.raise_for_status()
        return str(resp.json()["droplet"]["id"])

    async def poll_status(self, provider_id: str) -> tuple[str, str | None]:
        resp = await self._client.get(f"/droplets/{provider_id}")
        resp.raise_for_status()
        droplet = resp.json()["droplet"]
        status = "active" if droplet["status"] == "active" else "creating"
        ip = None
        for net in droplet.get("networks", {}).get("v4", []):
            if net.get("type") == "public":
                ip = net["ip_address"]
                break
        return status, ip

    async def destroy_node(self, provider_id: str) -> None:
        resp = await self._client.delete(f"/droplets/{provider_id}")
        if resp.status_code not in (204, 404):
            resp.raise_for_status()
