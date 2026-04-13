"""CloudNodeProvider ABC and shared types for ephemeral infrastructure."""
from __future__ import annotations
import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class EphemeralNode(BaseModel):
    provider_id: str
    ip_address: str
    region: str
    ssh_key_fingerprint: str
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProvisioningError(Exception):
    pass


class ProvisioningTimeout(ProvisioningError):
    pass


class CloudNodeProvider(ABC):
    @abstractmethod
    async def create_node(self, region: str, ssh_public_key: str, tags: list[str]) -> str: ...

    @abstractmethod
    async def poll_status(self, provider_id: str) -> tuple[str, str | None]: ...

    @abstractmethod
    async def destroy_node(self, provider_id: str) -> None: ...

    async def wait_until_ready(
        self,
        provider_id: str,
        poll_interval: float = 3.0,
        max_polls: int = 60,
    ) -> str:
        for attempt in range(max_polls):
            status, ip = await self.poll_status(provider_id)
            if status == "active" and ip is not None:
                logger.info(
                    "Node %s ready at %s after %d polls",
                    provider_id,
                    ip,
                    attempt + 1,
                )
                return ip
            if status == "error":
                raise ProvisioningError(f"Node {provider_id} entered error state")
            await asyncio.sleep(poll_interval)
        raise ProvisioningTimeout(
            f"Node {provider_id} not ready after {max_polls * poll_interval:.0f}s"
        )
