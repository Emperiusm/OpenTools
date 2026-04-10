"""Base class for enrichment providers."""

from abc import ABC, abstractmethod
import asyncio


class EnrichmentProvider(ABC):
    name: str = ""
    supported_types: list[str] = []
    ttl_seconds: int = 86400
    rate_limit: float = 1.0
    confidence_by_type: dict[str, float] = {}

    def __init__(self):
        self._semaphore = asyncio.Semaphore(1)

    async def enrich_with_rate_limit(self, ioc_type: str, value: str) -> dict:
        async with self._semaphore:
            result = await self.enrich(ioc_type, value)
            if self.rate_limit < 1.0:
                await asyncio.sleep(1.0 / self.rate_limit)
            return result

    @abstractmethod
    async def enrich(self, ioc_type: str, value: str) -> dict:
        ...

    @abstractmethod
    def normalize_risk_score(self, data: dict) -> int | None:
        ...

    @abstractmethod
    def extract_tags(self, data: dict) -> list[str]:
        ...

    def get_confidence(self, ioc_type: str) -> float:
        return self.confidence_by_type.get(ioc_type, 0.5)

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.supported_types
