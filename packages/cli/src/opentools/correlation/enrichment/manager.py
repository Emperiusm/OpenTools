"""Enrichment manager — orchestrates providers, caching, and batch operations."""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4
from typing import Optional

from opentools.correlation.enrichment.base import EnrichmentProvider
from opentools.models import EnrichmentResult, IOCEnrichmentRecord


class EnrichmentManager:
    def __init__(self, providers: list[EnrichmentProvider], cache: Optional[dict] = None):
        self._providers = providers
        self._cache: dict[str, IOCEnrichmentRecord] = cache if cache is not None else {}

    def _cache_key(self, ioc_type: str, value: str, provider: str) -> str:
        return f"{provider}:{ioc_type}:{value}"

    def _is_stale(self, record: IOCEnrichmentRecord) -> bool:
        if not record.fetched_at:
            return True
        age = (datetime.now(timezone.utc) - record.fetched_at).total_seconds()
        return age > record.ttl_seconds

    async def enrich_single(self, ioc_type: str, value: str,
                            force_refresh: bool = False) -> list[EnrichmentResult]:
        results = []
        for provider in self._providers:
            if not provider.supports(ioc_type):
                continue
            key = self._cache_key(ioc_type, value, provider.name)
            cached = self._cache.get(key)
            if cached and not force_refresh and not self._is_stale(cached):
                results.append(EnrichmentResult(
                    provider=provider.name, risk_score=cached.risk_score,
                    tags=cached.tags, data=cached.data, fetched_at=cached.fetched_at,
                    is_stale=False, confidence=provider.get_confidence(ioc_type),
                ))
                continue
            try:
                data = await provider.enrich_with_rate_limit(ioc_type, value)
                risk_score = provider.normalize_risk_score(data)
                tags = provider.extract_tags(data)
                now = datetime.now(timezone.utc)
                record = IOCEnrichmentRecord(
                    id=str(uuid4()), ioc_type=ioc_type, ioc_value=value,
                    provider=provider.name, data=data, risk_score=risk_score,
                    tags=tags, fetched_at=now, ttl_seconds=provider.ttl_seconds,
                )
                self._cache[key] = record
                results.append(EnrichmentResult(
                    provider=provider.name, risk_score=risk_score, tags=tags,
                    data=data, fetched_at=now, is_stale=False,
                    confidence=provider.get_confidence(ioc_type),
                ))
            except Exception:
                results.append(EnrichmentResult(
                    provider=provider.name, is_stale=True,
                    confidence=provider.get_confidence(ioc_type),
                ))
        return results

    async def enrich_batch(self, iocs: list[tuple[str, str]],
                           force_refresh: bool = False) -> dict[tuple[str, str], list[EnrichmentResult]]:
        results: dict[tuple[str, str], list[EnrichmentResult]] = {}
        async def enrich_one(ioc_type, value):
            results[(ioc_type, value)] = await self.enrich_single(ioc_type, value, force_refresh)
        await asyncio.gather(*[enrich_one(t, v) for t, v in iocs])
        return results

    @staticmethod
    def aggregate_risk_score(enrichments: list[EnrichmentResult], ioc_type: str) -> int | None:
        total_weight = 0.0
        weighted_sum = 0.0
        for e in enrichments:
            if e.risk_score is not None:
                weighted_sum += e.risk_score * e.confidence
                total_weight += e.confidence
        return round(weighted_sum / total_weight) if total_weight > 0 else None
