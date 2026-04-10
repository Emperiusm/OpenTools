"""Tests for enrichment manager with mock providers."""

import asyncio
from datetime import datetime, timezone
import pytest
from opentools.correlation.enrichment.base import EnrichmentProvider
from opentools.correlation.enrichment.manager import EnrichmentManager
from opentools.models import EnrichmentResult


class MockProvider(EnrichmentProvider):
    name = "mock"
    supported_types = ["ip", "domain"]
    ttl_seconds = 3600
    rate_limit = 10.0
    confidence_by_type = {"ip": 0.9, "domain": 0.7}

    def __init__(self, call_count=None):
        super().__init__()
        self.call_count = call_count if call_count is not None else [0]

    async def enrich(self, ioc_type, value):
        self.call_count[0] += 1
        return {"score": 75, "info": f"Mock data for {value}"}

    def normalize_risk_score(self, data):
        return data.get("score", 0)

    def extract_tags(self, data):
        return ["mock-tag"]


class FailingProvider(EnrichmentProvider):
    name = "failing"
    supported_types = ["ip"]
    rate_limit = 10.0

    async def enrich(self, ioc_type, value):
        raise RuntimeError("API down")

    def normalize_risk_score(self, data):
        return None

    def extract_tags(self, data):
        return []


def test_enrich_single():
    mgr = EnrichmentManager([MockProvider()])
    results = asyncio.run(mgr.enrich_single("ip", "10.0.0.1"))
    assert len(results) == 1
    assert results[0].provider == "mock"
    assert results[0].risk_score == 75
    assert "mock-tag" in results[0].tags


def test_enrich_caching():
    provider = MockProvider()
    mgr = EnrichmentManager([provider])
    asyncio.run(mgr.enrich_single("ip", "10.0.0.1"))
    asyncio.run(mgr.enrich_single("ip", "10.0.0.1"))
    # Should be called only once due to cache
    assert provider.call_count[0] == 1


def test_enrich_force_refresh():
    provider = MockProvider()
    mgr = EnrichmentManager([provider])
    asyncio.run(mgr.enrich_single("ip", "10.0.0.1"))
    asyncio.run(mgr.enrich_single("ip", "10.0.0.1", force_refresh=True))
    # Second call bypasses cache
    assert provider.call_count[0] == 2


def test_enrich_unsupported_type():
    mgr = EnrichmentManager([MockProvider()])
    results = asyncio.run(mgr.enrich_single("hash_sha256", "abc123"))
    assert len(results) == 0


def test_enrich_handles_provider_failure():
    mgr = EnrichmentManager([FailingProvider()])
    results = asyncio.run(mgr.enrich_single("ip", "10.0.0.1"))
    assert len(results) == 1
    assert results[0].is_stale is True


def test_aggregate_risk_score():
    results = [
        EnrichmentResult(provider="a", risk_score=80, confidence=0.9),
        EnrichmentResult(provider="b", risk_score=40, confidence=0.5),
    ]
    score = EnrichmentManager.aggregate_risk_score(results, "ip")
    # (80*0.9 + 40*0.5) / (0.9 + 0.5) = 92/1.4 = 65.7 → 66
    assert score == 66


def test_aggregate_risk_score_no_scores():
    results = [EnrichmentResult(provider="a", risk_score=None, confidence=0.9)]
    assert EnrichmentManager.aggregate_risk_score(results, "ip") is None


def test_aggregate_risk_score_empty():
    assert EnrichmentManager.aggregate_risk_score([], "ip") is None


def test_enrich_batch():
    mgr = EnrichmentManager([MockProvider()])
    iocs = [("ip", "10.0.0.1"), ("domain", "evil.com"), ("hash_sha256", "abc")]
    results = asyncio.run(mgr.enrich_batch(iocs))
    assert ("ip", "10.0.0.1") in results
    assert ("domain", "evil.com") in results
    assert ("hash_sha256", "abc") in results
    assert len(results[("hash_sha256", "abc")]) == 0


def test_provider_supports():
    p = MockProvider()
    assert p.supports("ip") is True
    assert p.supports("hash_sha256") is False


def test_provider_confidence():
    p = MockProvider()
    assert p.get_confidence("ip") == 0.9
    assert p.get_confidence("domain") == 0.7
    assert p.get_confidence("unknown") == 0.5
