"""AlienVault OTX enrichment provider."""

import os
import httpx
from opentools.correlation.enrichment.base import EnrichmentProvider

_TYPE_PATH = {
    "ip": "IPv4", "domain": "domain", "url": "url",
    "hash_md5": "file", "hash_sha256": "file",
}

class OTXProvider(EnrichmentProvider):
    name = "otx"
    supported_types = ["ip", "domain", "url", "hash_md5", "hash_sha256"]
    ttl_seconds = 86400
    rate_limit = 0.17
    confidence_by_type = {
        "ip": 0.70, "domain": 0.70, "url": 0.60,
        "hash_sha256": 0.75, "hash_md5": 0.70,
    }

    async def enrich(self, ioc_type: str, value: str) -> dict:
        api_key = os.environ.get("OTX_API_KEY")
        if not api_key:
            return {}
        type_path = _TYPE_PATH.get(ioc_type, "file")
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/{type_path}/{value}/general",
                headers={"X-OTX-API-KEY": api_key},
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
            return {}

    def normalize_risk_score(self, data: dict) -> int | None:
        count = data.get("pulse_info", {}).get("count", 0)
        return min(count * 10, 100) if count else 0

    def extract_tags(self, data: dict) -> list[str]:
        pulses = data.get("pulse_info", {}).get("pulses", [])
        return [p.get("name", "") for p in pulses[:5] if p.get("name")]
