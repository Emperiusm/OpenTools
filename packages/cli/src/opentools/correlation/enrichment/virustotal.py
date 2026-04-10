"""VirusTotal enrichment provider."""

import os
from base64 import urlsafe_b64encode

import httpx

from opentools.correlation.enrichment.base import EnrichmentProvider


class VirusTotalProvider(EnrichmentProvider):
    name = "virustotal"
    supported_types = ["ip", "domain", "url", "hash_md5", "hash_sha256"]
    ttl_seconds = 86400
    rate_limit = 0.066
    confidence_by_type = {
        "hash_sha256": 0.95, "hash_md5": 0.90, "domain": 0.80,
        "url": 0.70, "ip": 0.60,
    }

    _TYPE_PATH = {
        "ip": "ip_addresses", "domain": "domains", "url": "urls",
        "hash_md5": "files", "hash_sha256": "files",
    }

    async def enrich(self, ioc_type: str, value: str) -> dict:
        api_key = os.environ.get("VIRUSTOTAL_API_KEY")
        if not api_key:
            return {}
        path = self._TYPE_PATH.get(ioc_type, "files")
        lookup_value = urlsafe_b64encode(value.encode()).decode().rstrip("=") if ioc_type == "url" else value
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/{path}/{lookup_value}",
                headers={"x-apikey": api_key},
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
            return {}

    def normalize_risk_score(self, data: dict) -> int | None:
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        total = sum(stats.values())
        if total == 0:
            return None
        return round(stats.get("malicious", 0) / total * 100)

    def extract_tags(self, data: dict) -> list[str]:
        attrs = data.get("data", {}).get("attributes", {})
        tags = []
        classification = attrs.get("popular_threat_classification", {})
        if label := classification.get("suggested_threat_label"):
            tags.append(label)
        return tags
