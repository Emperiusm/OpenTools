"""AbuseIPDB enrichment provider."""

import os
import httpx
from opentools.correlation.enrichment.base import EnrichmentProvider

_CATEGORY_NAMES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute-Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted",
}

class AbuseIPDBProvider(EnrichmentProvider):
    name = "abuseipdb"
    supported_types = ["ip"]
    ttl_seconds = 21600
    rate_limit = 0.012
    confidence_by_type = {"ip": 0.95}

    async def enrich(self, ioc_type: str, value: str) -> dict:
        api_key = os.environ.get("ABUSEIPDB_API_KEY")
        if not api_key:
            return {}
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": value, "maxAgeInDays": "90", "verbose": ""},
                headers={"Key": api_key, "Accept": "application/json"},
                timeout=10,
            )
            if resp.status_code == 200:
                return resp.json()
            return {}

    def normalize_risk_score(self, data: dict) -> int | None:
        return data.get("data", {}).get("abuseConfidenceScore")

    def extract_tags(self, data: dict) -> list[str]:
        reports = data.get("data", {}).get("reports", [])
        categories = set()
        for report in reports[:20]:
            for cat_id in report.get("categories", []):
                if name := _CATEGORY_NAMES.get(cat_id):
                    categories.add(name)
        return list(categories)[:5]
