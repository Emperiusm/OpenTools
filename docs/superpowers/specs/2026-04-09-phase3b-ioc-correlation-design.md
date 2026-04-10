# Phase 3B: IOC Correlation & Trending — Design Specification

**Date:** 2026-04-09
**Status:** Approved
**Author:** slabl + Claude
**Depends on:** Phase 3A web dashboard (merged)

## 1. Overview

Cross-engagement IOC correlation, external threat intel enrichment, and trending analytics. Surfaces IOCs that appear across multiple engagements, enriches them with data from VirusTotal, AbuseIPDB, and AlienVault OTX, and provides time-series frequency analysis, lifecycle tracking, and hot-IOC ranking.

Features surface in both web (charts, sparklines, enrichment cards) and CLI (text tables). The correlation engine lives in the shared CLI package; the web backend wraps it with async and user-scoping.

## 2. Decisions

| Decision | Choice |
|----------|--------|
| Correlation scope | Cross-engagement overlap + external enrichment |
| Trending scope | Time-series frequency + lifecycle tracking + hot-IOC ranking |
| Surface in | Web (charts/sparklines) + CLI (text tables) |
| External sources | VirusTotal + AbuseIPDB + OTX, extensible provider interface |
| Caching | Persistent DB cache with per-provider TTL + manual refresh |
| Rate limiting | Per-provider token bucket (transparent to caller) |
| Enrichment batch | Parallel providers, sequential per rate limit within provider |
| Risk score | Aggregated weighted average by provider confidence per IOC type |
| User scoping | Engine accepts optional user_id (None=all for CLI, set for web) |
| Trending optimization | Postgres materialized view, refreshed periodically |
| Sparkline charts | Chart.js + vue-chartjs (lazy loaded) |

## 3. Data Models

### 3.1 IOCEnrichment (new table)

Caches external enrichment results. One row per IOC per provider.

```python
class IOCEnrichment(SQLModel, table=True):
    __tablename__ = "ioc_enrichment"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)  # per-user cache
    ioc_type: str                 # ip, domain, hash_sha256, etc.
    ioc_value: str                # the actual IOC value
    provider: str                 # virustotal, abuseipdb, otx
    data: dict = Field(sa_column=Column(JSON))  # provider-specific result
    risk_score: int | None        # normalized 0-100
    tags: list = Field(default_factory=list, sa_column=Column(JSON))  # ["malware", "c2", ...]
    fetched_at: datetime
    ttl_seconds: int              # stale after fetched_at + ttl_seconds
```

Unique constraint: `(user_id, ioc_type, ioc_value, provider)`

Indexes:
```sql
CREATE INDEX idx_enrichment_ioc ON ioc_enrichment(ioc_type, ioc_value);
CREATE INDEX idx_enrichment_user ON ioc_enrichment(user_id, ioc_type, ioc_value);
CREATE INDEX idx_enrichment_stale ON ioc_enrichment(fetched_at)
    WHERE fetched_at < NOW() - INTERVAL '1 day';
```

### 3.2 Pydantic Response Models

```python
class CorrelationResult(BaseModel):
    ioc_type: str
    ioc_value: str
    engagements: list[dict]          # [{id, name, first_seen, last_seen}]
    engagement_count: int
    total_occurrences: int
    first_seen_global: datetime
    last_seen_global: datetime
    active_days: int
    enrichments: list[dict]          # cached enrichment results per provider
    aggregated_risk_score: int | None

class TrendingIOC(BaseModel):
    ioc_type: str
    ioc_value: str
    context: str | None
    engagement_count: int
    total_occurrences: int
    frequency_by_month: dict[str, int]  # {"2026-01": 2, "2026-02": 5}
    risk_score: int | None
    trend: str                          # "rising", "stable", "declining"

class EnrichmentResult(BaseModel):
    provider: str
    risk_score: int | None
    tags: list[str]
    data: dict
    fetched_at: datetime
    is_stale: bool
    confidence: float                   # provider confidence for this IOC type
```

### 3.3 Postgres Materialized View (Trending)

```sql
CREATE MATERIALIZED VIEW ioc_trending AS
SELECT user_id, ioc_type, value, 
       MAX(context) as context,
       COUNT(DISTINCT engagement_id) as engagement_count,
       COUNT(*) as total_occurrences,
       MIN(first_seen) as first_seen_global,
       MAX(COALESCE(last_seen, first_seen)) as last_seen_global
FROM ioc
GROUP BY user_id, ioc_type, value;

CREATE UNIQUE INDEX idx_ioc_trending ON ioc_trending(user_id, ioc_type, value);
```

Refreshed after bulk IOC inserts or on a 5-minute schedule via background task.

## 4. Correlation Engine (`cli/src/opentools/correlation/engine.py`)

Shared library used by both CLI and web. Queries the IOC table directly.

```python
class CorrelationEngine:
    def __init__(self, store_or_session, user_id: str | None = None):
        """
        store_or_session: EngagementStore (CLI/SQLite) or AsyncSession (web/Postgres)
        user_id: None = all engagements (CLI), set = user-filtered (web)
        """

    def correlate(self, ioc_value: str) -> CorrelationResult:
        """Find all engagements containing this IOC."""
        # Query: SELECT * FROM ioc WHERE value = :value [AND user_id = :uid]
        # Group by engagement_id
        # Return: engagement list, first/last seen, occurrence count

    def correlate_engagement(self, engagement_id: str) -> list[CorrelationResult]:
        """For each IOC in an engagement, find cross-engagement overlaps."""
        # Get all IOCs for this engagement
        # For each, count appearances in OTHER engagements
        # Return only IOCs appearing in 2+ engagements

    def find_common_iocs(self, engagement_ids: list[str]) -> list[CorrelationResult]:
        """Find IOCs shared between specific engagements."""
        # SELECT value, ioc_type FROM ioc
        # WHERE engagement_id IN (:ids) [AND user_id = :uid]
        # GROUP BY ioc_type, value HAVING COUNT(DISTINCT engagement_id) = :count
```

For CLI (SQLite): methods accept an `EngagementStore` and use `store._conn` with raw SQL. Synchronous.
For web (Postgres): `correlation_service.py` in the web backend reimplements the same queries using async SQLModel against the AsyncSession. The engine classes are NOT shared between CLI and web — they share the same ALGORITHM but have separate implementations to avoid async/sync contamination. The Pydantic response models (CorrelationResult, TrendingIOC, EnrichmentResult) ARE shared.

## 5. Trending Engine (`cli/src/opentools/correlation/trending.py`)

```python
class TrendingEngine:
    def __init__(self, store_or_session, user_id: str | None = None):
        ...

    def hot_iocs(self, limit: int = 10, days: int = 30) -> list[TrendingIOC]:
        """Top N most-seen IOCs in the last N days."""
        # Web: reads from materialized view
        # CLI: direct GROUP BY query

    def frequency(self, ioc_type: str, ioc_value: str, months: int = 6) -> dict[str, int]:
        """Monthly frequency of an IOC over time."""
        # GROUP BY date_trunc('month', first_seen), COUNT

    def lifecycle(self, ioc_type: str, ioc_value: str) -> dict:
        """First seen, last seen, active days, engagement timeline."""
        # MIN(first_seen), MAX(last_seen), engagement list with dates

    def classify_trend(self, frequency: dict[str, int]) -> str:
        """Classify as rising/stable/declining."""
        # Compare average of last 2 months vs earlier months
        # Rising: recent > historical * 1.5
        # Declining: recent < historical * 0.5
        # Stable: otherwise
```

## 6. Enrichment System

### 6.1 Provider Interface (`correlation/enrichment/base.py`)

```python
from abc import ABC, abstractmethod
import asyncio

class EnrichmentProvider(ABC):
    name: str
    supported_types: list[str]
    ttl_seconds: int = 86400
    rate_limit: float = 1.0           # requests per second
    confidence_by_type: dict[str, float] = {}

    def __init__(self):
        self._semaphore = asyncio.Semaphore(1)

    async def enrich_with_rate_limit(self, ioc_type: str, value: str) -> dict:
        """Rate-limited enrichment. Callers use this, not enrich() directly."""
        async with self._semaphore:
            result = await self.enrich(ioc_type, value)
            if self.rate_limit < 1.0:
                await asyncio.sleep(1.0 / self.rate_limit)
            return result

    @abstractmethod
    async def enrich(self, ioc_type: str, value: str) -> dict:
        """Look up an IOC. Returns provider-specific data dict."""

    @abstractmethod
    def normalize_risk_score(self, data: dict) -> int | None:
        """Normalize provider score to 0-100."""

    @abstractmethod
    def extract_tags(self, data: dict) -> list[str]:
        """Extract tags/labels from provider data."""

    def get_confidence(self, ioc_type: str) -> float:
        """Return confidence for this IOC type (0.0-1.0)."""
        return self.confidence_by_type.get(ioc_type, 0.5)
```

Auto-discovery: modules in `correlation/enrichment/` that subclass `EnrichmentProvider` are registered automatically (same pattern as `parsers/__init__.py`).

### 6.2 VirusTotal Provider

```python
class VirusTotalProvider(EnrichmentProvider):
    name = "virustotal"
    supported_types = ["ip", "domain", "url", "hash_md5", "hash_sha256"]
    ttl_seconds = 86400        # 24 hours
    rate_limit = 0.066         # 4 requests/minute (free tier)
    confidence_by_type = {
        "hash_sha256": 0.95,
        "hash_md5": 0.90,
        "domain": 0.80,
        "url": 0.70,
        "ip": 0.60,
    }

    async def enrich(self, ioc_type, value):
        # GET https://www.virustotal.com/api/v3/{type_path}/{value}
        # Headers: x-apikey: {VIRUSTOTAL_API_KEY}
        # type_path: ip_addresses, domains, urls (base64), files

    def normalize_risk_score(self, data):
        # last_analysis_stats.malicious / total * 100
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values()) or 1
        return round(malicious / total * 100)

    def extract_tags(self, data):
        # popular_threat_classification.suggested_threat_label
        attrs = data.get("data", {}).get("attributes", {})
        tags = []
        classification = attrs.get("popular_threat_classification", {})
        if label := classification.get("suggested_threat_label"):
            tags.append(label)
        return tags
```

### 6.3 AbuseIPDB Provider

```python
class AbuseIPDBProvider(EnrichmentProvider):
    name = "abuseipdb"
    supported_types = ["ip"]
    ttl_seconds = 21600        # 6 hours
    rate_limit = 0.012         # ~1000/day
    confidence_by_type = {"ip": 0.95}

    async def enrich(self, ioc_type, value):
        # GET https://api.abuseipdb.com/api/v2/check
        # Params: ipAddress={value}, maxAgeInDays=90, verbose=true
        # Headers: Key: {ABUSEIPDB_API_KEY}

    def normalize_risk_score(self, data):
        return data.get("data", {}).get("abuseConfidenceScore", 0)

    def extract_tags(self, data):
        # categories → human-readable labels
        categories = data.get("data", {}).get("reports", [])
        # Map category IDs to names
```

### 6.4 OTX Provider

```python
class OTXProvider(EnrichmentProvider):
    name = "otx"
    supported_types = ["ip", "domain", "url", "hash_md5", "hash_sha256"]
    ttl_seconds = 86400
    rate_limit = 0.17          # ~10k/day
    confidence_by_type = {
        "ip": 0.70, "domain": 0.70, "url": 0.60,
        "hash_sha256": 0.75, "hash_md5": 0.70,
    }

    async def enrich(self, ioc_type, value):
        # GET https://otx.alienvault.com/api/v1/indicators/{type}/{value}/general
        # Headers: X-OTX-API-KEY: {OTX_API_KEY}

    def normalize_risk_score(self, data):
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return min(pulse_count * 10, 100)

    def extract_tags(self, data):
        pulses = data.get("pulse_info", {}).get("pulses", [])
        return [p.get("name", "") for p in pulses[:5]]
```

### 6.5 Enrichment Manager

Orchestrates batch enrichment across providers:

```python
class EnrichmentManager:
    def __init__(self, providers: list[EnrichmentProvider], cache_store):
        ...

    async def enrich_single(self, ioc_type: str, value: str,
                            force_refresh: bool = False) -> list[EnrichmentResult]:
        """Enrich one IOC from all compatible providers. Uses cache."""
        results = []
        for provider in self._providers:
            if ioc_type not in provider.supported_types:
                continue
            cached = self._get_cached(ioc_type, value, provider.name)
            if cached and not force_refresh and not self._is_stale(cached):
                results.append(cached)
                continue
            data = await provider.enrich_with_rate_limit(ioc_type, value)
            result = self._save_cache(ioc_type, value, provider, data)
            results.append(result)
        return results

    async def enrich_batch(self, iocs: list[tuple[str, str]],
                           force_refresh: bool = False) -> dict:
        """Enrich multiple IOCs. Parallel across providers, rate-limited within."""
        # 1. Cache check — split cached vs uncached per provider
        # 2. Fan out to providers in parallel (asyncio.gather)
        # 3. Each provider processes its queue sequentially at its rate limit
        # 4. Save all results to cache
        # 5. Return {(ioc_type, value): [EnrichmentResult, ...]}

    def aggregate_risk_score(self, enrichments: list[EnrichmentResult],
                             ioc_type: str) -> int | None:
        """Weighted average risk score by provider confidence."""
        total_weight = 0.0
        weighted_sum = 0.0
        for e in enrichments:
            if e.risk_score is not None:
                conf = e.confidence
                weighted_sum += e.risk_score * conf
                total_weight += conf
        return round(weighted_sum / total_weight) if total_weight > 0 else None
```

## 7. Web API Endpoints (7 new)

```
GET  /api/v1/iocs/correlate?value=X              # single IOC cross-engagement correlation
GET  /api/v1/engagements/{id}/correlations        # all IOC overlaps for an engagement
GET  /api/v1/iocs/common?engagements=id1,id2      # shared IOCs between engagements
GET  /api/v1/iocs/trending?limit=10&days=30       # hot IOCs ranking
GET  /api/v1/iocs/{type}/{value}/timeline         # IOC lifecycle + monthly frequency
GET  /api/v1/iocs/{type}/{value}/enrichment       # cached enrichment (refresh=true to force)
POST /api/v1/iocs/{type}/{value}/enrich           # force fresh enrichment from all providers
```

All endpoints are user-scoped (filter by `current_user.id`). Enrichment cache is per-user.

Response for `/iocs/correlate`:
```json
{
  "ioc_type": "ip",
  "ioc_value": "10.0.0.1",
  "engagement_count": 3,
  "total_occurrences": 5,
  "first_seen_global": "2026-01-15T...",
  "last_seen_global": "2026-04-09T...",
  "active_days": 84,
  "engagements": [
    {"id": "eng-1", "name": "jan-audit", "first_seen": "...", "last_seen": "..."},
    {"id": "eng-2", "name": "mar-pentest", "first_seen": "...", "last_seen": "..."}
  ],
  "enrichments": [
    {"provider": "virustotal", "risk_score": 42, "tags": ["trojan.generic"], "confidence": 0.6},
    {"provider": "abuseipdb", "risk_score": 87, "tags": ["ssh-brute-force"], "confidence": 0.95}
  ],
  "aggregated_risk_score": 70
}
```

## 8. CLI Commands (3 new)

```bash
opentools iocs correlate 10.0.0.1
# Output:
# IOC: 10.0.0.1 (ip)
# Seen in 3 engagements, 5 total occurrences
# Active: 84 days (2026-01-15 to 2026-04-09)
#
# Engagements:
# ┌────────────────┬────────────┬────────────┐
# │ Name           │ First Seen │ Last Seen  │
# ├────────────────┼────────────┼────────────┤
# │ jan-audit      │ 2026-01-15 │ 2026-01-20 │
# │ mar-pentest    │ 2026-03-01 │ 2026-03-15 │
# │ apr-assessment │ 2026-04-05 │ 2026-04-09 │
# └────────────────┴────────────┴────────────┘
#
# Enrichment:
# ┌─────────────┬───────┬───────────────────────┬────────────┐
# │ Provider    │ Score │ Tags                  │ Confidence │
# ├─────────────┼───────┼───────────────────────┼────────────┤
# │ abuseipdb   │ 87    │ ssh-brute-force       │ 0.95       │
# │ virustotal  │ 42    │ trojan.generic        │ 0.60       │
# │ otx         │ 60    │ APT-29 infrastructure │ 0.70       │
# └─────────────┴───────┴───────────────────────┴────────────┘
# Aggregated Risk Score: 70

opentools iocs trending --limit 10 --days 30
# Output:
# Hot IOCs (last 30 days):
# ┌───┬────────┬──────────────────┬────────────┬───────┬────────┐
# │ # │ Type   │ Value            │ Engagements│ Score │ Trend  │
# ├───┼────────┼──────────────────┼────────────┼───────┼────────┤
# │ 1 │ ip     │ 10.0.0.1         │ 3          │ 70    │ rising │
# │ 2 │ domain │ evil.example.com │ 2          │ 85    │ stable │
# └───┴────────┴──────────────────┴────────────┴───────┴────────┘

opentools iocs enrich 10.0.0.1 --type ip
# Fetches fresh enrichment from all providers, displays results
```

## 9. Web Frontend (2 new views + 2 components)

### IOCCorrelationView (`/iocs/correlate`)

- Search input for IOC value
- Results show: engagement list, enrichment cards (one per provider), aggregated risk score
- "Refresh Enrichment" button forces fresh lookup
- Click engagement name → navigate to engagement detail

### IOCTrendingView (`/iocs/trending`)

- Timeframe selector (7d / 30d / 90d / 6m)
- Limit selector (10 / 25 / 50)
- DataTable: type, value, engagement count, aggregated risk score, trend indicator, sparkline
- Click IOC value → navigate to correlation view for that IOC

### IOCEnrichmentCard Component

PrimeVue Card showing provider name, risk score (as progress bar), tags (as Tag components), fetched timestamp, stale indicator. Used in correlation view — one card per provider.

### TrendSparkline Component

Chart.js line chart configured as a sparkline (no axes, no legend, ~40px tall). Shows monthly frequency data as a mini chart. Lazy-loaded with the trending view.

Uses `vue-chartjs` + `chart.js`:
```
npm install chart.js vue-chartjs
```

## 10. Files Summary

### New files in CLI package (packages/cli/)

| File | Purpose |
|------|---------|
| `src/opentools/correlation/__init__.py` | Package init |
| `src/opentools/correlation/engine.py` | Cross-engagement correlation queries |
| `src/opentools/correlation/trending.py` | Frequency, lifecycle, hot-IOCs, trend classification |
| `src/opentools/correlation/enrichment/__init__.py` | Provider registry (auto-discover) |
| `src/opentools/correlation/enrichment/base.py` | EnrichmentProvider ABC + rate limiter |
| `src/opentools/correlation/enrichment/virustotal.py` | VirusTotal provider |
| `src/opentools/correlation/enrichment/abuseipdb.py` | AbuseIPDB provider |
| `src/opentools/correlation/enrichment/otx.py` | OTX provider |
| `src/opentools/correlation/enrichment/manager.py` | EnrichmentManager (batch, cache, aggregate) |
| `tests/test_correlation.py` | Engine + trending tests |
| `tests/test_enrichment.py` | Provider + manager tests (mocked HTTP) |

### Modified CLI files

| File | Change |
|------|--------|
| `src/opentools/models.py` | Add IOCEnrichment, CorrelationResult, TrendingIOC, EnrichmentResult models |
| `src/opentools/cli.py` | Add `iocs correlate`, `iocs trending`, `iocs enrich` commands |

### New/modified web backend files

| File | Change |
|------|--------|
| `app/models.py` | Add IOCEnrichment SQLModel table |
| `app/services/correlation_service.py` | Async wrapper around CorrelationEngine + TrendingEngine |
| `app/routes/correlation.py` | 7 new endpoints |
| `alembic/versions/002_ioc_enrichment.py` | New table + indexes + materialized view |
| `tests/test_correlation.py` | API tests for correlation endpoints |

### New web frontend files

| File | Purpose |
|------|---------|
| `src/views/IOCCorrelationView.vue` | Correlation search + results + enrichment cards |
| `src/views/IOCTrendingView.vue` | Trending dashboard with sparklines |
| `src/components/IOCEnrichmentCard.vue` | Per-provider enrichment display |
| `src/components/TrendSparkline.vue` | Chart.js mini sparkline |

## 11. Testing Strategy

| Area | Tests |
|------|-------|
| Correlation engine | Single IOC lookup, engagement correlation, common IOCs, user scoping |
| Trending engine | Hot IOCs, frequency, lifecycle, trend classification (rising/stable/declining) |
| Enrichment providers | Each provider with mocked HTTP (VT, AbuseIPDB, OTX), risk score normalization, tag extraction |
| Enrichment manager | Cache hit/miss, stale detection, batch parallel execution, aggregate risk score |
| Rate limiting | Token bucket respects provider rate |
| Web API | Correlation endpoint returns correct structure, user isolation, enrichment refresh |
| Frontend | Sparkline renders, enrichment cards display, trending table populates |

CLI tests use in-memory SQLite. Web tests use test Postgres (or SQLite fallback). Enrichment tests mock HTTP responses (no real API calls).
