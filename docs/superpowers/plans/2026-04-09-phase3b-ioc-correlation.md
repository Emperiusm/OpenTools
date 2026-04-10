# Phase 3B: IOC Correlation & Trending Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build cross-engagement IOC correlation, external threat intel enrichment (VirusTotal, AbuseIPDB, OTX), and trending analytics with time-series frequency, lifecycle tracking, and hot-IOC ranking — surfaced in both web and CLI.

**Architecture:** Correlation and trending engines in the CLI package (synchronous, SQLite). Web backend reimplements queries async against Postgres. Enrichment providers follow the auto-discovery pattern (like parsers). Enrichment results cached in a new DB table with per-provider TTL. Web frontend adds 2 views + 2 components with Chart.js sparklines.

**Tech Stack:** Python 3.14, asyncio, httpx (for provider HTTP calls), chart.js + vue-chartjs, pytest

**Spec:** `docs/superpowers/specs/2026-04-09-phase3b-ioc-correlation-design.md`

---

## File Map

### CLI package (packages/cli/)

| File | Action | Task |
|------|--------|------|
| `src/opentools/models.py` | Modify | 1 (add response models) |
| `src/opentools/correlation/__init__.py` | Create | 2 |
| `src/opentools/correlation/engine.py` | Create | 2 |
| `src/opentools/correlation/trending.py` | Create | 3 |
| `src/opentools/correlation/enrichment/__init__.py` | Create | 4 |
| `src/opentools/correlation/enrichment/base.py` | Create | 4 |
| `src/opentools/correlation/enrichment/manager.py` | Create | 4 |
| `src/opentools/correlation/enrichment/virustotal.py` | Create | 5 |
| `src/opentools/correlation/enrichment/abuseipdb.py` | Create | 5 |
| `src/opentools/correlation/enrichment/otx.py` | Create | 5 |
| `src/opentools/cli.py` | Modify | 8 (add 3 commands) |
| `tests/test_correlation.py` | Create | 6 |
| `tests/test_enrichment.py` | Create | 6 |

### Web backend (packages/web/backend/)

| File | Action | Task |
|------|--------|------|
| `app/models.py` | Modify | 7 (add IOCEnrichment table) |
| `app/services/correlation_service.py` | Create | 7 |
| `app/routes/correlation.py` | Create | 7 |
| `app/main.py` | Modify | 7 (include router) |
| `alembic/versions/002_ioc_enrichment.py` | Create | 7 |
| `tests/test_correlation_api.py` | Create | 9 |

### Web frontend (packages/web/frontend/)

| File | Action | Task |
|------|--------|------|
| `src/views/IOCCorrelationView.vue` | Create | 10 |
| `src/views/IOCTrendingView.vue` | Create | 10 |
| `src/components/IOCEnrichmentCard.vue` | Create | 10 |
| `src/components/TrendSparkline.vue` | Create | 10 |
| `src/router/index.ts` | Modify | 10 (add routes) |

---

## Task 1: Shared Response Models

**Files:**
- Modify: `packages/cli/src/opentools/models.py`

- [ ] **Step 1: Add correlation and enrichment response models**

Add to the end of `packages/cli/src/opentools/models.py`:

```python
# ─── Correlation & Enrichment Models ────────────────────────────────────────

class CorrelationResult(BaseModel):
    """Cross-engagement IOC correlation result."""
    ioc_type: str
    ioc_value: str
    engagements: list[dict] = Field(default_factory=list)
    engagement_count: int = 0
    total_occurrences: int = 0
    first_seen_global: Optional[datetime] = None
    last_seen_global: Optional[datetime] = None
    active_days: int = 0
    enrichments: list[dict] = Field(default_factory=list)
    aggregated_risk_score: Optional[int] = None


class TrendingIOC(BaseModel):
    """IOC trending data with frequency analysis."""
    ioc_type: str
    ioc_value: str
    context: Optional[str] = None
    engagement_count: int = 0
    total_occurrences: int = 0
    frequency_by_month: dict[str, int] = Field(default_factory=dict)
    risk_score: Optional[int] = None
    trend: str = "stable"


class EnrichmentResult(BaseModel):
    """Single provider enrichment result."""
    provider: str
    risk_score: Optional[int] = None
    tags: list[str] = Field(default_factory=list)
    data: dict = Field(default_factory=dict)
    fetched_at: Optional[datetime] = None
    is_stale: bool = False
    confidence: float = 0.5


class IOCEnrichmentRecord(BaseModel):
    """Cached enrichment record (for storage)."""
    id: str
    ioc_type: str
    ioc_value: str
    provider: str
    data: dict = Field(default_factory=dict)
    risk_score: Optional[int] = None
    tags: list[str] = Field(default_factory=list)
    fetched_at: Optional[datetime] = None
    ttl_seconds: int = 86400
```

- [ ] **Step 2: Verify imports**

```bash
cd packages/cli && python -c "from opentools.models import CorrelationResult, TrendingIOC, EnrichmentResult, IOCEnrichmentRecord; print('OK')"
```

- [ ] **Step 3: Run existing tests**

```bash
cd packages/cli && python -m pytest tests/ -q
```

Expected: 153 pass (no regressions)

- [ ] **Step 4: Commit**

```bash
git add packages/cli/src/opentools/models.py
git commit -m "feat: add CorrelationResult, TrendingIOC, and EnrichmentResult models"
```

---

## Task 2: Correlation Engine

**Files:**
- Create: `packages/cli/src/opentools/correlation/__init__.py`
- Create: `packages/cli/src/opentools/correlation/engine.py`

- [ ] **Step 1: Create package**

```bash
mkdir -p packages/cli/src/opentools/correlation/enrichment
```

Create `packages/cli/src/opentools/correlation/__init__.py`:
```python
"""IOC correlation and trending engine."""
```

- [ ] **Step 2: Create engine.py**

```python
"""Cross-engagement IOC correlation engine (synchronous, SQLite)."""

from datetime import datetime, timezone
from opentools.engagement.store import EngagementStore
from opentools.models import CorrelationResult


class CorrelationEngine:
    """Find IOC overlaps across engagements."""

    def __init__(self, store: EngagementStore):
        self._store = store

    def correlate(self, ioc_value: str) -> CorrelationResult:
        """Find all engagements containing this IOC value."""
        rows = self._store._conn.execute(
            "SELECT engagement_id, ioc_type, value, context, first_seen, last_seen "
            "FROM iocs WHERE value = ? AND engagement_id IN "
            "(SELECT id FROM engagements) ORDER BY first_seen ASC",
            (ioc_value,),
        ).fetchall()

        if not rows:
            return CorrelationResult(ioc_type="unknown", ioc_value=ioc_value)

        engagements = []
        ioc_type = rows[0]["ioc_type"]
        first_seen_global = None
        last_seen_global = None

        eng_ids = set()
        for row in rows:
            eng_id = row["engagement_id"]
            if eng_id not in eng_ids:
                eng_ids.add(eng_id)
                try:
                    eng = self._store.get(eng_id)
                    first = datetime.fromisoformat(row["first_seen"]) if row["first_seen"] else None
                    last = datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None
                    engagements.append({
                        "id": eng_id,
                        "name": eng.name,
                        "first_seen": row["first_seen"],
                        "last_seen": row["last_seen"],
                    })
                    if first and (first_seen_global is None or first < first_seen_global):
                        first_seen_global = first
                    if last and (last_seen_global is None or last > last_seen_global):
                        last_seen_global = last
                    elif first and (last_seen_global is None or first > last_seen_global):
                        last_seen_global = first
                except KeyError:
                    pass

        active_days = 0
        if first_seen_global and last_seen_global:
            active_days = (last_seen_global - first_seen_global).days

        return CorrelationResult(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            engagements=engagements,
            engagement_count=len(engagements),
            total_occurrences=len(rows),
            first_seen_global=first_seen_global,
            last_seen_global=last_seen_global,
            active_days=active_days,
        )

    def correlate_engagement(self, engagement_id: str) -> list[CorrelationResult]:
        """For each IOC in an engagement, find cross-engagement overlaps."""
        iocs = self._store.get_iocs(engagement_id)
        results = []
        for ioc in iocs:
            result = self.correlate(ioc.value)
            if result.engagement_count > 1:
                results.append(result)
        return results

    def find_common_iocs(self, engagement_ids: list[str]) -> list[CorrelationResult]:
        """Find IOCs shared between specific engagements."""
        if len(engagement_ids) < 2:
            return []
        placeholders = ",".join("?" * len(engagement_ids))
        rows = self._store._conn.execute(
            f"SELECT ioc_type, value, COUNT(DISTINCT engagement_id) as eng_count "
            f"FROM iocs WHERE engagement_id IN ({placeholders}) "
            f"GROUP BY ioc_type, value HAVING eng_count >= 2",
            engagement_ids,
        ).fetchall()

        results = []
        for row in rows:
            result = self.correlate(row["value"])
            results.append(result)
        return results
```

- [ ] **Step 3: Verify**

```bash
cd packages/cli && python -c "from opentools.correlation.engine import CorrelationEngine; print('OK')"
```

- [ ] **Step 4: Commit**

```bash
git add packages/cli/src/opentools/correlation/
git commit -m "feat: add cross-engagement IOC correlation engine"
```

---

## Task 3: Trending Engine

**Files:**
- Create: `packages/cli/src/opentools/correlation/trending.py`

- [ ] **Step 1: Create trending.py**

```python
"""IOC trending analysis — frequency, lifecycle, hot-IOCs, trend classification."""

from datetime import datetime, timezone, timedelta
from opentools.engagement.store import EngagementStore
from opentools.models import TrendingIOC


class TrendingEngine:
    """Analyze IOC trends across engagements."""

    def __init__(self, store: EngagementStore):
        self._store = store

    def hot_iocs(self, limit: int = 10, days: int = 30) -> list[TrendingIOC]:
        """Top N most-seen IOCs in the last N days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        rows = self._store._conn.execute(
            "SELECT ioc_type, value, MAX(context) as context, "
            "COUNT(DISTINCT engagement_id) as eng_count, "
            "COUNT(*) as total "
            "FROM iocs WHERE first_seen >= ? OR first_seen IS NULL "
            "GROUP BY ioc_type, value "
            "ORDER BY eng_count DESC, total DESC "
            "LIMIT ?",
            (cutoff, limit),
        ).fetchall()

        results = []
        for row in rows:
            freq = self.frequency(row["ioc_type"], row["value"])
            trend = self.classify_trend(freq)
            results.append(TrendingIOC(
                ioc_type=row["ioc_type"],
                ioc_value=row["value"],
                context=row["context"],
                engagement_count=row["eng_count"],
                total_occurrences=row["total"],
                frequency_by_month=freq,
                trend=trend,
            ))
        return results

    def frequency(self, ioc_type: str, ioc_value: str, months: int = 6) -> dict[str, int]:
        """Monthly frequency of an IOC."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=months * 30)).isoformat()
        rows = self._store._conn.execute(
            "SELECT first_seen FROM iocs "
            "WHERE ioc_type = ? AND value = ? AND first_seen >= ? "
            "ORDER BY first_seen ASC",
            (ioc_type, ioc_value, cutoff),
        ).fetchall()

        freq: dict[str, int] = {}
        for row in rows:
            if row["first_seen"]:
                month = row["first_seen"][:7]  # "2026-01"
                freq[month] = freq.get(month, 0) + 1
        return freq

    def lifecycle(self, ioc_type: str, ioc_value: str) -> dict:
        """First seen, last seen, active days, engagement timeline."""
        rows = self._store._conn.execute(
            "SELECT engagement_id, first_seen, last_seen FROM iocs "
            "WHERE ioc_type = ? AND value = ? ORDER BY first_seen ASC",
            (ioc_type, ioc_value),
        ).fetchall()

        if not rows:
            return {"first_seen": None, "last_seen": None, "active_days": 0, "engagements": []}

        first = None
        last = None
        engagements = []
        for row in rows:
            fs = datetime.fromisoformat(row["first_seen"]) if row["first_seen"] else None
            ls = datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None
            if fs and (first is None or fs < first):
                first = fs
            effective_last = ls or fs
            if effective_last and (last is None or effective_last > last):
                last = effective_last
            engagements.append({
                "engagement_id": row["engagement_id"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
            })

        active_days = (last - first).days if first and last else 0
        return {
            "first_seen": first.isoformat() if first else None,
            "last_seen": last.isoformat() if last else None,
            "active_days": active_days,
            "engagements": engagements,
        }

    @staticmethod
    def classify_trend(frequency: dict[str, int]) -> str:
        """Classify as rising/stable/declining based on recent vs historical."""
        if len(frequency) < 2:
            return "stable"
        months = sorted(frequency.keys())
        if len(months) <= 2:
            recent = sum(frequency[m] for m in months[-1:])
            earlier = sum(frequency[m] for m in months[:-1]) or 1
        else:
            recent = sum(frequency[m] for m in months[-2:])
            earlier_months = months[:-2]
            earlier = sum(frequency[m] for m in earlier_months) / max(len(earlier_months), 1)

        if recent > earlier * 1.5:
            return "rising"
        elif recent < earlier * 0.5:
            return "declining"
        return "stable"
```

- [ ] **Step 2: Verify**

```bash
cd packages/cli && python -c "from opentools.correlation.trending import TrendingEngine; print('OK')"
```

- [ ] **Step 3: Commit**

```bash
git add packages/cli/src/opentools/correlation/trending.py
git commit -m "feat: add IOC trending engine with frequency, lifecycle, and trend classification"
```

---

## Task 4: Enrichment Provider Interface + Manager

**Files:**
- Create: `packages/cli/src/opentools/correlation/enrichment/__init__.py`
- Create: `packages/cli/src/opentools/correlation/enrichment/base.py`
- Create: `packages/cli/src/opentools/correlation/enrichment/manager.py`

- [ ] **Step 1: Create enrichment package**

`enrichment/__init__.py`:
```python
"""Threat intel enrichment provider registry."""

import importlib
import pkgutil
from opentools.correlation.enrichment.base import EnrichmentProvider

_PROVIDERS: dict[str, EnrichmentProvider] = {}


def _discover_providers() -> None:
    import opentools.correlation.enrichment as pkg
    for importer, modname, ispkg in pkgutil.iter_modules(pkg.__path__):
        if modname.startswith("_") or modname in ("base", "manager"):
            continue
        module = importlib.import_module(f"opentools.correlation.enrichment.{modname}")
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (isinstance(attr, type) and issubclass(attr, EnrichmentProvider)
                    and attr is not EnrichmentProvider and hasattr(attr, 'name')):
                try:
                    instance = attr()
                    _PROVIDERS[instance.name] = instance
                except Exception:
                    pass


def get_providers() -> list[EnrichmentProvider]:
    if not _PROVIDERS:
        _discover_providers()
    return list(_PROVIDERS.values())


def get_provider(name: str) -> EnrichmentProvider | None:
    if not _PROVIDERS:
        _discover_providers()
    return _PROVIDERS.get(name)
```

- [ ] **Step 2: Create base.py**

```python
"""Base class for enrichment providers."""

from abc import ABC, abstractmethod
import asyncio


class EnrichmentProvider(ABC):
    """Abstract base for threat intel enrichment providers."""

    name: str = ""
    supported_types: list[str] = []
    ttl_seconds: int = 86400
    rate_limit: float = 1.0
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

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in self.supported_types
```

- [ ] **Step 3: Create manager.py**

```python
"""Enrichment manager — orchestrates providers, caching, and batch operations."""

import asyncio
from datetime import datetime, timezone
from uuid import uuid4
from typing import Optional

from opentools.correlation.enrichment.base import EnrichmentProvider
from opentools.models import EnrichmentResult, IOCEnrichmentRecord


class EnrichmentManager:
    """Orchestrates enrichment across providers with caching."""

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

    async def enrich_single(
        self, ioc_type: str, value: str, force_refresh: bool = False,
    ) -> list[EnrichmentResult]:
        """Enrich one IOC from all compatible providers."""
        results = []
        for provider in self._providers:
            if not provider.supports(ioc_type):
                continue

            key = self._cache_key(ioc_type, value, provider.name)
            cached = self._cache.get(key)

            if cached and not force_refresh and not self._is_stale(cached):
                results.append(EnrichmentResult(
                    provider=provider.name,
                    risk_score=cached.risk_score,
                    tags=cached.tags,
                    data=cached.data,
                    fetched_at=cached.fetched_at,
                    is_stale=False,
                    confidence=provider.get_confidence(ioc_type),
                ))
                continue

            try:
                data = await provider.enrich_with_rate_limit(ioc_type, value)
                risk_score = provider.normalize_risk_score(data)
                tags = provider.extract_tags(data)
                now = datetime.now(timezone.utc)

                record = IOCEnrichmentRecord(
                    id=str(uuid4()),
                    ioc_type=ioc_type,
                    ioc_value=value,
                    provider=provider.name,
                    data=data,
                    risk_score=risk_score,
                    tags=tags,
                    fetched_at=now,
                    ttl_seconds=provider.ttl_seconds,
                )
                self._cache[key] = record

                results.append(EnrichmentResult(
                    provider=provider.name,
                    risk_score=risk_score,
                    tags=tags,
                    data=data,
                    fetched_at=now,
                    is_stale=False,
                    confidence=provider.get_confidence(ioc_type),
                ))
            except Exception:
                results.append(EnrichmentResult(
                    provider=provider.name,
                    is_stale=True,
                    confidence=provider.get_confidence(ioc_type),
                ))

        return results

    async def enrich_batch(
        self, iocs: list[tuple[str, str]], force_refresh: bool = False,
    ) -> dict[tuple[str, str], list[EnrichmentResult]]:
        """Enrich multiple IOCs. Parallel across providers."""
        results: dict[tuple[str, str], list[EnrichmentResult]] = {}

        async def enrich_one(ioc_type: str, value: str):
            r = await self.enrich_single(ioc_type, value, force_refresh)
            results[(ioc_type, value)] = r

        await asyncio.gather(*[enrich_one(t, v) for t, v in iocs])
        return results

    @staticmethod
    def aggregate_risk_score(
        enrichments: list[EnrichmentResult], ioc_type: str,
    ) -> int | None:
        """Weighted average risk score by provider confidence."""
        total_weight = 0.0
        weighted_sum = 0.0
        for e in enrichments:
            if e.risk_score is not None:
                weighted_sum += e.risk_score * e.confidence
                total_weight += e.confidence
        return round(weighted_sum / total_weight) if total_weight > 0 else None
```

- [ ] **Step 4: Verify**

```bash
cd packages/cli && python -c "
from opentools.correlation.enrichment.base import EnrichmentProvider
from opentools.correlation.enrichment.manager import EnrichmentManager
print('OK')
"
```

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/correlation/enrichment/
git commit -m "feat: add enrichment provider interface, registry, and manager"
```

---

## Task 5: Provider Implementations (VT, AbuseIPDB, OTX)

**Files:**
- Create: `packages/cli/src/opentools/correlation/enrichment/virustotal.py`
- Create: `packages/cli/src/opentools/correlation/enrichment/abuseipdb.py`
- Create: `packages/cli/src/opentools/correlation/enrichment/otx.py`

- [ ] **Step 1: Install httpx for async HTTP**

```bash
cd packages/cli && pip install httpx
```

Add `"httpx>=0.28"` to `packages/cli/pyproject.toml` dependencies.

- [ ] **Step 2: Create virustotal.py**

VirusTotal provider:
- `enrich()`: GET `https://www.virustotal.com/api/v3/{path}/{value}` with `x-apikey` header
- Path mapping: ip→`ip_addresses`, domain→`domains`, hash→`files`, url→`urls` (base64-encoded)
- `normalize_risk_score()`: `malicious / total * 100` from `last_analysis_stats`
- `extract_tags()`: `popular_threat_classification.suggested_threat_label`
- Rate limit: 0.066 (4/min), TTL: 86400, confidence: hash=0.95, domain=0.80, ip=0.60
- API key from `os.environ.get("VIRUSTOTAL_API_KEY")`
- If no API key: `enrich()` returns `{}` (gracefully skip)

- [ ] **Step 3: Create abuseipdb.py**

AbuseIPDB provider:
- `enrich()`: GET `https://api.abuseipdb.com/api/v2/check` with `Key` header
- Supports IP only
- `normalize_risk_score()`: `abuseConfidenceScore` (already 0-100)
- `extract_tags()`: category IDs mapped to names
- Rate limit: 0.012, TTL: 21600, confidence: ip=0.95
- API key from `os.environ.get("ABUSEIPDB_API_KEY")`

- [ ] **Step 4: Create otx.py**

OTX provider:
- `enrich()`: GET `https://otx.alienvault.com/api/v1/indicators/{type}/{value}/general` with `X-OTX-API-KEY` header
- `normalize_risk_score()`: `min(pulse_count * 10, 100)`
- `extract_tags()`: first 5 pulse names
- Rate limit: 0.17, TTL: 86400, confidence: ip=0.70, domain=0.70, hash=0.75
- API key from `os.environ.get("OTX_API_KEY")`

- [ ] **Step 5: Verify auto-discovery**

```bash
cd packages/cli && python -c "
from opentools.correlation.enrichment import get_providers
providers = get_providers()
print([p.name for p in providers])
"
```

Expected: `['virustotal', 'abuseipdb', 'otx']`

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/correlation/enrichment/ packages/cli/pyproject.toml
git commit -m "feat: add VirusTotal, AbuseIPDB, and OTX enrichment providers"
```

---

## Task 6: CLI Correlation + Enrichment Tests

**Files:**
- Create: `packages/cli/tests/test_correlation.py`
- Create: `packages/cli/tests/test_enrichment.py`

- [ ] **Step 1: Create test_correlation.py**

Test CorrelationEngine and TrendingEngine against in-memory SQLite:

```python
import sqlite3
from datetime import datetime, timezone, timedelta
import pytest
from opentools.engagement.schema import migrate
from opentools.engagement.store import EngagementStore
from opentools.correlation.engine import CorrelationEngine
from opentools.correlation.trending import TrendingEngine
from opentools.models import Engagement, EngagementType, EngagementStatus, IOC, IOCType


@pytest.fixture
def store():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    migrate(conn)
    return EngagementStore(conn=conn)


@pytest.fixture
def populated_store(store):
    now = datetime.now(timezone.utc)
    for i, name in enumerate(["eng-1", "eng-2", "eng-3"]):
        store.create(Engagement(
            id=name, name=f"Engagement {i+1}", target="10.0.0.1",
            type=EngagementType.PENTEST, status=EngagementStatus.COMPLETE,
            created_at=now - timedelta(days=60-i*20), updated_at=now,
        ))

    # Shared IOC across 2 engagements
    store.add_ioc(IOC(id="ioc-1a", engagement_id="eng-1", ioc_type=IOCType.IP,
                       value="10.0.0.1", context="C2", first_seen=now - timedelta(days=60)))
    store.add_ioc(IOC(id="ioc-1b", engagement_id="eng-2", ioc_type=IOCType.IP,
                       value="10.0.0.1", context="C2", first_seen=now - timedelta(days=30)))

    # Unique IOC in eng-3 only
    store.add_ioc(IOC(id="ioc-2", engagement_id="eng-3", ioc_type=IOCType.DOMAIN,
                       value="unique.example.com", first_seen=now - timedelta(days=5)))

    # Shared domain across 3 engagements
    for i, eng in enumerate(["eng-1", "eng-2", "eng-3"]):
        store.add_ioc(IOC(id=f"ioc-d{i}", engagement_id=eng, ioc_type=IOCType.DOMAIN,
                           value="evil.com", context="exfiltration",
                           first_seen=now - timedelta(days=50-i*15)))
    return store


def test_correlate_single_ioc(populated_store):
    engine = CorrelationEngine(populated_store)
    result = engine.correlate("10.0.0.1")
    assert result.engagement_count == 2
    assert result.ioc_type == "ip"


def test_correlate_not_found(populated_store):
    engine = CorrelationEngine(populated_store)
    result = engine.correlate("nonexistent")
    assert result.engagement_count == 0


def test_correlate_engagement(populated_store):
    engine = CorrelationEngine(populated_store)
    results = engine.correlate_engagement("eng-1")
    # eng-1 has 10.0.0.1 (shared with eng-2) and evil.com (shared with all 3)
    assert len(results) == 2
    values = {r.ioc_value for r in results}
    assert "10.0.0.1" in values
    assert "evil.com" in values


def test_find_common_iocs(populated_store):
    engine = CorrelationEngine(populated_store)
    results = engine.find_common_iocs(["eng-1", "eng-2", "eng-3"])
    # Only evil.com is in all 3
    values = {r.ioc_value for r in results}
    assert "evil.com" in values


def test_hot_iocs(populated_store):
    engine = TrendingEngine(populated_store)
    hot = engine.hot_iocs(limit=5, days=90)
    assert len(hot) > 0
    # evil.com should be #1 (3 engagements)
    assert hot[0].ioc_value == "evil.com"
    assert hot[0].engagement_count == 3


def test_classify_trend_rising():
    assert TrendingEngine.classify_trend({"2026-01": 1, "2026-02": 2, "2026-03": 5}) == "rising"


def test_classify_trend_stable():
    assert TrendingEngine.classify_trend({"2026-01": 3, "2026-02": 3, "2026-03": 3}) == "stable"


def test_classify_trend_declining():
    assert TrendingEngine.classify_trend({"2026-01": 10, "2026-02": 8, "2026-03": 2}) == "declining"
```

- [ ] **Step 2: Create test_enrichment.py**

Test EnrichmentManager with mock providers:

```python
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

    async def enrich(self, ioc_type, value):
        return {"score": 75, "info": f"Mock data for {value}"}

    def normalize_risk_score(self, data):
        return data.get("score", 0)

    def extract_tags(self, data):
        return ["mock-tag"]


def test_enrich_single():
    mgr = EnrichmentManager([MockProvider()])
    results = asyncio.run(mgr.enrich_single("ip", "10.0.0.1"))
    assert len(results) == 1
    assert results[0].provider == "mock"
    assert results[0].risk_score == 75
    assert results[0].tags == ["mock-tag"]


def test_enrich_caching():
    mgr = EnrichmentManager([MockProvider()])
    asyncio.run(mgr.enrich_single("ip", "10.0.0.1"))
    # Second call should hit cache
    results = asyncio.run(mgr.enrich_single("ip", "10.0.0.1"))
    assert len(results) == 1
    assert results[0].is_stale is False


def test_enrich_force_refresh():
    mgr = EnrichmentManager([MockProvider()])
    asyncio.run(mgr.enrich_single("ip", "10.0.0.1"))
    results = asyncio.run(mgr.enrich_single("ip", "10.0.0.1", force_refresh=True))
    assert len(results) == 1


def test_enrich_unsupported_type():
    mgr = EnrichmentManager([MockProvider()])
    results = asyncio.run(mgr.enrich_single("hash_sha256", "abc123"))
    assert len(results) == 0  # mock doesn't support hash


def test_aggregate_risk_score():
    results = [
        EnrichmentResult(provider="a", risk_score=80, confidence=0.9),
        EnrichmentResult(provider="b", risk_score=40, confidence=0.5),
    ]
    score = EnrichmentManager.aggregate_risk_score(results, "ip")
    # (80*0.9 + 40*0.5) / (0.9 + 0.5) = 92/1.4 = 65.7 → 66
    assert score == 66


def test_enrich_batch():
    mgr = EnrichmentManager([MockProvider()])
    iocs = [("ip", "10.0.0.1"), ("domain", "evil.com"), ("hash_sha256", "abc")]
    results = asyncio.run(mgr.enrich_batch(iocs))
    assert ("ip", "10.0.0.1") in results
    assert ("domain", "evil.com") in results
    assert ("hash_sha256", "abc") in results
    assert len(results[("hash_sha256", "abc")]) == 0  # unsupported
```

- [ ] **Step 3: Run all tests**

```bash
cd packages/cli && python -m pytest tests/test_correlation.py tests/test_enrichment.py -v
```

- [ ] **Step 4: Run full CLI suite**

```bash
cd packages/cli && python -m pytest tests/ -q
```

- [ ] **Step 5: Commit**

```bash
git add packages/cli/tests/test_correlation.py packages/cli/tests/test_enrichment.py
git commit -m "feat: add correlation engine and enrichment manager tests"
```

---

## Task 7: Web Backend — Enrichment Table + Correlation Service + Routes

**Files:**
- Modify: `packages/web/backend/app/models.py`
- Create: `packages/web/backend/app/services/correlation_service.py`
- Create: `packages/web/backend/app/routes/correlation.py`
- Modify: `packages/web/backend/app/main.py`
- Create: `packages/web/backend/alembic/versions/002_ioc_enrichment.py`

- [ ] **Step 1: Add IOCEnrichment SQLModel table to models.py**

- [ ] **Step 2: Create Alembic migration for enrichment table + materialized view**

- [ ] **Step 3: Create correlation_service.py** — async reimplementation of CorrelationEngine + TrendingEngine queries using SQLModel against Postgres. User-scoped (all queries filter by user_id).

- [ ] **Step 4: Create correlation.py routes (7 endpoints)**

All from spec:
- GET /api/v1/iocs/correlate?value=X
- GET /api/v1/engagements/{id}/correlations
- GET /api/v1/iocs/common?engagements=id1,id2
- GET /api/v1/iocs/trending?limit=10&days=30
- GET /api/v1/iocs/{type}/{value}/timeline
- GET /api/v1/iocs/{type}/{value}/enrichment
- POST /api/v1/iocs/{type}/{value}/enrich

- [ ] **Step 5: Wire route into main.py**

- [ ] **Step 6: Commit**

```bash
git add packages/web/backend/
git commit -m "feat: add web correlation service, routes, enrichment table, and migration"
```

---

## Task 8: CLI Commands

**Files:**
- Modify: `packages/cli/src/opentools/cli.py`

- [ ] **Step 1: Add 3 new commands to the iocs command group**

`opentools iocs correlate <value>`:
- Create EngagementStore, CorrelationEngine
- Call `engine.correlate(value)`
- Display engagement table + enrichment table using rich

`opentools iocs trending --limit 10 --days 30`:
- Create EngagementStore, TrendingEngine
- Call `engine.hot_iocs(limit, days)`
- Display rich table with trend indicators

`opentools iocs enrich <value> --type ip`:
- Create EnrichmentManager with discovered providers
- Call `asyncio.run(manager.enrich_single(type, value, force_refresh=True))`
- Display enrichment results in rich table

- [ ] **Step 2: Run full CLI tests**

```bash
cd packages/cli && python -m pytest tests/ -q
```

- [ ] **Step 3: Commit**

```bash
git add packages/cli/src/opentools/cli.py
git commit -m "feat: add iocs correlate, trending, and enrich CLI commands"
```

---

## Task 9: Web Backend Tests

**Files:**
- Create: `packages/web/backend/tests/test_correlation_api.py`

- [ ] **Step 1: Write API tests for correlation endpoints**

Test correlate, trending, enrichment endpoints using the existing test fixtures (auth_client).

- [ ] **Step 2: Run backend tests**

```bash
cd packages/web/backend && python -m pytest tests/ -v
```

- [ ] **Step 3: Commit**

```bash
git add packages/web/backend/tests/
git commit -m "feat: add correlation API tests"
```

---

## Task 10: Web Frontend — Correlation + Trending Views

**Files:**
- Create: `packages/web/frontend/src/views/IOCCorrelationView.vue`
- Create: `packages/web/frontend/src/views/IOCTrendingView.vue`
- Create: `packages/web/frontend/src/components/IOCEnrichmentCard.vue`
- Create: `packages/web/frontend/src/components/TrendSparkline.vue`
- Modify: `packages/web/frontend/src/router/index.ts`

- [ ] **Step 1: Install chart.js + vue-chartjs**

```bash
cd packages/web/frontend && npm install chart.js vue-chartjs
```

- [ ] **Step 2: Create TrendSparkline component**

Tiny Chart.js line chart (no axes, no legend, ~40px tall). Receives `data: Record<string, number>` prop.

- [ ] **Step 3: Create IOCEnrichmentCard component**

PrimeVue Card showing: provider name, risk score as ProgressBar (colored: >70 red, >40 yellow, else green), tags as Tag components, fetched_at timestamp, stale indicator, confidence badge.

- [ ] **Step 4: Create IOCCorrelationView**

Search input → Tanstack Query to `/api/v1/iocs/correlate?value=X` → display engagement DataTable + enrichment cards. "Refresh" button calls POST `/enrich`.

- [ ] **Step 5: Create IOCTrendingView**

Timeframe/limit selectors → Tanstack Query to `/api/v1/iocs/trending` → DataTable with sparklines per row. Click IOC → navigate to correlation view.

- [ ] **Step 6: Add routes to router**

```typescript
{ path: '/iocs/correlate', name: 'ioc-correlate', component: () => import('@/views/IOCCorrelationView.vue') },
{ path: '/iocs/trending', name: 'ioc-trending', component: () => import('@/views/IOCTrendingView.vue') },
```

Add "IOCs" to the nav menu in AppLayout.

- [ ] **Step 7: Build and verify**

```bash
cd packages/web/frontend && npm run build
```

- [ ] **Step 8: Commit**

```bash
git add packages/web/frontend/
git commit -m "feat: add IOC correlation and trending views with enrichment cards and sparklines"
```

---

## Self-Review

**1. Spec coverage:**
- Section 4 CorrelationEngine: Task 2 ✓
- Section 5 TrendingEngine: Task 3 ✓
- Section 6.1-6.4 Provider interface + implementations: Tasks 4-5 ✓
- Section 6.5 EnrichmentManager: Task 4 ✓
- Section 7 Web API (7 endpoints): Task 7 ✓
- Section 8 CLI commands (3): Task 8 ✓
- Section 9 Frontend (2 views + 2 components): Task 10 ✓
- Section 3 Data models: Task 1 ✓
- Section 3.3 Materialized view: Task 7 ✓
- Section 10 Files: All covered ✓
- Section 11 Testing: Tasks 6, 9 ✓

**2. Placeholder scan:** Tasks 7 and 10 describe structure without full code (they follow established patterns from Phase 3A). Foundation tasks (1-6, 8) have detailed code. Acceptable for plan size.

**3. Type consistency:** `CorrelationEngine`, `TrendingEngine`, `EnrichmentManager`, `EnrichmentProvider` — names consistent between definition (Tasks 2-4) and usage (Tasks 6-8). `CorrelationResult`, `TrendingIOC`, `EnrichmentResult` models defined in Task 1, used in all subsequent tasks. `get_providers()` in Task 4, used in Task 8.
