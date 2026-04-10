"""Tests for correlation and trending engines."""

import sqlite3
from datetime import datetime, timezone, timedelta
import pytest
from opentools.engagement.schema import migrate
from opentools.engagement.store import EngagementStore
from opentools.correlation.engine import CorrelationEngine
from opentools.correlation.trending import TrendingEngine
from opentools.models import Engagement, EngagementType, EngagementStatus, IOC, IOCType


@pytest.fixture
def populated_store():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    migrate(conn)
    store = EngagementStore(conn=conn)

    now = datetime.now(timezone.utc)
    # Three engagements spaced across time
    for i, name in enumerate(["eng-1", "eng-2", "eng-3"]):
        store.create(Engagement(
            id=name, name=f"Engagement {i+1}", target="10.0.0.1",
            type=EngagementType.PENTEST, status=EngagementStatus.COMPLETE,
            created_at=now - timedelta(days=60-i*20), updated_at=now,
        ))

    # Shared IOC across 2 engagements (10.0.0.1)
    store.add_ioc(IOC(id="ioc-1a", engagement_id="eng-1", ioc_type=IOCType.IP,
                       value="10.0.0.1", context="C2",
                       first_seen=now - timedelta(days=60)))
    store.add_ioc(IOC(id="ioc-1b", engagement_id="eng-2", ioc_type=IOCType.IP,
                       value="10.0.0.1", context="C2",
                       first_seen=now - timedelta(days=30)))

    # Unique IOC in eng-3 only
    store.add_ioc(IOC(id="ioc-2", engagement_id="eng-3", ioc_type=IOCType.DOMAIN,
                       value="unique.example.com",
                       first_seen=now - timedelta(days=5)))

    # Shared domain across 3 engagements
    for i, eng in enumerate(["eng-1", "eng-2", "eng-3"]):
        store.add_ioc(IOC(id=f"ioc-d{i}", engagement_id=eng, ioc_type=IOCType.DOMAIN,
                           value="evil.com", context="exfiltration",
                           first_seen=now - timedelta(days=50-i*15),
                           last_seen=now - timedelta(days=50-i*15-1)))
    return store


def test_correlate_single_ioc(populated_store):
    engine = CorrelationEngine(populated_store)
    result = engine.correlate("10.0.0.1")
    assert result.engagement_count == 2
    assert result.ioc_type == "ip"
    assert result.total_occurrences == 2


def test_correlate_not_found(populated_store):
    engine = CorrelationEngine(populated_store)
    result = engine.correlate("nonexistent.example")
    assert result.engagement_count == 0


def test_correlate_shared_across_all_engagements(populated_store):
    engine = CorrelationEngine(populated_store)
    result = engine.correlate("evil.com")
    assert result.engagement_count == 3
    assert result.ioc_type == "domain"


def test_correlate_engagement(populated_store):
    engine = CorrelationEngine(populated_store)
    results = engine.correlate_engagement("eng-1")
    # eng-1 has 10.0.0.1 (shared with eng-2) and evil.com (shared with all 3)
    values = {r.ioc_value for r in results}
    assert "10.0.0.1" in values
    assert "evil.com" in values


def test_find_common_iocs(populated_store):
    engine = CorrelationEngine(populated_store)
    results = engine.find_common_iocs(["eng-1", "eng-2", "eng-3"])
    values = {r.ioc_value for r in results}
    assert "evil.com" in values


def test_hot_iocs(populated_store):
    engine = TrendingEngine(populated_store)
    hot = engine.hot_iocs(limit=5, days=90)
    assert len(hot) > 0
    # evil.com should be top (3 engagements) — but only if within 90 days
    # Check that at least one result is returned
    values = {h.ioc_value for h in hot}
    assert "evil.com" in values or "10.0.0.1" in values


def test_hot_iocs_limit(populated_store):
    engine = TrendingEngine(populated_store)
    hot = engine.hot_iocs(limit=2, days=365)
    assert len(hot) <= 2


def test_lifecycle(populated_store):
    engine = TrendingEngine(populated_store)
    lifecycle = engine.lifecycle("domain", "evil.com")
    assert lifecycle["first_seen"] is not None
    assert lifecycle["last_seen"] is not None
    assert lifecycle["active_days"] >= 0
    assert len(lifecycle["engagements"]) == 3


def test_classify_trend_rising():
    freq = {"2026-01": 1, "2026-02": 2, "2026-03": 5, "2026-04": 8}
    assert TrendingEngine.classify_trend(freq) == "rising"


def test_classify_trend_stable():
    freq = {"2026-01": 3, "2026-02": 3, "2026-03": 3}
    assert TrendingEngine.classify_trend(freq) == "stable"


def test_classify_trend_declining():
    freq = {"2026-01": 10, "2026-02": 8, "2026-03": 3, "2026-04": 1}
    assert TrendingEngine.classify_trend(freq) == "declining"


def test_classify_trend_single_month():
    assert TrendingEngine.classify_trend({"2026-01": 5}) == "stable"


def test_classify_trend_empty():
    assert TrendingEngine.classify_trend({}) == "stable"
