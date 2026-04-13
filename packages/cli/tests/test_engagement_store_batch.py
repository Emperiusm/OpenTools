"""Tests for EngagementStore.get_sidebar_summaries batch method."""

import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from opentools.engagement.store import EngagementStore
from opentools.models import (
    Engagement,
    EngagementType,
    EngagementStatus,
    Finding,
    Severity,
)


@pytest.fixture
def store():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    return EngagementStore(conn=conn)


@pytest.fixture
def seeded_store(store):
    now = datetime.now(timezone.utc)
    for i in range(3):
        eng = Engagement(
            id=f"eng-{i}",
            name=f"Engagement {i}",
            target=f"10.0.{i}.0",
            type=EngagementType.PENTEST,
            status=EngagementStatus.ACTIVE,
            created_at=now,
            updated_at=now,
        )
        store.create(eng)
        for sev in ["critical", "high", "medium"]:
            finding = Finding(
                id=str(uuid4()),
                engagement_id=f"eng-{i}",
                tool="semgrep",
                title=f"Finding {sev}",
                severity=Severity(sev),
                created_at=now,
            )
            store.add_finding(finding)
    return store


def test_get_sidebar_summaries_returns_all_engagements(seeded_store):
    """Batch method returns one entry per engagement with severity counts."""
    results = seeded_store.get_sidebar_summaries()
    assert len(results) == 3
    for eng_id, critical, high in results:
        assert eng_id.startswith("eng-")
        assert critical == 1
        assert high == 1


def test_get_sidebar_summaries_empty_db(store):
    """Batch method returns empty list for empty database."""
    results = store.get_sidebar_summaries()
    assert results == []
