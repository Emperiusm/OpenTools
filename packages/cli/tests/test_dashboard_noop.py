"""Tests for no-op rebuild detection in dashboard tabs."""

import sqlite3
from datetime import datetime, timezone

import pytest

from opentools.engagement.store import EngagementStore
from opentools.dashboard.state import DashboardState
from opentools.models import (
    Engagement,
    EngagementType,
    EngagementStatus,
    Finding,
    Severity,
)


@pytest.fixture
def state():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    store = EngagementStore(conn=conn)
    now = datetime.now(timezone.utc)

    eng = Engagement(
        id="eng-1", name="Test", target="10.0.0.1",
        type=EngagementType.PENTEST, status=EngagementStatus.ACTIVE,
        created_at=now, updated_at=now,
    )
    store.create(eng)
    for i in range(3):
        store.add_finding(Finding(
            id=f"f-{i}", engagement_id="eng-1", tool="semgrep",
            title=f"Finding {i}", severity=Severity.HIGH, created_at=now,
        ))
    s = DashboardState(store)
    s.selected_id = "eng-1"
    s.refresh_selected()
    return s


def test_findings_snapshot_detects_change(state):
    """_data_snapshot should change when findings list changes."""
    from opentools.dashboard.tabs.findings import FindingsTab

    tab = FindingsTab.__new__(FindingsTab)
    tab.state = state
    tab._filter_text = ""
    tab._last_snapshot = None

    snap1 = tab._data_snapshot()
    assert snap1 is not None

    tab._last_snapshot = snap1
    snap2 = tab._data_snapshot()
    assert snap1 == snap2

    # Add a finding and re-snapshot
    state.findings.append(Finding(
        id="f-new", engagement_id="eng-1", tool="nmap",
        title="New finding", severity=Severity.CRITICAL,
        created_at=datetime.now(timezone.utc),
    ))
    snap3 = tab._data_snapshot()
    assert snap3 != snap1
