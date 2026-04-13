"""Tests for lazy per-tab data fetching in DashboardState."""

import sqlite3
from datetime import datetime, timezone
from unittest.mock import MagicMock
from uuid import uuid4

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
    for i in range(5):
        store.add_finding(Finding(
            id=str(uuid4()), engagement_id="eng-1", tool="semgrep",
            title=f"Finding {i}", severity=Severity.HIGH, created_at=now,
        ))

    s = DashboardState(store, container_mgr=MagicMock())
    s.selected_id = "eng-1"
    return s


def test_refresh_findings_only(state):
    """When needs={'findings'}, only findings and summary are fetched."""
    state.refresh_selected(needs={"findings"})

    assert len(state.findings) == 5
    assert state.summary is not None
    # Timeline and IOCs should not have been fetched
    assert state.timeline == []
    assert state.iocs == []
    # Docker should not have been called
    state.container_mgr.status.assert_not_called()


def test_refresh_containers_calls_docker(state):
    """When needs={'containers'}, Docker status is called."""
    state.container_mgr.status.return_value = []
    state.refresh_selected(needs={"containers"})

    state.container_mgr.status.assert_called_once()


def test_refresh_all_backward_compatible(state):
    """Default (no needs arg) fetches everything for backward compat."""
    state.container_mgr.status.return_value = []
    state.refresh_selected()

    assert len(state.findings) == 5
    assert state.summary is not None
    state.container_mgr.status.assert_called_once()
