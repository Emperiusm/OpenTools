"""Tests for the TUI dashboard state management."""

import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from opentools.engagement.schema import migrate
from opentools.engagement.store import EngagementStore
from opentools.models import (
    Engagement,
    EngagementType,
    EngagementStatus,
    Finding,
    FindingStatus,
    Severity,
    IOC,
    IOCType,
)
from opentools.dashboard.state import DashboardState


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def dashboard_state():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    migrate(conn)
    store = EngagementStore(conn=conn)
    return DashboardState(store=store)


@pytest.fixture
def populated_state(dashboard_state):
    now = datetime.now(timezone.utc)
    eng = Engagement(
        id="eng-1",
        name="test-pentest",
        target="10.0.0.1",
        type=EngagementType.PENTEST,
        status=EngagementStatus.ACTIVE,
        skills_used=["pentest"],
        created_at=now,
        updated_at=now,
    )
    dashboard_state.store.create(eng)
    dashboard_state.store.add_finding(Finding(
        id="f-1",
        engagement_id="eng-1",
        tool="semgrep",
        title="SQL Injection",
        severity=Severity.CRITICAL,
        cwe="CWE-89",
        file_path="src/api.py",
        line_start=42,
        created_at=now,
    ))
    dashboard_state.store.add_finding(Finding(
        id="f-2",
        engagement_id="eng-1",
        tool="nuclei",
        title="XSS in search",
        severity=Severity.HIGH,
        cwe="CWE-79",
        created_at=now,
    ))
    dashboard_state.store.add_ioc(IOC(
        id="ioc-1",
        engagement_id="eng-1",
        ioc_type=IOCType.IP,
        value="10.0.0.1",
        context="C2",
    ))
    return dashboard_state


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_state_refresh_engagements(dashboard_state):
    """Create an engagement and verify refresh_engagements loads it."""
    now = datetime.now(timezone.utc)
    eng = Engagement(
        id="eng-r1",
        name="refresh-test",
        target="192.168.0.1",
        type=EngagementType.PENTEST,
        status=EngagementStatus.ACTIVE,
        skills_used=[],
        created_at=now,
        updated_at=now,
    )
    dashboard_state.store.create(eng)

    dashboard_state.refresh_engagements()

    assert len(dashboard_state.engagements) == 1
    assert dashboard_state.engagements[0].name == "refresh-test"


def test_state_refresh_selected(populated_state):
    """Set selected_id, call refresh_selected(), verify findings/iocs/summary."""
    populated_state.selected_id = "eng-1"
    changes = populated_state.refresh_selected()

    assert len(populated_state.findings) == 2
    assert len(populated_state.iocs) == 1
    assert populated_state.summary is not None
    assert populated_state.summary.finding_counts.get("critical", 0) == 1


def test_state_change_detection(populated_state):
    """Adding a new finding after baseline refresh appears in returned changes."""
    populated_state.selected_id = "eng-1"

    # Prime state so findings list is populated (prev_count goes from 0 -> 2)
    populated_state.refresh_selected()

    # Baseline refresh now has prev_count == 2, so no delta expected
    first_changes = populated_state.refresh_selected()
    assert "findings" not in first_changes

    # Add a third finding
    now = datetime.now(timezone.utc)
    populated_state.store.add_finding(Finding(
        id="f-3",
        engagement_id="eng-1",
        tool="bandit",
        title="Command Injection",
        severity=Severity.HIGH,
        cwe="CWE-78",
        created_at=now,
    ))

    # Second refresh should detect new=1
    second_changes = populated_state.refresh_selected()
    assert "findings" in second_changes
    assert second_changes["findings"]["new"] == 1


def test_state_flag_false_positive(populated_state):
    """flag_false_positive marks the finding in the store."""
    populated_state.selected_id = "eng-1"
    populated_state.refresh_selected()

    populated_state.flag_false_positive("f-1")

    findings = populated_state.store.get_findings("eng-1")
    flagged = next((f for f in findings if f.id == "f-1"), None)
    assert flagged is not None
    assert flagged.false_positive is True


def test_state_cycle_finding_status(populated_state):
    """cycle_finding_status advances status: discovered -> confirmed -> reported."""
    populated_state.selected_id = "eng-1"
    populated_state.refresh_selected()

    # First cycle: discovered -> confirmed
    populated_state.cycle_finding_status("f-1")
    # Reload findings to see persisted state
    populated_state.refresh_selected()
    f1 = next(f for f in populated_state.findings if f.id == "f-1")
    assert f1.status == FindingStatus.CONFIRMED

    # Second cycle: confirmed -> reported
    populated_state.cycle_finding_status("f-1")
    populated_state.refresh_selected()
    f1 = next(f for f in populated_state.findings if f.id == "f-1")
    assert f1.status == FindingStatus.REPORTED


def test_state_empty_engagement(dashboard_state):
    """An engagement with no findings/IOCs should still produce a valid summary."""
    now = datetime.now(timezone.utc)
    eng = Engagement(
        id="eng-empty",
        name="empty-engagement",
        target="172.16.0.1",
        type=EngagementType.FORENSICS,
        status=EngagementStatus.ACTIVE,
        skills_used=[],
        created_at=now,
        updated_at=now,
    )
    dashboard_state.store.create(eng)
    dashboard_state.selected_id = "eng-empty"

    dashboard_state.refresh_selected()

    assert dashboard_state.findings == []
    assert dashboard_state.summary is not None


def test_app_constructs():
    """DashboardApp can be instantiated without crashing."""
    from opentools.dashboard.app import DashboardApp

    # ignore_cleanup_errors avoids Windows file-lock errors on the SQLite WAL file
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        db_path = Path(tmp) / "test.db"
        app = DashboardApp(db_path=db_path)
        assert app.TITLE == "OpenTools Dashboard"
