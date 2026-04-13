# Performance Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the top CPU bottlenecks identified by cProfile profiling across the scan engine, TUI dashboard, and backend pipeline.

**Architecture:** Five independent optimization targets. (1) Cache YAML profile parsing so the same file is never parsed twice. (2) Eliminate N+1 queries in the sidebar. (3) Only refresh the visible tab, not all four. (4) Memoize CWE alias resolution. (5) Lazy data fetching — only query SQLite/Docker for what the visible tab needs, skip entirely when data hasn't changed. (6) Skip no-op table rebuilds and sidebar reflows when the underlying data hasn't changed. Tasks 1-4 have no ordering dependencies. Task 5 depends on Task 3. Task 6 depends on Tasks 2 and 5.

**Tech Stack:** Python 3.12+, Pydantic v2, SQLite, Textual, PyYAML, functools.lru_cache

---

## Profiling Evidence (summary)

| Subsystem | Bottleneck | Impact |
|-----------|-----------|--------|
| Scan Engine | `yaml.safe_load()` called per `api.plan()` — never cached | 73% of engine runtime (1.08s / 1.56s) |
| TUI Dashboard | `get_summary()` N+1 (7 SQL queries * N engagements per refresh) | 700 calls / 100 refreshes = 4,200 SQL execs |
| TUI Dashboard | `table.clear()` + full rebuild on ALL tabs every 3s | 16,300 Pydantic `model_construct` calls / 100 refreshes |
| TUI Dashboard | `refresh_selected()` fetches ALL data every 3s (findings, timeline, IOCs, Docker) regardless of what's visible | 6,706 SQL executions + Docker HTTP per 100 refreshes |
| TUI Dashboard | `table.clear()` + rebuild even when data hasn't changed (no-op rebuild) | Full Textual layout reflow on every tick |
| TUI Dashboard | Rich markup strings rebuilt from scratch every cycle — no caching | String concatenation + Rich parsing per row per tick |
| Backend Pipeline | `CWEHierarchy.resolve_alias()` full dict scan fallback | 4,000 calls, 0.042s cumulative (per-call overhead compounds at scale) |

---

## File Structure

| File | Role | Task |
|------|------|------|
| `packages/cli/src/opentools/scanner/profiles.py` | Add `@lru_cache` to `load_builtin_profile` | Task 1 |
| `packages/cli/tests/test_scanner/test_profiles.py` | Test that caching works and returns identical objects | Task 1 |
| `packages/cli/src/opentools/engagement/store.py` | Add `get_summaries_batch()` method | Task 2 |
| `packages/cli/tests/test_engagement_store_batch.py` | Test batch summary query | Task 2 |
| `packages/cli/src/opentools/dashboard/sidebar.py` | Use batch summary, skip offscreen tabs | Task 3 |
| `packages/cli/src/opentools/dashboard/app.py` | Only refresh visible tab | Task 3 |
| `packages/cli/src/opentools/dashboard/state.py` | Add `refresh_selected_lazy()` with change detection | Task 3 |
| `packages/cli/tests/test_dashboard.py` | Test selective refresh behavior | Task 3 |
| `packages/cli/src/opentools/scanner/cwe.py` | Pre-build lowercase alias index in `__init__` | Task 4 |
| `packages/cli/tests/test_scanner/test_cwe.py` | Test alias resolution still works | Task 4 |
| `packages/cli/src/opentools/dashboard/state.py` | Lazy per-tab data fetching + skip Docker when Containers tab inactive | Task 5 |
| `packages/cli/src/opentools/dashboard/app.py` | Pass active tab ID to refresh worker | Task 5 |
| `packages/cli/tests/test_dashboard_lazy.py` | Test that only the needed data is fetched per tab | Task 5 |
| `packages/cli/src/opentools/dashboard/tabs/findings.py` | Skip `table.clear()` + rebuild when data hasn't changed | Task 6 |
| `packages/cli/src/opentools/dashboard/tabs/timeline.py` | Skip no-op rebuild | Task 6 |
| `packages/cli/src/opentools/dashboard/tabs/iocs.py` | Skip no-op rebuild | Task 6 |
| `packages/cli/src/opentools/dashboard/tabs/containers.py` | Skip no-op rebuild | Task 6 |
| `packages/cli/src/opentools/dashboard/sidebar.py` | Skip sidebar ListView rebuild when engagement list unchanged | Task 6 |
| `packages/cli/tests/test_dashboard_noop.py` | Test that no-op refreshes don't touch the table | Task 6 |

---

### Task 1: Cache YAML Profile Parsing

**Why:** `load_builtin_profile()` reads and parses the same YAML file on every call to `ScanPlanner.plan()`. The profiler shows YAML scanning consumes 73% of engine runtime (1.08s out of 1.56s over 200 plan calls). Since profile files are static at runtime, the parsed `ScanProfile` object should be cached.

**Files:**
- Modify: `packages/cli/src/opentools/scanner/profiles.py:125-157`
- Test: `packages/cli/tests/test_scanner/test_profiles.py`

- [ ] **Step 1: Write the failing test for caching behavior**

Add to `packages/cli/tests/test_scanner/test_profiles.py`:

```python
def test_load_builtin_profile_is_cached():
    """Loading the same profile twice should return the same object (cached)."""
    from opentools.scanner.profiles import load_builtin_profile, _profile_cache

    # Clear any prior cache state
    _profile_cache.clear()

    profile_a = load_builtin_profile("web-full")
    profile_b = load_builtin_profile("web-full")

    assert profile_a is profile_b, "Expected cached (identical) object"
    assert len(_profile_cache) == 1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest packages/cli/tests/test_scanner/test_profiles.py::test_load_builtin_profile_is_cached -v`
Expected: FAIL — `_profile_cache` does not exist yet.

- [ ] **Step 3: Implement the cache**

In `packages/cli/src/opentools/scanner/profiles.py`, add a module-level cache dict and modify `load_builtin_profile`:

```python
# Add after line 112 (_PROFILES_DIR = ...)
_profile_cache: dict[str, ScanProfile] = {}


def load_builtin_profile(name: str) -> ScanProfile:
    """Load a built-in profile by name, caching the parsed result.

    Args:
        name: Profile name (e.g. "source-quick"). Hyphens are converted
            to underscores for filename lookup.

    Returns:
        Parsed ScanProfile (cached after first load).

    Raises:
        FileNotFoundError: If the profile YAML does not exist.
    """
    cached = _profile_cache.get(name)
    if cached is not None:
        return cached

    filename = name.replace("-", "_") + ".yaml"
    filepath = _PROFILES_DIR / filename
    if not filepath.exists():
        raise FileNotFoundError(
            f"Built-in profile '{name}' not found at {filepath}"
        )
    profile = load_profile_yaml(filepath.read_text(encoding="utf-8"))
    _profile_cache[name] = profile
    return profile
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest packages/cli/tests/test_scanner/test_profiles.py::test_load_builtin_profile_is_cached -v`
Expected: PASS

- [ ] **Step 5: Run full profile test suite for regressions**

Run: `python -m pytest packages/cli/tests/test_scanner/test_profiles.py -v`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/scanner/profiles.py packages/cli/tests/test_scanner/test_profiles.py
git commit -m "perf(scanner): cache parsed YAML profiles in load_builtin_profile

Profile parsing consumed 73% of engine runtime. The same YAML file was
re-parsed on every ScanPlanner.plan() call. Since profiles are static at
runtime, cache the parsed ScanProfile in a module-level dict."
```

---

### Task 2: Batch Summary Query for Sidebar

**Why:** `EngagementSidebar.update_from_state()` calls `store.get_summary(eng.id)` once per engagement. `get_summary()` executes 7 SQL statements internally. With 6 engagements and 100 refresh cycles, that's 4,200 SQL executions just for the sidebar. A single batch query eliminates the N+1.

**Files:**
- Modify: `packages/cli/src/opentools/engagement/store.py`
- Create: `packages/cli/tests/test_engagement_store_batch.py`

- [ ] **Step 1: Write the failing test**

Create `packages/cli/tests/test_engagement_store_batch.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest packages/cli/tests/test_engagement_store_batch.py -v`
Expected: FAIL — `get_sidebar_summaries` does not exist yet.

- [ ] **Step 3: Implement `get_sidebar_summaries`**

Add to `packages/cli/src/opentools/engagement/store.py`, after the `get_summary` method (around line 230):

```python
    def get_sidebar_summaries(self) -> list[tuple[str, int, int]]:
        """Return (engagement_id, critical_count, high_count) for all engagements.

        Single query — replaces N calls to get_summary() for sidebar rendering.
        """
        rows = self._conn.execute(
            """
            SELECT e.id,
                   COALESCE(SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END), 0) AS critical,
                   COALESCE(SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END), 0) AS high
            FROM engagements e
            LEFT JOIN findings f
                ON f.engagement_id = e.id AND f.deleted_at IS NULL
            GROUP BY e.id
            """,
        ).fetchall()
        return [(r["id"], r["critical"], r["high"]) for r in rows]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest packages/cli/tests/test_engagement_store_batch.py -v`
Expected: PASS

- [ ] **Step 5: Run full store test suite**

Run: `python -m pytest packages/cli/tests/ -k "engagement" -v`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/engagement/store.py packages/cli/tests/test_engagement_store_batch.py
git commit -m "perf(store): add get_sidebar_summaries batch query

Replaces the N+1 pattern where get_summary() (7 SQL queries) was called
per-engagement in the sidebar refresh loop. Single LEFT JOIN query returns
engagement_id + critical/high counts for all engagements at once."
```

---

### Task 3: Selective Dashboard Refresh (Only Visible Tab)

**Why:** Every 3-second auto-refresh calls `update_from_state()` on ALL 5 widgets (summary strip + 4 tabs), even though only 1 tab is visible. Each `update_from_state()` does `table.clear()` followed by re-adding every row. This causes 16,300 `model_construct` calls per 100 refresh cycles. We fix two things: (a) only refresh the active tab, (b) use the batch sidebar query from Task 2.

**Files:**
- Modify: `packages/cli/src/opentools/dashboard/app.py:132-175`
- Modify: `packages/cli/src/opentools/dashboard/sidebar.py:79-94`
- Modify: `packages/cli/src/opentools/dashboard/state.py:75-114`
- Test: `packages/cli/tests/test_dashboard.py`

- [ ] **Step 1: Write the failing test for selective refresh**

Add to `packages/cli/tests/test_dashboard.py`:

```python
def test_apply_refresh_only_updates_active_tab(dashboard_state):
    """Only the currently visible tab should be refreshed, not all four."""
    from unittest.mock import MagicMock

    state = dashboard_state
    # Create mock tabs with update_from_state
    findings_tab = MagicMock()
    timeline_tab = MagicMock()
    iocs_tab = MagicMock()
    containers_tab = MagicMock()

    tabs = {
        "findings": findings_tab,
        "timeline": timeline_tab,
        "iocs": iocs_tab,
        "containers": containers_tab,
    }

    active_tab = "findings"

    # Simulate _apply_refresh logic: only call update_from_state on active tab
    tabs[active_tab].update_from_state()

    findings_tab.update_from_state.assert_called_once()
    timeline_tab.update_from_state.assert_not_called()
    iocs_tab.update_from_state.assert_not_called()
    containers_tab.update_from_state.assert_not_called()
```

- [ ] **Step 2: Run test to verify it passes (this tests the design, not the wiring)**

Run: `python -m pytest packages/cli/tests/test_dashboard.py::test_apply_refresh_only_updates_active_tab -v`
Expected: PASS (this is a unit test of the design pattern).

- [ ] **Step 3: Add change-detection hash to DashboardState**

In `packages/cli/src/opentools/dashboard/state.py`, add a `_last_finding_count` field and modify `refresh_selected` to return a `changed` flag:

```python
class DashboardState:
    def __init__(
        self,
        store: EngagementStore,
        container_mgr: Optional[ContainerManager] = None,
        config: Optional[ToolkitConfig] = None,
    ) -> None:
        self.store = store
        self.container_mgr = container_mgr
        self.config = config

        self.engagements: list[Engagement] = []
        self.selected_id: Optional[str] = None
        self.summary: Optional[EngagementSummary] = None
        self.findings: list = []
        self.timeline: list[TimelineEvent] = []
        self.iocs: list[IOC] = []
        self.containers: list[ContainerStatus] = []

        # Change tracking for skip-refresh optimization
        self._last_finding_count: int = 0
        self._last_timeline_count: int = 0
        self._last_ioc_count: int = 0
```

- [ ] **Step 4: Modify `_apply_refresh` in `app.py` to only update the visible tab**

In `packages/cli/src/opentools/dashboard/app.py`, replace the `_apply_refresh` method:

```python
    def _apply_refresh(self, changes: dict) -> None:
        try:
            self.query_one(SummaryStrip).update_from_state()
        except Exception:
            pass

        # Only refresh the currently active tab
        try:
            active = self.query_one(TabbedContent).active
        except Exception:
            active = "findings"

        tab_map = {
            "findings": FindingsTab,
            "timeline": TimelineTab,
            "iocs": IOCsTab,
            "containers": ContainersTab,
        }
        tab_class = tab_map.get(active)
        if tab_class is not None:
            try:
                self.query_one(tab_class).update_from_state()
            except Exception:
                pass

        if "findings" in changes:
            c = changes["findings"]
            sev = "warning" if c.get("critical", 0) > 0 else "information"
            self.notify(
                f"{c['new']} new finding(s) ({c.get('critical', 0)} critical, {c.get('high', 0)} high)",
                severity=sev,
            )
```

- [ ] **Step 5: Modify sidebar to use batch query**

In `packages/cli/src/opentools/dashboard/sidebar.py`, replace the `update_from_state` method:

```python
    def update_from_state(self) -> None:
        """Rebuild the list from ``self.state.engagements`` using batch query."""
        # Single query instead of N calls to get_summary()
        summary_map: dict[str, tuple[int, int]] = {}
        try:
            for eng_id, critical, high in self.state.store.get_sidebar_summaries():
                summary_map[eng_id] = (critical, high)
        except Exception:
            pass

        self._all_items = []
        for eng in self.state.engagements:
            critical, high = summary_map.get(eng.id, (0, 0))
            self._all_items.append((eng, critical, high))

        # Apply current filter value (if the widget is already mounted)
        try:
            filter_input = self.query_one("#sidebar-filter", Input)
            self._apply_filter(filter_input.value)
        except Exception:
            self._apply_filter("")
```

- [ ] **Step 6: Also refresh the active tab on tab switch**

In `packages/cli/src/opentools/dashboard/app.py`, modify `action_switch_tab`:

```python
    def action_switch_tab(self, tab_id: str) -> None:
        try:
            self.query_one(TabbedContent).active = tab_id
        except Exception:
            pass
        # Refresh the newly visible tab so it's up to date
        tab_map = {
            "findings": FindingsTab,
            "timeline": TimelineTab,
            "iocs": IOCsTab,
            "containers": ContainersTab,
        }
        tab_class = tab_map.get(tab_id)
        if tab_class is not None:
            try:
                self.query_one(tab_class).update_from_state()
            except Exception:
                pass
```

- [ ] **Step 7: Run dashboard tests**

Run: `python -m pytest packages/cli/tests/test_dashboard.py -v`
Expected: All tests PASS.

- [ ] **Step 8: Commit**

```bash
git add packages/cli/src/opentools/dashboard/app.py packages/cli/src/opentools/dashboard/sidebar.py packages/cli/src/opentools/dashboard/state.py packages/cli/tests/test_dashboard.py
git commit -m "perf(dashboard): selective tab refresh + batch sidebar query

_apply_refresh now only calls update_from_state() on the visible tab
instead of all 4 tabs. Tab switches trigger an immediate refresh of the
newly visible tab. Sidebar uses get_sidebar_summaries() batch query
instead of N calls to get_summary() (7 SQL statements each)."
```

---

### Task 4: Memoize CWE Alias Resolution

**Why:** `CWEHierarchy.resolve_alias()` is called 4,000 times in a 20-round pipeline benchmark. The fallback path (line 109) does a full linear scan of the aliases dict on every miss. Since CWE data is static, we pre-build a lowercase-keyed lookup dict in `__init__` to make all lookups O(1).

**Files:**
- Modify: `packages/cli/src/opentools/scanner/cwe.py:91-113`
- Test: `packages/cli/tests/test_scanner/test_cwe.py`

- [ ] **Step 1: Write the failing test**

Add to `packages/cli/tests/test_scanner/test_cwe.py`:

```python
def test_resolve_alias_no_linear_scan():
    """resolve_alias should not iterate over all aliases (O(1) lookup)."""
    from opentools.scanner.cwe import CWEHierarchy

    cwe = CWEHierarchy()

    # Verify the _aliases_lower index exists and has entries
    assert hasattr(cwe, "_aliases_lower"), "Expected pre-built lowercase alias index"
    assert len(cwe._aliases_lower) > 0

    # Verify a case-insensitive lookup works via the index
    # Get a known alias key from the aliases dict
    if cwe._aliases:
        first_key = next(iter(cwe._aliases))
        result = cwe.resolve_alias(first_key.upper())
        assert result is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest packages/cli/tests/test_scanner/test_cwe.py::test_resolve_alias_no_linear_scan -v`
Expected: FAIL — `_aliases_lower` attribute does not exist.

- [ ] **Step 3: Implement the pre-built lowercase index**

In `packages/cli/src/opentools/scanner/cwe.py`, modify `__init__` and `resolve_alias`:

```python
class CWEHierarchy:
    """Loads and queries CWE parent/child relationships, resolves aliases, and maps to OWASP."""

    def __init__(self) -> None:
        self._hierarchy = _load_json("cwe_hierarchy.json")
        self._aliases = _load_json("cwe_aliases.json")
        self._owasp = _load_json("cwe_owasp_map.json")

        # Pre-build lowercase alias index for O(1) case-insensitive lookup
        self._aliases_lower: dict[str, str] = {
            k.lower(): v for k, v in self._aliases.items()
        }
```

Replace the `resolve_alias` method:

```python
    def resolve_alias(self, alias: str) -> str | None:
        """Resolve alias/shorthand to canonical CWE ID.

        If already a canonical CWE ID, returns it directly.
        Case-insensitive O(1) lookup via pre-built index.
        """
        # Pass-through for canonical IDs that exist in the hierarchy
        if alias in self._hierarchy:
            return alias

        # O(1) case-insensitive lookup
        return self._aliases_lower.get(alias.lower())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest packages/cli/tests/test_scanner/test_cwe.py::test_resolve_alias_no_linear_scan -v`
Expected: PASS

- [ ] **Step 5: Run full CWE test suite for regressions**

Run: `python -m pytest packages/cli/tests/test_scanner/test_cwe.py -v`
Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/scanner/cwe.py packages/cli/tests/test_scanner/test_cwe.py
git commit -m "perf(cwe): pre-build lowercase alias index for O(1) resolution

resolve_alias() had a linear scan fallback over all alias keys for
case-insensitive matching. Pre-building a lowercase-keyed dict in
__init__ makes all lookups O(1). Profiler showed 4,000 calls during
pipeline normalization."
```

---

### Task 5: Lazy Data Fetching — Only Query What the Visible Tab Needs

**Why:** `DashboardState.refresh_selected()` fetches ALL data on every 3-second tick: findings, timeline, IOCs, summary (7 SQL queries), and Docker container status (HTTP API call). But if the user is on the Findings tab, the timeline, IOC, and Docker queries are pure waste. The Docker call is network I/O every 3 seconds regardless of whether the Containers tab is visible. This task makes `refresh_selected` accept a set of data categories and only fetch what's requested.

**Depends on:** Task 3 (which routes the active tab ID to `_apply_refresh`).

**Files:**
- Modify: `packages/cli/src/opentools/dashboard/state.py:75-114`
- Modify: `packages/cli/src/opentools/dashboard/app.py:149-153`
- Create: `packages/cli/tests/test_dashboard_lazy.py`

- [ ] **Step 1: Write the failing test**

Create `packages/cli/tests/test_dashboard_lazy.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest packages/cli/tests/test_dashboard_lazy.py -v`
Expected: FAIL — `refresh_selected()` does not accept a `needs` parameter.

- [ ] **Step 3: Modify `refresh_selected` to accept a `needs` set**

In `packages/cli/src/opentools/dashboard/state.py`, replace `refresh_selected`:

```python
    # Map tab IDs to the data categories they need
    _TAB_NEEDS: dict[str, set[str]] = {
        "findings": {"summary", "findings"},
        "timeline": {"summary", "timeline"},
        "iocs": {"summary", "iocs"},
        "containers": {"summary", "containers"},
    }

    def refresh_selected(self, needs: set[str] | None = None) -> dict[str, Any]:
        """Reload data for the selected engagement.

        Args:
            needs: Set of data categories to fetch. Valid values:
                   'summary', 'findings', 'timeline', 'iocs', 'containers'.
                   If None, fetches everything (backward compatible).

        Returns a change-notification dict.
        """
        changes: dict[str, Any] = {}

        if self.selected_id is None:
            return changes

        fetch_all = needs is None
        if fetch_all:
            needs = {"summary", "findings", "timeline", "iocs", "containers"}

        prev_finding_count = len(self.findings)

        if "summary" in needs:
            self.summary = self.store.get_summary(self.selected_id)

        if "findings" in needs:
            self.findings = self.store.get_findings(self.selected_id)

        if "timeline" in needs:
            self.timeline = self.store.get_timeline(self.selected_id)

        if "iocs" in needs:
            self.iocs = self.store.get_iocs(self.selected_id)

        if "containers" in needs and self.container_mgr is not None:
            self.containers = self.container_mgr.status()

        new_count = len(self.findings)
        delta = new_count - prev_finding_count
        if delta > 0:
            fc = self.summary.finding_counts if self.summary else {}
            changes["findings"] = {
                "new": delta,
                "critical": fc.get("critical", 0),
                "high": fc.get("high", 0),
            }

        return changes
```

- [ ] **Step 4: Modify `_do_refresh` in `app.py` to pass the active tab's needs**

In `packages/cli/src/opentools/dashboard/app.py`, replace `_do_refresh`:

```python
    @work(thread=True)
    def _do_refresh(self) -> None:
        # Determine what data the visible tab needs
        try:
            active = self.query_one(TabbedContent).active
        except Exception:
            active = "findings"

        needs = DashboardState._TAB_NEEDS.get(active, {"summary", "findings"})
        changes = self.state.refresh_selected(needs=needs)
        self.call_from_thread(self._apply_refresh, changes)
```

Add the import at the top of `app.py` if not already present:

```python
from opentools.dashboard.state import DashboardState
```

Note: `DashboardState` is already used via `self.state`, but the class-level `_TAB_NEEDS` dict access requires the import.

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest packages/cli/tests/test_dashboard_lazy.py -v`
Expected: PASS

- [ ] **Step 6: Run full dashboard test suite**

Run: `python -m pytest packages/cli/tests/test_dashboard.py packages/cli/tests/test_dashboard_lazy.py -v`
Expected: All tests PASS.

- [ ] **Step 7: Commit**

```bash
git add packages/cli/src/opentools/dashboard/state.py packages/cli/src/opentools/dashboard/app.py packages/cli/tests/test_dashboard_lazy.py
git commit -m "perf(dashboard): lazy data fetching — only query for visible tab

refresh_selected() now accepts a 'needs' set specifying which data
categories to fetch. The Findings tab only queries findings + summary.
Docker container status HTTP call is skipped unless the Containers tab
is active. Eliminates 3 of 4 SQLite queries and the Docker API call
on most refresh ticks."
```

---

### Task 6: Skip No-Op Table Rebuilds and Sidebar Reflows

**Why:** Even after Tasks 3 and 5 limit refreshes to the visible tab and only fetch its data, the visible tab still does `table.clear()` + full row rebuild on every tick — even when the data hasn't changed. With 50 findings, that's 50 `add_row` calls + 50 Rich markup parses + a full Textual layout reflow every 3 seconds for zero visual change. Similarly, the sidebar does `list_view.clear()` + re-appends all `EngagementListItem` widgets even when the engagement list is identical. This task adds lightweight change detection so rebuilds only happen when data actually changes.

**Depends on:** Task 2 (batch sidebar query), Task 5 (lazy fetching).

**Files:**
- Modify: `packages/cli/src/opentools/dashboard/tabs/findings.py:64-117`
- Modify: `packages/cli/src/opentools/dashboard/tabs/timeline.py:42-59`
- Modify: `packages/cli/src/opentools/dashboard/tabs/iocs.py:46-78`
- Modify: `packages/cli/src/opentools/dashboard/tabs/containers.py:50-70`
- Modify: `packages/cli/src/opentools/dashboard/sidebar.py:79-94`
- Create: `packages/cli/tests/test_dashboard_noop.py`

- [ ] **Step 1: Write the failing test for no-op detection**

Create `packages/cli/tests/test_dashboard_noop.py`:

```python
"""Tests for no-op rebuild detection in dashboard tabs."""

import sqlite3
from datetime import datetime, timezone
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
    # Same data, same snapshot
    assert snap1 == snap2

    # Add a finding and re-snapshot
    state.findings.append(Finding(
        id="f-new", engagement_id="eng-1", tool="nmap",
        title="New finding", severity=Severity.CRITICAL,
        created_at=datetime.now(timezone.utc),
    ))
    snap3 = tab._data_snapshot()
    assert snap3 != snap1
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest packages/cli/tests/test_dashboard_noop.py -v`
Expected: FAIL — `_data_snapshot` method does not exist.

- [ ] **Step 3: Add `_data_snapshot` and guard to FindingsTab**

In `packages/cli/src/opentools/dashboard/tabs/findings.py`, add a snapshot method and modify `update_from_state`:

```python
class FindingsTab(Widget):
    # ... existing BINDINGS, _SEVERITY_MARKUP ...

    def __init__(self, state: DashboardState, **kwargs) -> None:
        super().__init__(**kwargs)
        self.state = state
        self._filter_text: str = ""
        self._last_snapshot: tuple | None = None

    def _data_snapshot(self) -> tuple:
        """Lightweight fingerprint of the current data. Cheap to compute."""
        return (
            len(self.state.findings),
            self._filter_text,
            tuple(f.id for f in self.state.findings[:5]),  # first 5 IDs as sentinel
            tuple(f.id for f in self.state.findings[-5:]),  # last 5 IDs
        )

    def update_from_state(self) -> None:
        """Clear and rebuild the table from ``self.state.findings``."""
        snapshot = self._data_snapshot()
        if snapshot == self._last_snapshot:
            return  # No-op: data hasn't changed
        self._last_snapshot = snapshot

        # ... rest of existing update_from_state unchanged ...
```

- [ ] **Step 4: Apply the same pattern to TimelineTab**

In `packages/cli/src/opentools/dashboard/tabs/timeline.py`:

```python
class TimelineTab(Widget):
    def __init__(self, state: DashboardState, **kwargs) -> None:
        super().__init__(**kwargs)
        self.state = state
        self._last_snapshot: tuple | None = None

    def _data_snapshot(self) -> tuple:
        return (
            len(self.state.timeline),
            self.state.timeline[0].id if self.state.timeline else None,
            self.state.timeline[-1].id if self.state.timeline else None,
        )

    def update_from_state(self) -> None:
        """Clear and rebuild the table from ``self.state.timeline``."""
        snapshot = self._data_snapshot()
        if snapshot == self._last_snapshot:
            return
        self._last_snapshot = snapshot

        table = self.query_one("#timeline-table", DataTable)
        table.clear()

        for event in reversed(self.state.timeline):
            timestamp_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            conf_key = str(event.confidence).lower()
            confidence_cell = self._CONFIDENCE_MARKUP.get(conf_key, str(event.confidence))

            table.add_row(
                timestamp_str,
                event.source,
                event.event,
                confidence_cell,
                key=event.id,
            )
```

- [ ] **Step 5: Apply the same pattern to IOCsTab**

In `packages/cli/src/opentools/dashboard/tabs/iocs.py`:

```python
class IOCsTab(Widget):
    def __init__(self, state: DashboardState, **kwargs) -> None:
        super().__init__(**kwargs)
        self.state = state
        self._filter_text: str = ""
        self._last_snapshot: tuple | None = None

    def _data_snapshot(self) -> tuple:
        return (
            len(self.state.iocs),
            self._filter_text,
            self.state.iocs[0].id if self.state.iocs else None,
            self.state.iocs[-1].id if self.state.iocs else None,
        )

    def update_from_state(self) -> None:
        """Clear and rebuild the table from ``self.state.iocs``."""
        snapshot = self._data_snapshot()
        if snapshot == self._last_snapshot:
            return
        self._last_snapshot = snapshot

        # ... rest of existing update_from_state unchanged ...
```

- [ ] **Step 6: Apply the same pattern to ContainersTab**

In `packages/cli/src/opentools/dashboard/tabs/containers.py`:

```python
class ContainersTab(Widget):
    def __init__(self, state: DashboardState, **kwargs) -> None:
        super().__init__(**kwargs)
        self.state = state
        self._last_snapshot: tuple | None = None

    def _data_snapshot(self) -> tuple:
        return (
            len(self.state.containers),
            tuple((c.name, c.state) for c in self.state.containers),
        )

    def update_from_state(self) -> None:
        """Clear and rebuild the table from ``self.state.containers``."""
        snapshot = self._data_snapshot()
        if snapshot == self._last_snapshot:
            return
        self._last_snapshot = snapshot

        # ... rest of existing update_from_state unchanged ...
```

- [ ] **Step 7: Apply the same pattern to the Sidebar**

In `packages/cli/src/opentools/dashboard/sidebar.py`, add snapshot detection to `update_from_state`:

```python
class EngagementSidebar(Widget):
    def __init__(self, state: DashboardState, **kwargs) -> None:
        super().__init__(**kwargs)
        self.state = state
        self._all_items: list[tuple[Engagement, int, int]] = []
        self._last_snapshot: tuple | None = None

    def update_from_state(self) -> None:
        """Rebuild the list from ``self.state.engagements`` using batch query."""
        # Single query instead of N calls to get_summary()
        summary_map: dict[str, tuple[int, int]] = {}
        try:
            for eng_id, critical, high in self.state.store.get_sidebar_summaries():
                summary_map[eng_id] = (critical, high)
        except Exception:
            pass

        # Check if anything changed before triggering a layout reflow
        snapshot = (
            tuple(e.id for e in self.state.engagements),
            tuple(summary_map.get(e.id, (0, 0)) for e in self.state.engagements),
        )
        if snapshot == self._last_snapshot:
            return
        self._last_snapshot = snapshot

        self._all_items = []
        for eng in self.state.engagements:
            critical, high = summary_map.get(eng.id, (0, 0))
            self._all_items.append((eng, critical, high))

        try:
            filter_input = self.query_one("#sidebar-filter", Input)
            self._apply_filter(filter_input.value)
        except Exception:
            self._apply_filter("")
```

- [ ] **Step 8: Handle filter input changes — force rebuild on filter change**

The `_data_snapshot` for FindingsTab and IOCsTab includes `self._filter_text`, so typing in the filter box will change the snapshot and trigger a rebuild. No additional work needed — the `on_input_changed` handler already calls `update_from_state()`, and the snapshot will differ because `_filter_text` changed.

- [ ] **Step 9: Run tests**

Run: `python -m pytest packages/cli/tests/test_dashboard_noop.py packages/cli/tests/test_dashboard.py -v`
Expected: All tests PASS.

- [ ] **Step 10: Commit**

```bash
git add packages/cli/src/opentools/dashboard/tabs/findings.py packages/cli/src/opentools/dashboard/tabs/timeline.py packages/cli/src/opentools/dashboard/tabs/iocs.py packages/cli/src/opentools/dashboard/tabs/containers.py packages/cli/src/opentools/dashboard/sidebar.py packages/cli/tests/test_dashboard_noop.py
git commit -m "perf(dashboard): skip no-op table rebuilds via data snapshots

Each tab and the sidebar now compute a lightweight tuple snapshot of
their data before rebuilding. If the snapshot matches the previous tick,
the table.clear() + rebuild is skipped entirely — no Rich markup parsing,
no Textual layout reflow, no Pydantic model_construct calls. Only actual
data changes trigger a visual update."
```

---

## Expected Impact

| # | Optimization | Before | After | Speedup |
|---|-------------|--------|-------|---------|
| 1 | Profile YAML caching | 1.08s (200 plans) | ~0.005s (1 parse + 199 cache hits) | **~200x** |
| 2 | Sidebar batch query | 42 SQL queries / refresh | 1 SQL query / refresh | **~42x** |
| 3 | Selective tab refresh | 4 table rebuilds / tick | 1 table rebuild / tick | **~4x** |
| 4 | CWE alias resolution | O(n) linear scan fallback | O(1) dict lookup | **~n×** (n = alias count) |
| 5 | Lazy data fetching | 4 SQLite queries + Docker HTTP / tick | 1-2 queries / tick (only visible tab's data) | **~3-5x** fewer queries |
| 6 | No-op rebuild skip | Full table.clear() + rebuild + Rich parse + layout reflow every 3s | Zero work when data unchanged (typical steady state) | **~∞** (0 vs N work) |

### Combined TUI impact (Tasks 2+3+5+6 together)

**Before (every 3-second tick):**
- 42 SQL queries (sidebar N+1) + 4 data queries + Docker HTTP
- 4 full table rebuilds (all tabs) with Rich markup parsing
- 16,300 `model_construct` calls per 100 ticks
- Full Textual layout reflow on every widget

**After (every 3-second tick, steady state):**
- 1 SQL query (batch sidebar) — skipped if snapshot unchanged
- 1 data query (visible tab only) — skipped if snapshot unchanged
- Docker HTTP only when Containers tab is active
- 0 table rebuilds when data hasn't changed (typical case)
- Layout reflow only on actual data changes

## Verification

After implementing all 6 tasks, re-run the profiling script to confirm:

```bash
python scripts/profile_cprofile.py engine
python scripts/profile_cprofile.py tui
```

Key metrics to compare:
- Engine: `yaml.*` functions should drop from 73% to <5% of runtime
- TUI: `get_summary` should disappear from top-40; `model_construct` call count should drop ~4x
- TUI: `sqlite3.Connection.execute` call count should drop from 6,706 to under 1,000
- TUI: `table.clear` / `add_row` should largely disappear in steady state
- Backend: `cwe.resolve_alias` should disappear from self-time top-20
