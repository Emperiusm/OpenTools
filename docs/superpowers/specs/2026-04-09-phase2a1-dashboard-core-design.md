# Phase 2A-1: Dashboard Core — Design Specification

**Date:** 2026-04-09
**Status:** Approved
**Author:** slabl + Claude
**Depends on:** Phase 1 + 2B + 2C (all merged)

## 1. Overview

Build a Textual TUI dashboard for monitoring engagements, findings, IOCs, containers, and timeline events. Features a collapsible sidebar with engagement list, a summary strip, tabbed content area (Findings, Timeline, IOCs, Containers), auto-refresh for active engagements, light actions (flag false positive, cycle finding status, start/stop containers), and a finding detail modal.

This is Phase 2A-1 (read-only views + light actions). Phase 2A-2 (full interactive CRUD forms) builds on this later.

## 2. Architecture

### 2.1 File Structure

```
packages/cli/src/opentools/dashboard/
├── __init__.py          # re-exports launch_dashboard()
├── app.py               # DashboardApp(App) — compose, keybindings, refresh timer
├── state.py             # DashboardState — shared data context, worker-safe refresh
├── sidebar.py           # EngagementSidebar — ListView + Input filter + status dots
├── summary_strip.py     # SummaryStrip — engagement name + severity/container/IOC counts
├── detail.py            # FindingDetailScreen — modal overlay for full finding view
├── tabs/
│   ├── __init__.py
│   ├── findings.py      # FindingsTab — DataTable + filter + f/s key actions
│   ├── timeline.py      # TimelineTab — DataTable sorted by timestamp
│   ├── iocs.py          # IOCsTab — DataTable + filter
│   └── containers.py    # ContainersTab — DataTable + Enter/r actions
└── dashboard.tcss       # Textual CSS (layout, colors, sidebar, severity badges)
```

The existing stub at `packages/cli/src/opentools/dashboard.py` becomes a thin launcher that imports from the subpackage.

### 2.2 Data Flow

```
DashboardState (state.py)
    │ owns: EngagementStore, ContainerManager, PreflightRunner
    │ holds: current engagement_id, findings, timeline, iocs, containers, engagements
    │
    ├── refresh() — called by timer (active) or manual (r key)
    │   runs in @work(thread=True) to avoid blocking UI
    │   after refresh, compares counts to detect new data → triggers notifications
    │
    └── widgets read from state, never from store directly
```

All widgets receive a reference to the same `DashboardState` instance. No widget creates its own DB connection.

### 2.3 Refresh Strategy

- **Active engagements:** `set_interval(3.0, self.refresh_data)` polls the store. The timer is started when an active engagement is selected and stopped when a complete/paused engagement is selected.
- **Complete/paused engagements:** no auto-refresh. Press `r` for manual one-shot refresh.
- **Change detection:** after each refresh, compare finding count, IOC count, and container states to previous values. If changed, update widgets and fire `self.notify()` for significant changes (new critical/high findings).

## 3. DashboardState (`state.py`)

Central data context shared by all widgets.

```python
class DashboardState:
    def __init__(self, store: EngagementStore, container_mgr: ContainerManager | None, config: ToolkitConfig | None):
        self.store = store
        self.container_mgr = container_mgr
        self.config = config

        # Current selection
        self.selected_engagement_id: str | None = None

        # Cached data (refreshed periodically or on demand)
        self.engagements: list[Engagement] = []
        self.summary: EngagementSummary | None = None
        self.findings: list[Finding] = []
        self.timeline: list[TimelineEvent] = []
        self.iocs: list[IOC] = []
        self.containers: list[ContainerStatus] = []

        # Previous counts for change detection
        self._prev_finding_count: int = 0
        self._prev_ioc_count: int = 0

    def refresh_engagements(self) -> None:
        """Refresh the engagement list (blocking — call from worker)."""
        self.engagements = self.store.list_all()

    def refresh_selected(self) -> dict:
        """Refresh data for selected engagement. Returns change report."""
        if not self.selected_engagement_id:
            return {}

        self.summary = self.store.get_summary(self.selected_engagement_id)
        self.findings = self.store.get_findings(self.selected_engagement_id)
        self.timeline = self.store.get_timeline(self.selected_engagement_id)
        self.iocs = self.store.get_iocs(self.selected_engagement_id)

        if self.container_mgr:
            try:
                self.containers = self.container_mgr.status()
            except Exception:
                self.containers = []

        # Change detection
        changes = {}
        new_finding_count = len(self.findings)
        new_ioc_count = len(self.iocs)
        if new_finding_count > self._prev_finding_count:
            diff = new_finding_count - self._prev_finding_count
            new_crits = sum(1 for f in self.findings[:diff] if str(f.severity) == "critical")
            new_highs = sum(1 for f in self.findings[:diff] if str(f.severity) == "high")
            changes["findings"] = {"new": diff, "critical": new_crits, "high": new_highs}

        self._prev_finding_count = new_finding_count
        self._prev_ioc_count = new_ioc_count
        return changes

    # ─── Light Actions ──────────────────────────────────────────────────

    def flag_false_positive(self, finding_id: str) -> None:
        self.store.flag_false_positive(finding_id)

    def update_finding_status(self, finding_id: str, new_status: str) -> None:
        self.store.update_finding_status(finding_id, new_status)

    def start_container(self, name: str) -> bool:
        if not self.container_mgr:
            return False
        result = self.container_mgr.start([name], wait=False)
        return result.success

    def stop_container(self, name: str) -> bool:
        if not self.container_mgr:
            return False
        result = self.container_mgr.stop([name])
        return result.success

    def restart_container(self, name: str) -> bool:
        if not self.container_mgr:
            return False
        result = self.container_mgr.restart([name])
        return result.success
```

## 4. DashboardApp (`app.py`)

Textual `App` subclass. Composes the layout, manages keybindings, and owns the refresh timer.

### 4.1 Layout

```
┌──────────────┬──────────────────────────────────────────────────────────┐
│  Sidebar     │  Summary Strip                                          │
│              ├──────────────────────────────────────────────────────────┤
│  [/] Filter  │  [Findings] [Timeline] [IOCs] [Containers]              │
│              │                                                          │
│  > my-audit ●│  ┌──────────────────────────────────────────────────┐    │
│    active    │  │                                                  │    │
│    2C 5H     │  │         Active Tab Content                       │    │
│              │  │         (DataTable with filter)                   │    │
│  old-pentest │  │                                                  │    │
│    complete  │  │                                                  │    │
│    0C 3H     │  └──────────────────────────────────────────────────┘    │
│              │                                                          │
├──────────────┴──────────────────────────────────────────────────────────┤
│  Footer: q Quit │ Tab Sidebar │ 1-4 Tabs │ / Filter │ r Refresh        │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Compose

```python
class DashboardApp(App):
    CSS_PATH = "dashboard.tcss"
    TITLE = "OpenTools Dashboard"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("tab", "toggle_sidebar", "Sidebar"),
        Binding("r", "refresh", "Refresh"),
        Binding("1", "switch_tab('findings')", "Findings"),
        Binding("2", "switch_tab('timeline')", "Timeline"),
        Binding("3", "switch_tab('iocs')", "IOCs"),
        Binding("4", "switch_tab('containers')", "Containers"),
        Binding("slash", "focus_filter", "Filter"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            yield EngagementSidebar(self.state)
            with Vertical(id="main"):
                yield SummaryStrip(self.state)
                with TabbedContent():
                    with TabPane("Findings", id="findings"):
                        yield FindingsTab(self.state)
                    with TabPane("Timeline", id="timeline"):
                        yield TimelineTab(self.state)
                    with TabPane("IOCs", id="iocs"):
                        yield IOCsTab(self.state)
                    with TabPane("Containers", id="containers"):
                        yield ContainersTab(self.state)
        yield Footer()
```

### 4.3 Refresh Timer

```python
def on_mount(self) -> None:
    self.refresh_timer = None
    self._load_engagements()

def _start_auto_refresh(self) -> None:
    if self.refresh_timer:
        self.refresh_timer.stop()
    self.refresh_timer = self.set_interval(3.0, self._do_refresh)

def _stop_auto_refresh(self) -> None:
    if self.refresh_timer:
        self.refresh_timer.stop()
        self.refresh_timer = None

@work(thread=True)
def _do_refresh(self) -> None:
    changes = self.state.refresh_selected()
    self.call_from_thread(self._apply_refresh, changes)

def _apply_refresh(self, changes: dict) -> None:
    # Update all widgets
    self.query_one(SummaryStrip).update_from_state()
    self.query_one(FindingsTab).update_from_state()
    self.query_one(TimelineTab).update_from_state()
    self.query_one(IOCsTab).update_from_state()
    self.query_one(ContainersTab).update_from_state()

    # Notify on significant changes
    if "findings" in changes:
        c = changes["findings"]
        self.notify(
            f"{c['new']} new finding(s) ({c['critical']} critical, {c['high']} high)",
            severity="warning" if c["critical"] > 0 else "information",
        )
```

### 4.4 Engagement Selection

When user clicks/selects an engagement in the sidebar:

```python
def on_engagement_selected(self, engagement_id: str) -> None:
    self.state.selected_engagement_id = engagement_id
    engagement = self.state.store.get(engagement_id)

    if str(engagement.status) == "active":
        self._start_auto_refresh()
    else:
        self._stop_auto_refresh()

    self._do_refresh()  # immediate load
```

## 5. Sidebar (`sidebar.py`)

### 5.1 Widget Structure

```python
class EngagementSidebar(Widget):
    def compose(self) -> ComposeResult:
        yield Input(placeholder="Filter...", id="sidebar-filter")
        yield ListView(id="engagement-list")
```

### 5.2 Engagement List Items

Custom `ListItem` for each engagement:

```
> my-audit          ●
  active  2C 5H
```

- Name (bold if selected)
- Status line: status text + critical count (`C`) + high count (`H`)
- Status dot: `●` green (auto-refreshing active), `○` gray (complete/paused)
- Clicking or pressing Enter selects the engagement and posts `EngagementSelected` message (a custom `Message` subclass with `engagement_id: str`):

```python
class EngagementSelected(Message):
    def __init__(self, engagement_id: str) -> None:
        self.engagement_id = engagement_id
        super().__init__()
```

The `DashboardApp` handles this message in `on_engagement_selected()`.

### 5.3 Filter

`Input.Changed` event filters the `ListView` client-side. Match against engagement name (case-insensitive substring).

### 5.4 Collapse

`Tab` key toggles a CSS class that sets `display: none` on the sidebar. The main area expands to fill the space.

## 6. Summary Strip (`summary_strip.py`)

One-line `Static` widget:

```
my-audit (192.168.1.0/24) │ CRIT:2  HIGH:5  MED:3  LOW:1 │ Containers: 8/12 │ IOCs: 14 │ Auto ●
```

- Engagement name and target from `state.summary.engagement`
- Severity counts from `state.summary.finding_counts`
- Container count: running / total from `state.containers`
- IOC count from `len(state.iocs)`
- Refresh indicator: `Auto ●` (green, pulsing) for auto-refresh, `Manual` for manual

`update_from_state()` rebuilds the text from current state.

## 7. Findings Tab (`tabs/findings.py`)

### 7.1 DataTable

```python
class FindingsTab(Widget):
    BINDINGS = [
        Binding("f", "flag_fp", "Flag FP"),
        Binding("s", "cycle_status", "Status"),
        Binding("enter", "show_detail", "Detail"),
        Binding("slash", "toggle_filter", "Filter"),
    ]
```

Columns: `#`, `Severity`, `CWE`, `Tool`, `Title`, `Location`, `Status`

- Severity cells colored by level (via Textual Rich renderables)
- Tool column shows `tool (+N)` when corroborated
- Location column: `file_path:line_start` or `N/A`

### 7.2 Filter

`/` toggles an `Input` widget above the DataTable. Typing filters rows client-side against title, CWE, tool, and file_path. `Esc` clears and hides filter.

### 7.3 Actions

- `f` on selected row: calls `state.flag_false_positive(finding_id)`, refreshes, shows toast "Flagged as false positive"
- `s` on selected row: cycles status (discovered → confirmed → reported → remediated → verified → discovered), calls `state.update_finding_status()`, refreshes, shows toast
- `Enter` on selected row: pushes `FindingDetailScreen` with the selected finding

## 8. Timeline Tab (`tabs/timeline.py`)

DataTable with columns: `Timestamp`, `Source`, `Event`, `Confidence`

- Sorted by timestamp descending (newest first)
- Timestamps formatted as `YYYY-MM-DD HH:MM:SS`
- Confidence colored: HIGH=green, MEDIUM=yellow, LOW=red
- Read-only — no actions beyond scrolling and viewing

## 9. IOCs Tab (`tabs/iocs.py`)

DataTable with columns: `Type`, `Value`, `Context`, `First Seen`, `Last Seen`

- Sorted by type, then value
- Long values truncated to fit column width (hash values show first 16 + `...`)
- `/` toggles filter (matches against value, type, context)
- Read-only — no actions

## 10. Containers Tab (`tabs/containers.py`)

```python
class ContainersTab(Widget):
    BINDINGS = [
        Binding("enter", "toggle_container", "Start/Stop"),
        Binding("r", "restart_container", "Restart"),
    ]
```

DataTable with columns: `Container`, `State`, `Health`, `Profile`, `Uptime`

- State cells colored: green=running, red=exited, gray=stopped
- **Actions:**
  - `Enter`: if running → `state.stop_container(name)`, if stopped/exited → `state.start_container(name)`. Shows toast confirmation: "Starting nmap-mcp..." or "Stopping nmap-mcp..."
  - `r`: `state.restart_container(name)`. Shows toast: "Restarting nmap-mcp..."
- On action failure: toast with error severity: "Failed to start nmap-mcp: Docker daemon not running"

## 11. Finding Detail Modal (`detail.py`)

Pushed via `app.push_screen(FindingDetailScreen(finding))` when Enter is pressed on a findings row.

```python
class FindingDetailScreen(ModalScreen):
    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("f", "flag_fp", "Flag FP"),
        Binding("s", "cycle_status", "Status"),
    ]
```

Layout: scrollable `Static` widget with Rich-formatted content:

```
┌─────────── Finding Detail ───────────────────────────┐
│ FINDING-001: SQL Injection in login                  │
│                                                       │
│ Severity: CRITICAL (CVSS 9.8)                        │
│ CWE: CWE-89                                         │
│ Tool: semgrep (corroborated by: codebadger, nuclei)  │
│ Status: confirmed                                    │
│ Phase: vuln-analysis                                 │
│ Location: src/api.py:42-45                           │
│ Dedup Confidence: HIGH                               │
│                                                       │
│ ── Description ──────────────────────────────────────│
│ Unsanitized user input flows directly into SQL query  │
│ via string concatenation in the login handler.        │
│                                                       │
│ ── Evidence ─────────────────────────────────────────│
│ query = f"SELECT * FROM users WHERE id = '{input}'"  │
│                                                       │
│ ── Remediation ──────────────────────────────────────│
│ Use parameterized queries or an ORM.                 │
│                                                       │
│ [f] Flag FP  [s] Cycle Status  [Esc] Close           │
└───────────────────────────────────────────────────────┘
```

Actions `f` and `s` work the same as in the findings tab — update store, dismiss with result so the findings table refreshes.

## 12. Textual CSS (`dashboard.tcss`)

Key layout rules:

```css
/* Main layout */
Horizontal { height: 100%; }

EngagementSidebar {
    width: 28;
    dock: left;
}

EngagementSidebar.collapsed {
    display: none;
}

#main {
    width: 1fr;
}

SummaryStrip {
    height: 1;
    dock: top;
}

/* Severity colors */
.severity-critical { color: red; text-style: bold; }
.severity-high { color: #ff8c00; }
.severity-medium { color: yellow; }
.severity-low { color: #4169e1; }
.severity-info { color: gray; }

/* Container states */
.state-running { color: green; }
.state-exited { color: red; }
.state-stopped { color: gray; }

/* Sidebar */
#engagement-list { height: 1fr; }
#sidebar-filter { dock: top; }

/* Finding detail modal */
FindingDetailScreen {
    align: center middle;
}

FindingDetailScreen > Vertical {
    width: 80%;
    max-width: 100;
    height: 80%;
    border: thick $primary;
    background: $surface;
    padding: 1 2;
}
```

## 13. CLI Integration

Update `packages/cli/src/opentools/dashboard.py` (existing stub):

```python
from pathlib import Path
from opentools.dashboard.app import DashboardApp

def launch_dashboard(db_path: Path | None = None, plugin_dir: Path | None = None) -> None:
    app = DashboardApp(db_path=db_path, plugin_dir=plugin_dir)
    app.run()
```

Update `cli.py` — replace the existing dashboard command (if any) or add one:

```bash
opentools dashboard [--engagement NAME]
```

If `--engagement` is provided, auto-select it on launch.

## 14. Files Changed Summary

| File | Action | Description |
|------|--------|-------------|
| `packages/cli/src/opentools/dashboard/__init__.py` | Create | re-export `launch_dashboard` |
| `packages/cli/src/opentools/dashboard/app.py` | Create | DashboardApp: compose, bindings, refresh |
| `packages/cli/src/opentools/dashboard/state.py` | Create | DashboardState: shared data, change detection |
| `packages/cli/src/opentools/dashboard/sidebar.py` | Create | EngagementSidebar: ListView + filter |
| `packages/cli/src/opentools/dashboard/summary_strip.py` | Create | SummaryStrip: one-line counts |
| `packages/cli/src/opentools/dashboard/detail.py` | Create | FindingDetailScreen: modal overlay |
| `packages/cli/src/opentools/dashboard/tabs/__init__.py` | Create | empty |
| `packages/cli/src/opentools/dashboard/tabs/findings.py` | Create | FindingsTab: DataTable + actions |
| `packages/cli/src/opentools/dashboard/tabs/timeline.py` | Create | TimelineTab: DataTable |
| `packages/cli/src/opentools/dashboard/tabs/iocs.py` | Create | IOCsTab: DataTable + filter |
| `packages/cli/src/opentools/dashboard/tabs/containers.py` | Create | ContainersTab: DataTable + actions |
| `packages/cli/src/opentools/dashboard/dashboard.tcss` | Create | Layout, colors, responsive sidebar |
| `packages/cli/src/opentools/dashboard.py` | Modify | Replace stub with launcher |
| `packages/cli/src/opentools/cli.py` | Modify | Add/update dashboard command |
| `packages/cli/pyproject.toml` | Modify | Add `textual>=0.80` dependency |
| `packages/cli/tests/test_dashboard.py` | Create | Tests using `app.run_test()` |

## 15. Testing Strategy

Textual provides `app.run_test()` for headless testing. Tests verify:

| Test | What It Verifies |
|------|-----------------|
| App launches without crash | Compose works, CSS loads, no import errors |
| Sidebar lists engagements | DashboardState.engagements populated, ListView rendered |
| Selecting engagement updates main area | Summary strip and tabs show data for selected engagement |
| Tab switching | Pressing 1-4 switches active tab |
| Sidebar collapse/expand | Tab key toggles sidebar visibility |
| Finding filter | Typing in filter input reduces DataTable rows |
| Finding detail modal | Enter on finding row pushes modal, Esc dismisses |
| Flag false positive | f key updates finding in store, toast shown |
| Container start/stop | Enter key on container row calls ContainerManager |
| Auto-refresh for active engagement | Timer fires, data updates, notification on new findings |
| Manual refresh | r key triggers one-shot refresh |
| Empty engagement | Dashboard handles zero findings/IOCs gracefully |

Tests use in-memory SQLite and mock `ContainerManager` (no real Docker).
