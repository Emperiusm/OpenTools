# Phase 2A-1: Dashboard Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Textual TUI dashboard with engagement sidebar, summary strip, tabbed content (Findings, Timeline, IOCs, Containers), finding detail modal, auto-refresh, and light actions.

**Architecture:** Textual `App` subclass with a shared `DashboardState` data layer. Widgets compose via Textual CSS layout. Data fetching runs in worker threads (`@work(thread=True)`) to avoid blocking the UI. Auto-refresh via `set_interval()` for active engagements. The existing `dashboard.py` stub becomes a launcher for the subpackage.

**Tech Stack:** Python 3.14, textual>=8.0, pytest

**Spec:** `docs/superpowers/specs/2026-04-09-phase2a1-dashboard-core-design.md`

---

## File Map

| File | Action | Task |
|------|--------|------|
| `packages/cli/pyproject.toml` | Modify | 1 (add textual dep) |
| `packages/cli/src/opentools/dashboard/__init__.py` | Create | 1 |
| `packages/cli/src/opentools/dashboard/state.py` | Create | 1 |
| `packages/cli/src/opentools/dashboard/sidebar.py` | Create | 2 |
| `packages/cli/src/opentools/dashboard/summary_strip.py` | Create | 3 |
| `packages/cli/src/opentools/dashboard/tabs/__init__.py` | Create | 4 |
| `packages/cli/src/opentools/dashboard/tabs/findings.py` | Create | 4 |
| `packages/cli/src/opentools/dashboard/tabs/timeline.py` | Create | 5 |
| `packages/cli/src/opentools/dashboard/tabs/iocs.py` | Create | 5 |
| `packages/cli/src/opentools/dashboard/tabs/containers.py` | Create | 6 |
| `packages/cli/src/opentools/dashboard/detail.py` | Create | 7 |
| `packages/cli/src/opentools/dashboard/app.py` | Create | 8 |
| `packages/cli/src/opentools/dashboard/dashboard.tcss` | Create | 8 |
| `packages/cli/src/opentools/dashboard.py` | Modify | 8 (replace stub) |
| `packages/cli/src/opentools/cli.py` | Modify | 8 (add dashboard command) |
| `packages/cli/tests/test_dashboard.py` | Create | 9 |

---

## Task 1: DashboardState + Package Setup

**Files:**
- Modify: `packages/cli/pyproject.toml`
- Create: `packages/cli/src/opentools/dashboard/__init__.py`
- Create: `packages/cli/src/opentools/dashboard/state.py`
- Create: `packages/cli/src/opentools/dashboard/tabs/__init__.py`

- [ ] **Step 1: Add textual dependency**

Add `"textual>=8.0"` to `packages/cli/pyproject.toml` dependencies and install:

```bash
cd packages/cli && pip install -e .
```

- [ ] **Step 2: Create package structure**

```bash
mkdir -p packages/cli/src/opentools/dashboard/tabs
```

Create `packages/cli/src/opentools/dashboard/__init__.py`:

```python
"""OpenTools TUI Dashboard."""
```

Create `packages/cli/src/opentools/dashboard/tabs/__init__.py`:

```python
"""Dashboard tab widgets."""
```

- [ ] **Step 3: Create state.py**

Create `packages/cli/src/opentools/dashboard/state.py`:

```python
"""Shared data context for the dashboard — all widgets read from here."""

from typing import Optional

from opentools.engagement.store import EngagementStore
from opentools.containers import ContainerManager
from opentools.models import (
    Engagement, EngagementSummary, Finding, FindingStatus,
    TimelineEvent, IOC, ContainerStatus, ToolkitConfig,
)


_FINDING_STATUS_ORDER = [
    FindingStatus.DISCOVERED,
    FindingStatus.CONFIRMED,
    FindingStatus.REPORTED,
    FindingStatus.REMEDIATED,
    FindingStatus.VERIFIED,
]


class DashboardState:
    """Central data context shared by all dashboard widgets."""

    def __init__(
        self,
        store: EngagementStore,
        container_mgr: Optional[ContainerManager] = None,
        config: Optional[ToolkitConfig] = None,
    ) -> None:
        self.store = store
        self.container_mgr = container_mgr
        self.config = config

        self.selected_engagement_id: Optional[str] = None
        self.engagements: list[Engagement] = []
        self.summary: Optional[EngagementSummary] = None
        self.findings: list[Finding] = []
        self.timeline: list[TimelineEvent] = []
        self.iocs: list[IOC] = []
        self.containers: list[ContainerStatus] = []

        self._prev_finding_count: int = 0
        self._prev_ioc_count: int = 0

    def refresh_engagements(self) -> None:
        """Refresh the engagement list. Call from worker thread."""
        self.engagements = self.store.list_all()

    def refresh_selected(self) -> dict:
        """Refresh all data for the selected engagement. Returns change report."""
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

        changes = {}
        new_count = len(self.findings)
        if new_count > self._prev_finding_count:
            diff = new_count - self._prev_finding_count
            new_crits = sum(1 for f in self.findings if str(f.severity) == "critical")
            new_highs = sum(1 for f in self.findings if str(f.severity) == "high")
            changes["findings"] = {"new": diff, "critical": new_crits, "high": new_highs}
        self._prev_finding_count = new_count
        self._prev_ioc_count = len(self.iocs)
        return changes

    def flag_false_positive(self, finding_id: str) -> None:
        self.store.flag_false_positive(finding_id)

    def cycle_finding_status(self, finding_id: str) -> str:
        """Advance finding to the next status. Returns the new status."""
        for f in self.findings:
            if f.id == finding_id:
                idx = _FINDING_STATUS_ORDER.index(f.status)
                new_status = _FINDING_STATUS_ORDER[(idx + 1) % len(_FINDING_STATUS_ORDER)]
                self.store.update_finding_status(finding_id, new_status)
                return str(new_status)
        return ""

    def start_container(self, name: str) -> bool:
        if not self.container_mgr:
            return False
        return self.container_mgr.start([name], wait=False).success

    def stop_container(self, name: str) -> bool:
        if not self.container_mgr:
            return False
        return self.container_mgr.stop([name]).success

    def restart_container(self, name: str) -> bool:
        if not self.container_mgr:
            return False
        return self.container_mgr.restart([name]).success
```

- [ ] **Step 4: Commit**

```bash
git add packages/cli/pyproject.toml packages/cli/src/opentools/dashboard/
git commit -m "feat: add dashboard package with DashboardState data layer"
```

---

## Task 2: Engagement Sidebar

**Files:**
- Create: `packages/cli/src/opentools/dashboard/sidebar.py`

- [ ] **Step 1: Create sidebar.py**

```python
"""Engagement sidebar with list, filter, and status indicators."""

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import Input, Static, ListView, ListItem, Label
from textual.widget import Widget

from opentools.dashboard.state import DashboardState


class EngagementSelected(Message):
    """Posted when an engagement is selected in the sidebar."""
    def __init__(self, engagement_id: str) -> None:
        self.engagement_id = engagement_id
        super().__init__()


class EngagementListItem(ListItem):
    """A single engagement entry in the sidebar."""

    def __init__(self, engagement_id: str, name: str, status: str,
                 critical: int = 0, high: int = 0) -> None:
        self.engagement_id = engagement_id
        self._eng_name = name
        self._eng_status = status
        self._critical = critical
        self._high = high
        super().__init__()

    def compose(self) -> ComposeResult:
        dot = "[green]●[/]" if self._eng_status == "active" else "[dim]○[/]"
        counts = f"[red]{self._critical}C[/] [#ff8c00]{self._high}H[/]" if (self._critical or self._high) else ""
        yield Label(f"{self._eng_name}  {dot}")
        yield Label(f"  [dim]{self._eng_status}[/]  {counts}")


class EngagementSidebar(Widget):
    """Sidebar with engagement list and filter input."""

    DEFAULT_CSS = """
    EngagementSidebar {
        width: 28;
        dock: left;
        border-right: solid $primary;
    }
    EngagementSidebar.collapsed {
        display: none;
    }
    #sidebar-filter {
        dock: top;
        margin: 0 1;
    }
    """

    def __init__(self, state: DashboardState, **kwargs) -> None:
        self.state = state
        self._filter_text = ""
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield Input(placeholder="Filter...", id="sidebar-filter")
        yield ListView(id="engagement-list")

    def update_from_state(self) -> None:
        """Rebuild the engagement list from current state."""
        list_view = self.query_one("#engagement-list", ListView)
        list_view.clear()
        for eng in self.state.engagements:
            if self._filter_text and self._filter_text.lower() not in eng.name.lower():
                continue
            summary = self.state.store.get_summary(eng.id)
            critical = summary.finding_counts.get("critical", 0)
            high = summary.finding_counts.get("high", 0)
            item = EngagementListItem(
                engagement_id=eng.id,
                name=eng.name,
                status=str(eng.status),
                critical=critical,
                high=high,
            )
            list_view.append(item)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "sidebar-filter":
            self._filter_text = event.value
            self.update_from_state()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item = event.item
        if isinstance(item, EngagementListItem):
            self.post_message(EngagementSelected(item.engagement_id))
```

- [ ] **Step 2: Commit**

```bash
git add packages/cli/src/opentools/dashboard/sidebar.py
git commit -m "feat: add engagement sidebar with filter and status dots"
```

---

## Task 3: Summary Strip

**Files:**
- Create: `packages/cli/src/opentools/dashboard/summary_strip.py`

- [ ] **Step 1: Create summary_strip.py**

```python
"""One-line summary strip showing engagement name, severity counts, and refresh status."""

from textual.widgets import Static
from opentools.dashboard.state import DashboardState


class SummaryStrip(Static):
    """Horizontal summary bar at the top of the main area."""

    DEFAULT_CSS = """
    SummaryStrip {
        height: 1;
        dock: top;
        background: $boost;
        padding: 0 1;
    }
    """

    def __init__(self, state: DashboardState, **kwargs) -> None:
        self.state = state
        self._auto_refresh = False
        super().__init__("No engagement selected", **kwargs)

    def set_auto_refresh(self, enabled: bool) -> None:
        self._auto_refresh = enabled
        self.update_from_state()

    def update_from_state(self) -> None:
        if not self.state.summary:
            self.update("No engagement selected")
            return

        eng = self.state.summary.engagement
        fc = self.state.summary.finding_counts
        crit = fc.get("critical", 0)
        high = fc.get("high", 0)
        med = fc.get("medium", 0)
        low = fc.get("low", 0)
        info = fc.get("info", 0)

        running = sum(1 for c in self.state.containers if c.state == "running")
        total_containers = len(self.state.containers)
        ioc_count = len(self.state.iocs)

        refresh_indicator = "[green]Auto ●[/]" if self._auto_refresh else "Manual"

        self.update(
            f"[bold]{eng.name}[/] ({eng.target}) │ "
            f"[red]CRIT:{crit}[/]  [#ff8c00]HIGH:{high}[/]  [yellow]MED:{med}[/]  "
            f"[#4169e1]LOW:{low}[/]  [dim]INFO:{info}[/] │ "
            f"Containers: {running}/{total_containers} │ "
            f"IOCs: {ioc_count} │ {refresh_indicator}"
        )
```

- [ ] **Step 2: Commit**

```bash
git add packages/cli/src/opentools/dashboard/summary_strip.py
git commit -m "feat: add summary strip with severity counts and refresh indicator"
```

---

## Task 4: Findings Tab

**Files:**
- Create: `packages/cli/src/opentools/dashboard/tabs/findings.py`

- [ ] **Step 1: Create findings.py**

```python
"""Findings tab with DataTable, filter, and light actions."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import DataTable, Input
from textual.widget import Widget

from opentools.dashboard.state import DashboardState

_SEV_COLORS = {
    "critical": "red",
    "high": "#ff8c00",
    "medium": "yellow",
    "low": "#4169e1",
    "info": "gray",
}


class FindingsTab(Widget):
    """Findings DataTable with filter and key actions."""

    BINDINGS = [
        Binding("f", "flag_fp", "Flag FP", show=True),
        Binding("s", "cycle_status", "Status", show=True),
        Binding("enter", "show_detail", "Detail", show=True),
        Binding("slash", "toggle_filter", "Filter", show=True),
    ]

    def __init__(self, state: DashboardState, **kwargs) -> None:
        self.state = state
        self._filter_visible = False
        self._filter_text = ""
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield Input(placeholder="Filter findings...", id="findings-filter", classes="hidden")
        yield DataTable(id="findings-table")

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("#", "Severity", "CWE", "Tool", "Title", "Location", "Status")

    def update_from_state(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        for i, f in enumerate(self.state.findings):
            if self._filter_text:
                search = self._filter_text.lower()
                searchable = f"{f.title} {f.cwe or ''} {f.tool} {f.file_path or ''}".lower()
                if search not in searchable:
                    continue

            sev = str(f.severity)
            color = _SEV_COLORS.get(sev, "white")
            tool_display = f.tool
            if f.corroborated_by:
                tool_display += f" (+{len(f.corroborated_by)})"
            location = f"{f.file_path}:{f.line_start}" if f.file_path and f.line_start else (f.file_path or "N/A")

            table.add_row(
                str(i + 1),
                f"[{color}]{sev.upper()}[/]",
                f.cwe or "---",
                tool_display,
                f.title[:60],
                location[:30],
                str(f.status),
                key=f.id,
            )

    def _get_selected_finding_id(self) -> str | None:
        table = self.query_one("#findings-table", DataTable)
        if table.cursor_row is not None:
            try:
                row_key = table.get_row_at(table.cursor_row)
                # row_key is the data; we used key=f.id in add_row
                return str(table.get_cell_at((table.cursor_row, 0))).strip()  # fallback
            except Exception:
                pass
        # Lookup by cursor position
        try:
            cursor = table.cursor_row
            if cursor is not None and cursor < len(self.state.findings):
                filtered = [f for f in self.state.findings
                           if not self._filter_text or self._filter_text.lower() in
                           f"{f.title} {f.cwe or ''} {f.tool} {f.file_path or ''}".lower()]
                if cursor < len(filtered):
                    return filtered[cursor].id
        except Exception:
            pass
        return None

    def action_flag_fp(self) -> None:
        fid = self._get_selected_finding_id()
        if fid:
            self.state.flag_false_positive(fid)
            self.app.notify("Flagged as false positive")
            self.update_from_state()

    def action_cycle_status(self) -> None:
        fid = self._get_selected_finding_id()
        if fid:
            new_status = self.state.cycle_finding_status(fid)
            self.app.notify(f"Status: {new_status}")
            self.update_from_state()

    def action_show_detail(self) -> None:
        fid = self._get_selected_finding_id()
        if fid:
            finding = next((f for f in self.state.findings if f.id == fid), None)
            if finding:
                from opentools.dashboard.detail import FindingDetailScreen
                self.app.push_screen(FindingDetailScreen(finding, self.state))

    def action_toggle_filter(self) -> None:
        filter_input = self.query_one("#findings-filter", Input)
        self._filter_visible = not self._filter_visible
        filter_input.toggle_class("hidden")
        if self._filter_visible:
            filter_input.focus()
        else:
            self._filter_text = ""
            self.update_from_state()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "findings-filter":
            self._filter_text = event.value
            self.update_from_state()
```

- [ ] **Step 2: Commit**

```bash
git add packages/cli/src/opentools/dashboard/tabs/findings.py
git commit -m "feat: add findings tab with DataTable, filter, and flag/status actions"
```

---

## Task 5: Timeline and IOCs Tabs

**Files:**
- Create: `packages/cli/src/opentools/dashboard/tabs/timeline.py`
- Create: `packages/cli/src/opentools/dashboard/tabs/iocs.py`

- [ ] **Step 1: Create timeline.py**

```python
"""Timeline tab with chronological event DataTable."""

from textual.app import ComposeResult
from textual.widgets import DataTable
from textual.widget import Widget

from opentools.dashboard.state import DashboardState

_CONF_COLORS = {"high": "green", "medium": "yellow", "low": "red"}


class TimelineTab(Widget):
    """Chronological timeline event table."""

    def __init__(self, state: DashboardState, **kwargs) -> None:
        self.state = state
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield DataTable(id="timeline-table")

    def on_mount(self) -> None:
        table = self.query_one("#timeline-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Timestamp", "Source", "Event", "Confidence")

    def update_from_state(self) -> None:
        table = self.query_one("#timeline-table", DataTable)
        table.clear()
        for event in reversed(self.state.timeline):
            ts = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            conf = str(event.confidence)
            color = _CONF_COLORS.get(conf, "white")
            table.add_row(ts, event.source, event.event[:80], f"[{color}]{conf.upper()}[/]")
```

- [ ] **Step 2: Create iocs.py**

```python
"""IOCs tab with DataTable and filter."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable, Input
from textual.widget import Widget

from opentools.dashboard.state import DashboardState


class IOCsTab(Widget):
    """IOC DataTable with filter."""

    BINDINGS = [
        Binding("slash", "toggle_filter", "Filter", show=True),
    ]

    def __init__(self, state: DashboardState, **kwargs) -> None:
        self.state = state
        self._filter_visible = False
        self._filter_text = ""
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield Input(placeholder="Filter IOCs...", id="iocs-filter", classes="hidden")
        yield DataTable(id="iocs-table")

    def on_mount(self) -> None:
        table = self.query_one("#iocs-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Type", "Value", "Context", "First Seen", "Last Seen")

    def update_from_state(self) -> None:
        table = self.query_one("#iocs-table", DataTable)
        table.clear()
        for ioc in self.state.iocs:
            if self._filter_text:
                searchable = f"{ioc.ioc_type} {ioc.value} {ioc.context or ''}".lower()
                if self._filter_text.lower() not in searchable:
                    continue

            value_display = ioc.value if len(ioc.value) <= 40 else ioc.value[:37] + "..."
            first_seen = ioc.first_seen.strftime("%Y-%m-%d") if ioc.first_seen else "---"
            last_seen = ioc.last_seen.strftime("%Y-%m-%d") if ioc.last_seen else "---"
            table.add_row(
                str(ioc.ioc_type),
                value_display,
                (ioc.context or "---")[:40],
                first_seen,
                last_seen,
            )

    def action_toggle_filter(self) -> None:
        filter_input = self.query_one("#iocs-filter", Input)
        self._filter_visible = not self._filter_visible
        filter_input.toggle_class("hidden")
        if self._filter_visible:
            filter_input.focus()
        else:
            self._filter_text = ""
            self.update_from_state()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "iocs-filter":
            self._filter_text = event.value
            self.update_from_state()
```

- [ ] **Step 3: Commit**

```bash
git add packages/cli/src/opentools/dashboard/tabs/timeline.py packages/cli/src/opentools/dashboard/tabs/iocs.py
git commit -m "feat: add timeline and IOCs tabs with DataTable"
```

---

## Task 6: Containers Tab

**Files:**
- Create: `packages/cli/src/opentools/dashboard/tabs/containers.py`

- [ ] **Step 1: Create containers.py**

```python
"""Containers tab with DataTable and start/stop/restart actions."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable
from textual.widget import Widget

from opentools.dashboard.state import DashboardState

_STATE_COLORS = {"running": "green", "exited": "red", "stopped": "gray", "created": "yellow"}


class ContainersTab(Widget):
    """Docker container status table with actions."""

    BINDINGS = [
        Binding("enter", "toggle_container", "Start/Stop", show=True),
        Binding("r", "restart_container", "Restart", show=True),
    ]

    def __init__(self, state: DashboardState, **kwargs) -> None:
        self.state = state
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield DataTable(id="containers-table")

    def on_mount(self) -> None:
        table = self.query_one("#containers-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Container", "State", "Health", "Profile", "Uptime")

    def update_from_state(self) -> None:
        table = self.query_one("#containers-table", DataTable)
        table.clear()
        for c in self.state.containers:
            color = _STATE_COLORS.get(c.state, "white")
            profile_str = ", ".join(c.profile) if c.profile else "---"
            table.add_row(
                c.name,
                f"[{color}]{c.state}[/]",
                c.health or "---",
                profile_str,
                c.uptime or "---",
                key=c.name,
            )

    def _get_selected_container(self) -> tuple[str, str] | None:
        table = self.query_one("#containers-table", DataTable)
        try:
            cursor = table.cursor_row
            if cursor is not None and cursor < len(self.state.containers):
                c = self.state.containers[cursor]
                return c.name, c.state
        except Exception:
            pass
        return None

    def action_toggle_container(self) -> None:
        sel = self._get_selected_container()
        if not sel:
            return
        name, state = sel
        if state == "running":
            success = self.state.stop_container(name)
            action = "Stopping"
        else:
            success = self.state.start_container(name)
            action = "Starting"

        if success:
            self.app.notify(f"{action} {name}...")
        else:
            self.app.notify(f"Failed to {action.lower()} {name}", severity="error")

    def action_restart_container(self) -> None:
        sel = self._get_selected_container()
        if not sel:
            return
        name, _ = sel
        success = self.state.restart_container(name)
        if success:
            self.app.notify(f"Restarting {name}...")
        else:
            self.app.notify(f"Failed to restart {name}", severity="error")
```

- [ ] **Step 2: Commit**

```bash
git add packages/cli/src/opentools/dashboard/tabs/containers.py
git commit -m "feat: add containers tab with start/stop/restart actions"
```

---

## Task 7: Finding Detail Modal

**Files:**
- Create: `packages/cli/src/opentools/dashboard/detail.py`

- [ ] **Step 1: Create detail.py**

```python
"""Finding detail modal screen."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static

from opentools.dashboard.state import DashboardState
from opentools.models import Finding


class FindingDetailScreen(ModalScreen):
    """Modal overlay showing full finding details."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("f", "flag_fp", "Flag FP"),
        Binding("s", "cycle_status", "Status"),
    ]

    DEFAULT_CSS = """
    FindingDetailScreen {
        align: center middle;
    }
    #detail-container {
        width: 80%;
        max-width: 100;
        height: 80%;
        border: thick $primary;
        background: $surface;
        padding: 1 2;
    }
    """

    def __init__(self, finding: Finding, state: DashboardState, **kwargs) -> None:
        self.finding = finding
        self.state = state
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        with Vertical(id="detail-container"):
            yield VerticalScroll(Static(self._render_detail(), id="detail-content"))

    def _render_detail(self) -> str:
        f = self.finding
        lines = [
            f"[bold]FINDING: {f.title}[/bold]",
            "",
            f"[bold]Severity:[/bold] [{self._sev_color(f.severity)}]{str(f.severity).upper()}[/]"
            + (f" (CVSS {f.cvss})" if f.cvss else ""),
            f"[bold]CWE:[/bold] {f.cwe or 'Not classified'}",
            f"[bold]Tool:[/bold] {f.tool}"
            + (f" (corroborated by: {', '.join(f.corroborated_by)})" if f.corroborated_by else ""),
            f"[bold]Status:[/bold] {f.status}",
        ]

        if f.phase:
            lines.append(f"[bold]Phase:[/bold] {f.phase}")
        if f.file_path:
            loc = f.file_path
            if f.line_start:
                loc += f":{f.line_start}"
            if f.line_end:
                loc += f"-{f.line_end}"
            lines.append(f"[bold]Location:[/bold] {loc}")
        if f.dedup_confidence:
            lines.append(f"[bold]Dedup Confidence:[/bold] {f.dedup_confidence}")
        if f.severity_by_tool and len(f.severity_by_tool) > 1:
            sbt = ", ".join(f"{t}={s}" for t, s in f.severity_by_tool.items())
            lines.append(f"[bold]Severity by tool:[/bold] {sbt}")

        if f.description:
            lines.extend(["", "[bold]── Description ──[/bold]", f.description])
        if f.evidence:
            lines.extend(["", "[bold]── Evidence ──[/bold]", f.evidence])
        if f.remediation:
            lines.extend(["", "[bold]── Remediation ──[/bold]", f.remediation])

        lines.extend(["", "[dim][f] Flag FP  [s] Cycle Status  [Esc] Close[/dim]"])
        return "\n".join(lines)

    @staticmethod
    def _sev_color(severity) -> str:
        return {"critical": "red", "high": "#ff8c00", "medium": "yellow",
                "low": "#4169e1", "info": "gray"}.get(str(severity), "white")

    def action_flag_fp(self) -> None:
        self.state.flag_false_positive(self.finding.id)
        self.app.notify("Flagged as false positive")
        self.dismiss(True)

    def action_cycle_status(self) -> None:
        new_status = self.state.cycle_finding_status(self.finding.id)
        self.app.notify(f"Status: {new_status}")
        self.dismiss(True)
```

- [ ] **Step 2: Commit**

```bash
git add packages/cli/src/opentools/dashboard/detail.py
git commit -m "feat: add finding detail modal with actions"
```

---

## Task 8: DashboardApp + CSS + Launcher + CLI Command

**Files:**
- Create: `packages/cli/src/opentools/dashboard/app.py`
- Create: `packages/cli/src/opentools/dashboard/dashboard.tcss`
- Modify: `packages/cli/src/opentools/dashboard.py` (replace stub)
- Modify: `packages/cli/src/opentools/cli.py` (add dashboard command)

- [ ] **Step 1: Create dashboard.tcss**

Create `packages/cli/src/opentools/dashboard/dashboard.tcss`:

```css
/* Hidden class for filter inputs */
.hidden {
    display: none;
}

/* Tab content fills available space */
TabbedContent {
    height: 1fr;
}

TabPane {
    height: 1fr;
    padding: 0;
}

/* DataTables fill their tab */
DataTable {
    height: 1fr;
}

/* Footer at bottom */
Footer {
    dock: bottom;
}
```

- [ ] **Step 2: Create app.py**

```python
"""Main dashboard application."""

from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, TabbedContent, TabPane

from opentools.config import ConfigLoader
from opentools.containers import ContainerManager
from opentools.engagement.store import EngagementStore
from opentools.plugin import discover_plugin_dir

from opentools.dashboard.state import DashboardState
from opentools.dashboard.sidebar import EngagementSidebar, EngagementSelected
from opentools.dashboard.summary_strip import SummaryStrip
from opentools.dashboard.tabs.findings import FindingsTab
from opentools.dashboard.tabs.timeline import TimelineTab
from opentools.dashboard.tabs.iocs import IOCsTab
from opentools.dashboard.tabs.containers import ContainersTab


class DashboardApp(App):
    """OpenTools TUI Dashboard."""

    CSS_PATH = "dashboard.tcss"
    TITLE = "OpenTools Dashboard"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("tab", "toggle_sidebar", "Sidebar"),
        Binding("r", "manual_refresh", "Refresh"),
        Binding("1", "switch_tab('findings')", "Findings"),
        Binding("2", "switch_tab('timeline')", "Timeline"),
        Binding("3", "switch_tab('iocs')", "IOCs"),
        Binding("4", "switch_tab('containers')", "Containers"),
    ]

    def __init__(self, db_path: Path | None = None, plugin_dir: Path | None = None,
                 initial_engagement: str | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._initial_engagement = initial_engagement

        # Initialize data sources
        if plugin_dir is None:
            try:
                plugin_dir = discover_plugin_dir()
            except FileNotFoundError:
                plugin_dir = None

        if db_path is None:
            if plugin_dir:
                db_path = plugin_dir.parent.parent / "engagements" / "opentools.db"
            else:
                db_path = Path("engagements/opentools.db")
        db_path.parent.mkdir(parents=True, exist_ok=True)

        store = EngagementStore(db_path=db_path)

        container_mgr = None
        config = None
        if plugin_dir:
            try:
                config = ConfigLoader(plugin_dir).load()
                container_mgr = ContainerManager(config)
            except Exception:
                pass

        self.state = DashboardState(store, container_mgr, config)
        self._refresh_timer = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            yield EngagementSidebar(self.state, id="sidebar")
            with Vertical(id="main"):
                yield SummaryStrip(self.state, id="summary-strip")
                with TabbedContent(id="tabs"):
                    with TabPane("Findings", id="findings"):
                        yield FindingsTab(self.state, id="findings-tab")
                    with TabPane("Timeline", id="timeline"):
                        yield TimelineTab(self.state, id="timeline-tab")
                    with TabPane("IOCs", id="iocs"):
                        yield IOCsTab(self.state, id="iocs-tab")
                    with TabPane("Containers", id="containers"):
                        yield ContainersTab(self.state, id="containers-tab")
        yield Footer()

    def on_mount(self) -> None:
        self._load_engagements()
        if self._initial_engagement:
            self._select_engagement(self._initial_engagement)

    @work(thread=True)
    def _load_engagements(self) -> None:
        self.state.refresh_engagements()
        self.call_from_thread(self._update_sidebar)

    def _update_sidebar(self) -> None:
        try:
            self.query_one(EngagementSidebar).update_from_state()
        except Exception:
            pass

    def on_engagement_selected(self, message: EngagementSelected) -> None:
        self._select_engagement(message.engagement_id)

    def _select_engagement(self, engagement_id: str) -> None:
        self.state.selected_engagement_id = engagement_id

        try:
            eng = self.state.store.get(engagement_id)
            if str(eng.status) == "active":
                self._start_auto_refresh()
            else:
                self._stop_auto_refresh()
        except Exception:
            self._stop_auto_refresh()

        self._do_refresh()

    def _start_auto_refresh(self) -> None:
        self._stop_auto_refresh()
        self._refresh_timer = self.set_interval(3.0, self._do_refresh)
        try:
            self.query_one(SummaryStrip).set_auto_refresh(True)
        except Exception:
            pass

    def _stop_auto_refresh(self) -> None:
        if self._refresh_timer:
            self._refresh_timer.stop()
            self._refresh_timer = None
        try:
            self.query_one(SummaryStrip).set_auto_refresh(False)
        except Exception:
            pass

    @work(thread=True)
    def _do_refresh(self) -> None:
        changes = self.state.refresh_selected()
        self.call_from_thread(self._apply_refresh, changes)

    def _apply_refresh(self, changes: dict) -> None:
        try:
            self.query_one(SummaryStrip).update_from_state()
            self.query_one(FindingsTab).update_from_state()
            self.query_one(TimelineTab).update_from_state()
            self.query_one(IOCsTab).update_from_state()
            self.query_one(ContainersTab).update_from_state()
        except Exception:
            pass

        if "findings" in changes:
            c = changes["findings"]
            severity = "warning" if c.get("critical", 0) > 0 else "information"
            self.notify(
                f"{c['new']} new finding(s) ({c.get('critical', 0)} critical, {c.get('high', 0)} high)",
                severity=severity,
            )

    def action_toggle_sidebar(self) -> None:
        sidebar = self.query_one("#sidebar", EngagementSidebar)
        sidebar.toggle_class("collapsed")

    def action_manual_refresh(self) -> None:
        self._do_refresh()

    def action_switch_tab(self, tab_id: str) -> None:
        try:
            self.query_one(TabbedContent).active = tab_id
        except Exception:
            pass
```

- [ ] **Step 3: Replace dashboard.py stub**

Replace `packages/cli/src/opentools/dashboard.py` content with:

```python
"""Dashboard launcher — delegates to the dashboard subpackage."""

from pathlib import Path
from typing import Optional


def launch_dashboard(
    db_path: Optional[Path] = None,
    plugin_dir: Optional[Path] = None,
    engagement: Optional[str] = None,
) -> None:
    """Launch the interactive TUI dashboard."""
    from opentools.dashboard.app import DashboardApp
    app = DashboardApp(db_path=db_path, plugin_dir=plugin_dir, initial_engagement=engagement)
    app.run()
```

- [ ] **Step 4: Add dashboard CLI command**

Add to `packages/cli/src/opentools/cli.py` — a top-level `dashboard` command:

```python
@app.command()
def dashboard(
    engagement: str = typer.Option(None, help="Auto-select engagement on launch"),
):
    """Launch the interactive TUI dashboard."""
    from opentools.dashboard import launch_dashboard as _launch
    try:
        plugin_dir, config = _get_config()
        db_path = plugin_dir.parent.parent / "engagements" / "opentools.db"
        _launch(db_path=db_path, plugin_dir=plugin_dir, engagement=engagement)
    except Exception:
        # Fallback: launch without config
        from opentools.dashboard import launch_dashboard as _launch2
        _launch2(engagement=engagement)
```

- [ ] **Step 5: Update dashboard/__init__.py to re-export**

Update `packages/cli/src/opentools/dashboard/__init__.py`:

```python
"""OpenTools TUI Dashboard."""

from opentools.dashboard.app import DashboardApp

__all__ = ["DashboardApp"]
```

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/dashboard/ packages/cli/src/opentools/cli.py
git commit -m "feat: add DashboardApp with layout, auto-refresh, keybindings, and CLI command"
```

---

## Task 9: Tests

**Files:**
- Create: `packages/cli/tests/test_dashboard.py`

- [ ] **Step 1: Create test_dashboard.py**

```python
"""Tests for the TUI dashboard using Textual's headless testing."""

import sqlite3
from datetime import datetime, timezone

import pytest

from opentools.dashboard.state import DashboardState
from opentools.engagement.schema import migrate
from opentools.engagement.store import EngagementStore
from opentools.models import (
    Engagement, EngagementType, EngagementStatus,
    Finding, Severity, IOC, IOCType,
)


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
        id="eng-1", name="test-pentest", target="10.0.0.1",
        type=EngagementType.PENTEST, status=EngagementStatus.ACTIVE,
        skills_used=["pentest"], created_at=now, updated_at=now,
    )
    dashboard_state.store.create(eng)
    dashboard_state.store.add_finding(Finding(
        id="f-1", engagement_id="eng-1", tool="semgrep",
        title="SQL Injection", severity=Severity.CRITICAL,
        cwe="CWE-89", file_path="src/api.py", line_start=42,
        created_at=now,
    ))
    dashboard_state.store.add_finding(Finding(
        id="f-2", engagement_id="eng-1", tool="nuclei",
        title="XSS in search", severity=Severity.HIGH,
        cwe="CWE-79", created_at=now,
    ))
    dashboard_state.store.add_ioc(IOC(
        id="ioc-1", engagement_id="eng-1",
        ioc_type=IOCType.IP, value="10.0.0.1", context="C2",
    ))
    return dashboard_state


def test_state_refresh_engagements(dashboard_state):
    now = datetime.now(timezone.utc)
    dashboard_state.store.create(Engagement(
        id="eng-1", name="test", target="10.0.0.1",
        type=EngagementType.PENTEST, status=EngagementStatus.ACTIVE,
        created_at=now, updated_at=now,
    ))
    dashboard_state.refresh_engagements()
    assert len(dashboard_state.engagements) == 1
    assert dashboard_state.engagements[0].name == "test"


def test_state_refresh_selected(populated_state):
    populated_state.selected_engagement_id = "eng-1"
    changes = populated_state.refresh_selected()
    assert len(populated_state.findings) == 2
    assert len(populated_state.iocs) == 1
    assert populated_state.summary is not None
    assert populated_state.summary.finding_counts.get("critical", 0) == 1


def test_state_change_detection(populated_state):
    populated_state.selected_engagement_id = "eng-1"
    populated_state.refresh_selected()  # first load, sets baseline

    # Add a new finding
    now = datetime.now(timezone.utc)
    populated_state.store.add_finding(Finding(
        id="f-3", engagement_id="eng-1", tool="nikto",
        title="Directory listing", severity=Severity.MEDIUM,
        created_at=now,
    ))
    changes = populated_state.refresh_selected()
    assert "findings" in changes
    assert changes["findings"]["new"] == 1


def test_state_flag_false_positive(populated_state):
    populated_state.selected_engagement_id = "eng-1"
    populated_state.refresh_selected()
    populated_state.flag_false_positive("f-1")
    findings = populated_state.store.get_findings("eng-1")
    flagged = [f for f in findings if f.id == "f-1"]
    assert flagged[0].false_positive is True


def test_state_cycle_finding_status(populated_state):
    populated_state.selected_engagement_id = "eng-1"
    populated_state.refresh_selected()
    new_status = populated_state.cycle_finding_status("f-1")
    assert new_status == "confirmed"
    new_status2 = populated_state.cycle_finding_status("f-1")
    assert new_status2 == "reported"


def test_state_empty_engagement(dashboard_state):
    now = datetime.now(timezone.utc)
    dashboard_state.store.create(Engagement(
        id="eng-1", name="empty", target="nowhere",
        type=EngagementType.PENTEST, status=EngagementStatus.ACTIVE,
        created_at=now, updated_at=now,
    ))
    dashboard_state.selected_engagement_id = "eng-1"
    dashboard_state.refresh_selected()
    assert len(dashboard_state.findings) == 0
    assert len(dashboard_state.iocs) == 0
    assert dashboard_state.summary is not None


def test_app_launches():
    """Verify the app can be constructed without crashing."""
    from opentools.dashboard.app import DashboardApp
    app = DashboardApp(db_path=None, plugin_dir=None)
    # Just verify it constructs — full run_test requires async
    assert app.TITLE == "OpenTools Dashboard"
```

- [ ] **Step 2: Run tests**

```bash
cd packages/cli && python -m pytest tests/test_dashboard.py -v
```

Expected: All 7 tests PASS.

- [ ] **Step 3: Run full suite**

```bash
cd packages/cli && python -m pytest tests/ -q
```

Expected: All pass (138 existing + 7 new = 145)

- [ ] **Step 4: Commit**

```bash
git add packages/cli/tests/test_dashboard.py
git commit -m "feat: add dashboard tests for state management and app construction"
```

---

## Self-Review

**1. Spec coverage:**
- Section 2.1 (File structure): All files in file map ✓
- Section 2.2 (Data flow / DashboardState): Task 1 ✓
- Section 2.3 (Refresh strategy): Task 8 (app.py timer logic) ✓
- Section 3 (DashboardState): Task 1 ✓
- Section 4 (DashboardApp compose/refresh/selection): Task 8 ✓
- Section 5 (Sidebar): Task 2 ✓
- Section 6 (Summary strip): Task 3 ✓
- Section 7 (Findings tab): Task 4 ✓
- Section 8 (Timeline tab): Task 5 ✓
- Section 9 (IOCs tab): Task 5 ✓
- Section 10 (Containers tab): Task 6 ✓
- Section 11 (Finding detail modal): Task 7 ✓
- Section 12 (CSS): Task 8 ✓
- Section 13 (CLI integration): Task 8 ✓
- Section 14 (Files changed): All covered ✓
- Section 15 (Testing): Task 9 ✓

**2. Placeholder scan:** No TBDs. All code blocks are complete.

**3. Type consistency:** `DashboardState` methods (`refresh_selected`, `flag_false_positive`, `cycle_finding_status`, `start_container`, `stop_container`, `restart_container`) consistent between state.py definition and widget calls. `EngagementSelected` message defined in sidebar.py, handled in app.py. `update_from_state()` method name consistent across all widgets.
