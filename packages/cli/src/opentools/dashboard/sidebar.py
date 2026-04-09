"""Engagement Sidebar for the OpenTools TUI dashboard."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Input, ListItem, ListView, Label

from opentools.dashboard.state import DashboardState
from opentools.models import Engagement, EngagementStatus


class EngagementSelected(Message):
    """Posted when the user selects an engagement from the sidebar list."""

    def __init__(self, engagement_id: str) -> None:
        super().__init__()
        self.engagement_id = engagement_id


class EngagementListItem(ListItem):
    """A single row in the engagement list.

    Displays the engagement name, status dot, and critical/high finding counts.
    """

    def __init__(self, engagement: Engagement, critical: int, high: int) -> None:
        super().__init__()
        self.engagement = engagement
        self._critical = critical
        self._high = high

    def compose(self) -> ComposeResult:
        dot = "[green]●[/]" if self.engagement.status == EngagementStatus.ACTIVE else "[dim]○[/]"
        counts = f"[red]{self._critical}C[/] [#ff8c00]{self._high}H[/]"
        text = f"{dot} {self.engagement.name}  {counts}"
        yield Label(text)


class EngagementSidebar(Widget):
    """Left sidebar showing a filterable list of engagements.

    DEFAULT_CSS sets width 28, docks left, and adds a right border.
    The ``Collapsed`` class hides the widget entirely (``display: none``).
    """

    BINDINGS = [
        Binding("d", "delete_engagement", "Delete", show=True),
        Binding("e", "export_engagement", "Export", show=True),
    ]

    DEFAULT_CSS = """
    EngagementSidebar {
        width: 28;
        dock: left;
        border-right: solid $primary;
    }
    EngagementSidebar.Collapsed {
        display: none;
    }
    """

    def __init__(self, state: DashboardState, **kwargs) -> None:
        super().__init__(**kwargs)
        self.state = state
        # Internal cache: all items before filtering
        self._all_items: list[tuple[Engagement, int, int]] = []

    def compose(self) -> ComposeResult:
        yield Input(placeholder="Filter engagements…", id="sidebar-filter")
        yield ListView(id="sidebar-list")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_from_state(self) -> None:
        """Rebuild the list from ``self.state.engagements``."""
        self._all_items = []
        for eng in self.state.engagements:
            summary = self.state.store.get_summary(eng.id)
            fc = summary.finding_counts
            critical = fc.get("critical", 0)
            high = fc.get("high", 0)
            self._all_items.append((eng, critical, high))

        # Apply current filter value (if the widget is already mounted)
        try:
            filter_input = self.query_one("#sidebar-filter", Input)
            self._apply_filter(filter_input.value)
        except Exception:
            self._apply_filter("")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Re-filter the list whenever the search field changes."""
        if event.input.id == "sidebar-filter":
            self._apply_filter(event.value)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Post EngagementSelected when the user picks a row."""
        item = event.item
        if isinstance(item, EngagementListItem):
            self.post_message(EngagementSelected(item.engagement.id))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _apply_filter(self, query: str) -> None:
        """Repopulate the ListView with items matching *query* (substring)."""
        try:
            list_view = self.query_one("#sidebar-list", ListView)
        except Exception:
            return

        needle = query.strip().lower()
        filtered = [
            (eng, crit, high)
            for eng, crit, high in self._all_items
            if needle in eng.name.lower()
        ]

        list_view.clear()
        for eng, crit, high in filtered:
            list_view.append(EngagementListItem(eng, crit, high))

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_delete_engagement(self) -> None:
        if self.state.selected_id:
            from opentools.dashboard.dialogs.engagement_delete import EngagementDeleteDialog
            def on_dismiss(result):
                if result:
                    self.update_from_state()
            self.app.push_screen(
                EngagementDeleteDialog(self.state, self.state.selected_id),
                callback=on_dismiss,
            )

    def action_export_engagement(self) -> None:
        if self.state.selected_id:
            from opentools.dashboard.dialogs.export_dialog import ExportDialog
            self.app.push_screen(ExportDialog(self.state, "engagement"))
