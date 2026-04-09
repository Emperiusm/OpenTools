"""TimelineTab — read-only DataTable of timeline events."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable

from opentools.dashboard.state import DashboardState


class TimelineTab(Widget):
    """Displays timeline events for the selected engagement.

    Events are shown newest-first (descending by timestamp).
    No actions or bindings — read-only view.
    """

    _CONFIDENCE_MARKUP: dict[str, str] = {
        "high": "[green]HIGH[/]",
        "medium": "[yellow]MEDIUM[/]",
        "low": "[red]LOW[/]",
    }

    def __init__(self, state: DashboardState, **kwargs) -> None:
        super().__init__(**kwargs)
        self.state = state

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        table: DataTable = DataTable(id="timeline-table", cursor_type="row")
        table.add_columns("Timestamp", "Source", "Event", "Confidence")
        yield table

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_from_state(self) -> None:
        """Clear and rebuild the table from ``self.state.timeline``."""
        table = self.query_one("#timeline-table", DataTable)
        table.clear()

        # Newest first
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
