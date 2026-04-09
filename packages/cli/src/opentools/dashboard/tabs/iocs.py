"""IOCsTab — filterable DataTable of Indicators of Compromise."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.widget import Widget
from textual.widgets import DataTable, Input

from opentools.dashboard.state import DashboardState


class IOCsTab(Widget):
    """Displays IOCs for the selected engagement with filter support.

    Bindings
    --------
    /    — toggle the filter input
    """

    BINDINGS = [
        Binding("/", "toggle_filter", "Filter"),
    ]

    def __init__(self, state: DashboardState, **kwargs) -> None:
        super().__init__(**kwargs)
        self.state = state
        self._filter_text: str = ""

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Input(placeholder="Filter IOCs…", id="iocs-filter", classes="hidden")
        table: DataTable = DataTable(id="iocs-table", cursor_type="row")
        table.add_columns("Type", "Value", "Context", "First Seen", "Last Seen")
        yield table

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_from_state(self) -> None:
        """Clear and rebuild the table from ``self.state.iocs``."""
        table = self.query_one("#iocs-table", DataTable)
        table.clear()

        needle = self._filter_text.strip().lower()

        for ioc in self.state.iocs:
            ioc_type = str(ioc.ioc_type)
            value = ioc.value
            context = ioc.context or ""

            # Apply filter across type + value + context
            if needle:
                searchable = f"{ioc_type} {value} {context}".lower()
                if needle not in searchable:
                    continue

            # Truncate value to 40 chars
            value_display = value if len(value) <= 40 else value[:40]

            # Format dates
            first_seen = ioc.first_seen.strftime("%Y-%m-%d") if ioc.first_seen else "---"
            last_seen = ioc.last_seen.strftime("%Y-%m-%d") if ioc.last_seen else "---"

            table.add_row(
                ioc_type,
                value_display,
                context,
                first_seen,
                last_seen,
                key=ioc.id,
            )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_toggle_filter(self) -> None:
        """Show or hide the filter input."""
        filter_input = self.query_one("#iocs-filter", Input)
        filter_input.toggle_class("hidden")
        if not filter_input.has_class("hidden"):
            filter_input.focus()

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Re-filter the table whenever the filter field changes."""
        if event.input.id == "iocs-filter":
            self._filter_text = event.value
            self.update_from_state()
