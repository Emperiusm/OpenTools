"""FindingsTab — filterable CheckboxTable of security findings."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.widget import Widget
from textual.widgets import Input

from opentools.dashboard.state import DashboardState
from opentools.dashboard.widgets.checkbox_table import CheckboxTable


class FindingsTab(Widget):
    """Displays all findings for the selected engagement with filter support.

    Bindings
    --------
    f        — flag the selected finding as a false positive (or all checked)
    s        — cycle the selected finding's status
    enter    — show full detail in a modal overlay
    /        — toggle the filter input
    a        — add a new finding
    e        — export findings
    """

    BINDINGS = [
        Binding("f", "flag_fp", "Flag FP"),
        Binding("s", "cycle_status", "Cycle Status"),
        Binding("enter", "show_detail", "Detail"),
        Binding("/", "toggle_filter", "Filter"),
        Binding("a", "add_finding", "Add", show=True),
        Binding("e", "export_findings", "Export", show=True),
    ]

    # Severity → Rich markup label
    _SEVERITY_MARKUP: dict[str, str] = {
        "critical": "[red]CRITICAL[/]",
        "high": "[#ff8c00]HIGH[/]",
        "medium": "[yellow]MEDIUM[/]",
        "low": "[#4169e1]LOW[/]",
        "info": "[dim]INFO[/]",
    }

    def __init__(self, state: DashboardState, **kwargs) -> None:
        super().__init__(**kwargs)
        self.state = state
        self._filter_text: str = ""
        self._last_snapshot: tuple | None = None
        self._visible_findings: list = []

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Input(placeholder="Filter findings…", id="findings-filter", classes="hidden")
        table = CheckboxTable(id="findings-table", cursor_type="row")
        table.add_columns("", "#", "Severity", "CWE", "Tool", "Title", "Location", "Status")
        yield table

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def _data_snapshot(self) -> tuple:
        """Lightweight fingerprint of the current data. Cheap to compute."""
        return (
            len(self.state.findings),
            self._filter_text,
            tuple(f.id for f in self.state.findings[:5]),
            tuple(f.id for f in self.state.findings[-5:]),
        )

    def update_from_state(self) -> None:
        """Clear and rebuild the table from ``self.state.findings``."""
        snapshot = self._data_snapshot()
        if snapshot == self._last_snapshot:
            return
        self._last_snapshot = snapshot

        table = self.query_one("#findings-table", CheckboxTable)
        table.clear()

        needle = self._filter_text.strip().lower()
        findings = self.state.findings

        # Build and cache visible findings list for _get_selected_finding
        self._visible_findings = []
        row_num = 1
        for finding in findings:
            # Apply filter across severity, title, tool, file_path, cwe
            if needle:
                searchable = " ".join([
                    str(finding.severity),
                    finding.title,
                    finding.tool,
                    finding.file_path or "",
                    finding.cwe or "",
                    str(finding.status),
                ]).lower()
                if needle not in searchable:
                    continue

            self._visible_findings.append(finding)
            sev_key = str(finding.severity).lower()
            severity_cell = self._SEVERITY_MARKUP.get(sev_key, str(finding.severity))

            cwe = finding.cwe or ""

            # Tool column: show "+N" when corroborated
            tool_label = finding.tool
            if finding.corroborated_by:
                tool_label = f"{finding.tool} (+{len(finding.corroborated_by)})"

            # Location
            if finding.file_path:
                location = finding.file_path
                if finding.line_start is not None:
                    location = f"{location}:{finding.line_start}"
            else:
                location = "N/A"

            status = str(finding.status)

            table.add_checked_row(
                str(row_num),
                severity_cell,
                cwe,
                tool_label,
                finding.title,
                location,
                status,
                key=finding.id,
            )
            row_num += 1

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_flag_fp(self) -> None:
        """Flag the selected or all checked findings as false positives."""
        table = self.query_one(CheckboxTable)
        checked = table.get_checked_keys()
        if checked:
            for fid in checked:
                self.state.flag_false_positive(fid)
            self.app.notify(f"Flagged {len(checked)} finding(s)")
            table.action_deselect_all()
        else:
            finding = self._get_selected_finding()
            if finding is None:
                return
            self.state.flag_false_positive(finding.id)
            self.app.notify(f"Flagged as false positive: {finding.title}")
        self.update_from_state()

    def action_cycle_status(self) -> None:
        """Cycle the selected finding to the next status."""
        finding = self._get_selected_finding()
        if finding is None:
            return
        self.state.cycle_finding_status(finding.id)
        self.app.notify(f"Status updated for: {finding.title}")
        self.update_from_state()

    def action_show_detail(self) -> None:
        """Push a detail modal for the selected finding."""
        finding = self._get_selected_finding()
        if finding is None:
            return
        from opentools.dashboard.detail import FindingDetailScreen
        self.app.push_screen(FindingDetailScreen(finding))

    def action_toggle_filter(self) -> None:
        """Show or hide the filter input."""
        filter_input = self.query_one("#findings-filter", Input)
        filter_input.toggle_class("hidden")
        if not filter_input.has_class("hidden"):
            filter_input.focus()

    def action_add_finding(self) -> None:
        from opentools.dashboard.dialogs.finding_add import FindingAddDialog
        def on_dismiss(result):
            if result:
                self.update_from_state()
        self.app.push_screen(FindingAddDialog(self.state), callback=on_dismiss)

    def action_export_findings(self) -> None:
        from opentools.dashboard.dialogs.export_dialog import ExportDialog
        self.app.push_screen(ExportDialog(self.state, "findings"))

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Re-filter the table whenever the filter field changes."""
        if event.input.id == "findings-filter":
            self._filter_text = event.value
            self.update_from_state()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_selected_finding(self):
        """Return the Finding at the current cursor row, or None."""
        table = self.query_one("#findings-table", CheckboxTable)
        if table.cursor_row is None:
            return None

        idx = table.cursor_row
        if idx < 0 or idx >= len(self._visible_findings):
            return None
        return self._visible_findings[idx]
