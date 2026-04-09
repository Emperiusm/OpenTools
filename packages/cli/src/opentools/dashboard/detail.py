"""Finding detail modal screen."""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
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
        overflow-y: auto;
    }
    """

    def __init__(self, finding: Finding, state: DashboardState, **kwargs):
        self.finding = finding
        self.state = state
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="detail-container"):
            yield Static(self._render_detail(), id="detail-content")

    def _render_detail(self) -> str:
        f = self.finding
        sev_color = {"critical": "red", "high": "#ff8c00", "medium": "yellow", "low": "#4169e1", "info": "gray"}.get(str(f.severity), "white")

        lines = [
            f"[bold]FINDING: {f.title}[/bold]",
            "",
            f"[bold]Severity:[/bold] [{sev_color}]{str(f.severity).upper()}[/]" + (f" (CVSS {f.cvss})" if f.cvss else ""),
            f"[bold]CWE:[/bold] {f.cwe or 'Not classified'}",
            f"[bold]Tool:[/bold] {f.tool}" + (f" (corroborated by: {', '.join(f.corroborated_by)})" if f.corroborated_by else ""),
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
            lines.extend(["", "[bold]-- Description --[/bold]", f.description])
        if f.evidence:
            lines.extend(["", "[bold]-- Evidence --[/bold]", f.evidence])
        if f.remediation:
            lines.extend(["", "[bold]-- Remediation --[/bold]", f.remediation])
        lines.extend(["", "[dim][f] Flag FP  [s] Cycle Status  [Esc] Close[/dim]"])
        return "\n".join(lines)

    def action_flag_fp(self):
        self.state.flag_false_positive(self.finding.id)
        self.app.notify("Flagged as false positive")
        self.dismiss(True)

    def action_cycle_status(self):
        new_status = self.state.cycle_finding_status(self.finding.id)
        self.app.notify(f"Status: {new_status}")
        self.dismiss(True)
