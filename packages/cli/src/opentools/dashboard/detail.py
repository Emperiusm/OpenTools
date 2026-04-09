"""FindingDetailScreen — modal screen for displaying full finding details."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.screen import ModalScreen
from textual.widgets import Label, Button, Static
from textual.containers import Vertical


class FindingDetailScreen(ModalScreen):
    """Modal overlay showing all fields of a single finding."""

    DEFAULT_CSS = """
    FindingDetailScreen {
        align: center middle;
    }
    FindingDetailScreen > Vertical {
        width: 80;
        height: auto;
        max-height: 90%;
        background: $surface;
        border: round $primary;
        padding: 1 2;
    }
    """

    BINDINGS = [("escape", "dismiss", "Close"), ("q", "dismiss", "Close")]

    def __init__(self, finding) -> None:
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        f = self.finding
        severity_map = {
            "critical": "[red]CRITICAL[/]",
            "high": "[#ff8c00]HIGH[/]",
            "medium": "[yellow]MEDIUM[/]",
            "low": "[#4169e1]LOW[/]",
            "info": "[dim]INFO[/]",
        }
        sev_label = severity_map.get(str(f.severity).lower(), str(f.severity))
        location = "N/A"
        if f.file_path:
            location = f.file_path
            if f.line_start:
                location = f"{location}:{f.line_start}"

        lines = [
            f"[bold]Title:[/]       {f.title}",
            f"[bold]Severity:[/]    {sev_label}",
            f"[bold]Status:[/]      {f.status}",
            f"[bold]Tool:[/]        {f.tool}",
            f"[bold]CWE:[/]         {f.cwe or 'N/A'}",
            f"[bold]Location:[/]    {location}",
            f"[bold]CVSS:[/]        {f.cvss if f.cvss is not None else 'N/A'}",
            f"[bold]False Pos:[/]   {f.false_positive}",
            "",
            f"[bold]Description:[/]",
            f"{f.description or '(none)'}",
            "",
            f"[bold]Evidence:[/]",
            f"{f.evidence or '(none)'}",
            "",
            f"[bold]Remediation:[/]",
            f"{f.remediation or '(none)'}",
        ]
        if f.corroborated_by:
            lines.append(f"\n[bold]Corroborated by:[/] {', '.join(f.corroborated_by)}")

        with Vertical():
            yield Static("\n".join(lines))
            yield Button("Close [dim](Esc)[/]", id="close-btn", variant="default")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close-btn":
            self.dismiss()
