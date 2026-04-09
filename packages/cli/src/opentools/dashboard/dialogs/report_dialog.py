"""Report generation dialog — collects template/format/metadata and dismisses with a config dict."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Select, Static

from opentools.dashboard.state import DashboardState
from opentools.dashboard.widgets.form_field import FormField

_TEMPLATE_OPTIONS: list[tuple[str, str]] = [
    ("Pentest Report", "pentest-report"),
    ("Incident Report", "incident-report"),
    ("Cloud Security Report", "cloud-security-report"),
    ("Mobile Security Report", "mobile-security-report"),
]

_FORMAT_OPTIONS: list[tuple[str, str]] = [
    ("Markdown", "markdown"),
    ("HTML", "html"),
]


class ReportDialog(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    ReportDialog { align: center middle; }
    #report-container { width: 70%; max-width: 90; height: auto; max-height: 85%;
        border: thick $primary; background: $surface; padding: 1 2; overflow-y: auto; }
    """

    def __init__(self, state: DashboardState, **kwargs) -> None:
        self.state = state
        super().__init__(**kwargs)

    def _engagement_name(self) -> str:
        if self.state.summary:
            return self.state.summary.engagement.name.lower().replace(" ", "-")
        return "engagement"

    def _default_path(self) -> str:
        return f"{self._engagement_name()}-report.md"

    def compose(self) -> ComposeResult:
        with Vertical(id="report-container"):
            yield Static("[bold]Generate Report[/bold]")
            yield FormField(
                "Template",
                Select(_TEMPLATE_OPTIONS, value="pentest-report", id="rep-template"),
                required=True,
                field_id="rep-template",
            )
            yield FormField(
                "Format",
                Select(_FORMAT_OPTIONS, value="markdown", id="rep-format"),
                required=True,
                field_id="rep-format",
            )
            yield FormField(
                "Output Path",
                Input(id="rep-path", value=self._default_path()),
                required=True,
                field_id="rep-path",
            )
            yield FormField(
                "Client",
                Input(id="rep-client", placeholder="Client name (optional)"),
                field_id="rep-client",
            )
            yield FormField(
                "Assessor",
                Input(id="rep-assessor", placeholder="Assessor name (optional)"),
                field_id="rep-assessor",
            )
            yield FormField(
                "Classification",
                Input(id="rep-classification", placeholder="INTERNAL"),
                field_id="rep-classification",
            )
            with Horizontal():
                yield Button("Generate", variant="primary", id="btn-generate")
                yield Button("Cancel", id="btn-cancel")

    def on_select_changed(self, event: Select.Changed) -> None:
        """Update output path extension when format changes."""
        if event.select.id == "rep-format":
            fmt = str(event.value) if event.value is not Select.BLANK else "markdown"
            ext = "html" if fmt == "html" else "md"
            try:
                path_input = self.query_one("#rep-path", Input)
                current = path_input.value
                stem = current.rsplit(".", 1)[0] if "." in current else current
                path_input.value = f"{stem}.{ext}"
            except Exception:
                pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
        elif event.button.id == "btn-generate":
            self._do_generate()

    def _do_generate(self) -> None:
        fields = {f._field_id: f for f in self.query(FormField)}
        if not all(f.validate() for f in fields.values()):
            return

        result = {
            "template": fields["rep-template"].get_value(),
            "format": fields["rep-format"].get_value(),
            "output_path": fields["rep-path"].get_value().strip(),
            "client": fields["rep-client"].get_value() or None,
            "assessor": fields["rep-assessor"].get_value() or None,
            "classification": fields["rep-classification"].get_value() or "INTERNAL",
        }
        self.dismiss(result)
