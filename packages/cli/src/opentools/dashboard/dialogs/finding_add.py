from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Select, Static, TextArea

from opentools.dashboard.state import DashboardState
from opentools.dashboard.widgets.form_field import FormField
from opentools.models import Severity


class FindingAddDialog(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    FindingAddDialog { align: center middle; }
    #finding-container { width: 70%; max-width: 90; height: auto; max-height: 85%;
        border: thick $primary; background: $surface; padding: 1 2; overflow-y: auto; }
    """

    def __init__(self, state: DashboardState, **kwargs):
        self.state = state
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        with Vertical(id="finding-container"):
            yield Static("[bold]Add Finding[/bold]")
            yield FormField("Tool", Input(id="f-tool", placeholder="semgrep"), required=True, field_id="f-tool")
            yield FormField("Title", Input(id="f-title", placeholder="SQL Injection in login"), required=True, field_id="f-title")
            yield FormField("Severity", Select(
                [(s.value, s.value) for s in Severity],
                value=Severity.MEDIUM.value, id="f-severity",
            ), required=True, field_id="f-severity")
            yield FormField("CWE", Input(id="f-cwe", placeholder="CWE-89"), field_id="f-cwe")
            yield FormField("File Path", Input(id="f-filepath", placeholder="src/api.py"), field_id="f-filepath")
            yield FormField("Line", Input(id="f-line", placeholder="42"), field_id="f-line")
            yield FormField("Description", TextArea(id="f-desc"), field_id="f-desc")
            yield FormField("Evidence", TextArea(id="f-evidence"), field_id="f-evidence")
            with Horizontal():
                yield Button("Add", variant="primary", id="btn-add")
                yield Button("Cancel", id="btn-cancel")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-cancel":
            self.dismiss(False)
        elif event.button.id == "btn-add":
            fields = {f._field_id: f for f in self.query(FormField)}
            if all(f.validate() for f in fields.values()):
                line_str = fields["f-line"].get_value()
                line_start = int(line_str) if line_str.strip().isdigit() else None
                try:
                    self.state.add_finding(
                        self.state.selected_id,
                        tool=fields["f-tool"].get_value(),
                        title=fields["f-title"].get_value(),
                        severity=fields["f-severity"].get_value(),
                        cwe=fields["f-cwe"].get_value() or None,
                        file_path=fields["f-filepath"].get_value() or None,
                        line_start=line_start,
                        description=fields["f-desc"].get_value() or None,
                        evidence=fields["f-evidence"].get_value() or None,
                    )
                    self.app.notify("Finding added")
                    self.dismiss(True)
                except Exception as e:
                    self.app.notify(str(e), severity="error")
