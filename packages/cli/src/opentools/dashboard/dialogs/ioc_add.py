from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Select, Static

from opentools.dashboard.state import DashboardState
from opentools.dashboard.widgets.form_field import FormField
from opentools.models import IOCType


class IOCAddDialog(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    IOCAddDialog { align: center middle; }
    #ioc-container { width: 60%; max-width: 70; height: auto;
        border: thick $primary; background: $surface; padding: 1 2; }
    """

    def __init__(self, state: DashboardState, **kwargs):
        self.state = state
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        with Vertical(id="ioc-container"):
            yield Static("[bold]Add IOC[/bold]")
            yield FormField("Type", Select(
                [(t.value, t.value) for t in IOCType],
                value=IOCType.IP.value, id="ioc-type",
            ), required=True, field_id="ioc-type")
            yield FormField("Value", Input(id="ioc-value", placeholder="10.0.0.1"), required=True, field_id="ioc-value")
            yield FormField("Context", Input(id="ioc-context", placeholder="C2 callback server"), field_id="ioc-context")
            with Horizontal():
                yield Button("Add", variant="primary", id="btn-add")
                yield Button("Cancel", id="btn-cancel")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-cancel":
            self.dismiss(False)
        elif event.button.id == "btn-add":
            fields = {f._field_id: f for f in self.query(FormField)}
            if all(f.validate() for f in fields.values()):
                try:
                    self.state.add_ioc(
                        self.state.selected_id,
                        ioc_type=fields["ioc-type"].get_value(),
                        value=fields["ioc-value"].get_value(),
                        context=fields["ioc-context"].get_value() or None,
                    )
                    self.app.notify("IOC added")
                    self.dismiss(True)
                except Exception as e:
                    self.app.notify(str(e), severity="error")
