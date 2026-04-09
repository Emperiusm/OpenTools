from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Select, Static

from opentools.dashboard.state import DashboardState
from opentools.dashboard.widgets.form_field import FormField
from opentools.models import EngagementType


class EngagementCreateDialog(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    EngagementCreateDialog { align: center middle; }
    #create-container { width: 60%; max-width: 80; height: auto; max-height: 80%;
        border: thick $primary; background: $surface; padding: 1 2; }
    """

    def __init__(self, state: DashboardState, **kwargs):
        self.state = state
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        with Vertical(id="create-container"):
            yield Static("[bold]New Engagement[/bold]")
            yield FormField("Name", Input(id="eng-name", placeholder="my-pentest"), required=True, field_id="eng-name")
            yield FormField("Target", Input(id="eng-target", placeholder="192.168.1.0/24"), required=True, field_id="eng-target")
            yield FormField("Type", Select(
                [(t.value, t.value) for t in EngagementType],
                value=EngagementType.PENTEST.value, id="eng-type",
            ), field_id="eng-type")
            yield FormField("Scope", Input(id="eng-scope", placeholder="Optional scope description"), field_id="eng-scope")
            with Horizontal():
                yield Button("Create", variant="primary", id="btn-create")
                yield Button("Cancel", id="btn-cancel")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-cancel":
            self.dismiss(False)
        elif event.button.id == "btn-create":
            fields = list(self.query(FormField))
            if all(f.validate() for f in fields):
                name = fields[0].get_value()
                target = fields[1].get_value()
                eng_type = fields[2].get_value()
                scope = fields[3].get_value() or None
                try:
                    self.state.create_engagement(name, target, eng_type, scope)
                    self.app.notify(f"Created engagement: {name}")
                    self.dismiss(True)
                except Exception as e:
                    self.app.notify(str(e), severity="error")
