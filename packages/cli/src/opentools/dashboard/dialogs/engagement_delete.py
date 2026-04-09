from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from opentools.dashboard.state import DashboardState


class EngagementDeleteDialog(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    EngagementDeleteDialog { align: center middle; }
    #delete-container { width: 60%; max-width: 70; height: auto;
        border: thick $error; background: $surface; padding: 1 2; }
    """

    def __init__(self, state: DashboardState, engagement_id: str, **kwargs):
        self.state = state
        self._engagement_id = engagement_id
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        summary = self.state.store.get_summary(self._engagement_id)
        eng = summary.engagement
        finding_count = sum(summary.finding_counts.values())
        ioc_count = sum(summary.ioc_counts_by_type.values())
        timeline_count = summary.timeline_event_count

        with Vertical(id="delete-container"):
            yield Static(f"[bold red]Delete engagement \"{eng.name}\"?[/bold red]")
            yield Static("")
            yield Static(f"This will permanently delete:")
            yield Static(f"  - {finding_count} finding(s)")
            yield Static(f"  - {ioc_count} IOC(s)")
            yield Static(f"  - {timeline_count} timeline event(s)")
            yield Static(f"  - {summary.artifact_count} artifact(s)")
            yield Static("")
            yield Static("[bold]This cannot be undone.[/bold]")
            yield Static("")
            with Horizontal():
                yield Button("Delete", variant="error", id="btn-delete")
                yield Button("Cancel", id="btn-cancel")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-cancel":
            self.dismiss(False)
        elif event.button.id == "btn-delete":
            try:
                self.state.delete_engagement(self._engagement_id)
                self.app.notify("Engagement deleted")
                self.dismiss(True)
            except Exception as e:
                self.app.notify(str(e), severity="error")
