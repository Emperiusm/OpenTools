"""Import engagement dialog — prompts for a file path and imports the engagement."""

from __future__ import annotations

from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from opentools.dashboard.state import DashboardState
from opentools.dashboard.widgets.form_field import FormField


class ImportDialog(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    ImportDialog { align: center middle; }
    #import-container { width: 60%; max-width: 80; height: auto;
        border: thick $primary; background: $surface; padding: 1 2; }
    """

    def __init__(self, state: DashboardState, **kwargs) -> None:
        self.state = state
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        with Vertical(id="import-container"):
            yield Static("[bold]Import Engagement[/bold]")
            yield FormField(
                "File Path",
                Input(
                    id="imp-path",
                    placeholder="Path to .json or .zip export file",
                ),
                required=True,
                field_id="imp-path",
            )
            with Horizontal():
                yield Button("Import", variant="primary", id="btn-import")
                yield Button("Cancel", id="btn-cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
        elif event.button.id == "btn-import":
            self._do_import()

    def _do_import(self) -> None:
        fields = {f._field_id: f for f in self.query(FormField)}
        if not all(f.validate() for f in fields.values()):
            return

        file_path = Path(fields["imp-path"].get_value().strip())

        try:
            from opentools.engagement.export import import_engagement

            new_id = import_engagement(self.state.store, file_path)
            self.app.notify(f"Engagement imported (ID: {new_id})")
            self.dismiss(new_id)
        except Exception as exc:
            self.app.notify(str(exc), severity="error")
