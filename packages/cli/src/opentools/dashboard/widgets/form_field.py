"""Reusable form field with label, input, and validation."""

from textual.app import ComposeResult
from textual.widgets import Input, Label, Select, Static, TextArea
from textual.widget import Widget


class FormField(Widget):
    """Label + input widget + validation error message."""

    DEFAULT_CSS = """
    FormField { height: auto; margin: 0 0 1 0; }
    FormField .field-error { color: red; display: none; }
    FormField .field-error.visible { display: block; }
    """

    def __init__(self, label: str, input_widget: Input | Select | TextArea,
                 required: bool = False, field_id: str | None = None, **kwargs):
        self._label_text = label + (" *" if required else "")
        self._input = input_widget
        self._required = required
        self._field_id = field_id or (getattr(input_widget, 'id', None) or label.lower().replace(" ", "_"))
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield Label(self._label_text)
        yield self._input
        yield Static("", classes="field-error", id=f"{self._field_id}-error")

    def validate(self) -> bool:
        value = self.get_value()
        if self._required and not value.strip():
            self.show_error(f"{self._label_text.rstrip(' *')} is required")
            return False
        self.clear_error()
        return True

    def get_value(self) -> str:
        if isinstance(self._input, Select):
            val = self._input.value
            return str(val) if val is not Select.BLANK else ""
        if isinstance(self._input, TextArea):
            return self._input.text
        return self._input.value

    def show_error(self, message: str) -> None:
        try:
            error = self.query_one(f"#{self._field_id}-error", Static)
            error.update(message)
            error.add_class("visible")
        except Exception:
            pass

    def clear_error(self) -> None:
        try:
            error = self.query_one(f"#{self._field_id}-error", Static)
            error.update("")
            error.remove_class("visible")
        except Exception:
            pass
