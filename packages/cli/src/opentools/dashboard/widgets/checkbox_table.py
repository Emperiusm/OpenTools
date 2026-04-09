"""DataTable subclass with checkbox column and multi-select support."""

from textual.binding import Binding
from textual.widgets import DataTable


class CheckboxTable(DataTable):
    """DataTable with a checkbox first column for multi-select."""

    BINDINGS = [
        Binding("space", "toggle_check", "Check", show=False),
        Binding("ctrl+a", "select_all", "Select All", show=True),
        Binding("ctrl+d", "deselect_all", "Deselect", show=True),
    ]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._checked: set[str] = set()
        self._row_keys: list[str] = []

    def add_checked_row(self, *cells, key: str):
        """Add a row with checkbox prepended. Track by key."""
        checkbox = "[x]" if key in self._checked else "[ ]"
        self.add_row(checkbox, *cells, key=key)
        if key not in self._row_keys:
            self._row_keys.append(key)

    def clear(self, columns: bool = False):
        self._row_keys.clear()
        super().clear(columns=columns)

    def action_toggle_check(self):
        if self.cursor_row is None:
            return
        try:
            row_key = self._row_keys[self.cursor_row]
        except IndexError:
            return
        if row_key in self._checked:
            self._checked.discard(row_key)
        else:
            self._checked.add(row_key)
        self._refresh_checkbox(self.cursor_row, row_key)

    def action_select_all(self):
        for i, key in enumerate(self._row_keys):
            self._checked.add(key)
            self._refresh_checkbox(i, key)

    def action_deselect_all(self):
        for i, key in enumerate(self._row_keys):
            self._checked.discard(key)
            self._refresh_checkbox(i, key)

    def get_checked_keys(self) -> list[str]:
        return [k for k in self._row_keys if k in self._checked]

    def _refresh_checkbox(self, row_index: int, key: str):
        checkbox = "[x]" if key in self._checked else "[ ]"
        try:
            self.update_cell_at((row_index, 0), checkbox)
        except Exception:
            pass
