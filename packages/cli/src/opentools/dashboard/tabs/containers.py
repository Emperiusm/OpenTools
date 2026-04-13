"""ContainersTab — DataTable of Docker containers with start/stop/restart actions."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.widget import Widget
from textual.widgets import DataTable

from opentools.dashboard.state import DashboardState


class ContainersTab(Widget):
    """Displays live Docker container status with toggle and restart actions.

    Bindings
    --------
    enter    — toggle the selected container (start if stopped/exited, stop if running)
    r        — restart the selected container
    """

    BINDINGS = [
        Binding("enter", "toggle_container", "Toggle"),
        Binding("r", "restart_container", "Restart"),
    ]

    _STATE_MARKUP: dict[str, str] = {
        "running": "[green]running[/]",
        "exited": "[red]exited[/]",
        "stopped": "[dim]stopped[/]",
    }

    def __init__(self, state: DashboardState, **kwargs) -> None:
        super().__init__(**kwargs)
        self.state = state
        self._last_snapshot: tuple | None = None

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------

    def compose(self) -> ComposeResult:
        table: DataTable = DataTable(id="containers-table", cursor_type="row")
        table.add_columns("Container", "State", "Health", "Profile", "Uptime")
        yield table

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def _data_snapshot(self) -> tuple:
        return (
            len(self.state.containers),
            tuple((c.name, c.state) for c in self.state.containers),
        )

    def update_from_state(self) -> None:
        """Clear and rebuild the table from ``self.state.containers``."""
        snapshot = self._data_snapshot()
        if snapshot == self._last_snapshot:
            return
        self._last_snapshot = snapshot

        table = self.query_one("#containers-table", DataTable)
        table.clear()

        for container in self.state.containers:
            state_key = str(container.state).lower()
            state_cell = self._STATE_MARKUP.get(state_key, str(container.state))

            health = container.health or ""
            profile = ", ".join(container.profile) if container.profile else "---"
            uptime = container.uptime or ""

            table.add_row(
                container.name,
                state_cell,
                health,
                profile,
                uptime,
                key=container.name,
            )

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def action_toggle_container(self) -> None:
        """Start a stopped/exited container, or stop a running one."""
        container = self._get_selected_container()
        if container is None:
            return

        state = str(container.state).lower()
        if state == "running":
            self.state.stop_container(container.name)
            self.app.notify(f"Stopping container: {container.name}")
        else:
            self.state.start_container(container.name)
            self.app.notify(f"Starting container: {container.name}")

        self.update_from_state()

    def action_restart_container(self) -> None:
        """Restart the selected container."""
        container = self._get_selected_container()
        if container is None:
            return

        self.state.restart_container(container.name)
        self.app.notify(f"Restarting container: {container.name}")
        self.update_from_state()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_selected_container(self):
        """Return the ContainerStatus at the current cursor row, or None."""
        table = self.query_one("#containers-table", DataTable)
        if table.cursor_row is None:
            return None

        idx = table.cursor_row
        containers = self.state.containers
        if idx < 0 or idx >= len(containers):
            return None
        return containers[idx]
