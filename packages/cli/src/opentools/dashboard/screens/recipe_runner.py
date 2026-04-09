"""Recipe execution screen with per-step progress."""

import asyncio
from pathlib import Path
from typing import Optional

from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, RichLog, Static

from opentools.recipes import RecipeRunner


class RecipeRunnerScreen(Screen):
    """Full-screen recipe execution with live progress."""

    BINDINGS = [
        Binding("o", "toggle_output", "Output"),
        Binding("escape", "go_back", "Back"),
    ]

    DEFAULT_CSS = """
    #runner-header { height: 3; padding: 0 1; background: $boost; }
    #steps-table { height: 1fr; }
    #output-log { height: 10; display: none; border-top: solid $primary; }
    #output-log.visible { display: block; }
    """

    def __init__(self, runner: RecipeRunner, recipe_id: str,
                 variables: dict, dry_run: bool = False, **kwargs):
        self._runner = runner
        self._recipe_id = recipe_id
        self._variables = variables
        self._dry_run = dry_run
        self._complete = False
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        yield Header()
        recipe = self._runner.get_recipe(self._recipe_id)
        status = "DRY RUN" if self._dry_run else "STARTING"
        yield Static(
            f"[bold]Recipe:[/bold] {recipe.name}  |  "
            f"[bold]Status:[/bold] {status}",
            id="runner-header",
        )
        table = DataTable(id="steps-table")
        table.cursor_type = "row"
        yield table
        yield RichLog(id="output-log", wrap=True, highlight=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#steps-table", DataTable)
        table.add_columns("Status", "Step", "Duration", "Result")

        # Pre-populate with pending steps
        recipe = self._runner.get_recipe(self._recipe_id)
        for step in recipe.steps:
            table.add_row("[ ]", step.name, "---", "PENDING", key=step.name)

        self._execute()

    @work(thread=True)
    def _execute(self) -> None:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(self._run_recipe())
        finally:
            loop.close()
        self.call_from_thread(self._on_complete)

    async def _run_recipe(self) -> None:
        async for event_type, step_name, result in self._runner.run_with_progress(
            self._recipe_id, self._variables, dry_run=self._dry_run,
        ):
            if event_type == "started":
                self.call_from_thread(self._update_step, step_name, "[>]", "---", "RUNNING")
            elif event_type == "completed" and result:
                status_icon = "[x]" if result.status in ("success", "dry_run") else "[!]"
                duration = f"{result.duration_ms}ms" if result.duration_ms else "---"
                self.call_from_thread(
                    self._update_step, step_name, status_icon, duration,
                    result.status.upper(),
                )
                if result.stdout:
                    self.call_from_thread(self._append_output, step_name, result.stdout)
                if result.stderr and result.status == "error":
                    self.call_from_thread(self._append_output, step_name, f"STDERR: {result.stderr}")
            elif event_type == "error":
                self.call_from_thread(
                    self._update_step, step_name, "[!]", "---",
                    f"ERROR: {result.stderr if result else 'Unknown'}",
                )

    def _update_step(self, step_name: str, status: str, duration: str, result: str) -> None:
        table = self.query_one("#steps-table", DataTable)
        try:
            # Find and update the row by iterating
            for i, key in enumerate(table.rows.keys()):
                if str(key) == step_name or key.value == step_name:
                    table.update_cell_at((i, 0), status)
                    table.update_cell_at((i, 2), duration)
                    table.update_cell_at((i, 3), result)
                    break
        except Exception:
            pass

        # Update header
        try:
            recipe = self._runner.get_recipe(self._recipe_id)
            header = self.query_one("#runner-header", Static)
            header.update(
                f"[bold]Recipe:[/bold] {recipe.name}  |  "
                f"[bold]Status:[/bold] {'RUNNING' if not self._complete else 'COMPLETE'}"
            )
        except Exception:
            pass

    def _append_output(self, step_name: str, text: str) -> None:
        try:
            log = self.query_one("#output-log", RichLog)
            log.write(f"[dim][{step_name}][/dim] {text}")
        except Exception:
            pass

    def _on_complete(self) -> None:
        self._complete = True
        try:
            recipe = self._runner.get_recipe(self._recipe_id)
            header = self.query_one("#runner-header", Static)
            header.update(
                f"[bold]Recipe:[/bold] {recipe.name}  |  "
                f"[bold green]Status: COMPLETE[/bold green]  |  Press Esc to return"
            )
        except Exception:
            pass
        self.notify("Recipe execution complete")

    def action_toggle_output(self) -> None:
        try:
            self.query_one("#output-log", RichLog).toggle_class("visible")
        except Exception:
            pass

    def action_go_back(self) -> None:
        self.app.pop_screen()
