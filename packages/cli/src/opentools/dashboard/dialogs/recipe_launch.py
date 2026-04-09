"""Recipe picker + variable fields dialog for launching security workflow recipes."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, Input, Select, Static

from opentools.dashboard.state import DashboardState
from opentools.dashboard.widgets.form_field import FormField
from opentools.models import Recipe


class RecipeLaunchDialog(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    RecipeLaunchDialog { align: center middle; }
    #recipe-container { width: 75%; max-width: 100; height: auto; max-height: 90%;
        border: thick $primary; background: $surface; padding: 1 2; overflow-y: auto; }
    #var-fields { height: auto; }
    .var-group { height: auto; display: none; }
    .var-group.active { display: block; }
    """

    def __init__(
        self,
        state: DashboardState,
        recipes: list[Recipe],
        **kwargs,
    ) -> None:
        self.state = state
        self.recipes = recipes
        # Build a map for quick lookup
        self._recipe_map: dict[str, Recipe] = {r.id: r for r in recipes}
        # Track which recipe's var group is currently visible
        self._active_recipe_id: str | None = recipes[0].id if recipes else None
        super().__init__(**kwargs)

    def compose(self) -> ComposeResult:
        recipe_options = [(r.name, r.id) for r in self.recipes]
        default_recipe_id = self.recipes[0].id if self.recipes else Select.BLANK

        with Vertical(id="recipe-container"):
            yield Static("[bold]Launch Recipe[/bold]")

            yield FormField(
                "Recipe",
                Select(recipe_options, value=default_recipe_id, id="rec-select"),
                required=True,
                field_id="rec-select",
            )

            # Variable fields — one group per recipe, shown/hidden based on selection
            with Vertical(id="var-fields"):
                for recipe in self.recipes:
                    is_active = recipe.id == self._active_recipe_id
                    with Vertical(
                        id=f"vars-{recipe.id}",
                        classes=f"var-group{'  active' if is_active else ''}".strip(),
                    ):
                        if recipe.variables:
                            for vname, vspec in recipe.variables.items():
                                field_id = f"var-{recipe.id}-{vname}"
                                placeholder = vspec.default or vspec.description
                                yield FormField(
                                    vname,
                                    Input(
                                        id=field_id,
                                        value=vspec.default or "",
                                        placeholder=placeholder,
                                    ),
                                    required=vspec.required,
                                    field_id=field_id,
                                )
                        else:
                            yield Static(
                                "[dim]No variables required for this recipe[/dim]",
                                id=f"no-vars-{recipe.id}",
                            )

            yield Checkbox("Dry Run", id="rec-dry-run")

            with Horizontal():
                yield Button("Launch", variant="primary", id="btn-launch")
                yield Button("Cancel", id="btn-cancel")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "rec-select":
            return
        if event.value is Select.BLANK:
            return

        new_recipe_id = str(event.value)

        # Hide old active group
        if self._active_recipe_id is not None:
            try:
                old_group = self.query_one(f"#vars-{self._active_recipe_id}")
                old_group.remove_class("active")
            except Exception:
                pass

        # Show new active group
        self._active_recipe_id = new_recipe_id
        try:
            new_group = self.query_one(f"#vars-{new_recipe_id}")
            new_group.add_class("active")
        except Exception:
            pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(None)
        elif event.button.id == "btn-launch":
            self._do_launch()

    def _do_launch(self) -> None:
        # Validate the recipe selector
        try:
            recipe_select = self.query_one("#rec-select", Select)
        except Exception:
            self.app.notify("No recipe selector found", severity="error")
            return

        if recipe_select.value is Select.BLANK:
            self.app.notify("Please select a recipe", severity="warning")
            return

        recipe_id = str(recipe_select.value)
        recipe = self._recipe_map.get(recipe_id)
        if recipe is None:
            self.app.notify("Recipe not found", severity="error")
            return

        # Collect variable values for the active recipe only
        variables: dict[str, str] = {}
        valid = True
        for vname, vspec in recipe.variables.items():
            field_id = f"var-{recipe_id}-{vname}"
            try:
                form_field = self.query_one(f"[id='{field_id}']", FormField)
                if not form_field.validate():
                    valid = False
                value = form_field.get_value()
                if value:
                    variables[vname] = value
                elif vspec.default is not None:
                    variables[vname] = vspec.default
            except Exception:
                # Field not found — use default if available
                if vspec.default is not None:
                    variables[vname] = vspec.default
                elif vspec.required:
                    self.app.notify(f"Missing required variable: {vname}", severity="error")
                    valid = False

        if not valid:
            return

        # Read dry-run checkbox
        dry_run = False
        try:
            checkbox = self.query_one("#rec-dry-run", Checkbox)
            dry_run = checkbox.value
        except Exception:
            pass

        self.dismiss((recipe_id, variables, dry_run))
