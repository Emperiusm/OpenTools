"""Main dashboard application."""

from pathlib import Path
from typing import Optional

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, TabbedContent, TabPane

from opentools.config import ConfigLoader
from opentools.containers import ContainerManager
from opentools.engagement.store import EngagementStore
from opentools.plugin import discover_plugin_dir

from opentools.dashboard.state import DashboardState
from opentools.dashboard.sidebar import EngagementSidebar, EngagementSelected
from opentools.dashboard.summary_strip import SummaryStrip
from opentools.dashboard.tabs.findings import FindingsTab
from opentools.dashboard.tabs.timeline import TimelineTab
from opentools.dashboard.tabs.iocs import IOCsTab
from opentools.dashboard.tabs.containers import ContainersTab


class DashboardApp(App):
    CSS_PATH = "dashboard.tcss"
    TITLE = "OpenTools Dashboard"

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("tab", "toggle_sidebar", "Sidebar"),
        Binding("r", "manual_refresh", "Refresh"),
        Binding("1", "switch_tab('findings')", "Findings"),
        Binding("2", "switch_tab('timeline')", "Timeline"),
        Binding("3", "switch_tab('iocs')", "IOCs"),
        Binding("4", "switch_tab('containers')", "Containers"),
        Binding("n", "new_engagement", "New"),
        Binding("R", "run_recipe", "Recipe", key_display="Shift+R"),
        Binding("G", "generate_report", "Report", key_display="Shift+G"),
        Binding("I", "import_engagement", "Import", key_display="Shift+I"),
    ]

    def __init__(
        self,
        db_path: Optional[Path] = None,
        plugin_dir: Optional[Path] = None,
        initial_engagement: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._initial_engagement = initial_engagement

        # Discover plugin dir
        if plugin_dir is None:
            try:
                plugin_dir = discover_plugin_dir()
            except FileNotFoundError:
                plugin_dir = None

        # Setup DB path
        if db_path is None:
            if plugin_dir:
                db_path = plugin_dir.parent.parent / "engagements" / "opentools.db"
            else:
                db_path = Path("engagements/opentools.db")
        db_path.parent.mkdir(parents=True, exist_ok=True)

        store = EngagementStore(db_path=db_path)

        # Setup container manager (optional)
        container_mgr = None
        config = None
        if plugin_dir:
            try:
                config = ConfigLoader(plugin_dir).load()
                container_mgr = ContainerManager(config)
            except Exception:
                pass

        self.state = DashboardState(store, container_mgr, config)
        self._refresh_timer = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            yield EngagementSidebar(self.state, id="sidebar")
            with Vertical(id="main"):
                yield SummaryStrip(self.state, id="summary-strip")
                with TabbedContent(id="tabs"):
                    with TabPane("Findings", id="findings"):
                        yield FindingsTab(self.state, id="findings-tab")
                    with TabPane("Timeline", id="timeline"):
                        yield TimelineTab(self.state, id="timeline-tab")
                    with TabPane("IOCs", id="iocs"):
                        yield IOCsTab(self.state, id="iocs-tab")
                    with TabPane("Containers", id="containers"):
                        yield ContainersTab(self.state, id="containers-tab")
        yield Footer()

    def on_mount(self) -> None:
        self._load_engagements()
        if self._initial_engagement:
            self._select_engagement(self._initial_engagement)

    @work(thread=True)
    def _load_engagements(self) -> None:
        self.state.refresh_engagements()
        self.call_from_thread(self._update_sidebar)

    def _update_sidebar(self) -> None:
        try:
            self.query_one(EngagementSidebar).update_from_state()
        except Exception:
            pass

    def on_engagement_selected(self, message: EngagementSelected) -> None:
        self._select_engagement(message.engagement_id)

    def _select_engagement(self, engagement_id: str) -> None:
        self.state.selected_id = engagement_id
        try:
            eng = self.state.store.get(engagement_id)
            if str(eng.status) == "active":
                self._start_auto_refresh()
            else:
                self._stop_auto_refresh()
        except Exception:
            self._stop_auto_refresh()
        self._do_refresh()

    def _start_auto_refresh(self) -> None:
        self._stop_auto_refresh()
        self._refresh_timer = self.set_interval(3.0, self._do_refresh)
        try:
            self.query_one(SummaryStrip).set_auto_refresh(True)
        except Exception:
            pass

    def _stop_auto_refresh(self) -> None:
        if self._refresh_timer:
            self._refresh_timer.stop()
            self._refresh_timer = None
        try:
            self.query_one(SummaryStrip).set_auto_refresh(False)
        except Exception:
            pass

    @work(thread=True)
    def _do_refresh(self) -> None:
        changes = self.state.refresh_selected()
        self.call_from_thread(self._apply_refresh, changes)

    def _apply_refresh(self, changes: dict) -> None:
        try:
            self.query_one(SummaryStrip).update_from_state()
        except Exception:
            pass
        try:
            self.query_one(FindingsTab).update_from_state()
        except Exception:
            pass
        try:
            self.query_one(TimelineTab).update_from_state()
        except Exception:
            pass
        try:
            self.query_one(IOCsTab).update_from_state()
        except Exception:
            pass
        try:
            self.query_one(ContainersTab).update_from_state()
        except Exception:
            pass

        if "findings" in changes:
            c = changes["findings"]
            sev = "warning" if c.get("critical", 0) > 0 else "information"
            self.notify(
                f"{c['new']} new finding(s) ({c.get('critical', 0)} critical, {c.get('high', 0)} high)",
                severity=sev,
            )

    def action_toggle_sidebar(self) -> None:
        try:
            self.query_one("#sidebar", EngagementSidebar).toggle_class("collapsed")
        except Exception:
            pass

    def action_manual_refresh(self) -> None:
        self._do_refresh()

    def action_switch_tab(self, tab_id: str) -> None:
        try:
            self.query_one(TabbedContent).active = tab_id
        except Exception:
            pass

    def action_new_engagement(self) -> None:
        from opentools.dashboard.dialogs.engagement_create import EngagementCreateDialog
        def on_dismiss(result):
            if result:
                self._load_engagements()
        self.push_screen(EngagementCreateDialog(self.state), callback=on_dismiss)

    def action_run_recipe(self) -> None:
        from opentools.dashboard.dialogs.recipe_launch import RecipeLaunchDialog
        # Build recipe list
        try:
            plugin_dir = self.state.config.plugin_dir if self.state.config and self.state.config.plugin_dir else None
            if plugin_dir:
                from opentools.recipes import RecipeRunner
                from opentools.models import ToolkitConfig
                recipes_path = plugin_dir / "recipes.json"
                runner = RecipeRunner(self.state.config or ToolkitConfig(), recipes_path)
                recipes = runner.list_recipes()
            else:
                recipes = []
                runner = None
        except Exception:
            recipes = []
            runner = None

        if not recipes:
            self.notify("No recipes found", severity="warning")
            return

        def on_dismiss(result):
            if result and runner:
                recipe_id, variables, dry_run = result
                from opentools.dashboard.screens.recipe_runner import RecipeRunnerScreen
                self.push_screen(RecipeRunnerScreen(runner, recipe_id, variables, dry_run))

        self.push_screen(RecipeLaunchDialog(self.state, recipes), callback=on_dismiss)

    def action_generate_report(self) -> None:
        from opentools.dashboard.dialogs.report_dialog import ReportDialog
        def on_dismiss(result):
            if result:
                self.notify(f"Report config: {result}")  # actual generation in future
        self.push_screen(ReportDialog(self.state), callback=on_dismiss)

    def action_import_engagement(self) -> None:
        from opentools.dashboard.dialogs.import_dialog import ImportDialog
        def on_dismiss(result):
            if result:
                self._load_engagements()
        self.push_screen(ImportDialog(self.state), callback=on_dismiss)
