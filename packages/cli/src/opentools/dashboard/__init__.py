"""OpenTools TUI Dashboard."""

from pathlib import Path
from typing import Optional


def launch_dashboard(
    db_path: Optional[Path] = None,
    plugin_dir: Optional[Path] = None,
    engagement: Optional[str] = None,
) -> None:
    """Launch the interactive TUI dashboard."""
    from opentools.dashboard.app import DashboardApp
    app = DashboardApp(db_path=db_path, plugin_dir=plugin_dir, initial_engagement=engagement)
    app.run()
