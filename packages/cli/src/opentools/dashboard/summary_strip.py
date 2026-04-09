"""SummaryStrip — one-line header strip for the OpenTools TUI dashboard."""

from __future__ import annotations

from textual.widgets import Static

from opentools.dashboard.state import DashboardState


class SummaryStrip(Static):
    """A single-line strip docked at the top of the dashboard.

    Displays engagement name, target, severity counts, container status,
    IOC count, and an auto-refresh indicator.

    Example output::

        my-audit (10.0.0.1) │ CRIT:2  HIGH:5  MED:3  LOW:1  INFO:0 │ Containers: 8/12 │ IOCs: 14 │ Auto ●
    """

    DEFAULT_CSS = """
    SummaryStrip {
        height: 1;
        dock: top;
        background: $boost;
        padding: 0 1;
    }
    """

    def __init__(self, state: DashboardState, **kwargs) -> None:
        super().__init__("", **kwargs)
        self.state = state
        self._auto_refresh: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_auto_refresh(self, enabled: bool) -> None:
        """Toggle the auto-refresh indicator dot."""
        self._auto_refresh = enabled
        self.update_from_state()

    def update_from_state(self) -> None:
        """Rebuild the strip text from current state data."""
        self.update(self._build_text())

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_text(self) -> str:
        summary = self.state.summary
        containers = self.state.containers
        iocs = self.state.iocs

        # Engagement identity
        if summary is not None:
            eng = summary.engagement
            identity = f"{eng.name} ({eng.target})"
            fc = summary.finding_counts
        else:
            identity = "No engagement selected"
            fc = {}

        # Severity counts with Rich colour markup
        crit = fc.get("critical", 0)
        high = fc.get("high", 0)
        med = fc.get("medium", 0)
        low = fc.get("low", 0)
        info = fc.get("info", 0)

        severity_str = (
            f"[red]CRIT:{crit}[/]  "
            f"[#ff8c00]HIGH:{high}[/]  "
            f"[yellow]MED:{med}[/]  "
            f"[blue]LOW:{low}[/]  "
            f"[dim]INFO:{info}[/]"
        )

        # Container counts
        running = sum(1 for c in containers if c.state == "running")
        total = len(containers)
        container_str = f"Containers: {running}/{total}"

        # IOC count
        ioc_str = f"IOCs: {len(iocs)}"

        # Auto-refresh indicator
        auto_str = "Auto [green]●[/]" if self._auto_refresh else "Auto [dim]○[/]"

        sep = " [dim]│[/] "
        return sep.join([identity, severity_str, container_str, ioc_str, auto_str])
