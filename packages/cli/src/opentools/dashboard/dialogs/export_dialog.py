"""Context-sensitive export dialog for findings, IOCs, and engagements."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, Horizontal
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Select, Static

from opentools.dashboard.state import DashboardState
from opentools.dashboard.widgets.form_field import FormField

ExportContext = Literal["findings", "iocs", "engagement"]

_FORMAT_OPTIONS: dict[str, list[tuple[str, str]]] = {
    "findings": [("SARIF", "sarif"), ("CSV", "csv"), ("JSON", "json")],
    "iocs": [("CSV", "csv"), ("JSON", "json"), ("STIX", "stix")],
    "engagement": [("JSON", "json"), ("ZIP", "zip")],
}

_DEFAULT_EXT: dict[str, str] = {
    "sarif": "sarif",
    "csv": "csv",
    "json": "json",
    "stix": "json",
    "zip": "zip",
}

_TLP_OPTIONS: list[tuple[str, str]] = [
    ("WHITE", "white"),
    ("GREEN", "green"),
    ("AMBER", "amber"),
    ("RED", "red"),
]


class ExportDialog(ModalScreen):
    BINDINGS = [Binding("escape", "dismiss", "Cancel")]
    DEFAULT_CSS = """
    ExportDialog { align: center middle; }
    #export-container { width: 70%; max-width: 90; height: auto; max-height: 85%;
        border: thick $primary; background: $surface; padding: 1 2; overflow-y: auto; }
    #tlp-row { display: none; height: auto; }
    #tlp-row.visible { display: block; }
    """

    # Per-session memory: last format chosen per context
    _last_settings: dict[str, str] = {}

    def __init__(
        self,
        state: DashboardState,
        export_context: ExportContext = "findings",
        **kwargs,
    ) -> None:
        self.state = state
        self.export_context = export_context
        super().__init__(**kwargs)

    def _engagement_name(self) -> str:
        if self.state.summary:
            return self.state.summary.engagement.name.lower().replace(" ", "-")
        return "engagement"

    def _default_format(self) -> str:
        opts = _FORMAT_OPTIONS[self.export_context]
        last = self.__class__._last_settings.get(self.export_context)
        if last and any(v == last for _, v in opts):
            return last
        return opts[0][1]

    def _default_path(self, fmt: str) -> str:
        ext = _DEFAULT_EXT.get(fmt, fmt)
        return f"{self._engagement_name()}-{self.export_context}.{ext}"

    def compose(self) -> ComposeResult:
        fmt_options = _FORMAT_OPTIONS[self.export_context]
        default_fmt = self._default_format()
        default_path = self._default_path(default_fmt)

        with Vertical(id="export-container"):
            yield Static(f"[bold]Export {self.export_context.title()}[/bold]")
            yield FormField(
                "Format",
                Select(fmt_options, value=default_fmt, id="exp-format"),
                required=True,
                field_id="exp-format",
            )
            yield FormField(
                "Output Path",
                Input(id="exp-path", value=default_path),
                required=True,
                field_id="exp-path",
            )
            # TLP row — only relevant for STIX, hidden by default
            with Vertical(id="tlp-row"):
                yield FormField(
                    "TLP",
                    Select(_TLP_OPTIONS, value="green", id="exp-tlp"),
                    field_id="exp-tlp",
                )
            with Horizontal():
                yield Button("Export", variant="primary", id="btn-export")
                yield Button("Cancel", id="btn-cancel")

    def on_mount(self) -> None:
        # Show TLP row if initial format is STIX
        if self._default_format() == "stix":
            self.query_one("#tlp-row").add_class("visible")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "exp-format":
            fmt = str(event.value) if event.value is not Select.BLANK else ""
            # Update path extension
            try:
                path_input = self.query_one("#exp-path", Input)
                current = path_input.value
                # Replace extension
                stem = current.rsplit(".", 1)[0] if "." in current else current
                ext = _DEFAULT_EXT.get(fmt, fmt)
                path_input.value = f"{stem}.{ext}"
            except Exception:
                pass
            # Toggle TLP visibility
            try:
                tlp_row = self.query_one("#tlp-row")
                if fmt == "stix":
                    tlp_row.add_class("visible")
                else:
                    tlp_row.remove_class("visible")
            except Exception:
                pass

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-cancel":
            self.dismiss(False)
        elif event.button.id == "btn-export":
            self._do_export()

    def _do_export(self) -> None:
        fields = {f._field_id: f for f in self.query(FormField)}
        if not all(f.validate() for f in fields.values()):
            return

        fmt = fields["exp-format"].get_value()
        output_path = Path(fields["exp-path"].get_value().strip())
        tlp = fields["exp-tlp"].get_value() if fmt == "stix" else None

        # Persist last-used format for this context
        self.__class__._last_settings[self.export_context] = fmt

        try:
            if self.export_context == "findings":
                self._export_findings(fmt, output_path)
            elif self.export_context == "iocs":
                self._export_iocs(fmt, output_path, tlp)
            elif self.export_context == "engagement":
                self._export_engagement(fmt, output_path)

            self.app.notify(f"Exported to {output_path}")
            self.dismiss(True)
        except Exception as exc:
            self.app.notify(str(exc), severity="error")

    # ------------------------------------------------------------------
    # Per-context export helpers
    # ------------------------------------------------------------------

    def _export_findings(self, fmt: str, output_path: Path) -> None:
        from opentools.findings import export_sarif, export_csv, export_json

        findings = self.state.findings
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "sarif":
            data = export_sarif(findings)
            output_path.write_text(json.dumps(data, indent=2))
        elif fmt == "csv":
            output_path.write_text(export_csv(findings))
        elif fmt == "json":
            output_path.write_text(export_json(findings))
        else:
            raise ValueError(f"Unknown findings format: {fmt}")

    def _export_iocs(self, fmt: str, output_path: Path, tlp: str | None) -> None:
        import csv as csv_mod
        import io

        iocs = self.state.iocs
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "json":
            output_path.write_text(
                json.dumps([i.model_dump(mode="json") for i in iocs], indent=2)
            )
        elif fmt == "csv":
            buf = io.StringIO()
            writer = csv_mod.writer(buf)
            writer.writerow(["id", "ioc_type", "value", "context"])
            for ioc in iocs:
                writer.writerow([ioc.id, ioc.ioc_type, ioc.value, ioc.context or ""])
            output_path.write_text(buf.getvalue())
        elif fmt == "stix":
            from opentools.stix_export import export_stix

            engagement = self.state.store.get(self.state.selected_id)
            stix_json = export_stix(iocs, engagement, tlp=tlp)
            output_path.write_text(stix_json)
        else:
            raise ValueError(f"Unknown IOC format: {fmt}")

    def _export_engagement(self, fmt: str, output_path: Path) -> None:
        from opentools.engagement.export import export_engagement

        bundle = fmt == "zip"
        export_engagement(
            self.state.store,
            self.state.selected_id,
            output_path,
            bundle=bundle,
        )
