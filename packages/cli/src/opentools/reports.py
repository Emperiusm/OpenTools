"""Report generation using Jinja2 templates."""

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader

from opentools.engagement.store import EngagementStore
from opentools.models import Finding, Severity


class ReportGenerator:
    """Generate reports from engagement data using Jinja2 templates."""

    def __init__(self, template_dir: Path, store: EngagementStore) -> None:
        self._store = store
        self._template_dir = template_dir
        self._env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=False,  # markdown templates, not HTML
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def list_templates(self) -> list[str]:
        """Return names of available .md.j2 templates."""
        if not self._template_dir.exists():
            return []
        return [
            f.stem.replace(".md", "")  # "pentest-report.md.j2" -> "pentest-report"
            for f in self._template_dir.iterdir()
            if f.name.endswith(".md.j2")
        ]

    def generate(
        self,
        engagement_id: str,
        template_name: str,
        output_path: Optional[Path] = None,
    ) -> str:
        """Render a report template with engagement data. Returns rendered markdown."""
        # Build context from engagement store
        summary = self._store.get_summary(engagement_id)
        findings = self._store.get_findings(engagement_id)
        timeline = self._store.get_timeline(engagement_id)
        iocs = self._store.get_iocs(engagement_id)
        artifacts = self._store.get_artifacts(engagement_id)

        # Group findings
        findings_by_severity = {}
        for sev in Severity:
            group = [f for f in findings if f.severity == sev]
            if group:
                findings_by_severity[sev.value] = group

        findings_by_status = {}
        for f in findings:
            findings_by_status.setdefault(f.status, []).append(f)

        findings_by_phase = {}
        for f in findings:
            if f.phase:
                findings_by_phase.setdefault(f.phase, []).append(f)

        # Severity conflicts
        severity_conflicts = [f for f in findings if len(set(f.severity_by_tool.values())) > 1]

        tools_used = sorted(set(f.tool for f in findings))

        iocs_by_type = {}
        for ioc in iocs:
            iocs_by_type.setdefault(ioc.ioc_type, []).append(ioc)

        context = {
            "engagement": summary.engagement,
            "findings": findings,
            "findings_by_severity": findings_by_severity,
            "findings_by_status": findings_by_status,
            "findings_by_phase": findings_by_phase,
            "severity_conflicts": severity_conflicts,
            "timeline": timeline,
            "iocs": iocs,
            "iocs_by_type": iocs_by_type,
            "artifacts": artifacts,
            "tools_used": tools_used,
            "summary": summary,
            "generated_at": datetime.now(timezone.utc),
        }

        # Try .md.j2 extension first, then .md
        template_file = f"{template_name}.md.j2"
        try:
            template = self._env.get_template(template_file)
        except Exception:
            template_file = f"{template_name}.md"
            template = self._env.get_template(template_file)

        rendered = template.render(**context)

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered, encoding="utf-8")

        return rendered
