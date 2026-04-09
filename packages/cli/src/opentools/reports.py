"""Report generation using Jinja2 templates with context builders."""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader

from opentools.engagement.store import EngagementStore
from opentools.models import Finding, Severity


# ─── CWE → Category Mapping Dicts ───────────────────────────────────────────

OWASP_CWE_MAP = {
    "Information Gathering": [],
    "Configuration": ["CWE-16", "CWE-1004", "CWE-614"],
    "Authentication": ["CWE-287", "CWE-798", "CWE-307", "CWE-521"],
    "Authorization": ["CWE-862", "CWE-863", "CWE-639"],
    "Session Management": ["CWE-384", "CWE-613", "CWE-614"],
    "Input Validation": ["CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-611", "CWE-918", "CWE-502"],
    "Error Handling": ["CWE-209", "CWE-200"],
    "Cryptography": ["CWE-327", "CWE-328", "CWE-330"],
    "Business Logic": [],
    "Client-side": ["CWE-79", "CWE-1021", "CWE-352"],
}

MOBILE_TOP10_CWE_MAP = {
    "M1: Improper Credential Usage": ["CWE-798", "CWE-522", "CWE-256"],
    "M2: Inadequate Supply Chain Security": [],
    "M3: Insecure Authentication/Authorization": ["CWE-287", "CWE-306", "CWE-862"],
    "M4: Insufficient Input/Output Validation": ["CWE-89", "CWE-79", "CWE-78", "CWE-134"],
    "M5: Insecure Communication": ["CWE-319", "CWE-295"],
    "M6: Inadequate Privacy Controls": ["CWE-532", "CWE-200"],
    "M7: Insufficient Binary Protections": [],
    "M8: Security Misconfiguration": ["CWE-16"],
    "M9: Insecure Data Storage": ["CWE-312", "CWE-922"],
    "M10: Insufficient Cryptography": ["CWE-327", "CWE-330"],
}

CLOUD_CATEGORY_CWE_MAP = {
    "IAM": ["CWE-287", "CWE-862", "CWE-798", "CWE-521"],
    "Storage": ["CWE-312", "CWE-319", "CWE-922"],
    "Network": ["CWE-284", "CWE-668"],
    "Logging": ["CWE-778"],
    "Encryption": ["CWE-327", "CWE-311"],
    "Container": ["CWE-250", "CWE-269"],
}

ATTACK_TACTIC_CWE_MAP = {
    "Initial Access": ["CWE-287", "CWE-798", "CWE-79"],
    "Execution": ["CWE-78", "CWE-94", "CWE-502"],
    "Persistence": ["CWE-912"],
    "Privilege Escalation": ["CWE-269", "CWE-250"],
    "Defense Evasion": [],
    "Credential Access": ["CWE-522", "CWE-521", "CWE-798"],
    "Discovery": [],
    "Lateral Movement": [],
    "Collection": ["CWE-200", "CWE-532"],
    "Exfiltration": ["CWE-319"],
}


# ─── Context Builders ────────────────────────────────────────────────────────

def _map_findings_to_categories(findings: list[Finding], cwe_map: dict) -> dict:
    """Map findings to categories based on CWE."""
    result = {}
    for category, cwes in cwe_map.items():
        matched = [f for f in findings if f.cwe in cwes]
        result[category] = matched
    return result


def _build_pentest_context(findings: list[Finding], **kwargs) -> dict:
    return {"owasp_matrix": _map_findings_to_categories(findings, OWASP_CWE_MAP)}


def _build_incident_context(findings: list[Finding], **kwargs) -> dict:
    return {"attack_tactics": _map_findings_to_categories(findings, ATTACK_TACTIC_CWE_MAP)}


def _build_cloud_context(findings: list[Finding], **kwargs) -> dict:
    return {"cloud_categories": _map_findings_to_categories(findings, CLOUD_CATEGORY_CWE_MAP)}


def _build_mobile_context(findings: list[Finding], **kwargs) -> dict:
    return {"mobile_top10": _map_findings_to_categories(findings, MOBILE_TOP10_CWE_MAP)}


_TEMPLATE_CONTEXT_BUILDERS = {
    "pentest-report": _build_pentest_context,
    "incident-report": _build_incident_context,
    "cloud-security-report": _build_cloud_context,
    "mobile-security-report": _build_mobile_context,
}


# ─── Custom Jinja2 Filters ──────────────────────────────────────────────────

def _datefmt(dt, fmt="%Y-%m-%d %H:%M UTC"):
    return dt.strftime(fmt) if dt else "—"


def _cwe_link(cwe):
    if cwe and "-" in cwe:
        num = cwe.split("-")[1]
        return f"[{cwe}](https://cwe.mitre.org/data/definitions/{num}.html)"
    return cwe or "—"


def _severity_icon(s):
    icons = {"critical": "!!!", "high": "!!", "medium": "!", "low": "~", "info": "."}
    return icons.get(str(s), str(s))


# ─── Report Generator ────────────────────────────────────────────────────────

class ReportGenerator:
    """Generate reports from engagement data using Jinja2 templates."""

    def __init__(self, template_dir: Path, store: EngagementStore) -> None:
        self._store = store
        self._template_dir = template_dir
        self._env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._env.filters["datefmt"] = _datefmt
        self._env.filters["cwe_link"] = _cwe_link
        self._env.filters["severity_icon"] = _severity_icon

    def list_templates(self) -> list[str]:
        if not self._template_dir.exists():
            return []
        return [
            f.name.replace(".md.j2", "")
            for f in self._template_dir.iterdir()
            if f.name.endswith(".md.j2") and not f.name.startswith("_")
        ]

    def generate(
        self,
        engagement_id: str,
        template_name: str,
        output_path: Optional[Path] = None,
        extra_context: Optional[dict] = None,
    ) -> str:
        context = self._build_base_context(engagement_id)

        builder = _TEMPLATE_CONTEXT_BUILDERS.get(template_name)
        if builder:
            context.update(builder(context["findings"]))

        if extra_context:
            context.update(extra_context)

        template_file = f"{template_name}.md.j2"
        try:
            template = self._env.get_template(template_file)
        except Exception:
            template = self._env.get_template(f"{template_name}.md")

        rendered = template.render(**context)

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered, encoding="utf-8")

        return rendered

    def _build_base_context(self, engagement_id: str) -> dict:
        summary = self._store.get_summary(engagement_id)
        findings = self._store.get_findings(engagement_id)
        timeline = self._store.get_timeline(engagement_id)
        iocs = self._store.get_iocs(engagement_id)
        artifacts = self._store.get_artifacts(engagement_id)

        findings_by_severity = {}
        for sev in Severity:
            group = [f for f in findings if f.severity == sev]
            if group:
                findings_by_severity[sev.value] = group

        findings_by_status = {}
        for f in findings:
            findings_by_status.setdefault(str(f.status), []).append(f)

        findings_by_phase = {}
        for f in findings:
            if f.phase:
                findings_by_phase.setdefault(f.phase, []).append(f)

        severity_conflicts = [f for f in findings if len(set(f.severity_by_tool.values())) > 1]
        tools_used = sorted(set(f.tool for f in findings))

        iocs_by_type = {}
        for ioc in iocs:
            iocs_by_type.setdefault(str(ioc.ioc_type), []).append(ioc)

        return {
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
