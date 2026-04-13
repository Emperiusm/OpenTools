"""Markdown attack path report generation."""
from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ChainFindingRelation, Engagement, Finding


async def export_path_markdown(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    finding_ids: list[str],
    engagement_id: str | None = None,
) -> str:
    """Generate a Markdown attack path report from an ordered list of finding IDs."""
    import orjson

    # Fetch engagement name if provided
    eng_name = "Unknown Engagement"
    if engagement_id:
        eng_stmt = select(Engagement).where(
            Engagement.id == engagement_id, Engagement.user_id == user_id
        )
        eng_result = await session.execute(eng_stmt)
        eng = eng_result.scalar_one_or_none()
        if eng:
            eng_name = eng.name

    # Fetch all findings in order
    findings: list[Any] = []
    for fid in finding_ids:
        stmt = select(Finding).where(Finding.id == fid, Finding.user_id == user_id)
        result = await session.execute(stmt)
        f = result.scalar_one_or_none()
        if f is None:
            raise ValueError(f"Finding {fid} not found")
        findings.append(f)

    # Fetch relations between consecutive findings
    relations: list[Any] = []
    for i in range(len(findings) - 1):
        src_id = findings[i].id
        tgt_id = findings[i + 1].id
        rel_stmt = select(ChainFindingRelation).where(
            ChainFindingRelation.user_id == user_id,
            ChainFindingRelation.source_finding_id == src_id,
            ChainFindingRelation.target_finding_id == tgt_id,
        )
        rel_result = await session.execute(rel_stmt)
        rel = rel_result.scalar_one_or_none()
        relations.append(rel)

    # Compute risk score
    severity_multipliers = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    max_sev = max(severity_multipliers.get(f.severity, 1) for f in findings)
    edge_weight_sum = sum(r.weight for r in relations if r)
    hop_count = len(findings) - 1
    raw_score = (edge_weight_sum * max_sev) / max(math.sqrt(hop_count), 1)
    risk_score = min(raw_score, 10.0)

    # Build markdown
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Attack Path Report",
        "",
        f"**Engagement:** {eng_name}",
        f"**Generated:** {now}",
        f"**Path length:** {len(findings)} steps",
        f"**Risk score:** {risk_score:.1f}/10",
        "",
        "## Summary",
        "",
        _build_summary(findings, relations),
        "",
    ]

    for i, finding in enumerate(findings):
        sev = finding.severity.upper() if finding.severity else "UNKNOWN"
        lines.append(f"## Step {i + 1}: {finding.title} ({sev})")
        lines.append("")
        lines.append(f"- **Tool:** {finding.tool}")
        if finding.phase:
            lines.append(f"- **Phase:** {finding.phase}")
        if finding.evidence:
            evidence = finding.evidence[:500]
            lines.append(f"- **Evidence:** {evidence}")
        if finding.remediation:
            lines.append(f"- **Remediation:** {finding.remediation}")

        if i < len(relations) and relations[i]:
            rel = relations[i]
            reasons_data = orjson.loads(rel.reasons_json) if rel.reasons_json else []
            reason_names = [r.get("rule", "unknown") for r in reasons_data]
            lines.append("")
            lines.append(
                f"**Link to Step {i + 2}:** {', '.join(reason_names)}, "
                f"weight: {rel.weight:.2f}"
            )
        lines.append("")

    # Recommendations
    remediations = [f.remediation for f in findings if f.remediation]
    if remediations:
        lines.append("## Recommendations")
        lines.append("")
        seen = set()
        for rem in remediations:
            if rem not in seen:
                seen.add(rem)
                lines.append(f"{len(seen)}. {rem}")
        lines.append("")

    return "\n".join(lines)


def _build_summary(findings: list, relations: list) -> str:
    """Template-based path summary."""
    if not findings:
        return "No findings in path."

    first = findings[0]
    last = findings[-1]
    steps = len(findings)

    return (
        f"This attack path spans {steps} steps, starting from "
        f"**{first.title}** ({first.severity}) and culminating in "
        f"**{last.title}** ({last.severity}). "
        f"The path traverses {steps - 1} link(s) through the target environment."
    )
