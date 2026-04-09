"""Parser for Capa JSON output."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from opentools.models import Finding, Severity


def parse(raw_output: str) -> list[Finding]:
    """Parse Capa JSON output into Finding objects.

    Each matched rule becomes a finding with severity=medium (capability
    detection, not a confirmed vulnerability).

    Expected input format::

        {
            "rules": {
                "rule-name": {
                    "meta": {
                        "name": "...",
                        "att&ck": [
                            {"technique": "...", "id": "T1059"}
                        ]
                    },
                    "matches": ...
                }
            }
        }
    """
    data = json.loads(raw_output)
    findings: list[Finding] = []

    for rule_key, rule_data in data.get("rules", {}).items():
        meta = rule_data.get("meta", {})
        name = meta.get("name", rule_key)

        attack_entries = meta.get("att&ck", [])
        technique_parts = []
        for entry in attack_entries:
            technique = entry.get("technique", "")
            tid = entry.get("id", "")
            if technique and tid:
                technique_parts.append(f"{technique} ({tid})")
            elif technique:
                technique_parts.append(technique)
            elif tid:
                technique_parts.append(tid)

        description = (
            "ATT&CK: " + ", ".join(technique_parts) if technique_parts else None
        )

        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                engagement_id="",
                tool="capa",
                title=name,
                description=description,
                severity=Severity.MEDIUM,
                created_at=datetime.now(timezone.utc),
            )
        )

    return findings
