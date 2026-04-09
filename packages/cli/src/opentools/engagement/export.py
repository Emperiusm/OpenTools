"""Engagement export and import."""

import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from opentools.engagement.store import EngagementStore
from opentools.engagement.schema import LATEST_VERSION


def export_engagement(store: EngagementStore, engagement_id: str, output_path: Path, bundle: bool = False) -> Path:
    """Export an engagement to a JSON file or a zip bundle.

    Includes all findings, timeline events, IOCs, artifacts metadata, and audit log.
    When bundle=True, creates a zip archive containing engagement.json and artifact files.
    """
    engagement = store.get(engagement_id)
    findings = store.get_findings(engagement_id)
    timeline = store.get_timeline(engagement_id)
    iocs = store.get_iocs(engagement_id)
    artifacts = store.get_artifacts(engagement_id)
    audit = store.get_audit_log(engagement_id=engagement_id)

    data = {
        "schema_version": LATEST_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "engagement": engagement.model_dump(mode="json"),
        "findings": [f.model_dump(mode="json") for f in findings],
        "timeline_events": [e.model_dump(mode="json") for e in timeline],
        "iocs": [i.model_dump(mode="json") for i in iocs],
        "artifacts": [a.model_dump(mode="json") for a in artifacts],
        "audit_log": [a.model_dump(mode="json") for a in audit],
    }

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not bundle:
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        return output_path

    zip_path = output_path.with_suffix(".zip")
    missing = []

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("engagement.json", json.dumps(data, indent=2))

        for artifact in artifacts:
            src = Path(artifact.file_path)
            if src.exists():
                zf.write(src, f"artifacts/{src.name}")
            else:
                missing.append(artifact.file_path)

        if missing:
            zf.writestr("missing_artifacts.txt", "\n".join(missing))

    return zip_path


def import_engagement(store: EngagementStore, import_path: Path) -> str:
    """Import an engagement from a JSON export file or a zip bundle.

    Assigns new IDs to avoid conflicts. Returns the new engagement ID.
    """
    path = Path(import_path)

    if path.suffix == ".zip":
        with zipfile.ZipFile(path, "r") as zf:
            data = json.loads(zf.read("engagement.json"))
    else:
        with open(path) as f:
            data = json.load(f)

    # Remap IDs
    id_map: dict[str, str] = {}

    def new_id(old_id: str) -> str:
        if old_id not in id_map:
            id_map[old_id] = str(uuid4())
        return id_map[old_id]

    # Import engagement
    eng_data = data["engagement"]
    from opentools.models import Engagement
    engagement = Engagement(**{
        **eng_data,
        "id": new_id(eng_data["id"]),
    })
    store.create(engagement)

    # Import findings
    from opentools.models import Finding
    for f_data in data.get("findings", []):
        finding = Finding(**{
            **f_data,
            "id": new_id(f_data["id"]),
            "engagement_id": engagement.id,
        })
        # Use raw insert to avoid auto-creating duplicate timeline events
        store._conn.execute(
            "INSERT INTO findings (id, engagement_id, tool, corroborated_by, cwe, severity, "
            "severity_by_tool, status, phase, title, description, file_path, line_start, "
            "line_end, evidence, remediation, cvss, false_positive, dedup_confidence, "
            "created_at, deleted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (finding.id, finding.engagement_id, finding.tool,
             json.dumps(finding.corroborated_by), finding.cwe, str(finding.severity),
             json.dumps(finding.severity_by_tool), str(finding.status), finding.phase,
             finding.title, finding.description, finding.file_path,
             finding.line_start, finding.line_end, finding.evidence,
             finding.remediation, finding.cvss, int(finding.false_positive),
             str(finding.dedup_confidence) if finding.dedup_confidence else None,
             finding.created_at.isoformat(),
             finding.deleted_at.isoformat() if finding.deleted_at else None),
        )

    # Import timeline events
    from opentools.models import TimelineEvent
    for e_data in data.get("timeline_events", []):
        event = TimelineEvent(**{
            **e_data,
            "id": new_id(e_data["id"]),
            "engagement_id": engagement.id,
            "finding_id": new_id(e_data["finding_id"]) if e_data.get("finding_id") else None,
        })
        store.add_event(event)

    # Import IOCs
    from opentools.models import IOC
    for i_data in data.get("iocs", []):
        ioc = IOC(**{
            **i_data,
            "id": new_id(i_data["id"]),
            "engagement_id": engagement.id,
            "source_finding_id": new_id(i_data["source_finding_id"]) if i_data.get("source_finding_id") else None,
        })
        store.add_ioc(ioc)

    # Import artifacts
    from opentools.models import Artifact
    for a_data in data.get("artifacts", []):
        artifact = Artifact(**{
            **a_data,
            "id": new_id(a_data["id"]),
            "engagement_id": engagement.id,
        })
        store.add_artifact(artifact)

    store._conn.commit()
    return engagement.id
