"""
SQLite-backed engagement store with full CRUD operations.

Accepts either a ``db_path`` (opens / creates a file) or an existing
``conn`` (used as-is, primarily for :memory: testing).
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from opentools.engagement.schema import migrate
from opentools.findings import check_duplicate, _normalize_path
from opentools.models import (
    Artifact,
    ArtifactType,
    AuditEntry,
    Confidence,
    Engagement,
    EngagementStatus,
    EngagementSummary,
    EngagementType,
    Finding,
    FindingStatus,
    IOC,
    IOCType,
    Severity,
    TimelineEvent,
)


_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _severity_rank(s: str) -> int:
    return _SEVERITY_ORDER.get(str(s), 0)


class EngagementStore:
    """Persistence layer for all engagement data."""

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(
        self,
        db_path: Optional[Path] = None,
        conn: Optional[sqlite3.Connection] = None,
    ) -> None:
        if conn is not None:
            self._conn = conn
        elif db_path is not None:
            self._conn = sqlite3.connect(str(db_path))
        else:
            raise ValueError("Provide either db_path or conn")

        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA foreign_keys=ON")
        migrate(self._conn)

    # ------------------------------------------------------------------
    # Engagement CRUD
    # ------------------------------------------------------------------

    def create(self, engagement: Engagement) -> str:
        self._conn.execute(
            """
            INSERT INTO engagements
                (id, name, target, type, scope, status, skills_used,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                engagement.name,
                engagement.target,
                str(engagement.type),
                engagement.scope,
                str(engagement.status),
                json.dumps(engagement.skills_used),
                engagement.created_at.isoformat(),
                engagement.updated_at.isoformat(),
            ),
        )
        self._conn.commit()
        return engagement.id

    def get(self, engagement_id: str) -> Engagement:
        row = self._conn.execute(
            "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"Engagement '{engagement_id}' not found")
        return self._row_to_engagement(row)

    def list_all(self) -> list[Engagement]:
        rows = self._conn.execute(
            "SELECT * FROM engagements ORDER BY created_at DESC"
        ).fetchall()
        return [self._row_to_engagement(r) for r in rows]

    def update_status(self, engagement_id: str, status: EngagementStatus) -> None:
        self._conn.execute(
            "UPDATE engagements SET status = ?, updated_at = ? WHERE id = ?",
            (str(status), datetime.now(timezone.utc).isoformat(), engagement_id),
        )
        self._conn.commit()

    def delete_engagement(self, engagement_id: str) -> None:
        """Delete an engagement and all associated data."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute("DELETE FROM audit_log WHERE engagement_id = ?", (engagement_id,))
            self._conn.execute("DELETE FROM artifacts WHERE engagement_id = ?", (engagement_id,))
            self._conn.execute("DELETE FROM iocs WHERE engagement_id = ?", (engagement_id,))
            self._conn.execute("DELETE FROM timeline_events WHERE engagement_id = ?", (engagement_id,))
            self._conn.execute("DELETE FROM findings WHERE engagement_id = ?", (engagement_id,))
            self._conn.execute("DELETE FROM engagements WHERE id = ?", (engagement_id,))
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def get_summary(self, engagement_id: str) -> EngagementSummary:
        engagement = self.get(engagement_id)

        # Finding counts by severity (exclude false positives)
        rows = self._conn.execute(
            """
            SELECT severity, COUNT(*) as cnt
            FROM findings
            WHERE engagement_id = ? AND deleted_at IS NULL
            GROUP BY severity
            """,
            (engagement_id,),
        ).fetchall()
        finding_counts: dict[str, int] = {r["severity"]: r["cnt"] for r in rows}

        # Finding counts by status
        rows = self._conn.execute(
            """
            SELECT status, COUNT(*) as cnt
            FROM findings
            WHERE engagement_id = ? AND deleted_at IS NULL
            GROUP BY status
            """,
            (engagement_id,),
        ).fetchall()
        finding_counts_by_status: dict[str, int] = {r["status"]: r["cnt"] for r in rows}

        # Finding counts by phase
        rows = self._conn.execute(
            """
            SELECT phase, COUNT(*) as cnt
            FROM findings
            WHERE engagement_id = ? AND deleted_at IS NULL AND phase IS NOT NULL
            GROUP BY phase
            """,
            (engagement_id,),
        ).fetchall()
        finding_counts_by_phase: dict[str, int] = {r["phase"]: r["cnt"] for r in rows}

        # IOC counts by type
        rows = self._conn.execute(
            """
            SELECT ioc_type, COUNT(*) as cnt
            FROM iocs
            WHERE engagement_id = ?
            GROUP BY ioc_type
            """,
            (engagement_id,),
        ).fetchall()
        ioc_counts_by_type: dict[str, int] = {r["ioc_type"]: r["cnt"] for r in rows}

        artifact_count: int = self._conn.execute(
            "SELECT COUNT(*) FROM artifacts WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchone()[0]

        timeline_event_count: int = self._conn.execute(
            "SELECT COUNT(*) FROM timeline_events WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchone()[0]

        false_positive_count: int = self._conn.execute(
            "SELECT COUNT(*) FROM findings WHERE engagement_id = ? AND false_positive = 1",
            (engagement_id,),
        ).fetchone()[0]

        # Severity conflicts: findings whose severity_by_tool disagrees
        rows = self._conn.execute(
            """
            SELECT id, title, severity, severity_by_tool
            FROM findings
            WHERE engagement_id = ? AND deleted_at IS NULL
              AND severity_by_tool IS NOT NULL AND severity_by_tool != '{}'
            """,
            (engagement_id,),
        ).fetchall()
        severity_conflicts = []
        for r in rows:
            sbt = json.loads(r["severity_by_tool"] or "{}")
            unique_vals = set(sbt.values())
            if len(unique_vals) > 1 or (unique_vals and r["severity"] not in unique_vals):
                severity_conflicts.append(
                    {"id": r["id"], "title": r["title"], "severity": r["severity"],
                     "severity_by_tool": sbt}
                )

        return EngagementSummary(
            engagement=engagement,
            finding_counts=finding_counts,
            finding_counts_by_status=finding_counts_by_status,
            finding_counts_by_phase=finding_counts_by_phase,
            ioc_counts_by_type=ioc_counts_by_type,
            artifact_count=artifact_count,
            timeline_event_count=timeline_event_count,
            false_positive_count=false_positive_count,
            severity_conflicts=severity_conflicts,
        )

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def add_finding(self, finding: Finding) -> str:
        # Normalize path
        normalized = _normalize_path(finding.file_path)
        if normalized != finding.file_path:
            finding = finding.model_copy(update={"file_path": normalized})

        self._conn.execute("BEGIN IMMEDIATE")
        try:
            candidates = self._query_dedup_candidates(finding)
            match = check_duplicate(finding, candidates)

            if match:
                result_id = self._merge_finding(match.match, finding, match.confidence)
            else:
                self._insert_finding_row(finding)
                self._insert_timeline_event(
                    finding.engagement_id, finding.tool,
                    f"Finding discovered: {finding.title}",
                    finding.created_at, finding.id,
                )
                result_id = finding.id

            self._conn.commit()
            return result_id
        except Exception:
            self._conn.rollback()
            raise

    def _query_dedup_candidates(self, finding: Finding) -> list[Finding]:
        if finding.file_path and finding.line_start is not None:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE engagement_id = ? AND file_path = ? "
                "AND line_start >= ? AND line_start <= ? AND deleted_at IS NULL",
                (finding.engagement_id, finding.file_path,
                 finding.line_start - 5, finding.line_start + 5),
            ).fetchall()
        elif finding.file_path:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE engagement_id = ? AND file_path = ? "
                "AND deleted_at IS NULL",
                (finding.engagement_id, finding.file_path),
            ).fetchall()
        elif finding.cwe:
            rows = self._conn.execute(
                "SELECT * FROM findings WHERE engagement_id = ? AND cwe = ? "
                "AND deleted_at IS NULL",
                (finding.engagement_id, finding.cwe),
            ).fetchall()
        else:
            return []
        return [self._row_to_finding(r) for r in rows]

    def _merge_finding(self, existing: Finding, new_finding: Finding, confidence) -> str:
        corroborated = list(set(existing.corroborated_by + [new_finding.tool]))
        sbt = {**existing.severity_by_tool, new_finding.tool: str(new_finding.severity)}
        severity = max(str(existing.severity), str(new_finding.severity), key=_severity_rank)
        desc = new_finding.description if (
            new_finding.description and len(new_finding.description) > len(existing.description or "")
        ) else existing.description

        self._conn.execute(
            "UPDATE findings SET corroborated_by=?, severity_by_tool=?, "
            "severity=?, description=?, dedup_confidence=? WHERE id=?",
            (json.dumps(corroborated), json.dumps(sbt), severity,
             desc, str(confidence), existing.id),
        )
        self._insert_timeline_event(
            existing.engagement_id, new_finding.tool,
            f"Finding corroborated by {new_finding.tool}: {existing.title}",
            new_finding.created_at, existing.id,
        )
        return existing.id

    def _insert_finding_row(self, finding: Finding) -> None:
        self._conn.execute(
            "INSERT INTO findings (id, engagement_id, tool, corroborated_by, cwe, "
            "severity, severity_by_tool, status, phase, title, description, "
            "file_path, line_start, line_end, evidence, remediation, cvss, "
            "false_positive, dedup_confidence, created_at, deleted_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (finding.id, finding.engagement_id, finding.tool,
             json.dumps(finding.corroborated_by), finding.cwe,
             str(finding.severity), json.dumps(finding.severity_by_tool),
             str(finding.status), finding.phase, finding.title,
             finding.description, finding.file_path, finding.line_start,
             finding.line_end, finding.evidence, finding.remediation,
             finding.cvss, 1 if finding.false_positive else 0,
             str(finding.dedup_confidence) if finding.dedup_confidence else None,
             finding.created_at.isoformat(),
             finding.deleted_at.isoformat() if finding.deleted_at else None),
        )

    def _insert_timeline_event(self, engagement_id, source, event_text, timestamp, finding_id):
        self._conn.execute(
            "INSERT INTO timeline_events (id, engagement_id, timestamp, source, "
            "event, confidence, finding_id) VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), engagement_id, timestamp.isoformat(),
             source, event_text, "high", finding_id),
        )

    def add_findings_batch(self, findings: list[Finding]) -> list[str]:
        results: list[str] = []
        batch_inserted: list[Finding] = []
        CHUNK = 100

        for i in range(0, len(findings), CHUNK):
            chunk = findings[i:i + CHUNK]
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for finding in chunk:
                    normalized = _normalize_path(finding.file_path)
                    if normalized != finding.file_path:
                        finding = finding.model_copy(update={"file_path": normalized})

                    candidates = self._query_dedup_candidates(finding)
                    batch_candidates = [f for f in batch_inserted if f.engagement_id == finding.engagement_id]
                    all_candidates = candidates + batch_candidates

                    match = check_duplicate(finding, all_candidates)
                    if match:
                        self._merge_finding(match.match, finding, match.confidence)
                        results.append(match.match.id)
                    else:
                        self._insert_finding_row(finding)
                        self._insert_timeline_event(
                            finding.engagement_id, finding.tool,
                            f"Finding discovered: {finding.title}",
                            finding.created_at, finding.id,
                        )
                        batch_inserted.append(finding)
                        results.append(finding.id)
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return results

    def get_findings(
        self,
        engagement_id: str,
        severity: Optional[Severity] = None,
        status: Optional[FindingStatus] = None,
        phase: Optional[str] = None,
    ) -> list[Finding]:
        query = (
            "SELECT * FROM findings WHERE engagement_id = ? AND deleted_at IS NULL"
        )
        params: list = [engagement_id]
        if severity is not None:
            query += " AND severity = ?"
            params.append(str(severity))
        if status is not None:
            query += " AND status = ?"
            params.append(str(status))
        if phase is not None:
            query += " AND phase = ?"
            params.append(phase)
        query += " ORDER BY created_at DESC"
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def update_finding_status(self, finding_id: str, status: FindingStatus) -> None:
        self._conn.execute(
            "UPDATE findings SET status = ? WHERE id = ?",
            (str(status), finding_id),
        )
        self._conn.commit()

    def flag_false_positive(self, finding_id: str) -> None:
        self._conn.execute(
            "UPDATE findings SET false_positive = 1 WHERE id = ?",
            (finding_id,),
        )
        self._conn.commit()

    def search_findings(self, query: str) -> list[Finding]:
        rows = self._conn.execute(
            """
            SELECT f.*
            FROM findings f
            JOIN findings_fts fts ON f.rowid = fts.rowid
            WHERE fts.findings_fts MATCH ?
              AND f.deleted_at IS NULL
            ORDER BY fts.rank
            """,
            (query,),
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    def add_event(self, event: TimelineEvent) -> str:
        self._conn.execute(
            """
            INSERT INTO timeline_events
                (id, engagement_id, timestamp, source, event, details,
                 confidence, finding_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.id,
                event.engagement_id,
                event.timestamp.isoformat(),
                event.source,
                event.event,
                event.details,
                str(event.confidence),
                event.finding_id,
            ),
        )
        self._conn.commit()
        return event.id

    def get_timeline(
        self,
        engagement_id: str,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> list[TimelineEvent]:
        query = "SELECT * FROM timeline_events WHERE engagement_id = ?"
        params: list = [engagement_id]
        if start is not None:
            query += " AND timestamp >= ?"
            params.append(start.isoformat())
        if end is not None:
            query += " AND timestamp <= ?"
            params.append(end.isoformat())
        query += " ORDER BY timestamp ASC"
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_timeline_event(r) for r in rows]

    # ------------------------------------------------------------------
    # IOCs
    # ------------------------------------------------------------------

    def add_ioc(self, ioc: IOC) -> str:
        existing = self._conn.execute(
            """
            SELECT id FROM iocs
            WHERE engagement_id = ? AND ioc_type = ? AND value = ?
            """,
            (ioc.engagement_id, str(ioc.ioc_type), ioc.value),
        ).fetchone()

        if existing:
            self._conn.execute(
                """
                UPDATE iocs
                SET last_seen = COALESCE(?, last_seen),
                    context   = COALESCE(?, context)
                WHERE engagement_id = ? AND ioc_type = ? AND value = ?
                """,
                (
                    ioc.last_seen.isoformat() if ioc.last_seen else None,
                    ioc.context,
                    ioc.engagement_id,
                    str(ioc.ioc_type),
                    ioc.value,
                ),
            )
            self._conn.commit()
            return existing["id"]

        self._conn.execute(
            """
            INSERT INTO iocs
                (id, engagement_id, ioc_type, value, context,
                 first_seen, last_seen, source_finding_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ioc.id,
                ioc.engagement_id,
                str(ioc.ioc_type),
                ioc.value,
                ioc.context,
                ioc.first_seen.isoformat() if ioc.first_seen else None,
                ioc.last_seen.isoformat() if ioc.last_seen else None,
                ioc.source_finding_id,
            ),
        )
        self._conn.commit()
        return ioc.id

    def get_iocs(
        self, engagement_id: str, ioc_type: Optional[IOCType] = None
    ) -> list[IOC]:
        query = "SELECT * FROM iocs WHERE engagement_id = ?"
        params: list = [engagement_id]
        if ioc_type is not None:
            query += " AND ioc_type = ?"
            params.append(str(ioc_type))
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_ioc(r) for r in rows]

    def search_ioc(self, value: str) -> list[IOC]:
        rows = self._conn.execute(
            "SELECT * FROM iocs WHERE value LIKE ?", (f"%{value}%",)
        ).fetchall()
        return [self._row_to_ioc(r) for r in rows]

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    def add_artifact(self, artifact: Artifact) -> str:
        self._conn.execute(
            """
            INSERT INTO artifacts
                (id, engagement_id, file_path, artifact_type, description,
                 source_tool, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                artifact.id,
                artifact.engagement_id,
                artifact.file_path,
                str(artifact.artifact_type),
                artifact.description,
                artifact.source_tool,
                artifact.created_at.isoformat(),
            ),
        )
        self._conn.commit()
        return artifact.id

    def get_artifacts(self, engagement_id: str) -> list[Artifact]:
        rows = self._conn.execute(
            "SELECT * FROM artifacts WHERE engagement_id = ?", (engagement_id,)
        ).fetchall()
        return [self._row_to_artifact(r) for r in rows]

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def log_action(self, entry: AuditEntry) -> None:
        self._conn.execute(
            """
            INSERT INTO audit_log
                (id, timestamp, command, args, engagement_id, result, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.id,
                entry.timestamp.isoformat(),
                entry.command,
                json.dumps(entry.args) if entry.args is not None else None,
                entry.engagement_id,
                entry.result,
                entry.details,
            ),
        )
        self._conn.commit()

    def get_audit_log(
        self,
        engagement_id: Optional[str] = None,
        since: Optional[datetime] = None,
    ) -> list[AuditEntry]:
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: list = []
        if engagement_id is not None:
            query += " AND engagement_id = ?"
            params.append(engagement_id)
        if since is not None:
            query += " AND timestamp >= ?"
            params.append(since.isoformat())
        query += " ORDER BY timestamp ASC"
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_audit_entry(r) for r in rows]

    # ------------------------------------------------------------------
    # Private row converters
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_engagement(row: sqlite3.Row) -> Engagement:
        return Engagement.model_construct(
            id=row["id"],
            name=row["name"],
            target=row["target"],
            type=EngagementType(row["type"]),
            scope=row["scope"],
            status=EngagementStatus(row["status"]),
            skills_used=json.loads(row["skills_used"] or "[]"),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        return Finding.model_construct(
            id=row["id"],
            engagement_id=row["engagement_id"],
            tool=row["tool"],
            corroborated_by=json.loads(row["corroborated_by"] or "[]"),
            cwe=row["cwe"],
            severity=Severity(row["severity"]),
            severity_by_tool=json.loads(row["severity_by_tool"] or "{}"),
            status=FindingStatus(row["status"]),
            phase=row["phase"],
            title=row["title"],
            description=row["description"],
            file_path=row["file_path"],
            line_start=row["line_start"],
            line_end=row["line_end"],
            evidence=row["evidence"],
            remediation=row["remediation"],
            cvss=row["cvss"],
            false_positive=bool(row["false_positive"]),
            dedup_confidence=Confidence(row["dedup_confidence"]) if row["dedup_confidence"] else None,
            created_at=datetime.fromisoformat(row["created_at"]),
            deleted_at=datetime.fromisoformat(row["deleted_at"]) if row["deleted_at"] else None,
        )

    @staticmethod
    def _row_to_timeline_event(row: sqlite3.Row) -> TimelineEvent:
        return TimelineEvent.model_construct(
            id=row["id"],
            engagement_id=row["engagement_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            source=row["source"] or "",
            event=row["event"],
            details=row["details"],
            confidence=Confidence(row["confidence"]),
            finding_id=row["finding_id"],
        )

    @staticmethod
    def _row_to_ioc(row: sqlite3.Row) -> IOC:
        return IOC.model_construct(
            id=row["id"],
            engagement_id=row["engagement_id"],
            ioc_type=IOCType(row["ioc_type"]),
            value=row["value"],
            context=row["context"],
            first_seen=datetime.fromisoformat(row["first_seen"]) if row["first_seen"] else None,
            last_seen=datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
            source_finding_id=row["source_finding_id"],
        )

    @staticmethod
    def _row_to_artifact(row: sqlite3.Row) -> Artifact:
        return Artifact.model_construct(
            id=row["id"],
            engagement_id=row["engagement_id"],
            file_path=row["file_path"],
            artifact_type=ArtifactType(row["artifact_type"]),
            description=row["description"],
            source_tool=row["source_tool"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    @staticmethod
    def _row_to_audit_entry(row: sqlite3.Row) -> AuditEntry:
        return AuditEntry.model_construct(
            id=row["id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            command=row["command"],
            args=json.loads(row["args"]) if row["args"] else None,
            engagement_id=row["engagement_id"],
            result=row["result"],
            details=row["details"],
        )
