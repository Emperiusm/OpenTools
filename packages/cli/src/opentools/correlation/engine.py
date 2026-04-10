"""Cross-engagement IOC correlation engine."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from opentools.models import CorrelationResult

if TYPE_CHECKING:
    from opentools.engagement.store import EngagementStore


class CorrelationEngine:
    """Correlate IOCs across multiple engagements."""

    def __init__(self, store: "EngagementStore") -> None:
        self._store = store

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate(self, ioc_value: str) -> CorrelationResult:
        """Return a CorrelationResult aggregating all engagements for *ioc_value*."""
        rows = self._store._conn.execute(
            """
            SELECT ioc_type, value, engagement_id, context,
                   first_seen, last_seen
            FROM iocs
            WHERE value = ?
            """,
            (ioc_value,),
        ).fetchall()

        if not rows:
            # Return a minimal result when the IOC is unknown
            return CorrelationResult(
                ioc_type="unknown",
                ioc_value=ioc_value,
            )

        ioc_type = rows[0]["ioc_type"]
        engagements: list[dict] = []
        all_first_seen: list[datetime] = []
        all_last_seen: list[datetime] = []
        seen_engagement_ids: set[str] = set()

        for row in rows:
            eng_id = row["engagement_id"]
            seen_engagement_ids.add(eng_id)

            first_seen: datetime | None = None
            last_seen: datetime | None = None

            if row["first_seen"]:
                try:
                    first_seen = datetime.fromisoformat(row["first_seen"])
                    all_first_seen.append(first_seen)
                except (ValueError, TypeError):
                    pass

            if row["last_seen"]:
                try:
                    last_seen = datetime.fromisoformat(row["last_seen"])
                    all_last_seen.append(last_seen)
                except (ValueError, TypeError):
                    pass

            engagements.append(
                {
                    "engagement_id": eng_id,
                    "context": row["context"],
                    "first_seen": first_seen.isoformat() if first_seen else None,
                    "last_seen": last_seen.isoformat() if last_seen else None,
                }
            )

        first_seen_global = min(all_first_seen) if all_first_seen else None
        last_seen_global = max(all_last_seen) if all_last_seen else None

        active_days = 0
        if first_seen_global and last_seen_global:
            active_days = (last_seen_global - first_seen_global).days

        return CorrelationResult(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            engagements=engagements,
            engagement_count=len(seen_engagement_ids),
            total_occurrences=len(rows),
            first_seen_global=first_seen_global,
            last_seen_global=last_seen_global,
            active_days=active_days,
        )

    def correlate_engagement(self, engagement_id: str) -> list[CorrelationResult]:
        """Return CorrelationResults for all IOCs in *engagement_id* that appear in 2+ engagements."""
        rows = self._store._conn.execute(
            "SELECT DISTINCT value FROM iocs WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchall()

        results: list[CorrelationResult] = []
        for row in rows:
            result = self.correlate(row["value"])
            if result.engagement_count >= 2:
                results.append(result)

        return results

    def find_common_iocs(self, engagement_ids: list[str]) -> list[CorrelationResult]:
        """Return IOCs that appear in at least 2 of the given engagements."""
        if not engagement_ids:
            return []

        placeholders = ",".join("?" * len(engagement_ids))
        rows = self._store._conn.execute(
            f"""
            SELECT ioc_type, value,
                   COUNT(DISTINCT engagement_id) AS eng_count,
                   COUNT(*) AS total_occ,
                   MIN(first_seen) AS first_seen_global,
                   MAX(last_seen) AS last_seen_global
            FROM iocs
            WHERE engagement_id IN ({placeholders})
            GROUP BY ioc_type, value
            HAVING COUNT(DISTINCT engagement_id) >= 2
            ORDER BY eng_count DESC, total_occ DESC
            """,
            tuple(engagement_ids),
        ).fetchall()

        results: list[CorrelationResult] = []
        for row in rows:
            first_seen_global: datetime | None = None
            last_seen_global: datetime | None = None
            active_days = 0

            if row["first_seen_global"]:
                try:
                    first_seen_global = datetime.fromisoformat(row["first_seen_global"])
                except (ValueError, TypeError):
                    pass

            if row["last_seen_global"]:
                try:
                    last_seen_global = datetime.fromisoformat(row["last_seen_global"])
                except (ValueError, TypeError):
                    pass

            if first_seen_global and last_seen_global:
                active_days = (last_seen_global - first_seen_global).days

            # Fetch engagement details for this IOC
            eng_rows = self._store._conn.execute(
                f"""
                SELECT engagement_id, context, first_seen, last_seen
                FROM iocs
                WHERE value = ? AND engagement_id IN ({placeholders})
                """,
                (row["value"], *engagement_ids),
            ).fetchall()

            engagements = [
                {
                    "engagement_id": er["engagement_id"],
                    "context": er["context"],
                    "first_seen": er["first_seen"],
                    "last_seen": er["last_seen"],
                }
                for er in eng_rows
            ]

            results.append(
                CorrelationResult(
                    ioc_type=row["ioc_type"],
                    ioc_value=row["value"],
                    engagements=engagements,
                    engagement_count=row["eng_count"],
                    total_occurrences=row["total_occ"],
                    first_seen_global=first_seen_global,
                    last_seen_global=last_seen_global,
                    active_days=active_days,
                )
            )

        return results
