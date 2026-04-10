"""IOC trending engine with frequency, lifecycle, and trend classification."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import TYPE_CHECKING

from opentools.models import TrendingIOC

if TYPE_CHECKING:
    from opentools.engagement.store import EngagementStore


class TrendingEngine:
    """Analyse IOC frequency trends across engagements."""

    def __init__(self, store: "EngagementStore") -> None:
        self._store = store

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def hot_iocs(self, limit: int = 10, days: int = 30) -> list[TrendingIOC]:
        """Return the most-seen IOCs whose first_seen falls within the last *days* days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

        rows = self._store._conn.execute(
            """
            SELECT ioc_type, value,
                   COUNT(DISTINCT engagement_id) AS eng_count,
                   COUNT(*) AS total_occ,
                   MIN(context) AS context
            FROM iocs
            WHERE first_seen >= ?
            GROUP BY ioc_type, value
            ORDER BY eng_count DESC, total_occ DESC
            LIMIT ?
            """,
            (cutoff, limit),
        ).fetchall()

        results: list[TrendingIOC] = []
        for row in rows:
            freq = self.frequency(row["ioc_type"], row["value"])
            trend = self.classify_trend(freq)
            results.append(
                TrendingIOC(
                    ioc_type=row["ioc_type"],
                    ioc_value=row["value"],
                    context=row["context"],
                    engagement_count=row["eng_count"],
                    total_occurrences=row["total_occ"],
                    frequency_by_month=freq,
                    trend=trend,
                )
            )

        return results

    def frequency(
        self,
        ioc_type: str,
        ioc_value: str,
        months: int = 6,
    ) -> dict[str, int]:
        """Return a month-keyed occurrence count dict for the given IOC.

        Only the most recent *months* months of data are returned.
        Month keys are ISO 8601 YYYY-MM strings derived from first_seen.
        """
        rows = self._store._conn.execute(
            """
            SELECT substr(first_seen, 1, 7) AS month,
                   COUNT(*) AS cnt
            FROM iocs
            WHERE ioc_type = ?
              AND value = ?
              AND first_seen IS NOT NULL
            GROUP BY month
            ORDER BY month DESC
            LIMIT ?
            """,
            (ioc_type, ioc_value, months),
        ).fetchall()

        # Return in ascending chronological order
        return {row["month"]: row["cnt"] for row in reversed(rows)}

    def lifecycle(self, ioc_type: str, ioc_value: str) -> dict:
        """Return first_seen, last_seen, active_days, and a list of engagements for the IOC."""
        rows = self._store._conn.execute(
            """
            SELECT engagement_id, context, first_seen, last_seen
            FROM iocs
            WHERE ioc_type = ? AND value = ?
            ORDER BY first_seen ASC
            """,
            (ioc_type, ioc_value),
        ).fetchall()

        if not rows:
            return {
                "first_seen": None,
                "last_seen": None,
                "active_days": 0,
                "engagements": [],
            }

        all_first: list[datetime] = []
        all_last: list[datetime] = []

        for row in rows:
            if row["first_seen"]:
                try:
                    all_first.append(datetime.fromisoformat(row["first_seen"]))
                except (ValueError, TypeError):
                    pass
            if row["last_seen"]:
                try:
                    all_last.append(datetime.fromisoformat(row["last_seen"]))
                except (ValueError, TypeError):
                    pass

        first_seen = min(all_first) if all_first else None
        last_seen = max(all_last) if all_last else None

        active_days = 0
        if first_seen and last_seen:
            active_days = (last_seen - first_seen).days

        engagements = [
            {
                "engagement_id": row["engagement_id"],
                "context": row["context"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
            }
            for row in rows
        ]

        return {
            "first_seen": first_seen.isoformat() if first_seen else None,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "active_days": active_days,
            "engagements": engagements,
        }

    @staticmethod
    def classify_trend(frequency: dict[str, int]) -> str:
        """Classify a frequency dict as 'rising', 'declining', or 'stable'.

        Compares the average of the last 2 months against the average of all
        earlier months.

        - rising   : recent_avg > historical_avg * 1.5
        - declining: recent_avg < historical_avg * 0.5
        - stable   : otherwise (also returned when there is insufficient data)
        """
        if len(frequency) < 2:
            return "stable"

        months = sorted(frequency.keys())
        recent_months = months[-2:]
        historical_months = months[:-2]

        recent_avg = sum(frequency[m] for m in recent_months) / len(recent_months)

        if not historical_months:
            return "stable"

        historical_avg = sum(frequency[m] for m in historical_months) / len(historical_months)

        if historical_avg == 0:
            return "rising" if recent_avg > 0 else "stable"

        ratio = recent_avg / historical_avg
        if ratio > 1.5:
            return "rising"
        if ratio < 0.5:
            return "declining"
        return "stable"
