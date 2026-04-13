"""CorroborationScorer and ConfidenceDecay.

CorroborationScorer: adjusts confidence based on tool diversity, parser tiers,
and FP history.

ConfidenceDecay: findings not reconfirmed in recent scans lose confidence
over time.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from opentools.scanner.models import DeduplicatedFinding

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Tool categories for corroboration boost
_TOOL_CATEGORIES: dict[str, str] = {
    "semgrep": "sast",
    "codebadger": "sast",
    "trivy": "sca",
    "gitleaks": "secrets",
    "nuclei": "dast",
    "nikto": "dast",
    "nmap": "recon",
    "sqlmap": "dast",
    "capa": "binary",
    "arkana": "binary",
    "hashcat": "password",
}


@lru_cache(maxsize=1)
def _load_parser_confidence() -> dict[str, float]:
    path = _DATA_DIR / "parser_confidence.json"
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return {k: v for k, v in data.items() if k != "_comment"}


class CorroborationScorer:
    """Adjusts finding confidence based on corroboration.

    Formula::

        confidence = base_confidence * corroboration_boost * fp_penalty

    Corroboration boost:
        - 1 tool: 1.0x
        - 2 tools same category: 1.2x
        - 2 tools different category: 1.4x
        - 3+ tools: 1.5x

    FP penalty: 0.3 if previously_marked_fp, else 1.0

    Result is capped at 1.0.
    """

    def __init__(self) -> None:
        self._parser_confidence = _load_parser_confidence()

    def score(self, findings: list[DeduplicatedFinding]) -> list[DeduplicatedFinding]:
        """Return new list with updated confidence_score."""
        return [self._score_one(f) for f in findings]

    def _score_one(self, f: DeduplicatedFinding) -> DeduplicatedFinding:
        # Base confidence: average of contributing tools' confidence tiers
        base = self._base_confidence(f.tools) if f.tools else f.confidence_score

        # Corroboration boost
        boost = self._corroboration_boost(f.tools)

        # FP penalty
        fp_penalty = 0.3 if f.previously_marked_fp else 1.0

        confidence = min(base * boost * fp_penalty, 1.0)
        return f.model_copy(update={"confidence_score": round(confidence, 4)})

    def _base_confidence(self, tools: list[str]) -> float:
        """Average parser confidence tier for the given tools."""
        if not tools:
            return 0.5
        total = sum(self._parser_confidence.get(t, 0.5) for t in tools)
        return total / len(tools)

    def _corroboration_boost(self, tools: list[str]) -> float:
        """Compute corroboration boost based on tool count and diversity."""
        if len(tools) <= 1:
            return 1.0

        categories = {_TOOL_CATEGORIES.get(t, t) for t in tools}

        if len(tools) >= 3:
            return 1.5

        # 2 tools
        if len(categories) >= 2:
            return 1.4  # Different categories
        return 1.2  # Same category


class ConfidenceDecay:
    """Decay confidence for findings not reconfirmed in recent scans.

    - 100% for first 30 days
    - -5% per 30-day period after that
    - Floor: 20%
    """

    def __init__(self, grace_days: int = 30, decay_per_period: float = 0.05, floor: float = 0.2) -> None:
        self._grace_days = grace_days
        self._decay_per_period = decay_per_period
        self._floor = floor

    def apply(
        self,
        findings: list[DeduplicatedFinding],
        reference_time: datetime | None = None,
    ) -> list[DeduplicatedFinding]:
        """Return new list with decayed confidence scores."""
        ref = reference_time or datetime.now(timezone.utc)
        return [self._decay_one(f, ref) for f in findings]

    def _decay_one(self, f: DeduplicatedFinding, ref: datetime) -> DeduplicatedFinding:
        if f.last_confirmed_at is None:
            return f

        elapsed_days = (ref - f.last_confirmed_at).total_seconds() / 86400

        if elapsed_days <= self._grace_days:
            return f

        periods_past_grace = (elapsed_days - self._grace_days) / self._grace_days
        decay_factor = max(
            1.0 - (self._decay_per_period * periods_past_grace),
            self._floor / max(f.confidence_score, 0.01),
        )
        new_confidence = max(f.confidence_score * decay_factor, self._floor)
        new_confidence = min(new_confidence, f.confidence_score)  # Never increase

        return f.model_copy(update={"confidence_score": round(new_confidence, 4)})
