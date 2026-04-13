"""Finding parsing pipeline — parsers, normalization, dedup, scoring, export."""

from opentools.scanner.parsing.router import ParserPlugin, ParserRouter
from opentools.scanner.parsing.normalization import NormalizationEngine
from opentools.scanner.parsing.dedup import DedupEngine
from opentools.scanner.parsing.engagement_dedup import EngagementDedupEngine
from opentools.scanner.parsing.confidence import CorroborationScorer, ConfidenceDecay
from opentools.scanner.parsing.suppression import SuppressionEngine
from opentools.scanner.parsing.lifecycle import FindingLifecycle
from opentools.scanner.parsing.correlation import FindingCorrelationEngine
from opentools.scanner.parsing.remediation import RemediationGrouper

__all__ = [
    "ParserPlugin",
    "ParserRouter",
    "NormalizationEngine",
    "DedupEngine",
    "EngagementDedupEngine",
    "CorroborationScorer",
    "ConfidenceDecay",
    "SuppressionEngine",
    "FindingLifecycle",
    "FindingCorrelationEngine",
    "RemediationGrouper",
]
