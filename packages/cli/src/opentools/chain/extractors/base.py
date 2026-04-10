"""Base protocols and data classes for the chain extraction pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from opentools.chain.types import MentionField
from opentools.models import Finding


@dataclass
class ExtractedEntity:
    """One entity mention emitted by an extractor.

    Offsets may be None for structured-source extractors (parser-aware,
    LLM) that don't track character positions.
    """
    type: str
    value: str
    field: MentionField
    offset_start: int | None
    offset_end: int | None
    extractor: str
    confidence: float


@dataclass
class ExtractionContext:
    """Context passed to each extractor during a pipeline run.

    ``already_extracted`` is populated by earlier pipeline stages so later
    stages (e.g. optional LLM) can avoid re-extracting what rules found.
    ``platform`` is used by platform-aware extractors to skip irrelevant
    work (e.g. WindowsPathExtractor on a Linux engagement).
    """
    finding: Finding
    already_extracted: list[ExtractedEntity] = field(default_factory=list)
    platform: str = "auto"
    engagement_metadata: dict = field(default_factory=dict)


@runtime_checkable
class SecurityExtractor(Protocol):
    """Regex/rule-based extractor operating on a single text field.

    Implementations declare their fixed entity type and confidence at
    class level and iterate matches within a text slice.
    """
    name: str
    entity_type: str
    confidence: float

    def applies_to(self, finding: Finding) -> bool: ...

    def extract(
        self,
        text: str,
        field: MentionField,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]: ...


@runtime_checkable
class ParserEntityExtractor(Protocol):
    """Parser-aware extractor reading structured parser output for a tool."""
    tool_name: str

    def extract(
        self,
        finding: Finding,
        parser_output: dict,
        ctx: ExtractionContext,
    ) -> list[ExtractedEntity]: ...
