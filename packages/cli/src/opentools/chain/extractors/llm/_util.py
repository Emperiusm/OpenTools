"""Shared utilities for LLM provider implementations."""
from __future__ import annotations

from opentools.chain.types import MentionField


def get_default_field(context) -> MentionField:
    """LLM extraction mentions don't know which field they came from.

    Default to DESCRIPTION since that's the most common LLM input source.
    """
    return MentionField.DESCRIPTION


def format_chain(findings, edges) -> str:
    """Format a list of findings and edges into a chain text for narration prompts."""
    lines = []
    for i, f in enumerate(findings, 1):
        lines.append(f"{i}. {getattr(f, 'title', '(unknown)')}")
        lines.append(f"   Tool: {getattr(f, 'tool', '?')}")
        desc = getattr(f, "description", "") or ""
        if desc:
            lines.append(f"   Description: {desc[:200]}")
    return "\n".join(lines)
