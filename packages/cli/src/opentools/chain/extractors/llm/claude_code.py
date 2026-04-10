"""Claude Code / Agent SDK LLM extraction provider.

Uses ``claude_agent_sdk.query()`` for the production path. The SDK is not
called at import time so tests that don't have credentials do not fail.

Tests inject ``call_fn`` (async str->str) to avoid real Agent SDK calls.

Known uncertainty: ``claude_agent_sdk.query()`` returns an async iterator
of message objects whose exact shape (content blocks, text attributes) may
vary across SDK versions. The production ``_invoke`` path wraps message
iteration defensively and skips blocks it cannot interpret. This path is
only exercised by smoke tests behind ``ENABLE_LLM_SMOKE_TESTS=1``.
"""
from __future__ import annotations

import logging
from typing import Awaitable, Callable

logger = logging.getLogger(__name__)


class ClaudeCodeProvider:
    """Extraction provider backed by the Claude Agent SDK.

    Production path uses ``claude_agent_sdk.query()`` to send a single-turn
    request. Unit tests inject ``call_fn`` to skip real Agent SDK calls.

    Note: ``instructor`` does not support the Claude Agent SDK, so all
    schema validation goes through ``PydanticRetryWrapper`` — the same
    path used by other providers in this codebase.
    """

    name = "claude_code"

    def __init__(
        self,
        *,
        model: str = "claude-sonnet-4-6",
        call_fn: Callable[[str], Awaitable[str]] | None = None,
    ) -> None:
        self.model = model
        self._call_fn = call_fn

    async def extract_entities(self, text: str, context) -> list:
        from opentools.chain.extractors.llm.prompts import format_extraction_prompt
        from opentools.chain.models import LLMExtractionResponse
        from opentools.chain.extractors.base import ExtractedEntity
        from opentools.chain.extractors.llm.base import PydanticRetryWrapper
        from opentools.chain.extractors.llm._util import get_default_field

        prompt = format_extraction_prompt(text)
        raw = await self._invoke(prompt)
        wrapper = PydanticRetryWrapper(max_retries=0)
        parsed = await wrapper.call(
            call_fn=_wrap_static(raw),
            schema_cls=LLMExtractionResponse,
            prompt=prompt,
        )
        field = get_default_field(context)
        return [
            ExtractedEntity(
                type=e.type,
                value=e.value,
                field=field,
                offset_start=None,
                offset_end=None,
                extractor=f"llm_{self.name}",
                confidence=e.confidence,
            )
            for e in parsed.entities
        ]

    async def classify_relation(self, finding_a, finding_b, shared_entities) -> object:
        from opentools.chain.extractors.llm.prompts import format_link_classification_prompt
        from opentools.chain.models import LLMLinkClassification
        from opentools.chain.extractors.llm.base import PydanticRetryWrapper

        summary = ", ".join(
            f"{e.type}:{e.canonical_value}" for e in shared_entities
        )
        prompt = format_link_classification_prompt(finding_a, finding_b, summary)
        raw = await self._invoke(prompt)
        wrapper = PydanticRetryWrapper(max_retries=0)
        return await wrapper.call(
            call_fn=_wrap_static(raw),
            schema_cls=LLMLinkClassification,
            prompt=prompt,
        )

    async def generate_path_narration(self, findings: list, edges: list) -> str:
        from opentools.chain.extractors.llm.prompts import format_narration_prompt
        from opentools.chain.extractors.llm._util import format_chain

        chain_text = format_chain(findings, edges)
        prompt = format_narration_prompt(chain_text)
        return await self._invoke(prompt)

    async def _invoke(self, prompt: str) -> str:
        if self._call_fn is not None:
            return await self._call_fn(prompt)
        # Production path — only exercised in smoke tests (ENABLE_LLM_SMOKE_TESTS=1).
        # The exact message/content structure from claude_agent_sdk.query() may differ
        # across SDK versions; we iterate defensively and skip unrecognised shapes.
        from claude_agent_sdk import query, ClaudeAgentOptions  # type: ignore[import]

        options = ClaudeAgentOptions(
            system_prompt="You are a security analyst producing precise, schema-valid JSON.",
            max_turns=1,
        )
        parts: list[str] = []
        try:
            async for message in query(prompt=prompt, options=options):
                try:
                    if hasattr(message, "content"):
                        for block in message.content:
                            if hasattr(block, "text"):
                                parts.append(block.text)
                except Exception as exc:  # noqa: BLE001
                    logger.debug(
                        "ClaudeCodeProvider: skipping unrecognised message block: %s", exc
                    )
        except Exception as exc:  # noqa: BLE001
            logger.warning("ClaudeCodeProvider._invoke failed: %s", exc)
        return "".join(parts)


def _wrap_static(text: str) -> Callable[[str], Awaitable[str]]:
    """Return an async callable that always returns ``text`` regardless of prompt."""

    async def _c(_prompt: str) -> str:
        return text

    return _c
