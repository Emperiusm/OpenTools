"""Ollama LLM extraction provider.

Uses the ollama Python client for the production path. Tests inject
``call_fn`` to avoid real API calls.
"""
from __future__ import annotations

import logging
from typing import Awaitable, Callable

logger = logging.getLogger(__name__)


class OllamaProvider:
    """Extraction provider backed by a local Ollama instance.

    Production path calls ``ollama.AsyncClient().generate()``.
    Unit tests inject ``call_fn`` (async str->str) to avoid real calls.
    """

    name = "ollama"

    def __init__(
        self,
        *,
        model: str = "llama3.1",
        client=None,
        call_fn: Callable[[str], Awaitable[str]] | None = None,
    ) -> None:
        self.model = model
        self._client = client
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
        # Production path — only exercised in smoke tests (ENABLE_LLM_SMOKE_TESTS=1)
        import ollama

        client = self._client or ollama.AsyncClient()
        response = await client.generate(model=self.model, prompt=prompt, format="json")
        return response["response"]


def _wrap_static(text: str) -> Callable[[str], Awaitable[str]]:
    """Return an async callable that always returns ``text`` regardless of prompt."""

    async def _c(_prompt: str) -> str:
        return text

    return _c
