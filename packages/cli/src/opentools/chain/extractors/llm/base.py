"""LLM provider protocol and PydanticRetryWrapper.

Defines the abstract interface that all LLM extraction providers
(Ollama, Anthropic API, OpenAI API, Claude Code) implement. Providers
are async-first. Structured output validation for providers that the
``instructor`` library supports (Ollama, Anthropic, OpenAI) is
handled by instructor directly; the Claude Agent SDK is not supported
by instructor so it uses PydanticRetryWrapper.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Awaitable, Callable, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


@runtime_checkable
class LLMExtractionProvider(Protocol):
    """Async interface implemented by all LLM providers.

    The same provider instance handles entity extraction, relation
    classification, and path narration so all three LLM touchpoints
    share one abstraction and one rate limit.
    """
    name: str
    model: str

    async def extract_entities(self, text: str, context) -> list: ...

    async def classify_relation(
        self,
        finding_a,
        finding_b,
        shared_entities: list,
    ): ...

    async def generate_path_narration(self, findings: list, edges: list) -> str: ...


_JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


class PydanticRetryWrapper:
    """Validate JSON callable output against a Pydantic schema with retries.

    Used by providers that instructor doesn't support (Claude Agent SDK).
    Calls the provided async callable, extracts a JSON object from the
    response, validates against the schema. On ValidationError or JSON
    decode error, appends the error to the prompt and retries up to
    ``max_retries`` times.

    After ``max_retries`` exhausted attempts the last error is raised as
    a ValueError so callers can log and fall back.
    """

    def __init__(self, max_retries: int = 3) -> None:
        self.max_retries = max_retries

    async def call(
        self,
        *,
        call_fn: Callable[[str], Awaitable[str]],
        schema_cls: type[T],
        prompt: str,
    ) -> T:
        current_prompt = prompt
        last_error: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                raw = await call_fn(current_prompt)
                parsed = _parse_and_validate(raw, schema_cls)
                return parsed
            except (ValidationError, ValueError, json.JSONDecodeError) as exc:
                last_error = exc
                if attempt >= self.max_retries:
                    break
                current_prompt = (
                    f"{prompt}\n\n"
                    f"Previous response failed validation with this error:\n"
                    f"{exc}\n\n"
                    f"Please respond again with valid JSON matching the schema."
                )
                logger.debug(
                    "PydanticRetryWrapper attempt %d failed: %s", attempt + 1, exc
                )

        raise ValueError(
            f"PydanticRetryWrapper exhausted {self.max_retries} retries; "
            f"last error: {last_error}"
        )


def _parse_and_validate(raw: str, schema_cls: type[T]) -> T:
    """Parse raw response text into a schema instance.

    Strategy: find the first JSON object in the response (models may
    wrap output in prose or markdown fences), parse it, validate.
    """
    stripped = raw.strip()
    # Strip markdown code fences if present
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        # Handle ```json ... ``` by removing the language tag
        if stripped.lower().startswith("json"):
            stripped = stripped[4:].lstrip("\n")

    # Try the whole thing first
    try:
        data = json.loads(stripped)
        return schema_cls.model_validate(data)
    except (json.JSONDecodeError, ValidationError):
        pass

    # Fallback: find the first JSON object in the text
    match = _JSON_OBJECT_RE.search(raw)
    if match is None:
        raise ValueError(f"no JSON object found in response: {raw[:200]}")
    data = json.loads(match.group(0))
    return schema_cls.model_validate(data)
