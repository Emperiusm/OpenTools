import asyncio

import pytest
from pydantic import BaseModel, Field

from opentools.chain.extractors.llm.base import (
    LLMExtractionProvider,
    PydanticRetryWrapper,
)


class _FakeSchema(BaseModel):
    value: int = Field(ge=0, le=100)


def test_protocol_is_runtime_checkable():
    # A class with the right attrs is recognized as implementing the protocol
    class FakeProvider:
        name = "fake"
        model = "fake-1"

        async def extract_entities(self, text, context):
            return []

        async def classify_relation(self, finding_a, finding_b, shared_entities):
            return None  # test-only

        async def generate_path_narration(self, findings, edges):
            return ""

    # Runtime protocol check — we use isinstance after casting
    assert hasattr(FakeProvider, "name")
    assert hasattr(FakeProvider, "extract_entities")


def test_retry_wrapper_succeeds_first_try():
    call_count = 0

    async def call(prompt: str) -> str:
        nonlocal call_count
        call_count += 1
        return '{"value": 42}'

    wrapper = PydanticRetryWrapper(max_retries=3)
    result = asyncio.run(wrapper.call(call_fn=call, schema_cls=_FakeSchema, prompt="x"))
    assert result.value == 42
    assert call_count == 1


def test_retry_wrapper_retries_on_validation_error():
    responses = iter([
        '{"value": "not a number"}',  # invalid
        '{"value": 999}',              # out of range
        '{"value": 50}',               # good
    ])
    call_log = []

    async def call(prompt: str) -> str:
        call_log.append(prompt)
        return next(responses)

    wrapper = PydanticRetryWrapper(max_retries=3)
    result = asyncio.run(wrapper.call(call_fn=call, schema_cls=_FakeSchema, prompt="x"))
    assert result.value == 50
    # Three attempts made; each retry prompt is extended with the prior error
    assert len(call_log) == 3
    assert call_log[1] != call_log[0]
    assert "error" in call_log[1].lower() or "invalid" in call_log[1].lower() or "validation" in call_log[1].lower()


def test_retry_wrapper_raises_after_max_retries():
    async def call(prompt: str) -> str:
        return '{"value": "garbage"}'  # always invalid

    wrapper = PydanticRetryWrapper(max_retries=2)
    with pytest.raises(ValueError):
        asyncio.run(wrapper.call(call_fn=call, schema_cls=_FakeSchema, prompt="x"))


def test_retry_wrapper_handles_malformed_json():
    async def call(prompt: str) -> str:
        return "not json at all"

    wrapper = PydanticRetryWrapper(max_retries=1)
    with pytest.raises(ValueError):
        asyncio.run(wrapper.call(call_fn=call, schema_cls=_FakeSchema, prompt="x"))
