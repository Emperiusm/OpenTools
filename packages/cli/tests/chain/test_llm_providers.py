"""Tests for LLM provider implementations (Tasks 14, 15, 16).

All providers are tested via injected mock call_fn so no real API calls
are made. Real-provider smoke tests are opt-in via ENABLE_LLM_SMOKE_TESTS=1.
"""
import asyncio
import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from opentools.chain.extractors.llm.ollama import OllamaProvider
from opentools.chain.extractors.llm.anthropic_api import AnthropicAPIProvider
from opentools.chain.extractors.llm.openai_api import OpenAIAPIProvider
from opentools.chain.extractors.llm.claude_code import ClaudeCodeProvider
from opentools.chain.extractors.llm.rate_limit import get_limiter, reset_limiter_cache
from opentools.chain.extractors.base import ExtractionContext
from opentools.chain.models import Entity, LLMLinkClassification, entity_id_for
from opentools.models import Finding, FindingStatus, Severity


# ─── Helpers ────────────────────────────────────────────────────────────────


def _finding(id_suffix: str = "1", **kwargs) -> Finding:
    defaults = dict(
        id=f"fnd_{id_suffix}",
        engagement_id="eng_t",
        tool="nmap",
        severity=Severity.HIGH,
        status=FindingStatus.DISCOVERED,
        title="Open port 22",
        description="SSH exposed on 10.0.0.5",
        created_at=datetime.now(timezone.utc),
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _ctx() -> ExtractionContext:
    return ExtractionContext(finding=_finding())


def _mock_call_fn_entities():
    async def _c(prompt):
        return '{"entities": [{"type": "ip", "value": "10.0.0.5", "confidence": 0.95}]}'

    return _c


def _mock_call_fn_classification():
    async def _c(prompt):
        return '{"related": true, "relation_type": "pivots_to", "rationale": "shared host", "confidence": 0.9}'

    return _c


def _mock_call_fn_narration():
    async def _c(prompt):
        return "The attacker pivoted from the SSH service to the admin panel."

    return _c


def _shared_entities():
    return [
        Entity(
            id=entity_id_for("host", "10.0.0.5"),
            type="host",
            canonical_value="10.0.0.5",
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
        )
    ]


# ─── OllamaProvider ─────────────────────────────────────────────────────────


def test_ollama_name():
    p = OllamaProvider(call_fn=_mock_call_fn_entities())
    assert p.name == "ollama"


def test_ollama_extract_entities_via_mock():
    p = OllamaProvider(call_fn=_mock_call_fn_entities())
    result = asyncio.run(p.extract_entities("SSH on 10.0.0.5", _ctx()))
    assert len(result) == 1
    assert result[0].type == "ip"
    assert result[0].value == "10.0.0.5"
    assert result[0].extractor == "llm_ollama"
    assert result[0].confidence == pytest.approx(0.95)


def test_ollama_classify_relation_via_mock():
    p = OllamaProvider(call_fn=_mock_call_fn_classification())
    a = _finding("1")
    b = _finding("2")
    result = asyncio.run(p.classify_relation(a, b, _shared_entities()))
    assert isinstance(result, LLMLinkClassification)
    assert result.related is True
    assert result.relation_type == "pivots_to"
    assert result.confidence == pytest.approx(0.9)


def test_ollama_narration_via_mock():
    p = OllamaProvider(call_fn=_mock_call_fn_narration())
    result = asyncio.run(p.generate_path_narration([_finding("1")], []))
    assert "pivoted" in result


# ─── AnthropicAPIProvider ────────────────────────────────────────────────────


def test_anthropic_name():
    p = AnthropicAPIProvider(call_fn=_mock_call_fn_entities())
    assert p.name == "anthropic_api"


def test_anthropic_extract_via_mock():
    p = AnthropicAPIProvider(call_fn=_mock_call_fn_entities())
    result = asyncio.run(p.extract_entities("text", _ctx()))
    assert len(result) == 1
    assert result[0].extractor == "llm_anthropic_api"
    assert result[0].type == "ip"


def test_anthropic_classify_via_mock():
    p = AnthropicAPIProvider(call_fn=_mock_call_fn_classification())
    a = _finding("1")
    b = _finding("2")
    result = asyncio.run(p.classify_relation(a, b, _shared_entities()))
    assert isinstance(result, LLMLinkClassification)
    assert result.related is True


def test_anthropic_narration_via_mock():
    p = AnthropicAPIProvider(call_fn=_mock_call_fn_narration())
    result = asyncio.run(p.generate_path_narration([_finding("1")], []))
    assert isinstance(result, str)
    assert len(result) > 0


# ─── OpenAIAPIProvider ───────────────────────────────────────────────────────


def test_openai_name():
    p = OpenAIAPIProvider(call_fn=_mock_call_fn_entities())
    assert p.name == "openai_api"


def test_openai_extract_via_mock():
    p = OpenAIAPIProvider(call_fn=_mock_call_fn_entities())
    result = asyncio.run(p.extract_entities("text", _ctx()))
    assert len(result) == 1
    assert result[0].extractor == "llm_openai_api"
    assert result[0].type == "ip"


def test_openai_classify_via_mock():
    p = OpenAIAPIProvider(call_fn=_mock_call_fn_classification())
    a = _finding("1")
    b = _finding("2")
    result = asyncio.run(p.classify_relation(a, b, _shared_entities()))
    assert isinstance(result, LLMLinkClassification)
    assert result.relation_type == "pivots_to"


def test_openai_narration_via_mock():
    p = OpenAIAPIProvider(call_fn=_mock_call_fn_narration())
    result = asyncio.run(p.generate_path_narration([_finding("1")], []))
    assert "pivoted" in result


# ─── ClaudeCodeProvider ──────────────────────────────────────────────────────


def test_claude_code_name():
    p = ClaudeCodeProvider(call_fn=_mock_call_fn_entities())
    assert p.name == "claude_code"


def test_claude_code_extract_via_mock():
    p = ClaudeCodeProvider(call_fn=_mock_call_fn_entities())
    result = asyncio.run(p.extract_entities("text", _ctx()))
    assert len(result) == 1
    assert result[0].extractor == "llm_claude_code"
    assert result[0].type == "ip"


def test_claude_code_classify_via_mock():
    p = ClaudeCodeProvider(call_fn=_mock_call_fn_classification())
    a = _finding("1")
    b = _finding("2")
    result = asyncio.run(p.classify_relation(a, b, _shared_entities()))
    assert isinstance(result, LLMLinkClassification)
    assert result.related is True


def test_claude_code_narration_via_mock():
    p = ClaudeCodeProvider(call_fn=_mock_call_fn_narration())
    result = asyncio.run(p.generate_path_narration([_finding("1")], []))
    assert "pivoted" in result


def test_claude_code_smoke_test_skipped_without_env():
    """Real SDK smoke test is opt-in via ENABLE_LLM_SMOKE_TESTS."""
    if os.getenv("ENABLE_LLM_SMOKE_TESTS") != "1":
        pytest.skip("LLM smoke tests disabled")
    # Would make a real Agent SDK call here if enabled
    p = ClaudeCodeProvider()
    # Just verify the provider constructs without calling
    assert p.model == "claude-sonnet-4-6"


# ─── Protocol conformance ────────────────────────────────────────────────────


def test_all_providers_satisfy_protocol():
    """All four providers satisfy the LLMExtractionProvider protocol."""
    from opentools.chain.extractors.llm.base import LLMExtractionProvider

    providers = [
        OllamaProvider(call_fn=_mock_call_fn_entities()),
        AnthropicAPIProvider(call_fn=_mock_call_fn_entities()),
        OpenAIAPIProvider(call_fn=_mock_call_fn_entities()),
        ClaudeCodeProvider(call_fn=_mock_call_fn_entities()),
    ]
    for p in providers:
        assert isinstance(p, LLMExtractionProvider), f"{p!r} does not satisfy protocol"


# ─── Rate limiter ────────────────────────────────────────────────────────────


def test_limiter_same_key_returns_same_instance():
    reset_limiter_cache()
    user_id = uuid4()
    a = get_limiter(provider="ollama", user_id=user_id)
    b = get_limiter(provider="ollama", user_id=user_id)
    assert a is b
    reset_limiter_cache()


def test_limiter_different_users_different_instances():
    reset_limiter_cache()
    a = get_limiter(provider="ollama", user_id=uuid4())
    b = get_limiter(provider="ollama", user_id=uuid4())
    assert a is not b
    reset_limiter_cache()


def test_limiter_anonymous_cli_user():
    reset_limiter_cache()
    a = get_limiter(provider="anthropic_api", user_id=None)
    b = get_limiter(provider="anthropic_api", user_id=None)
    assert a is b
    reset_limiter_cache()


def test_limiter_unknown_provider_raises():
    reset_limiter_cache()
    with pytest.raises(ValueError, match="unknown provider"):
        get_limiter(provider="nonexistent", user_id=None)
    reset_limiter_cache()


def test_limiter_all_known_providers():
    """All configured providers return a limiter without error."""
    reset_limiter_cache()
    for provider in ("ollama", "anthropic_api", "openai_api", "claude_code"):
        lim = get_limiter(provider=provider, user_id=None)
        assert lim is not None
    reset_limiter_cache()


def test_limiter_provider_specific_rate():
    """Anthropic and OpenAI configs have non-None RPM; Ollama default is None (high rate)."""
    from opentools.chain.config import ChainConfig

    reset_limiter_cache()
    cfg = ChainConfig()
    assert cfg.llm.anthropic_api.requests_per_minute == 50
    assert cfg.llm.openai_api.requests_per_minute == 60
    assert cfg.llm.claude_code.requests_per_minute == 30
    assert cfg.llm.ollama.requests_per_minute is None  # falls back to high-rate limiter
    reset_limiter_cache()
