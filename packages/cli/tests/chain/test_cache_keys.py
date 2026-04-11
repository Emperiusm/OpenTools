"""Tests for consolidated cache key functions."""
import pytest

from opentools.chain._cache_keys import (
    extraction_cache_key,
    link_classification_cache_key,
    narration_cache_key,
)


def test_extraction_cache_key_deterministic():
    k1 = extraction_cache_key(
        text="hello", provider="ollama", model="llama3.1",
        schema_version=1, user_id=None,
    )
    k2 = extraction_cache_key(
        text="hello", provider="ollama", model="llama3.1",
        schema_version=1, user_id=None,
    )
    assert k1 == k2
    assert len(k1) == 64  # sha256 hex


def test_extraction_cache_key_differs_on_user():
    import uuid
    k1 = extraction_cache_key(
        text="hello", provider="ollama", model="llama3.1",
        schema_version=1, user_id=None,
    )
    k2 = extraction_cache_key(
        text="hello", provider="ollama", model="llama3.1",
        schema_version=1, user_id=uuid.uuid4(),
    )
    assert k1 != k2


def test_link_classification_cache_key_shape():
    k = link_classification_cache_key(
        source_id="fnd_a", target_id="fnd_b",
        provider="ollama", model="llama3.1",
        schema_version=1, user_id=None,
    )
    assert len(k) == 64


def test_narration_cache_key_shape():
    k = narration_cache_key(
        path_finding_ids=["fnd_a", "fnd_b", "fnd_c"],
        edge_reasons_summary=["shared_strong_entity", "temporal"],
        provider="claude_code", model="claude-sonnet-4-6",
        schema_version=1, user_id=None,
    )
    assert len(k) == 64
