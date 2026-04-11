"""Verify ChainConfig is frozen to prevent mid-run mutation (spec O28)."""
import pytest
from pydantic import ValidationError

from opentools.chain.config import ChainConfig


def test_chain_config_is_frozen():
    cfg = ChainConfig()
    with pytest.raises((ValidationError, TypeError)):
        cfg.enabled = False  # Should raise because model is frozen


def test_nested_configs_are_frozen():
    cfg = ChainConfig()
    with pytest.raises((ValidationError, TypeError)):
        cfg.linker.confirmed_threshold = 2.0
