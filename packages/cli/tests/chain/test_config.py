from unittest.mock import patch

from opentools.chain.config import (
    ChainConfig,
    get_chain_config,
    reset_chain_config,
)


def test_chain_config_defaults():
    cfg = ChainConfig()
    assert cfg.enabled is True
    assert cfg.extraction.llm_enabled is False
    assert cfg.linker.confirmed_threshold == 1.0
    assert cfg.linker.candidate_min_weight == 0.3
    assert cfg.linker.max_edge_weight == 5.0
    assert cfg.linker.common_entity_pct == 0.20
    assert cfg.linker.idf_enabled is True
    assert cfg.query.default_k == 5
    assert cfg.query.default_max_hops == 6
    assert cfg.query.graph_cache_size == 8


def test_tool_chain_defaults_populated():
    cfg = ChainConfig()
    assert len(cfg.linker.tool_chains) >= 4
    names = {tc.from_tool for tc in cfg.linker.tool_chains}
    assert "nmap" in names
    assert "burp" in names


def test_rule_weight_overrides():
    cfg = ChainConfig.model_validate({
        "linker": {"rules": {"shared_strong_entity": {"weight": 2.0, "enabled": False}}}
    })
    assert cfg.linker.rules.shared_strong_entity.weight == 2.0
    assert cfg.linker.rules.shared_strong_entity.enabled is False
    # Other rules keep defaults
    assert cfg.linker.rules.temporal_proximity.weight == 0.5


def test_get_chain_config_returns_singleton():
    reset_chain_config()
    a = get_chain_config()
    b = get_chain_config()
    assert a is b


def test_reset_chain_config_clears_singleton():
    reset_chain_config()
    a = get_chain_config()
    reset_chain_config()
    b = get_chain_config()
    assert a is not b


def test_get_chain_config_falls_back_when_toolkit_missing(monkeypatch):
    """When ConfigLoader raises FileNotFoundError, return default ChainConfig."""
    reset_chain_config()
    from opentools.chain import config as chain_config_module

    class _FailingLoader:
        def load(self):
            raise FileNotFoundError("no config file")

    with patch("opentools.config.ConfigLoader", _FailingLoader):
        cfg = get_chain_config()
    assert isinstance(cfg, ChainConfig)
    assert cfg.enabled is True  # default
    reset_chain_config()
