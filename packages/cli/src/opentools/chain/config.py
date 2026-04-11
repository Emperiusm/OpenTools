"""Chain configuration schema.

Loaded as part of the top-level ToolkitConfig via a `chain:` key in toolkit.yaml.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RuleConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    weight: float
    enabled: bool = True
    window_minutes: int | None = None  # temporal_proximity only


class RulesConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    shared_strong_entity: RuleConfig = RuleConfig(weight=1.0)
    shared_weak_entity: RuleConfig = RuleConfig(weight=0.3)
    temporal_proximity: RuleConfig = RuleConfig(weight=0.5, window_minutes=15)
    tool_chain: RuleConfig = RuleConfig(weight=0.7)
    shared_ioc_cross_engagement: RuleConfig = RuleConfig(weight=0.8)
    cve_adjacency: RuleConfig = RuleConfig(weight=0.6)
    kill_chain_adjacency: RuleConfig = RuleConfig(weight=0.4)


class ToolChainEntry(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    from_tool: str = Field(alias="from")
    to_tool: str = Field(alias="to")
    weight: float


class LinkerConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    rules: RulesConfig = RulesConfig()
    confirmed_threshold: float = 1.0
    candidate_min_weight: float = 0.3
    max_edge_weight: float = 5.0
    stopwords_extra: list[str] = Field(default_factory=list)
    common_entity_pct: float = 0.20
    idf_enabled: bool = True
    tool_chains: list[ToolChainEntry] = Field(
        default_factory=lambda: [
            ToolChainEntry(from_tool="nmap", to_tool="nuclei", weight=0.7),
            ToolChainEntry(from_tool="burp", to_tool="sqlmap", weight=0.8),
            ToolChainEntry(from_tool="ffuf", to_tool="nuclei", weight=0.6),
            ToolChainEntry(from_tool="nuclei", to_tool="metasploit", weight=0.9),
        ]
    )


class ExtractionConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    llm_enabled: bool = False
    default_llm_provider: Literal["ollama", "anthropic_api", "openai_api", "claude_code"] | None = None
    schema_version: int = 1


class NormalizersConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    platform: Literal["auto", "linux", "windows", "macos"] = "auto"


class OllamaProviderConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    base_url: str = "http://localhost:11434"
    model: str = "llama3.1"
    max_concurrent: int = 10
    requests_per_minute: int | None = None


class AnthropicProviderConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    model: str = "claude-sonnet-4-6"
    max_concurrent: int = 5
    requests_per_minute: int = 50


class OpenAIProviderConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    model: str = "gpt-4o-mini"
    max_concurrent: int = 5
    requests_per_minute: int = 60


class ClaudeCodeProviderConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_concurrent: int = 5
    requests_per_minute: int = 30


class LinkClassificationConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    confidence_threshold: float = 0.7


class NarrationConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_paths_per_call: int = 1
    schema_version: int = 1


class LLMConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    claude_code: ClaudeCodeProviderConfig = ClaudeCodeProviderConfig()
    ollama: OllamaProviderConfig = OllamaProviderConfig()
    anthropic_api: AnthropicProviderConfig = AnthropicProviderConfig()
    openai_api: OpenAIProviderConfig = OpenAIProviderConfig()
    link_classification: LinkClassificationConfig = LinkClassificationConfig()
    narration: NarrationConfig = NarrationConfig()


class QueryConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    default_k: int = 5
    default_max_hops: int = 6
    simple_paths_timeout_sec: float = 10.0
    simple_paths_max_results: int = 50
    graph_cache_size: int = 8


class ChainConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    extraction: ExtractionConfig = ExtractionConfig()
    normalizers: NormalizersConfig = NormalizersConfig()
    linker: LinkerConfig = LinkerConfig()
    llm: LLMConfig = LLMConfig()
    query: QueryConfig = QueryConfig()


_config_singleton: ChainConfig | None = None


def get_chain_config() -> ChainConfig:
    """Return the singleton ChainConfig.

    Currently returns a default ChainConfig(). Toolkit YAML integration
    (loading from a ``chain:`` section in ``toolkit.yaml``) is deferred
    until a later phase adds a ``chain`` field to
    :class:`opentools.models.ToolkitConfig`. At that point this function
    will read the toolkit config and validate the ``chain`` subsection.

    For tests and future integration, the singleton can be overridden via
    :func:`set_chain_config` and cleared via :func:`reset_chain_config`.
    """
    global _config_singleton
    if _config_singleton is None:
        _config_singleton = ChainConfig()
    return _config_singleton


def set_chain_config(config: ChainConfig) -> None:
    """Override the singleton ChainConfig.

    Intended for tests and for the future toolkit-integration task to
    inject a config loaded from YAML. Passing a validated ChainConfig
    instance bypasses the default path entirely.
    """
    global _config_singleton
    _config_singleton = config


def reset_chain_config() -> None:
    """Clear the singleton so the next call returns a fresh default.

    Test helper — also used by :func:`set_chain_config` consumers who
    want to restore defaults after an override.
    """
    global _config_singleton
    _config_singleton = None
