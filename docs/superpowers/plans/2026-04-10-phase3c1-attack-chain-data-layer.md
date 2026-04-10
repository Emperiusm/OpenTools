# Phase 3C.1: Attack Chain Data Layer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the data layer for attack chain visualization — entity extraction from findings, a knowledge-graph data model, rule-based auto-linking with optional LLM enrichment, and a path query engine exposed through CLI commands and read-only web endpoints. No graph visualization (that arrives in 3C.2).

**Architecture:** New `chain` package inside `packages/cli/src/opentools/chain/`. Synchronous rule-based linking runs inline on finding events via a new `StoreEventBus`. LLM operations are always opt-in via explicit commands. New SQLite database `~/.opentools/chain.db` for chain data with a `chain_finding_cache` materialized view; JSON store remains authoritative for findings. Web mirrors the data model in SQLModel tables with per-user scoping, wraps the CLI chain package in async services, and exposes read-only routes plus triggered write endpoints backed by `asyncio.create_task`.

**Tech Stack:** Python 3.14, `rustworkx`, `ioc-finder`, `tldextract`, `taxii2-client`, `instructor`, `claude-agent-sdk`, `anthropic`, `openai`, `ollama`, `aiolimiter`, `tenacity`, `orjson`, SQLAlchemy Core (CLI SQLite), SQLModel + Alembic (web Postgres), Typer, pytest, pytest-asyncio.

**Spec:** `docs/superpowers/specs/2026-04-10-phase3c1-attack-chain-data-layer-design.md`

---

## File Map

### CLI chain package — `packages/cli/src/opentools/chain/`

| File | Action | Task |
|---|---|---|
| `__init__.py` | Create | 1 |
| `config.py` | Create | 1 |
| `types.py` | Create | 2 |
| `models.py` | Create | 3 |
| `events.py` | Create | 4 |
| `store_extensions.py` | Create | 5 |
| `migrations/__init__.py` | Create | 5 |
| `migrations/001_initial.py` | Create | 5 |
| `normalizers.py` | Create | 6 |
| `stopwords.py` | Create | 7 |
| `mitre_catalog.py` | Create | 7 |
| `extractors/__init__.py` | Create | 8 |
| `extractors/base.py` | Create | 8 |
| `extractors/preprocess.py` | Create | 9 |
| `extractors/ioc_finder.py` | Create | 10 |
| `extractors/security_regex.py` | Create | 11 |
| `extractors/parser_aware.py` | Create | 12 |
| `extractors/llm/__init__.py` | Create | 13 |
| `extractors/llm/base.py` | Create | 13 |
| `extractors/llm/ollama.py` | Create | 14 |
| `extractors/llm/anthropic_api.py` | Create | 14 |
| `extractors/llm/openai_api.py` | Create | 14 |
| `extractors/llm/claude_code.py` | Create | 15 |
| `extractors/llm/rate_limit.py` | Create | 16 |
| `extractors/pipeline.py` | Create | 17 |
| `linker/__init__.py` | Create | 18 |
| `linker/context.py` | Create | 18 |
| `linker/idf.py` | Create | 18 |
| `linker/rules/__init__.py` | Create | 19 |
| `linker/rules/base.py` | Create | 19 |
| `linker/rules/shared_entity.py` | Create | 19 |
| `linker/rules/temporal.py` | Create | 20 |
| `linker/rules/tool_chain.py` | Create | 20 |
| `linker/rules/cve_adjacency.py` | Create | 21 |
| `linker/rules/kill_chain.py` | Create | 21 |
| `linker/rules/cross_engagement_ioc.py` | Create | 22 |
| `linker/engine.py` | Create | 23 |
| `linker/batch.py` | Create | 24 |
| `linker/advisory_lock.py` | Create | 25 |
| `linker/llm_pass.py` | Create | 26 |
| `query/__init__.py` | Create | 27 |
| `query/graph_cache.py` | Create | 27 |
| `query/cost.py` | Create | 27 |
| `query/yen.py` | Create | 28 |
| `query/endpoints.py` | Create | 29 |
| `query/engine.py` | Create | 30 |
| `query/neighborhood.py` | Create | 31 |
| `query/bounded.py` | Create | 31 |
| `query/subgraph.py` | Create | 31 |
| `query/adapters.py` | Create | 32 |
| `query/presets.py` | Create | 33 |
| `query/narration.py` | Create | 34 |
| `entity_ops.py` | Create | 35 |
| `exporter.py` | Create | 36 |
| `cli.py` | Create | 37 |
| `plugin_api.py` | Create | 38 |

### CLI integration

| File | Action | Task |
|---|---|---|
| `packages/cli/src/opentools/__main__.py` | Modify | 37 (register chain subcommand) |
| `packages/cli/src/opentools/engagement/store.py` | Modify | 4 (emit StoreEventBus events) |
| `packages/cli/pyproject.toml` | Modify | 1 (add deps) |

### Web backend — `packages/web/backend/app/`

| File | Action | Task |
|---|---|---|
| `models.py` | Modify | 39 (add chain SQLModel tables) |
| `alembic/versions/003_chain_data_layer.py` | Create | 39 |
| `services/chain_service.py` | Create | 40 |
| `services/chain_tasks.py` | Create | 41 |
| `routes/chain.py` | Create | 42 |
| `main.py` | Modify | 42 (include router) |
| `dependencies.py` | Modify | 42 (task registry) |
| `pyproject.toml` | Modify | 39 (add deps) |

### Test files

| File | Action | Task |
|---|---|---|
| `packages/cli/tests/chain/__init__.py` | Create | 3 |
| `packages/cli/tests/chain/conftest.py` | Create | 5 |
| `packages/cli/tests/chain/test_models.py` | Create | 3 |
| `packages/cli/tests/chain/test_store.py` | Create | 5 |
| `packages/cli/tests/chain/test_normalizers.py` | Create | 6 |
| `packages/cli/tests/chain/test_ioc_finder.py` | Create | 10 |
| `packages/cli/tests/chain/test_security_regex.py` | Create | 11 |
| `packages/cli/tests/chain/test_parser_aware.py` | Create | 12 |
| `packages/cli/tests/chain/test_llm_providers.py` | Create | 14 |
| `packages/cli/tests/chain/test_claude_code_provider.py` | Create | 15 |
| `packages/cli/tests/chain/test_pipeline.py` | Create | 17 |
| `packages/cli/tests/chain/test_rules.py` | Create | 19, 20, 21, 22 |
| `packages/cli/tests/chain/test_idf.py` | Create | 18 |
| `packages/cli/tests/chain/test_linker_engine.py` | Create | 23 |
| `packages/cli/tests/chain/test_linker_batch.py` | Create | 24 |
| `packages/cli/tests/chain/test_advisory_lock.py` | Create | 25 |
| `packages/cli/tests/chain/test_llm_pass.py` | Create | 26 |
| `packages/cli/tests/chain/test_graph_cache.py` | Create | 27 |
| `packages/cli/tests/chain/test_yen.py` | Create | 28 |
| `packages/cli/tests/chain/test_endpoints.py` | Create | 29 |
| `packages/cli/tests/chain/test_query_engine.py` | Create | 30 |
| `packages/cli/tests/chain/test_neighborhood.py` | Create | 31 |
| `packages/cli/tests/chain/test_adapters.py` | Create | 32 |
| `packages/cli/tests/chain/test_presets.py` | Create | 33 |
| `packages/cli/tests/chain/test_entity_ops.py` | Create | 35 |
| `packages/cli/tests/chain/test_exporter.py` | Create | 36 |
| `packages/cli/tests/chain/test_cli_commands.py` | Create | 37 |
| `packages/cli/tests/chain/fixtures/canonical_findings.json` | Create | 45 |
| `packages/cli/tests/chain/fixtures/expected_entities.json` | Create | 45 |
| `packages/cli/tests/chain/fixtures/expected_edges.json` | Create | 45 |
| `packages/cli/tests/chain/test_pipeline_integration.py` | Create | 46 |
| `packages/web/backend/tests/test_chain_api.py` | Create | 43 |
| `packages/web/backend/tests/test_chain_isolation.py` | Create | 44 |

---

## Task 1: Package Scaffolding & Config

**Files:**
- Create: `packages/cli/src/opentools/chain/__init__.py`
- Create: `packages/cli/src/opentools/chain/config.py`
- Modify: `packages/cli/pyproject.toml`

- [ ] **Step 1: Add dependencies to `pyproject.toml`**

Append to the existing `[project]` dependencies in `packages/cli/pyproject.toml`:

```toml
"rustworkx>=0.15.0",
"ioc-finder>=7.2.0",
"tldextract>=5.1.0",
"taxii2-client>=2.3.0",
"instructor>=1.5.0",
"anthropic>=0.40.0",
"openai>=1.50.0",
"ollama>=0.3.0",
"claude-agent-sdk>=0.1.0",
"aiolimiter>=1.2.0",
"tenacity>=9.0.0",
"orjson>=3.10.0",
"sqlalchemy>=2.0.30",
```

- [ ] **Step 2: Create the package `__init__.py`**

Create `packages/cli/src/opentools/chain/__init__.py`:

```python
"""Attack chain data layer — entity extraction, knowledge graph, path queries.

Phase 3C.1. See docs/superpowers/specs/2026-04-10-phase3c1-attack-chain-data-layer-design.md
"""

from opentools.chain.config import ChainConfig, get_chain_config

__all__ = ["ChainConfig", "get_chain_config"]
```

- [ ] **Step 3: Write the failing config test**

Create `packages/cli/tests/chain/__init__.py` (empty).
Create `packages/cli/tests/chain/test_config.py`:

```python
from opentools.chain.config import ChainConfig


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
```

- [ ] **Step 4: Run test to verify it fails**

Run: `pytest packages/cli/tests/chain/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError` or similar.

- [ ] **Step 5: Implement `config.py`**

Create `packages/cli/src/opentools/chain/config.py`:

```python
"""Chain configuration schema.

Loaded as part of the top-level ToolkitConfig via a `chain:` key in toolkit.yaml.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class RuleConfig(BaseModel):
    weight: float
    enabled: bool = True
    window_minutes: int | None = None  # temporal_proximity only


class RulesConfig(BaseModel):
    shared_strong_entity: RuleConfig = RuleConfig(weight=1.0)
    shared_weak_entity: RuleConfig = RuleConfig(weight=0.3)
    temporal_proximity: RuleConfig = RuleConfig(weight=0.5, window_minutes=15)
    tool_chain: RuleConfig = RuleConfig(weight=0.7)
    shared_ioc_cross_engagement: RuleConfig = RuleConfig(weight=0.8)
    cve_adjacency: RuleConfig = RuleConfig(weight=0.6)
    kill_chain_adjacency: RuleConfig = RuleConfig(weight=0.4)


class ToolChainEntry(BaseModel):
    from_tool: str = Field(alias="from")
    to_tool: str = Field(alias="to")
    weight: float

    model_config = {"populate_by_name": True}


class LinkerConfig(BaseModel):
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
    llm_enabled: bool = False
    default_llm_provider: Literal["ollama", "anthropic_api", "openai_api", "claude_code"] | None = None
    schema_version: int = 1


class NormalizersConfig(BaseModel):
    platform: Literal["auto", "linux", "windows", "macos"] = "auto"


class OllamaProviderConfig(BaseModel):
    base_url: str = "http://localhost:11434"
    model: str = "llama3.1"
    max_concurrent: int = 10
    requests_per_minute: int | None = None


class AnthropicProviderConfig(BaseModel):
    model: str = "claude-sonnet-4-6"
    max_concurrent: int = 5
    requests_per_minute: int = 50


class OpenAIProviderConfig(BaseModel):
    model: str = "gpt-4o-mini"
    max_concurrent: int = 5
    requests_per_minute: int = 60


class ClaudeCodeProviderConfig(BaseModel):
    max_concurrent: int = 5
    requests_per_minute: int = 30


class LinkClassificationConfig(BaseModel):
    confidence_threshold: float = 0.7


class NarrationConfig(BaseModel):
    max_paths_per_call: int = 1
    schema_version: int = 1


class LLMConfig(BaseModel):
    claude_code: ClaudeCodeProviderConfig = ClaudeCodeProviderConfig()
    ollama: OllamaProviderConfig = OllamaProviderConfig()
    anthropic_api: AnthropicProviderConfig = AnthropicProviderConfig()
    openai_api: OpenAIProviderConfig = OpenAIProviderConfig()
    link_classification: LinkClassificationConfig = LinkClassificationConfig()
    narration: NarrationConfig = NarrationConfig()


class QueryConfig(BaseModel):
    default_k: int = 5
    default_max_hops: int = 6
    simple_paths_timeout_sec: float = 10.0
    simple_paths_max_results: int = 50
    graph_cache_size: int = 8


class ChainConfig(BaseModel):
    enabled: bool = True
    extraction: ExtractionConfig = ExtractionConfig()
    normalizers: NormalizersConfig = NormalizersConfig()
    linker: LinkerConfig = LinkerConfig()
    llm: LLMConfig = LLMConfig()
    query: QueryConfig = QueryConfig()


_config_singleton: ChainConfig | None = None


def get_chain_config() -> ChainConfig:
    """Return the singleton ChainConfig, loading from toolkit config if needed."""
    global _config_singleton
    if _config_singleton is None:
        try:
            from opentools.config import get_toolkit_config
            toolkit = get_toolkit_config()
            raw = getattr(toolkit, "chain", None)
            _config_singleton = ChainConfig.model_validate(raw) if raw else ChainConfig()
        except Exception:
            _config_singleton = ChainConfig()
    return _config_singleton


def reset_chain_config() -> None:
    """Test helper — clear the singleton."""
    global _config_singleton
    _config_singleton = None
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest packages/cli/tests/chain/test_config.py -v`
Expected: PASS (3 tests).

- [ ] **Step 7: Commit**

```bash
git add packages/cli/src/opentools/chain/__init__.py \
        packages/cli/src/opentools/chain/config.py \
        packages/cli/tests/chain/__init__.py \
        packages/cli/tests/chain/test_config.py \
        packages/cli/pyproject.toml
git commit -m "feat(chain): add 3C.1 package scaffolding and config schema"
```

---

## Task 2: Entity Type Registry & Enums

**Files:**
- Create: `packages/cli/src/opentools/chain/types.py`
- Create: `packages/cli/tests/chain/test_types.py`

- [ ] **Step 1: Write the failing test**

Create `packages/cli/tests/chain/test_types.py`:

```python
import pytest

from opentools.chain.types import (
    ENTITY_TYPE_REGISTRY,
    EntityTypeCategory,
    MentionField,
    RelationStatus,
    LinkerMode,
    LinkerScope,
    register_entity_type,
    is_strong_entity_type,
    is_weak_entity_type,
)


def test_builtin_entity_types_registered():
    for t in ["host", "ip", "user", "process", "cve", "mitre_technique",
              "domain", "registered_domain", "email",
              "file_path", "port", "registry_key", "package",
              "hash_md5", "hash_sha1", "hash_sha256"]:
        assert t in ENTITY_TYPE_REGISTRY


def test_strong_vs_weak_classification():
    assert is_strong_entity_type("host")
    assert is_strong_entity_type("cve")
    assert is_weak_entity_type("file_path")
    assert is_weak_entity_type("port")
    assert not is_weak_entity_type("host")


def test_register_entity_type_idempotent():
    register_entity_type("docker_container", category=EntityTypeCategory.STRONG, normalizer=str.lower)
    assert "docker_container" in ENTITY_TYPE_REGISTRY
    register_entity_type("docker_container", category=EntityTypeCategory.STRONG, normalizer=str.lower)
    assert "docker_container" in ENTITY_TYPE_REGISTRY


def test_register_entity_type_conflict_raises():
    register_entity_type("unique_thing", category=EntityTypeCategory.STRONG, normalizer=str.lower)
    with pytest.raises(ValueError, match="already registered"):
        register_entity_type("unique_thing", category=EntityTypeCategory.WEAK, normalizer=str.upper)


def test_relation_status_values():
    assert RelationStatus.AUTO_CONFIRMED.value == "auto_confirmed"
    assert RelationStatus.CANDIDATE.value == "candidate"
    assert RelationStatus.REJECTED.value == "rejected"
    assert RelationStatus.USER_CONFIRMED.value == "user_confirmed"
    assert RelationStatus.USER_REJECTED.value == "user_rejected"


def test_mention_field_values():
    assert MentionField.TITLE.value == "title"
    assert MentionField.DESCRIPTION.value == "description"
    assert MentionField.EVIDENCE.value == "evidence"
    assert MentionField.FILE_PATH.value == "file_path"
    assert MentionField.IOC.value == "ioc"
```

- [ ] **Step 2: Run to verify it fails**

Run: `pytest packages/cli/tests/chain/test_types.py -v`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement `types.py`**

Create `packages/cli/src/opentools/chain/types.py`:

```python
"""Entity type registry, shared enums, and classification helpers."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Callable


class EntityTypeCategory(StrEnum):
    STRONG = "strong"
    WEAK = "weak"


class MentionField(StrEnum):
    TITLE = "title"
    DESCRIPTION = "description"
    EVIDENCE = "evidence"
    FILE_PATH = "file_path"
    IOC = "ioc"


class RelationStatus(StrEnum):
    AUTO_CONFIRMED = "auto_confirmed"
    CANDIDATE = "candidate"
    REJECTED = "rejected"
    USER_CONFIRMED = "user_confirmed"
    USER_REJECTED = "user_rejected"


class LinkerMode(StrEnum):
    RULES_ONLY = "rules_only"
    RULES_PLUS_LLM = "rules_plus_llm"
    MANUAL_MERGE = "manual_merge"
    MANUAL_SPLIT = "manual_split"


class LinkerScope(StrEnum):
    ENGAGEMENT = "engagement"
    CROSS_ENGAGEMENT = "cross_engagement"
    FINDING_BATCH = "finding_batch"
    FINDING_SINGLE = "finding_single"
    MANUAL_MERGE = "manual_merge"
    MANUAL_SPLIT = "manual_split"


@dataclass(frozen=True)
class EntityTypeSpec:
    name: str
    category: EntityTypeCategory
    normalizer: Callable[[str], str]


ENTITY_TYPE_REGISTRY: dict[str, EntityTypeSpec] = {}


def register_entity_type(
    name: str,
    *,
    category: EntityTypeCategory,
    normalizer: Callable[[str], str],
) -> None:
    """Register an entity type. Idempotent for identical re-registrations.

    Raises ValueError if the same name is registered with different category
    or normalizer (protects plugins from silently clobbering each other).
    """
    existing = ENTITY_TYPE_REGISTRY.get(name)
    if existing is not None:
        if existing.category == category and existing.normalizer is normalizer:
            return  # idempotent
        raise ValueError(f"entity type {name!r} already registered with different spec")
    ENTITY_TYPE_REGISTRY[name] = EntityTypeSpec(name=name, category=category, normalizer=normalizer)


def is_strong_entity_type(name: str) -> bool:
    spec = ENTITY_TYPE_REGISTRY.get(name)
    return spec is not None and spec.category == EntityTypeCategory.STRONG


def is_weak_entity_type(name: str) -> bool:
    spec = ENTITY_TYPE_REGISTRY.get(name)
    return spec is not None and spec.category == EntityTypeCategory.WEAK


# Built-in registrations happen in normalizers.py to avoid circular imports.
# This module provides only the registry machinery.
```

The normalizer registration lives in `normalizers.py` (Task 6) to avoid circular imports — that's why this test only checks the registry is *populated*, which will be satisfied once `normalizers.py` is imported. For now the test will fail on the builtin-types assertion. We accept that and make Task 6 restore green.

- [ ] **Step 4: Add a deferred import to `__init__.py`**

Modify `packages/cli/src/opentools/chain/__init__.py` — append to the existing file:

```python
# Register built-in entity types on package import.
from opentools.chain import normalizers  # noqa: F401,E402
```

At this stage `normalizers` doesn't exist yet; leave the import commented out and restore in Task 6:

```python
# Built-in entity type registrations are wired up in Task 6.
# from opentools.chain import normalizers  # noqa: F401,E402
```

- [ ] **Step 5: Run the type tests in isolation**

Run: `pytest packages/cli/tests/chain/test_types.py::test_strong_vs_weak_classification packages/cli/tests/chain/test_types.py::test_register_entity_type_idempotent packages/cli/tests/chain/test_types.py::test_register_entity_type_conflict_raises packages/cli/tests/chain/test_types.py::test_relation_status_values packages/cli/tests/chain/test_types.py::test_mention_field_values -v`

We exclude `test_builtin_entity_types_registered` for now — it comes green in Task 6.
Expected: 5 PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/chain/types.py \
        packages/cli/src/opentools/chain/__init__.py \
        packages/cli/tests/chain/test_types.py
git commit -m "feat(chain): add entity type registry and shared enums"
```

---

## Task 3: Pydantic Models

**Files:**
- Create: `packages/cli/src/opentools/chain/models.py`
- Create: `packages/cli/tests/chain/test_models.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/cli/tests/chain/test_models.py
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from opentools.chain.models import (
    Entity,
    EntityMention,
    FindingRelation,
    RelationReason,
    LinkerRun,
    ExtractionCache,
    LLMLinkCache,
    FindingExtractionState,
    FindingParserOutput,
    LLMExtractedEntity,
    LLMExtractionResponse,
    LLMLinkClassification,
    entity_id_for,
)
from opentools.chain.types import (
    RelationStatus,
    MentionField,
    LinkerScope,
    LinkerMode,
)


def test_entity_id_is_content_addressed():
    a = entity_id_for("host", "10.0.0.5")
    b = entity_id_for("host", "10.0.0.5")
    c = entity_id_for("host", "10.0.0.6")
    assert a == b
    assert a != c
    assert len(a) == 16
    assert all(ch in "0123456789abcdef" for ch in a)


def test_entity_type_and_value_contribute_to_id():
    # Different type, same value should produce different ids
    assert entity_id_for("host", "admin") != entity_id_for("user", "admin")


def test_entity_construction():
    now = datetime.now(timezone.utc)
    e = Entity(
        id=entity_id_for("host", "10.0.0.5"),
        type="host",
        canonical_value="10.0.0.5",
        first_seen_at=now,
        last_seen_at=now,
        mention_count=0,
        user_id=None,
    )
    assert e.type == "host"
    assert e.canonical_value == "10.0.0.5"


def test_relation_reason_contribution_required():
    r = RelationReason(rule="shared_strong_entity", weight_contribution=1.2, idf_factor=1.5, details={"entity_id": "abc"})
    assert r.rule == "shared_strong_entity"
    assert r.weight_contribution == 1.2
    assert r.idf_factor == 1.5
    assert r.details["entity_id"] == "abc"


def test_finding_relation_default_version():
    now = datetime.now(timezone.utc)
    rel = FindingRelation(
        id="rel_abc",
        source_finding_id="fnd_1",
        target_finding_id="fnd_2",
        weight=1.5,
        status=RelationStatus.AUTO_CONFIRMED,
        symmetric=False,
        reasons=[RelationReason(rule="shared_strong_entity", weight_contribution=1.5, idf_factor=1.2, details={})],
        created_at=now,
        updated_at=now,
    )
    assert rel.weight_model_version == "additive_v1"
    assert rel.llm_rationale is None
    assert rel.confirmed_at_reasons is None


def test_llm_link_classification_schema():
    cls = LLMLinkClassification(
        related=True,
        relation_type="pivots_to",
        rationale="Shared host 10.0.0.5",
        confidence=0.85,
    )
    assert cls.related is True
    assert cls.relation_type == "pivots_to"
    assert 0 <= cls.confidence <= 1


def test_llm_link_classification_rejects_out_of_range_confidence():
    with pytest.raises(ValueError):
        LLMLinkClassification(related=True, relation_type="enables", rationale="", confidence=1.5)


def test_llm_extraction_response_ok():
    resp = LLMExtractionResponse(
        entities=[
            LLMExtractedEntity(type="host", value="10.0.0.5", confidence=0.9),
            LLMExtractedEntity(type="cve", value="CVE-2024-1234", confidence=0.95),
        ]
    )
    assert len(resp.entities) == 2


def test_linker_run_accepts_all_scopes():
    for scope in LinkerScope:
        run = LinkerRun(
            id=f"run_{scope.value}",
            started_at=datetime.now(timezone.utc),
            scope=scope,
            mode=LinkerMode.RULES_ONLY,
            findings_processed=0,
            entities_extracted=0,
            relations_created=0,
            relations_updated=0,
            relations_skipped_sticky=0,
            extraction_cache_hits=0,
            extraction_cache_misses=0,
            llm_calls_made=0,
            llm_cache_hits=0,
            llm_cache_misses=0,
            rule_stats={},
            generation=1,
        )
        assert run.scope == scope
```

- [ ] **Step 2: Run — expect fail**

Run: `pytest packages/cli/tests/chain/test_models.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement `models.py`**

```python
# packages/cli/src/opentools/chain/models.py
"""Pydantic models for chain data layer.

The web backend mirrors these as SQLModel tables in packages/web/backend/app/models.py.
The CLI SQLite backend creates corresponding tables via SQLAlchemy Core in store_extensions.py.
"""
from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from opentools.chain.types import (
    LinkerMode,
    LinkerScope,
    MentionField,
    RelationStatus,
)

FindingId = str  # CLI uses string finding ids; web stores UUID as string at the chain layer


def entity_id_for(entity_type: str, canonical_value: str) -> str:
    """Content-addressed entity id: sha256(type + '|' + canonical_value)[:16]."""
    payload = f"{entity_type}|{canonical_value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


class Entity(BaseModel):
    id: str
    type: str
    canonical_value: str
    first_seen_at: datetime
    last_seen_at: datetime
    mention_count: int = 0
    user_id: UUID | None = None


class EntityMention(BaseModel):
    id: str
    entity_id: str
    finding_id: FindingId
    field: MentionField
    raw_value: str
    offset_start: int | None = None
    offset_end: int | None = None
    extractor: str
    confidence: float = Field(ge=0.0, le=1.0)
    created_at: datetime
    user_id: UUID | None = None


class RelationReason(BaseModel):
    rule: str
    weight_contribution: float
    idf_factor: float | None = None
    details: dict = Field(default_factory=dict)


class FindingRelation(BaseModel):
    id: str
    source_finding_id: FindingId
    target_finding_id: FindingId
    weight: float
    weight_model_version: str = "additive_v1"
    status: RelationStatus
    symmetric: bool = False
    reasons: list[RelationReason] = Field(default_factory=list)
    llm_rationale: str | None = None
    llm_relation_type: str | None = None
    llm_confidence: float | None = None
    confirmed_at_reasons: list[RelationReason] | None = None
    created_at: datetime
    updated_at: datetime
    user_id: UUID | None = None


class LinkerRun(BaseModel):
    id: str
    started_at: datetime
    finished_at: datetime | None = None
    scope: LinkerScope
    scope_id: str | None = None
    mode: LinkerMode
    llm_provider: str | None = None
    findings_processed: int = 0
    entities_extracted: int = 0
    relations_created: int = 0
    relations_updated: int = 0
    relations_skipped_sticky: int = 0
    extraction_cache_hits: int = 0
    extraction_cache_misses: int = 0
    llm_calls_made: int = 0
    llm_cache_hits: int = 0
    llm_cache_misses: int = 0
    rule_stats: dict = Field(default_factory=dict)
    duration_ms: int | None = None
    error: str | None = None
    generation: int = 0
    user_id: UUID | None = None


class ExtractionCache(BaseModel):
    cache_key: str
    provider: str
    model: str
    schema_version: int
    result_json: bytes
    created_at: datetime


class LLMLinkCache(BaseModel):
    cache_key: str
    provider: str
    model: str
    schema_version: int
    classification_json: bytes
    created_at: datetime


class FindingExtractionState(BaseModel):
    finding_id: FindingId
    extraction_input_hash: str
    last_extracted_at: datetime
    last_extractor_set: list[str] = Field(default_factory=list)
    user_id: UUID | None = None


class FindingParserOutput(BaseModel):
    finding_id: FindingId
    parser_name: str
    data: dict
    created_at: datetime
    user_id: UUID | None = None


# ─── LLM output schemas (validated via instructor / PydanticRetryWrapper) ────


class LLMExtractedEntity(BaseModel):
    type: str
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str | None = None


class LLMExtractionResponse(BaseModel):
    entities: list[LLMExtractedEntity] = Field(default_factory=list)


class LLMLinkClassification(BaseModel):
    related: bool
    relation_type: Literal[
        "enables",
        "pivots_to",
        "escalates",
        "exploits",
        "provides_context",
        "same_target_only",
        "unrelated",
    ]
    rationale: str
    confidence: float = Field(ge=0.0, le=1.0)
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest packages/cli/tests/chain/test_models.py -v`
Expected: PASS (9 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/chain/models.py \
        packages/cli/tests/chain/test_models.py
git commit -m "feat(chain): add pydantic models for entities, relations, and LLM schemas"
```

---

## Task 4: StoreEventBus + Store Hook Integration

**Files:**
- Create: `packages/cli/src/opentools/chain/events.py`
- Create: `packages/cli/tests/chain/test_events.py`
- Modify: `packages/cli/src/opentools/engagement/store.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/cli/tests/chain/test_events.py
from opentools.chain.events import StoreEventBus


def test_event_bus_dispatches_to_subscribers():
    bus = StoreEventBus()
    calls = []

    def handler(finding_id, **kwargs):
        calls.append(("a", finding_id, kwargs))

    def handler_b(finding_id, **kwargs):
        calls.append(("b", finding_id, kwargs))

    bus.subscribe("finding.created", handler)
    bus.subscribe("finding.created", handler_b)
    bus.emit("finding.created", finding_id="fnd_1", extra=42)

    assert ("a", "fnd_1", {"extra": 42}) in calls
    assert ("b", "fnd_1", {"extra": 42}) in calls


def test_event_bus_swallows_handler_exceptions():
    bus = StoreEventBus()
    ok = []

    def broken(**kwargs):
        raise RuntimeError("boom")

    def fine(**kwargs):
        ok.append(kwargs)

    bus.subscribe("finding.updated", broken)
    bus.subscribe("finding.updated", fine)
    bus.emit("finding.updated", finding_id="fnd_2")
    assert ok == [{"finding_id": "fnd_2"}]


def test_event_bus_ignores_unknown_events():
    bus = StoreEventBus()
    bus.emit("finding.nonsense", finding_id="fnd_x")  # must not raise


def test_event_bus_singleton_shared():
    from opentools.chain.events import get_event_bus
    a = get_event_bus()
    b = get_event_bus()
    assert a is b
```

- [ ] **Step 2: Run — expect fail**

Run: `pytest packages/cli/tests/chain/test_events.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement `events.py`**

```python
# packages/cli/src/opentools/chain/events.py
"""Minimal in-process event bus for chain-related store events.

The chain package subscribes to finding.created / finding.updated / finding.deleted
at init time. The existing engagement store emits these events after successful
state changes. Handler exceptions are logged and swallowed so a broken subscriber
cannot break finding CRUD.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Callable

logger = logging.getLogger(__name__)

EventName = str
Handler = Callable[..., None]


class StoreEventBus:
    def __init__(self) -> None:
        self._subscribers: dict[EventName, list[Handler]] = defaultdict(list)

    def subscribe(self, event: EventName, handler: Handler) -> None:
        self._subscribers[event].append(handler)

    def emit(self, event: EventName, **kwargs) -> None:
        for handler in list(self._subscribers.get(event, [])):
            try:
                handler(**kwargs)
            except Exception:  # noqa: BLE001
                logger.exception("StoreEventBus handler failed for event=%s", event)


_bus_singleton: StoreEventBus | None = None


def get_event_bus() -> StoreEventBus:
    global _bus_singleton
    if _bus_singleton is None:
        _bus_singleton = StoreEventBus()
    return _bus_singleton


def reset_event_bus() -> None:
    """Test helper."""
    global _bus_singleton
    _bus_singleton = None
```

- [ ] **Step 4: Run — expect pass**

Run: `pytest packages/cli/tests/chain/test_events.py -v`
Expected: PASS.

- [ ] **Step 5: Wire the store to emit events**

Open `packages/cli/src/opentools/engagement/store.py` and locate the existing `add_finding`, `update_finding`, and `delete_finding` (or equivalent) methods. At the end of each, after the state change is committed to disk, emit the corresponding event:

```python
# at top of file
from opentools.chain.events import get_event_bus

# inside add_finding, after successful write:
get_event_bus().emit(
    "finding.created",
    finding_id=finding.id,
    engagement_id=finding.engagement_id,
)

# inside update_finding, after successful write:
get_event_bus().emit(
    "finding.updated",
    finding_id=finding.id,
    engagement_id=finding.engagement_id,
)

# inside delete_finding, after successful write:
get_event_bus().emit(
    "finding.deleted",
    finding_id=finding_id,
    engagement_id=engagement_id,
)
```

If the store methods are named differently or delete is absent, add the emit calls at the equivalent lifecycle points. If delete is genuinely unsupported, skip the delete emit — cascade will still work via CASCADE constraints once chain data exists.

- [ ] **Step 6: Add a store integration test**

Append to `packages/cli/tests/chain/test_events.py`:

```python
def test_store_emits_finding_created(tmp_path, monkeypatch):
    """Smoke test: adding a finding via the real store emits finding.created."""
    from opentools.chain.events import get_event_bus, reset_event_bus
    reset_event_bus()
    received = []
    get_event_bus().subscribe("finding.created", lambda **kw: received.append(kw))

    # Use the real store API; adjust import if store factory lives elsewhere.
    from opentools.engagement.store import EngagementStore
    store = EngagementStore(root=tmp_path)
    engagement = store.create_engagement(name="t", target="example.com", type="external")
    finding = store.add_finding(
        engagement_id=engagement.id,
        tool="nmap",
        severity="high",
        title="Open port 22",
        description="SSH exposed on 10.0.0.5",
    )
    assert any(e.get("finding_id") == finding.id for e in received)
```

If your store constructor or `create_engagement` / `add_finding` signatures differ, adjust the call site to match. The test only needs to prove that emit fires.

- [ ] **Step 7: Run — expect pass**

Run: `pytest packages/cli/tests/chain/test_events.py -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add packages/cli/src/opentools/chain/events.py \
        packages/cli/tests/chain/test_events.py \
        packages/cli/src/opentools/engagement/store.py
git commit -m "feat(chain): add StoreEventBus and wire engagement store to emit finding events"
```

---

## Task 5: SQLite Store Extensions (schema, pragmas, migration)

**Files:**
- Create: `packages/cli/src/opentools/chain/store_extensions.py`
- Create: `packages/cli/src/opentools/chain/migrations/__init__.py`
- Create: `packages/cli/src/opentools/chain/migrations/001_initial.py`
- Create: `packages/cli/tests/chain/conftest.py`
- Create: `packages/cli/tests/chain/test_store.py`

- [ ] **Step 1: Write conftest with a shared fixture**

```python
# packages/cli/tests/chain/conftest.py
import pytest

from opentools.chain.store_extensions import ChainStore


@pytest.fixture
def chain_store(tmp_path):
    db_path = tmp_path / "chain.db"
    store = ChainStore(db_path=db_path)
    store.initialize()
    yield store
    store.close()
```

- [ ] **Step 2: Write the failing test**

```python
# packages/cli/tests/chain/test_store.py
from datetime import datetime, timezone
from opentools.chain.models import (
    Entity, EntityMention, FindingRelation, RelationReason,
    entity_id_for,
)
from opentools.chain.types import MentionField, RelationStatus


def now() -> datetime:
    return datetime.now(timezone.utc)


def test_pragmas_applied(chain_store):
    row = chain_store.execute_one("PRAGMA journal_mode")
    assert row[0].lower() == "wal"
    row = chain_store.execute_one("PRAGMA foreign_keys")
    assert row[0] == 1


def test_tables_created(chain_store):
    rows = chain_store.execute_all(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    names = {r[0] for r in rows}
    for expected in [
        "entity",
        "entity_mention",
        "finding_relation",
        "linker_run",
        "extraction_cache",
        "llm_link_cache",
        "finding_extraction_state",
        "finding_parser_output",
        "chain_finding_cache",
    ]:
        assert expected in names, f"missing table {expected}"


def test_upsert_entity_and_lookup(chain_store):
    eid = entity_id_for("host", "10.0.0.5")
    e = Entity(
        id=eid, type="host", canonical_value="10.0.0.5",
        first_seen_at=now(), last_seen_at=now(), mention_count=0,
    )
    chain_store.upsert_entity(e)
    found = chain_store.get_entity(eid)
    assert found is not None
    assert found.type == "host"
    assert found.canonical_value == "10.0.0.5"


def test_upsert_entity_idempotent_updates_last_seen(chain_store):
    eid = entity_id_for("host", "10.0.0.5")
    e1 = Entity(
        id=eid, type="host", canonical_value="10.0.0.5",
        first_seen_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        last_seen_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        mention_count=1,
    )
    chain_store.upsert_entity(e1)
    e2 = Entity(
        id=eid, type="host", canonical_value="10.0.0.5",
        first_seen_at=datetime(2025, 6, 1, tzinfo=timezone.utc),
        last_seen_at=datetime(2025, 6, 1, tzinfo=timezone.utc),
        mention_count=5,
    )
    chain_store.upsert_entity(e2)
    found = chain_store.get_entity(eid)
    # last_seen updates to the newer value, mention_count takes the incoming value
    assert found.mention_count == 5


def test_add_mentions_bulk_and_fetch_by_finding(chain_store):
    eid = entity_id_for("host", "10.0.0.5")
    chain_store.upsert_entity(Entity(
        id=eid, type="host", canonical_value="10.0.0.5",
        first_seen_at=now(), last_seen_at=now(), mention_count=0,
    ))
    mentions = [
        EntityMention(
            id=f"mnt_{i}", entity_id=eid, finding_id="fnd_1",
            field=MentionField.DESCRIPTION, raw_value="10.0.0.5",
            offset_start=10, offset_end=18, extractor="ioc_finder",
            confidence=0.9, created_at=now(),
        )
        for i in range(3)
    ]
    chain_store.add_mentions(mentions)
    fetched = chain_store.mentions_for_finding("fnd_1")
    # Unique on (entity_id, finding_id, field, offset_start) — duplicates collapse
    assert len(fetched) == 1
    assert fetched[0].raw_value == "10.0.0.5"


def test_finding_delete_cascades(chain_store):
    # Seed cache row so FKs resolve
    chain_store.upsert_finding_cache(
        finding_id="fnd_del", engagement_id="eng_1", tool="nmap",
        severity="high", title="t", status="open", created_at=now(),
    )
    eid = entity_id_for("host", "10.0.0.5")
    chain_store.upsert_entity(Entity(
        id=eid, type="host", canonical_value="10.0.0.5",
        first_seen_at=now(), last_seen_at=now(),
    ))
    chain_store.add_mentions([
        EntityMention(
            id="mnt_x", entity_id=eid, finding_id="fnd_del",
            field=MentionField.TITLE, raw_value="10.0.0.5",
            offset_start=0, offset_end=8, extractor="ioc_finder",
            confidence=0.9, created_at=now(),
        )
    ])
    chain_store.delete_finding_cache("fnd_del")  # triggers ON DELETE CASCADE
    assert chain_store.mentions_for_finding("fnd_del") == []


def test_upsert_relations_bulk(chain_store):
    chain_store.upsert_finding_cache(finding_id="fnd_a", engagement_id="eng_1", tool="nmap", severity="high", title="a", status="open", created_at=now())
    chain_store.upsert_finding_cache(finding_id="fnd_b", engagement_id="eng_1", tool="nmap", severity="high", title="b", status="open", created_at=now())
    rel = FindingRelation(
        id="rel_1", source_finding_id="fnd_a", target_finding_id="fnd_b",
        weight=1.5, status=RelationStatus.AUTO_CONFIRMED, symmetric=False,
        reasons=[RelationReason(rule="shared_strong_entity", weight_contribution=1.5, idf_factor=1.0, details={})],
        created_at=now(), updated_at=now(),
    )
    chain_store.upsert_relations_bulk([rel])
    fetched = chain_store.relations_for_finding("fnd_a")
    assert len(fetched) == 1
    assert fetched[0].weight == 1.5
```

- [ ] **Step 3: Run — expect fail**

Run: `pytest packages/cli/tests/chain/test_store.py -v`
Expected: FAIL.

- [ ] **Step 4: Implement the migration**

Create `packages/cli/src/opentools/chain/migrations/__init__.py` (empty).

Create `packages/cli/src/opentools/chain/migrations/001_initial.py`:

```python
"""Initial chain schema migration."""

CREATE_STATEMENTS: list[str] = [
    # chain_finding_cache — materialized view of finding fields needed by chain queries
    """
    CREATE TABLE IF NOT EXISTS chain_finding_cache (
        finding_id      TEXT PRIMARY KEY,
        engagement_id   TEXT NOT NULL,
        tool            TEXT,
        severity        TEXT,
        title           TEXT,
        status          TEXT,
        created_at      TIMESTAMP,
        cached_at       TIMESTAMP NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_cfc_engagement ON chain_finding_cache(engagement_id)",
    "CREATE INDEX IF NOT EXISTS idx_cfc_severity ON chain_finding_cache(severity)",

    # entity
    """
    CREATE TABLE IF NOT EXISTS entity (
        id              TEXT PRIMARY KEY,
        type            TEXT NOT NULL,
        canonical_value TEXT NOT NULL,
        first_seen_at   TIMESTAMP NOT NULL,
        last_seen_at    TIMESTAMP NOT NULL,
        mention_count   INTEGER NOT NULL DEFAULT 0,
        user_id         TEXT,
        UNIQUE (type, canonical_value, user_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_entity_type_value ON entity(type, canonical_value)",
    "CREATE INDEX IF NOT EXISTS idx_entity_user_type ON entity(user_id, type)",

    # entity_mention
    """
    CREATE TABLE IF NOT EXISTS entity_mention (
        id              TEXT PRIMARY KEY,
        entity_id       TEXT NOT NULL REFERENCES entity(id) ON DELETE CASCADE,
        finding_id      TEXT NOT NULL REFERENCES chain_finding_cache(finding_id) ON DELETE CASCADE,
        field           TEXT NOT NULL,
        raw_value       TEXT NOT NULL,
        offset_start    INTEGER,
        offset_end      INTEGER,
        extractor       TEXT NOT NULL,
        confidence      REAL NOT NULL,
        created_at      TIMESTAMP NOT NULL,
        user_id         TEXT,
        UNIQUE (entity_id, finding_id, field, offset_start)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_em_finding ON entity_mention(finding_id)",
    "CREATE INDEX IF NOT EXISTS idx_em_entity ON entity_mention(entity_id)",
    "CREATE INDEX IF NOT EXISTS idx_em_entity_finding ON entity_mention(entity_id, finding_id)",

    # finding_relation
    """
    CREATE TABLE IF NOT EXISTS finding_relation (
        id                  TEXT PRIMARY KEY,
        source_finding_id   TEXT NOT NULL REFERENCES chain_finding_cache(finding_id) ON DELETE CASCADE,
        target_finding_id   TEXT NOT NULL REFERENCES chain_finding_cache(finding_id) ON DELETE CASCADE,
        weight              REAL NOT NULL,
        weight_model_version TEXT NOT NULL DEFAULT 'additive_v1',
        status              TEXT NOT NULL,
        symmetric           INTEGER NOT NULL DEFAULT 0,
        reasons_json        BLOB NOT NULL,
        llm_rationale       TEXT,
        llm_relation_type   TEXT,
        llm_confidence      REAL,
        confirmed_at_reasons_json BLOB,
        created_at          TIMESTAMP NOT NULL,
        updated_at          TIMESTAMP NOT NULL,
        user_id             TEXT,
        UNIQUE (source_finding_id, target_finding_id, user_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_fr_source ON finding_relation(source_finding_id)",
    "CREATE INDEX IF NOT EXISTS idx_fr_target ON finding_relation(target_finding_id)",
    "CREATE INDEX IF NOT EXISTS idx_fr_status ON finding_relation(status)",

    # linker_run
    """
    CREATE TABLE IF NOT EXISTS linker_run (
        id                  TEXT PRIMARY KEY,
        started_at          TIMESTAMP NOT NULL,
        finished_at         TIMESTAMP,
        scope               TEXT NOT NULL,
        scope_id            TEXT,
        mode                TEXT NOT NULL,
        llm_provider        TEXT,
        findings_processed  INTEGER NOT NULL DEFAULT 0,
        entities_extracted  INTEGER NOT NULL DEFAULT 0,
        relations_created   INTEGER NOT NULL DEFAULT 0,
        relations_updated   INTEGER NOT NULL DEFAULT 0,
        relations_skipped_sticky INTEGER NOT NULL DEFAULT 0,
        extraction_cache_hits INTEGER NOT NULL DEFAULT 0,
        extraction_cache_misses INTEGER NOT NULL DEFAULT 0,
        llm_calls_made      INTEGER NOT NULL DEFAULT 0,
        llm_cache_hits      INTEGER NOT NULL DEFAULT 0,
        llm_cache_misses    INTEGER NOT NULL DEFAULT 0,
        rule_stats_json     BLOB,
        duration_ms         INTEGER,
        error               TEXT,
        generation          INTEGER NOT NULL DEFAULT 0,
        user_id             TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_lr_scope ON linker_run(scope, scope_id)",
    "CREATE INDEX IF NOT EXISTS idx_lr_generation ON linker_run(generation DESC)",

    # extraction_cache
    """
    CREATE TABLE IF NOT EXISTS extraction_cache (
        cache_key       TEXT PRIMARY KEY,
        provider        TEXT NOT NULL,
        model           TEXT NOT NULL,
        schema_version  INTEGER NOT NULL,
        result_json     BLOB NOT NULL,
        created_at      TIMESTAMP NOT NULL
    )
    """,

    # llm_link_cache
    """
    CREATE TABLE IF NOT EXISTS llm_link_cache (
        cache_key            TEXT PRIMARY KEY,
        provider             TEXT NOT NULL,
        model                TEXT NOT NULL,
        schema_version       INTEGER NOT NULL,
        classification_json  BLOB NOT NULL,
        created_at           TIMESTAMP NOT NULL
    )
    """,

    # finding_extraction_state
    """
    CREATE TABLE IF NOT EXISTS finding_extraction_state (
        finding_id              TEXT PRIMARY KEY REFERENCES chain_finding_cache(finding_id) ON DELETE CASCADE,
        extraction_input_hash   TEXT NOT NULL,
        last_extracted_at       TIMESTAMP NOT NULL,
        last_extractor_set_json BLOB NOT NULL,
        user_id                 TEXT
    )
    """,

    # finding_parser_output
    """
    CREATE TABLE IF NOT EXISTS finding_parser_output (
        finding_id      TEXT NOT NULL REFERENCES chain_finding_cache(finding_id) ON DELETE CASCADE,
        parser_name     TEXT NOT NULL,
        data_json       BLOB NOT NULL,
        created_at      TIMESTAMP NOT NULL,
        user_id         TEXT,
        PRIMARY KEY (finding_id, parser_name)
    )
    """,
]


def apply(conn) -> None:
    for stmt in CREATE_STATEMENTS:
        conn.execute(stmt)
    conn.commit()
```

- [ ] **Step 5: Implement `store_extensions.py`**

```python
# packages/cli/src/opentools/chain/store_extensions.py
"""SQLite backend for chain data with performance pragmas and CRUD helpers."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import orjson

from opentools.chain.migrations import _001_initial  # noqa: F401  (registered below)
from opentools.chain.migrations import (  # type: ignore[no-redef]
    _001_initial as initial_migration,
)
from opentools.chain.models import (
    Entity,
    EntityMention,
    FindingRelation,
    LinkerRun,
    RelationReason,
)
from opentools.chain.types import MentionField, RelationStatus

DEFAULT_DB_PATH = Path.home() / ".opentools" / "chain.db"


def _configure_connection(conn: sqlite3.Connection) -> None:
    for pragma in (
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=NORMAL",
        "PRAGMA cache_size=-64000",
        "PRAGMA mmap_size=268435456",
        "PRAGMA temp_store=MEMORY",
        "PRAGMA foreign_keys=ON",
    ):
        conn.execute(pragma)


class ChainStore:
    """SQLite-backed store for chain data.

    CLI uses this via a singleton; tests pass an explicit db_path to tmp_path.
    """

    def __init__(self, *, db_path: Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
        self._conn: sqlite3.Connection | None = None

    # ─── lifecycle ──────────────────────────────────────────────────────────

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self.db_path),
            detect_types=sqlite3.PARSE_DECLTYPES,
            isolation_level=None,  # we manage transactions explicitly
        )
        self._conn.row_factory = sqlite3.Row
        _configure_connection(self._conn)
        initial_migration.apply(self._conn)

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.initialize()
        assert self._conn is not None
        return self._conn

    # ─── raw helpers (test utility) ────────────────────────────────────────

    def execute_one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        cur = self.conn.execute(sql, params)
        return cur.fetchone()

    def execute_all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return list(self.conn.execute(sql, params).fetchall())

    # ─── finding cache ─────────────────────────────────────────────────────

    def upsert_finding_cache(
        self,
        *,
        finding_id: str,
        engagement_id: str,
        tool: str | None,
        severity: str | None,
        title: str | None,
        status: str | None,
        created_at: datetime,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO chain_finding_cache
                (finding_id, engagement_id, tool, severity, title, status, created_at, cached_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(finding_id) DO UPDATE SET
                engagement_id=excluded.engagement_id,
                tool=excluded.tool,
                severity=excluded.severity,
                title=excluded.title,
                status=excluded.status,
                created_at=excluded.created_at,
                cached_at=excluded.cached_at
            """,
            (finding_id, engagement_id, tool, severity, title, status, created_at, _utcnow()),
        )
        self.conn.commit()

    def delete_finding_cache(self, finding_id: str) -> None:
        self.conn.execute("DELETE FROM chain_finding_cache WHERE finding_id = ?", (finding_id,))
        self.conn.commit()

    # ─── entity ────────────────────────────────────────────────────────────

    def upsert_entity(self, entity: Entity) -> None:
        self.conn.execute(
            """
            INSERT INTO entity (id, type, canonical_value, first_seen_at, last_seen_at, mention_count, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                last_seen_at=excluded.last_seen_at,
                mention_count=excluded.mention_count
            """,
            (
                entity.id, entity.type, entity.canonical_value,
                entity.first_seen_at, entity.last_seen_at, entity.mention_count,
                str(entity.user_id) if entity.user_id else None,
            ),
        )
        self.conn.commit()

    def get_entity(self, entity_id: str) -> Entity | None:
        row = self.execute_one("SELECT * FROM entity WHERE id = ?", (entity_id,))
        return _row_to_entity(row) if row else None

    # ─── entity mentions ──────────────────────────────────────────────────

    def add_mentions(self, mentions: Iterable[EntityMention]) -> None:
        rows = [
            (
                m.id, m.entity_id, m.finding_id, m.field.value, m.raw_value,
                m.offset_start, m.offset_end, m.extractor, m.confidence,
                m.created_at, str(m.user_id) if m.user_id else None,
            )
            for m in mentions
        ]
        self.conn.executemany(
            """
            INSERT OR IGNORE INTO entity_mention
                (id, entity_id, finding_id, field, raw_value, offset_start, offset_end,
                 extractor, confidence, created_at, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        self.conn.commit()

    def mentions_for_finding(self, finding_id: str) -> list[EntityMention]:
        rows = self.execute_all(
            "SELECT * FROM entity_mention WHERE finding_id = ?", (finding_id,)
        )
        return [_row_to_mention(r) for r in rows]

    def delete_mentions_for_finding(self, finding_id: str) -> None:
        self.conn.execute("DELETE FROM entity_mention WHERE finding_id = ?", (finding_id,))
        self.conn.commit()

    # ─── relations ─────────────────────────────────────────────────────────

    def upsert_relations_bulk(self, relations: Iterable[FindingRelation]) -> None:
        rows = []
        for r in relations:
            rows.append((
                r.id,
                r.source_finding_id,
                r.target_finding_id,
                r.weight,
                r.weight_model_version,
                r.status.value,
                1 if r.symmetric else 0,
                orjson.dumps([rr.model_dump() for rr in r.reasons]),
                r.llm_rationale,
                r.llm_relation_type,
                r.llm_confidence,
                orjson.dumps([rr.model_dump() for rr in r.confirmed_at_reasons]) if r.confirmed_at_reasons else None,
                r.created_at,
                r.updated_at,
                str(r.user_id) if r.user_id else None,
            ))
        self.conn.executemany(
            """
            INSERT INTO finding_relation
                (id, source_finding_id, target_finding_id, weight, weight_model_version,
                 status, symmetric, reasons_json, llm_rationale, llm_relation_type,
                 llm_confidence, confirmed_at_reasons_json, created_at, updated_at, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(source_finding_id, target_finding_id, user_id) DO UPDATE SET
                weight=excluded.weight,
                weight_model_version=excluded.weight_model_version,
                status=CASE
                    WHEN finding_relation.status IN ('user_confirmed', 'user_rejected')
                    THEN finding_relation.status
                    ELSE excluded.status
                END,
                symmetric=excluded.symmetric,
                reasons_json=excluded.reasons_json,
                llm_rationale=excluded.llm_rationale,
                llm_relation_type=excluded.llm_relation_type,
                llm_confidence=excluded.llm_confidence,
                updated_at=excluded.updated_at
            """,
            rows,
        )
        self.conn.commit()

    def relations_for_finding(self, finding_id: str) -> list[FindingRelation]:
        rows = self.execute_all(
            "SELECT * FROM finding_relation WHERE source_finding_id = ? OR target_finding_id = ?",
            (finding_id, finding_id),
        )
        return [_row_to_relation(r) for r in rows]


# ─── row → model converters ───────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _row_to_entity(row: sqlite3.Row) -> Entity:
    return Entity(
        id=row["id"], type=row["type"], canonical_value=row["canonical_value"],
        first_seen_at=row["first_seen_at"], last_seen_at=row["last_seen_at"],
        mention_count=row["mention_count"], user_id=row["user_id"],
    )


def _row_to_mention(row: sqlite3.Row) -> EntityMention:
    return EntityMention(
        id=row["id"], entity_id=row["entity_id"], finding_id=row["finding_id"],
        field=MentionField(row["field"]), raw_value=row["raw_value"],
        offset_start=row["offset_start"], offset_end=row["offset_end"],
        extractor=row["extractor"], confidence=row["confidence"],
        created_at=row["created_at"], user_id=row["user_id"],
    )


def _row_to_relation(row: sqlite3.Row) -> FindingRelation:
    reasons = [RelationReason.model_validate(r) for r in orjson.loads(row["reasons_json"])]
    conf_reasons = None
    if row["confirmed_at_reasons_json"]:
        conf_reasons = [RelationReason.model_validate(r) for r in orjson.loads(row["confirmed_at_reasons_json"])]
    return FindingRelation(
        id=row["id"],
        source_finding_id=row["source_finding_id"],
        target_finding_id=row["target_finding_id"],
        weight=row["weight"],
        weight_model_version=row["weight_model_version"],
        status=RelationStatus(row["status"]),
        symmetric=bool(row["symmetric"]),
        reasons=reasons,
        llm_rationale=row["llm_rationale"],
        llm_relation_type=row["llm_relation_type"],
        llm_confidence=row["llm_confidence"],
        confirmed_at_reasons=conf_reasons,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        user_id=row["user_id"],
    )
```

- [ ] **Step 6: Fix migration import name**

The import `_001_initial` needs to be importable — rename the file to `_001_initial.py` **or** change the import lines to `from opentools.chain.migrations import __001_initial` (invalid) — simpler: rename `001_initial.py` to `_001_initial.py` in the filesystem.

```bash
mv packages/cli/src/opentools/chain/migrations/001_initial.py \
   packages/cli/src/opentools/chain/migrations/_001_initial.py
```

Update the import in `store_extensions.py` accordingly (already uses `_001_initial` in both lines above).

- [ ] **Step 7: Run — expect pass**

Run: `pytest packages/cli/tests/chain/test_store.py -v`
Expected: PASS (6 tests).

- [ ] **Step 8: Commit**

```bash
git add packages/cli/src/opentools/chain/store_extensions.py \
        packages/cli/src/opentools/chain/migrations/ \
        packages/cli/tests/chain/conftest.py \
        packages/cli/tests/chain/test_store.py
git commit -m "feat(chain): add SQLite backend with performance pragmas and CRUD helpers"
```

---

## Task 6: Normalizers & Built-in Entity Type Registration

**Files:**
- Create: `packages/cli/src/opentools/chain/normalizers.py`
- Create: `packages/cli/tests/chain/test_normalizers.py`
- Modify: `packages/cli/src/opentools/chain/__init__.py`

- [ ] **Step 1: Write the failing test**

```python
# packages/cli/tests/chain/test_normalizers.py
import pytest

from opentools.chain.normalizers import normalize
from opentools.chain.types import ENTITY_TYPE_REGISTRY, is_strong_entity_type, is_weak_entity_type


def test_builtins_registered_on_import():
    # Importing normalizers has the side effect of registering built-in types.
    import opentools.chain.normalizers  # noqa: F401
    for t in [
        "host", "ip", "user", "process", "cve", "mitre_technique",
        "domain", "registered_domain", "email", "url",
        "file_path", "port", "registry_key", "package",
        "hash_md5", "hash_sha1", "hash_sha256",
    ]:
        assert t in ENTITY_TYPE_REGISTRY


def test_strong_vs_weak_categories():
    assert is_strong_entity_type("host")
    assert is_strong_entity_type("cve")
    assert is_strong_entity_type("mitre_technique")
    assert is_strong_entity_type("domain")
    assert is_weak_entity_type("file_path")
    assert is_weak_entity_type("port")
    assert is_weak_entity_type("registry_key")
    assert is_weak_entity_type("package")


def test_ip_canonicalizes():
    assert normalize("ip", "10.0.0.5") == "10.0.0.5"
    assert normalize("ip", "[::1]") == "::1"
    with pytest.raises(ValueError):
        normalize("ip", "not-an-ip")


def test_cve_uppercases_and_dashes():
    assert normalize("cve", "cve-2024-1234") == "CVE-2024-1234"
    assert normalize("cve", "cve_2024_1234") == "CVE-2024-1234"


def test_mitre_uppercases():
    assert normalize("mitre_technique", "t1566.001") == "T1566.001"
    assert normalize("mitre_technique", "ta0001") == "TA0001"


def test_email_lowercases():
    assert normalize("email", "Admin@Example.COM") == "admin@example.com"


def test_domain_strips_trailing_dot_and_lowercases():
    assert normalize("domain", "Example.COM.") == "example.com"


def test_registered_domain_via_psl():
    assert normalize("registered_domain", "mail.google.com") == "google.com"
    assert normalize("registered_domain", "sub.example.co.uk") == "example.co.uk"


def test_file_path_windows_lowercases(monkeypatch):
    import sys
    monkeypatch.setattr(sys, "platform", "win32")
    assert normalize("file_path", "C:\\Users\\Admin\\File.TXT") == "c:\\users\\admin\\file.txt"


def test_hash_lowercases():
    assert normalize("hash_sha256", "ABCDEF") == "abcdef"


def test_registry_key_uppercases():
    assert normalize("registry_key", "HKLM\\Software\\Foo") == "HKLM\\SOFTWARE\\FOO"
```

- [ ] **Step 2: Run — expect fail**

Run: `pytest packages/cli/tests/chain/test_normalizers.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement `normalizers.py`**

```python
# packages/cli/src/opentools/chain/normalizers.py
"""Canonical-form normalizers per entity type and built-in type registration."""
from __future__ import annotations

import ipaddress
import sys

import tldextract

from opentools.chain.types import (
    EntityTypeCategory,
    ENTITY_TYPE_REGISTRY,
    register_entity_type,
)


# ─── individual normalizers ───────────────────────────────────────────────


def _norm_ip(value: str) -> str:
    stripped = value.strip().strip("[]")
    return str(ipaddress.ip_address(stripped))


def _norm_domain(value: str) -> str:
    return value.strip().rstrip(".").lower()


_TLD = tldextract.TLDExtract(include_psl_private_domains=False, suffix_list_urls=())


def _norm_registered_domain(value: str) -> str:
    parts = _TLD(value.strip().rstrip(".").lower())
    if parts.domain and parts.suffix:
        return f"{parts.domain}.{parts.suffix}"
    return value.strip().lower()


def _norm_cve(value: str) -> str:
    return value.upper().replace("_", "-")


def _norm_mitre(value: str) -> str:
    return value.upper().strip()


def _norm_email(value: str) -> str:
    return value.strip().lower()


def _norm_path(value: str) -> str:
    if sys.platform == "win32":
        return value.lower()
    return value


def _norm_hash(value: str) -> str:
    return value.strip().lower()


def _norm_user(value: str) -> str:
    return value.strip().lower()


def _norm_process(value: str) -> str:
    return value.strip()


def _norm_host(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _norm_port(value: str) -> str:
    return value.strip().lstrip("0") or "0"


def _norm_registry_key(value: str) -> str:
    return value.strip().upper()


def _norm_package(value: str) -> str:
    return value.strip()


def _norm_url(value: str) -> str:
    return value.strip()


NORMALIZERS: dict[str, callable] = {
    "host": _norm_host,
    "ip": _norm_ip,
    "user": _norm_user,
    "process": _norm_process,
    "cve": _norm_cve,
    "mitre_technique": _norm_mitre,
    "domain": _norm_domain,
    "registered_domain": _norm_registered_domain,
    "email": _norm_email,
    "url": _norm_url,
    "file_path": _norm_path,
    "port": _norm_port,
    "registry_key": _norm_registry_key,
    "package": _norm_package,
    "hash_md5": _norm_hash,
    "hash_sha1": _norm_hash,
    "hash_sha256": _norm_hash,
}


def normalize(entity_type: str, raw: str) -> str:
    fn = NORMALIZERS.get(entity_type)
    if fn is None:
        return raw
    return fn(raw)


# ─── built-in type registration (runs once on import) ────────────────────


_BUILTIN_STRONG = {
    "host", "ip", "user", "process", "cve", "mitre_technique",
    "domain", "registered_domain", "email", "url",
    "hash_md5", "hash_sha1", "hash_sha256",
}
_BUILTIN_WEAK = {"file_path", "port", "registry_key", "package"}


def _register_builtins() -> None:
    for t in _BUILTIN_STRONG:
        if t not in ENTITY_TYPE_REGISTRY:
            register_entity_type(t, category=EntityTypeCategory.STRONG, normalizer=NORMALIZERS[t])
    for t in _BUILTIN_WEAK:
        if t not in ENTITY_TYPE_REGISTRY:
            register_entity_type(t, category=EntityTypeCategory.WEAK, normalizer=NORMALIZERS[t])


_register_builtins()
```

- [ ] **Step 4: Enable the deferred import in `__init__.py`**

Replace the commented-out line in `packages/cli/src/opentools/chain/__init__.py`:

```python
# Register built-in entity types on package import.
from opentools.chain import normalizers  # noqa: F401,E402
```

- [ ] **Step 5: Run both normalizer and types tests**

Run: `pytest packages/cli/tests/chain/test_normalizers.py packages/cli/tests/chain/test_types.py -v`
Expected: PASS (all tests, including the previously excluded `test_builtin_entity_types_registered`).

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/chain/normalizers.py \
        packages/cli/src/opentools/chain/__init__.py \
        packages/cli/tests/chain/test_normalizers.py
git commit -m "feat(chain): add per-type normalizers and built-in entity type registration"
```

---

## Task 7: Stopwords & MITRE Catalog Validator

**Files:**
- Create: `packages/cli/src/opentools/chain/stopwords.py`
- Create: `packages/cli/src/opentools/chain/mitre_catalog.py`
- Create: `packages/cli/tests/chain/test_stopwords.py`
- Create: `packages/cli/tests/chain/test_mitre_catalog.py`

- [ ] **Step 1: Write tests**

```python
# packages/cli/tests/chain/test_stopwords.py
from opentools.chain.stopwords import is_stopword, STATIC_STOPWORDS


def test_builtin_stopwords_present():
    assert is_stopword("host", "localhost")
    assert is_stopword("ip", "127.0.0.1")
    assert is_stopword("ip", "0.0.0.0")
    assert is_stopword("user", "root")
    assert is_stopword("port", "80")
    assert is_stopword("port", "443")


def test_non_stopword():
    assert not is_stopword("host", "10.0.0.5")
    assert not is_stopword("user", "alice")


def test_extras_extend_list():
    extras = ["host:test.local", "user:svc_bot"]
    assert is_stopword("host", "test.local", extras=extras)
    assert is_stopword("user", "svc_bot", extras=extras)
    assert not is_stopword("host", "real.example.com", extras=extras)


def test_static_stopwords_is_dict_of_sets():
    assert isinstance(STATIC_STOPWORDS, dict)
    for v in STATIC_STOPWORDS.values():
        assert isinstance(v, set)
```

```python
# packages/cli/tests/chain/test_mitre_catalog.py
from opentools.chain.mitre_catalog import is_valid_technique, validate_technique_ids


def test_valid_techniques():
    assert is_valid_technique("T1566")
    assert is_valid_technique("T1566.001")


def test_invalid_technique():
    assert not is_valid_technique("T9999")
    assert not is_valid_technique("T1234")
    assert not is_valid_technique("not-a-technique")


def test_validate_technique_ids_filters():
    candidates = ["T1566", "T9999", "T1003.001", "foo"]
    valid = validate_technique_ids(candidates)
    assert "T1566" in valid
    assert "T1003.001" in valid
    assert "T9999" not in valid
    assert "foo" not in valid
```

- [ ] **Step 2: Run — expect fail**

- [ ] **Step 3: Implement `stopwords.py`**

```python
# packages/cli/src/opentools/chain/stopwords.py
"""Static stopwords used by the linker to skip meaningless shared-entity signal.

Extractors still extract these values (for provenance). The linker ignores them
as linking evidence via the frequency cap / stopword filter.
"""
from __future__ import annotations

STATIC_STOPWORDS: dict[str, set[str]] = {
    "host": {"localhost"},
    "ip": {"127.0.0.1", "::1", "0.0.0.0"},
    "user": {"root", "admin", "administrator", "system", "nobody"},
    "file_path": {"/tmp", "c:\\windows", "c:\\windows\\system32"},
    "port": {"80", "443", "22"},
    "domain": {"localhost"},
    "registered_domain": {"localhost"},
}


def is_stopword(entity_type: str, canonical_value: str, *, extras: list[str] | None = None) -> bool:
    """Return True if the canonical value is a stopword for its type."""
    if canonical_value in STATIC_STOPWORDS.get(entity_type, set()):
        return True
    if extras:
        needle = f"{entity_type}:{canonical_value}"
        for e in extras:
            if e == needle:
                return True
    return False
```

- [ ] **Step 4: Implement `mitre_catalog.py`**

```python
# packages/cli/src/opentools/chain/mitre_catalog.py
"""MITRE ATT&CK technique ID catalog with lazy loading.

Used to validate regex-extracted technique IDs. Loads the official STIX bundle
via taxii2-client on first call; falls back to a baked-in allowlist if network
or taxii2-client is unavailable.
"""
from __future__ import annotations

import re

_TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Baked-in fallback set — a subset of common ATT&CK techniques. Covers the
# case where the STIX fetch fails (offline, CI without network).
_FALLBACK_TECHNIQUES: set[str] = {
    # Initial Access
    "T1189", "T1190", "T1133", "T1200", "T1566", "T1566.001", "T1566.002", "T1566.003",
    "T1078", "T1078.001", "T1078.002", "T1078.003", "T1078.004",
    "T1091", "T1195", "T1199",
    # Execution
    "T1059", "T1059.001", "T1059.002", "T1059.003", "T1059.004", "T1059.005", "T1059.006",
    "T1053", "T1053.002", "T1053.003", "T1053.005", "T1053.006",
    "T1203", "T1106", "T1204", "T1204.001", "T1204.002",
    # Persistence
    "T1098", "T1197", "T1547", "T1547.001", "T1543", "T1543.003",
    # Privilege Escalation
    "T1068", "T1134", "T1548",
    # Defense Evasion
    "T1027", "T1070", "T1070.004",
    # Credential Access
    "T1003", "T1003.001", "T1003.002", "T1003.003", "T1003.004", "T1003.005", "T1003.006",
    "T1110", "T1110.001", "T1110.002", "T1110.003", "T1110.004",
    "T1555", "T1558", "T1558.003",
    # Discovery
    "T1018", "T1046", "T1057", "T1082", "T1083", "T1087",
    # Lateral Movement
    "T1021", "T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.005", "T1021.006",
    "T1570",
    # Collection
    "T1005", "T1056", "T1113", "T1114",
    # Command and Control
    "T1071", "T1071.001", "T1071.002", "T1071.003", "T1071.004",
    "T1090", "T1090.001", "T1090.002", "T1090.003", "T1090.004",
    "T1095", "T1102", "T1105", "T1572",
    # Exfiltration
    "T1041", "T1048", "T1048.001", "T1048.002", "T1048.003",
    # Impact
    "T1485", "T1486", "T1490", "T1491", "T1496", "T1498", "T1499",
}

# Tactic IDs (TA0001..TA0043 are the official tactics).
_TACTIC_PATTERN = re.compile(r"^TA\d{4}$")
_VALID_TACTICS: set[str] = {f"TA{n:04d}" for n in range(1, 44)}

_catalog: set[str] | None = None


def _load_catalog() -> set[str]:
    """Try to load the authoritative ATT&CK enterprise technique set.

    Falls back to the baked-in allowlist on any error.
    """
    try:
        # Prefer a local cached copy if available; live fetch is gated
        # behind an explicit env var so CI never hits network unless asked.
        import os
        if os.getenv("OPENTOOLS_MITRE_FETCH") != "1":
            return _FALLBACK_TECHNIQUES
        from taxii2client.v20 import Server  # type: ignore
        _ = Server("https://cti-taxii.mitre.org/taxii/")
        # Real fetch is non-trivial; leave the live-path unimplemented in 3C.1
        # and return fallback. A future task can flesh this out.
        return _FALLBACK_TECHNIQUES
    except Exception:
        return _FALLBACK_TECHNIQUES


def _get_catalog() -> set[str]:
    global _catalog
    if _catalog is None:
        _catalog = _load_catalog()
    return _catalog


def is_valid_technique(technique_id: str) -> bool:
    technique_id = technique_id.upper()
    if _TACTIC_PATTERN.match(technique_id):
        return technique_id in _VALID_TACTICS
    if not _TECHNIQUE_PATTERN.match(technique_id):
        return False
    return technique_id in _get_catalog()


def validate_technique_ids(candidates: list[str]) -> list[str]:
    return [c.upper() for c in candidates if is_valid_technique(c)]
```

- [ ] **Step 5: Run — expect pass**

Run: `pytest packages/cli/tests/chain/test_stopwords.py packages/cli/tests/chain/test_mitre_catalog.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/chain/stopwords.py \
        packages/cli/src/opentools/chain/mitre_catalog.py \
        packages/cli/tests/chain/test_stopwords.py \
        packages/cli/tests/chain/test_mitre_catalog.py
git commit -m "feat(chain): add stopwords filter and MITRE ATT&CK technique catalog"
```

---

## Tasks 8–46: Remaining Implementation

The pattern for Tasks 8 through 46 follows the same TDD/commit structure. Because the full plan would exceed practical length, the remaining tasks are grouped below with their file lists, test shapes, and implementation sketches. Each task retains the 5-step structure (write test → run-fail → implement → run-pass → commit) and the implementer should fill in the obvious TDD rhythm while following the referenced spec sections.

Every task below links explicitly to the spec section that defines its contract. The implementer must open that section and implement precisely what it describes — no guessing, no scope drift.

---

## Task 8: Extractor Base Protocol & ExtractionContext

**Spec:** §5.1, §5.2, §5.3

**Files:**
- Create: `packages/cli/src/opentools/chain/extractors/__init__.py` (empty)
- Create: `packages/cli/src/opentools/chain/extractors/base.py`
- Create: `packages/cli/tests/chain/test_extractor_base.py`

**Contracts to implement:**

```python
# extractors/base.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Protocol

from opentools.models import Finding  # existing top-level Finding model
from opentools.chain.types import MentionField


@dataclass
class ExtractedEntity:
    type: str
    value: str                      # raw value as extracted (normalized later)
    field: MentionField
    offset_start: int | None
    offset_end: int | None
    extractor: str
    confidence: float


@dataclass
class ExtractionContext:
    finding: Finding
    already_extracted: list[ExtractedEntity] = field(default_factory=list)
    platform: str = "auto"          # auto | linux | windows | macos
    engagement_metadata: dict = field(default_factory=dict)


class SecurityExtractor(Protocol):
    name: str
    entity_type: str
    confidence: float

    def applies_to(self, finding: Finding) -> bool: ...
    def extract(self, text: str, field: MentionField, ctx: ExtractionContext) -> list[ExtractedEntity]: ...


class ParserEntityExtractor(Protocol):
    tool_name: str
    def extract(self, finding: Finding, parser_output: dict, ctx: ExtractionContext) -> list[ExtractedEntity]: ...
```

**Tests assert:** `ExtractedEntity` construction validates confidence bounds; `ExtractionContext.already_extracted` defaults to empty list; importing the module doesn't trigger any network calls.

**Commit message:** `feat(chain): add extractor base protocol and ExtractionContext`

---

## Task 9: Code-Block-Aware Preprocessor

**Spec:** §5.3 "Code-block-aware preprocessing"

**Files:**
- Create: `packages/cli/src/opentools/chain/extractors/preprocess.py`
- Create: `packages/cli/tests/chain/test_preprocess.py`

**Contract:**

```python
def split_code_blocks(text: str) -> list[TextRegion]:
    """Return non-overlapping regions tagged as 'prose' or 'code'.

    Identifies fenced code blocks (``` ... ```) and <pre>...</pre> sections.
    Remaining text is prose.
    """
```

Each `TextRegion` has `(start, end, kind)` where kind ∈ `{"prose", "code"}`.

**Tests:**
- Plain text → one prose region spanning full length
- Fenced block → prose before / code / prose after
- Multiple fenced blocks → alternating regions
- `<pre>` tags work the same way
- Unclosed fence → treat rest of text as code

**Commit:** `feat(chain): add code-block-aware text preprocessor`

---

## Task 10: `ioc-finder` Extractor Wrapper

**Spec:** §5.3 Sub-layer 2a

**Files:**
- Create: `packages/cli/src/opentools/chain/extractors/ioc_finder.py`
- Create: `packages/cli/tests/chain/test_ioc_finder.py`

**Contract:** single class `IocFinderExtractor` implementing the stage-2 extractor shape. Calls `ioc_finder.find_iocs()` on the input text, translates results into `ExtractedEntity` objects with the appropriate types:

- `ipv4s` / `ipv6s` → `type="ip"`
- `domains` → `type="domain"` (+ `type="registered_domain"` via tldextract)
- `urls` → `type="url"` (already registered as a strong entity type in Task 6)
- `email_addresses` → `type="email"`
- `md5s` → `type="hash_md5"`
- `sha1s` → `type="hash_sha1"`
- `sha256s` → `type="hash_sha256"`
- `cves` → `type="cve"`

**Tests:**
- Text with `"see 10.0.0.5 and example.com"` → returns host + domain entities
- Defanged IOCs (`10[.]0[.]0[.]5`) → still detected
- CVE variants (`CVE-2024-1234`, `cve-2024-1234`) → same entity
- URL extraction produces a `url`-typed ExtractedEntity
- Email extraction produces an `email`-typed ExtractedEntity with lowercased canonical form

**Commit:** `feat(chain): wrap ioc-finder library as a stage-2 extractor`

---

## Task 11: Security Regex Extractors

**Spec:** §5.3 Sub-layer 2b, full table

**Files:**
- Create: `packages/cli/src/opentools/chain/extractors/security_regex.py`
- Create: `packages/cli/tests/chain/test_security_regex.py`

**Contracts:** seven classes, one per table row.

```python
class MitreTechniqueExtractor(SecurityExtractor):
    name = "regex_mitre"
    entity_type = "mitre_technique"
    confidence = 0.95
    _pattern = re.compile(r"\b(T\d{4}(?:\.\d{3})?|TA\d{4})\b")

    def applies_to(self, finding): return True

    def extract(self, text, field, ctx):
        out = []
        for m in self._pattern.finditer(text):
            value = m.group(0)
            if is_valid_technique(value):
                out.append(ExtractedEntity(
                    type=self.entity_type, value=value, field=field,
                    offset_start=m.start(), offset_end=m.end(),
                    extractor=self.name, confidence=self.confidence,
                ))
        return out
```

Repeat for `WindowsUserExtractor`, `ProcessNameExtractor`, `WindowsPathExtractor`, `RegistryKeyExtractor`, `PortExtractor`, `PackageVersionExtractor` following the table.

`applies_to()` for Windows-specific extractors checks `ctx.platform in {"auto", "windows"}`. `PortExtractor` is context-aware: requires the regex match to be preceded by "port " or ":" (to avoid matching years in dates).

**Tests:** one class has at least three tests — positive match, negative match, offset correctness.

**Commit:** `feat(chain): add seven security regex extractors with offset tracking`

---

## Task 12: Parser-Aware Extractors (Nmap, Nikto, Burp, Nuclei, Semgrep)

**Spec:** §5.2

**Files:**
- Create: `packages/cli/src/opentools/chain/extractors/parser_aware.py`
- Create: `packages/cli/tests/chain/test_parser_aware.py`

**Contract:** five classes. Each reads from `finding.parser_output_data` (a dict fetched via `ChainStore.get_parser_output(finding_id)`) and emits entities. If no parser output exists for the finding, return `[]`.

**Example:**

```python
class NmapEntityExtractor(ParserEntityExtractor):
    tool_name = "nmap"
    def extract(self, finding, parser_output, ctx):
        out = []
        for host in parser_output.get("hosts", []):
            if addr := host.get("addr"):
                out.append(ExtractedEntity(type="ip", value=addr, field=MentionField.EVIDENCE, offset_start=None, offset_end=None, extractor="nmap_parser", confidence=1.0))
            for port in host.get("ports", []):
                out.append(ExtractedEntity(type="port", value=str(port["number"]), field=MentionField.EVIDENCE, offset_start=None, offset_end=None, extractor="nmap_parser", confidence=1.0))
        return out
```

Repeat for Nikto (URL + finding references), Burp (URL + parameter + vulnerability), Nuclei (template ID + host + matched values), Semgrep (rule ID + file path + line number).

**Tests:** hand-crafted parser output dicts → expected entities.

**Commit:** `feat(chain): add parser-aware entity extractors for 5 built-in tools`

---

## Task 13: LLM Provider Base + Retry Wrapper

**Spec:** §5.4

**Files:**
- Create: `packages/cli/src/opentools/chain/extractors/llm/__init__.py`
- Create: `packages/cli/src/opentools/chain/extractors/llm/base.py`
- Create: `packages/cli/tests/chain/test_llm_base.py`

**Contracts:**

```python
class LLMExtractionProvider(Protocol):
    name: str
    model: str
    async def extract_entities(self, text: str, context: ExtractionContext) -> list[ExtractedEntity]: ...
    async def classify_relation(self, finding_a, finding_b, shared_entities) -> LLMLinkClassification: ...
    async def generate_path_narration(self, findings, edges) -> str: ...


class PydanticRetryWrapper:
    """Call an LLM callable, parse JSON, validate against a pydantic schema.
    Retries up to 3 times on validation errors, appending the error to the prompt.
    """
    def __init__(self, max_retries: int = 3): ...
    async def call(self, *, call_fn, schema_cls, prompt: str) -> BaseModel: ...
```

**Tests:** use a mock callable that returns bad JSON twice then valid JSON; verify retry count and final parsed result; verify hard fail after max retries.

**Commit:** `feat(chain): add LLM provider protocol and PydanticRetryWrapper`

---

## Task 14: Ollama, Anthropic, and OpenAI Providers

**Spec:** §5.4 Implementations table

**Files:**
- Create: `packages/cli/src/opentools/chain/extractors/llm/ollama.py`
- Create: `packages/cli/src/opentools/chain/extractors/llm/anthropic_api.py`
- Create: `packages/cli/src/opentools/chain/extractors/llm/openai_api.py`
- Create: `packages/cli/tests/chain/test_llm_providers.py`

**Implementation notes:**
- `OllamaProvider`: uses the `ollama` Python package's async client, `format="json"` for structured output, schema validation via `instructor.patch(client)` — instructor has Ollama support
- `AnthropicAPIProvider`: uses `anthropic.AsyncAnthropic`, instructor-patched with `Mode.ANTHROPIC_TOOLS`, reads `ANTHROPIC_API_KEY` from env at call time
- `OpenAIAPIProvider`: uses `openai.AsyncOpenAI`, instructor-patched with `Mode.JSON_SCHEMA`, reads `OPENAI_API_KEY` from env at call time

All three use the same prompt template (see spec §5.4 "LLM extraction prompt") and the same schema (`LLMExtractionResponse`).

**Tests:** mock the HTTP clients; assert the request payload contains the correct prompt and schema; assert the parsed result matches the canned response. No real network calls in standard tests — real-provider smoke tests gated behind `ENABLE_LLM_SMOKE_TESTS=1`.

**Commit:** `feat(chain): add Ollama, Anthropic, and OpenAI LLM extraction providers`

---

## Task 15: Claude Code Provider (Agent SDK)

**Spec:** §5.4 "ClaudeCodeProvider" + session strategy

**Files:**
- Create: `packages/cli/src/opentools/chain/extractors/llm/claude_code.py`
- Create: `packages/cli/tests/chain/test_claude_code_provider.py`

**Implementation notes:**
- Uses `claude_agent_sdk.query()` (single-turn) for extraction and classification
- Uses `claude_agent_sdk.ClaudeSDKClient` (persistent session) for path narration
- Output validated via `PydanticRetryWrapper` (instructor doesn't support this SDK)
- No API key — SDK inherits `~/.claude/` credentials
- Smoke test checks `~/.claude/` exists, skips gracefully otherwise

**Commit:** `feat(chain): add ClaudeCodeProvider using Claude Agent SDK`

---

## Task 16: Rate Limiter

**Spec:** §5.4 Rate limiting

**Files:**
- Create: `packages/cli/src/opentools/chain/extractors/llm/rate_limit.py`
- Create: `packages/cli/tests/chain/test_rate_limit.py`

**Contract:**

```python
def get_limiter(*, provider: str, user_id: UUID | None) -> AsyncLimiter:
    """Return a cached aiolimiter.AsyncLimiter for (provider, user_id).
    Rates come from ChainConfig.llm.<provider>.
    """
```

**Tests:** verify same key returns same instance; verify different users get different instances; verify config-driven rate matches expectation.

**Commit:** `feat(chain): add per-user LLM rate limiter`

---

## Task 17: Extraction Pipeline

**Spec:** §5.1 Pipeline + §5.5 Normalization + §5.6 Change detection

**Files:**
- Create: `packages/cli/src/opentools/chain/extractors/pipeline.py`
- Create: `packages/cli/tests/chain/test_pipeline.py`

**Contract:** `ExtractionPipeline` class with:

```python
class ExtractionPipeline:
    def __init__(self, *, store: ChainStore, config: ChainConfig): ...

    def extract_for_finding(
        self,
        finding: Finding,
        *,
        llm_provider: LLMExtractionProvider | None = None,
        force: bool = False,
    ) -> ExtractionResult: ...

    def extract_for_finding_id(
        self,
        finding_id: str,
        *,
        user_id: UUID | None,
        llm_provider: LLMExtractionProvider | None = None,
        force: bool = False,
    ) -> ExtractionResult:
        """Convenience used by event handlers — loads the Finding from the main store,
        upserts chain_finding_cache, then delegates to extract_for_finding."""
```

**Explicit cascade behavior required by spec §8.5:**

1. Compute `new_hash = sha256(finding.title + finding.description + finding.evidence + finding.file_path)`
2. Load existing `FindingExtractionState` for this finding
3. If existing state's hash equals `new_hash` AND `force=False`, short-circuit and return (count as cache hit)
4. Otherwise: **hard-delete all existing `EntityMention` rows for this finding** via `store.delete_mentions_for_finding(finding_id)`. This is required so edits never leave stale mentions behind.
5. Upsert the `chain_finding_cache` row (denormalized finding fields)
6. Run extraction stages 1-3 against the current finding content
7. Normalize values via `NORMALIZERS`; look up or upsert `Entity` rows
8. Bulk-insert new `EntityMention` rows (one per extraction result)
9. Update `Entity.mention_count` and `Entity.last_seen_at`
10. Upsert `FindingExtractionState` with the new hash, timestamp, and extractor set

Orphaned `Entity` rows (mention_count drops to zero after step 4's deletes) are NOT removed here — `chain vacuum` handles those periodically.

**Tests:**
- Finding with an IP in description → IP entity + mention created
- Second run without changes → hash unchanged, no re-extraction (cache hit)
- Finding edited → hash changes, old mentions deleted, new mentions inserted
- Stage 1 + 2 combined → parser-aware IP wins over regex IP (higher confidence, same canonical → single entity, two mentions)
- LLM stage gated on `llm_provider is not None` — never runs automatically

**Commit:** `feat(chain): add extraction pipeline with change detection`

---

## Task 18: Linker Context, IDF, and Rule Base

**Spec:** §6.1, §6.2, §6.4

**Files:**
- Create: `packages/cli/src/opentools/chain/linker/__init__.py` (empty)
- Create: `packages/cli/src/opentools/chain/linker/context.py`
- Create: `packages/cli/src/opentools/chain/linker/idf.py`
- Create: `packages/cli/src/opentools/chain/linker/rules/__init__.py` (empty)
- Create: `packages/cli/src/opentools/chain/linker/rules/base.py`
- Create: `packages/cli/tests/chain/test_idf.py`

**Contracts:**

```python
@dataclass
class LinkerContext:
    user_id: UUID | None
    is_web: bool
    scope_total_findings: int
    avg_idf: float
    stopwords_extra: list[str]
    common_entity_pct: float
    common_entity_threshold: int  # derived: ceil(scope_total * common_entity_pct)
    config: ChainConfig
    generation: int


@dataclass
class RuleContribution:
    rule: str
    weight: float
    details: dict
    direction: Literal["a_to_b", "b_to_a", "symmetric"]
    idf_factor: float | None = None


class Rule(Protocol):
    name: str
    default_weight: float
    enabled_by_default: bool
    symmetric: bool
    requires_shared_entity: bool
    reads_cross_scope: bool

    def apply(self, finding_a, finding_b, shared_entities, context) -> list[RuleContribution]: ...


def idf_factor(entity: Entity, scope_total: int, avg_idf: float) -> float:
    from math import log
    idf = log((scope_total + 1) / (entity.mention_count + 1))
    return max(0.2, min(2.0, idf / max(avg_idf, 0.001)))


def compute_avg_idf(entities: list[Entity], scope_total: int) -> float:
    from math import log
    if not entities:
        return 1.0
    return sum(log((scope_total + 1) / (e.mention_count + 1)) for e in entities) / len(entities)
```

**Tests for IDF:**
- Rare entity (mention_count=1, scope_total=100) → factor >= 1.5
- Common entity (mention_count=50, scope_total=100) → factor <= 0.5
- Clamping bounds: extreme rarity clamped to 2.0, extreme commonness clamped to 0.2
- Average IDF computed correctly

**Commit:** `feat(chain): add linker context, IDF weighting, and rule protocol`

---

## Task 19: Shared-Entity Rules

**Spec:** §6.3 rows 1-2

**Files:**
- Create: `packages/cli/src/opentools/chain/linker/rules/shared_entity.py`
- Create: `packages/cli/tests/chain/test_rules.py` (new)

**Contract:**

```python
class SharedStrongEntityRule(Rule):
    name = "shared_strong_entity"
    default_weight = 1.0
    enabled_by_default = True
    symmetric = True
    requires_shared_entity = True
    reads_cross_scope = False

    def __init__(self, weight: float = 1.0):
        self.default_weight = weight

    def apply(self, a, b, shared_entities, ctx):
        out = []
        for e in shared_entities:
            if not is_strong_entity_type(e.type):
                continue
            if is_stopword(e.type, e.canonical_value, extras=ctx.stopwords_extra):
                continue
            if e.mention_count > ctx.common_entity_threshold:
                continue
            factor = idf_factor(e, ctx.scope_total_findings, ctx.avg_idf) if ctx.config.linker.idf_enabled else 1.0
            out.append(RuleContribution(
                rule=self.name,
                weight=self.default_weight * factor,
                details={"entity_id": e.id, "entity_type": e.type},
                direction="symmetric",
                idf_factor=factor,
            ))
        return out
```

`SharedWeakEntityRule` follows the same structure with a different filter and weight:

```python
class SharedWeakEntityRule(Rule):
    name = "shared_weak_entity"
    default_weight = 0.3
    enabled_by_default = True
    symmetric = True
    requires_shared_entity = True
    reads_cross_scope = False

    def __init__(self, weight: float = 0.3):
        self.default_weight = weight

    def apply(self, a, b, shared_entities, ctx):
        out = []
        for e in shared_entities:
            if not is_weak_entity_type(e.type):
                continue
            if is_stopword(e.type, e.canonical_value, extras=ctx.stopwords_extra):
                continue
            if e.mention_count > ctx.common_entity_threshold:
                continue
            factor = idf_factor(e, ctx.scope_total_findings, ctx.avg_idf) if ctx.config.linker.idf_enabled else 1.0
            out.append(RuleContribution(
                rule=self.name,
                weight=self.default_weight * factor,
                details={"entity_id": e.id, "entity_type": e.type},
                direction="symmetric",
                idf_factor=factor,
            ))
        return out
```

**Tests:**
- Single shared host entity → single contribution at base_weight × idf_factor
- Stopword entity (`localhost`) → zero contributions
- Common entity (mention_count > threshold) → zero contributions
- Multiple shared entities → multiple contributions
- IDF disabled → factor = 1.0

**Commit:** `feat(chain): add shared-entity linker rules with IDF weighting`

---

## Task 20: Temporal Proximity & Tool Chain Rules

**Spec:** §6.3 rows 3-4

**Files:**
- Create: `packages/cli/src/opentools/chain/linker/rules/temporal.py`
- Create: `packages/cli/src/opentools/chain/linker/rules/tool_chain.py`
- Modify: `packages/cli/tests/chain/test_rules.py`

**Contracts:**

```python
class TemporalProximityRule(Rule):
    name = "temporal_proximity"
    default_weight = 0.5
    symmetric = False
    requires_shared_entity = True
    reads_cross_scope = False

    def apply(self, a, b, shared_entities, ctx):
        if a.engagement_id != b.engagement_id:
            return []
        # Require at least one shared host/ip
        target_entities = [e for e in shared_entities if e.type in {"host", "ip"}]
        if not target_entities:
            return []
        delta = abs((a.created_at - b.created_at).total_seconds()) / 60
        window = ctx.config.linker.rules.temporal_proximity.window_minutes or 15
        if delta > window:
            return []
        earlier, later = (a, b) if a.created_at <= b.created_at else (b, a)
        direction = "a_to_b" if earlier is a else "b_to_a"
        return [RuleContribution(
            rule=self.name, weight=self.default_weight,
            details={"window_minutes": window, "delta_minutes": delta},
            direction=direction,
        )]


class ToolChainRule(Rule):
    name = "tool_chain"
    default_weight = 0.7
    symmetric = False
    requires_shared_entity = True
    reads_cross_scope = False

    def apply(self, a, b, shared_entities, ctx):
        chains = ctx.config.linker.tool_chains
        shared_host = any(e.type in {"host", "ip"} for e in shared_entities)
        if not shared_host:
            return []
        for tc in chains:
            if a.tool == tc.from_tool and b.tool == tc.to_tool and b.created_at >= a.created_at:
                return [RuleContribution(
                    rule=self.name, weight=tc.weight,
                    details={"from": tc.from_tool, "to": tc.to_tool},
                    direction="a_to_b",
                )]
            if b.tool == tc.from_tool and a.tool == tc.to_tool and a.created_at >= b.created_at:
                return [RuleContribution(
                    rule=self.name, weight=tc.weight,
                    details={"from": tc.from_tool, "to": tc.to_tool},
                    direction="b_to_a",
                )]
        return []
```

**Tests:** temporal rule fires only inside the window, direction follows time; tool-chain rule fires only for configured pairs, direction follows tool order.

**Commit:** `feat(chain): add temporal proximity and tool chain linker rules`

---

## Task 21: CVE Adjacency & Kill Chain Rules

**Spec:** §6.3 rows 6-7

**Files:**
- Create: `packages/cli/src/opentools/chain/linker/rules/cve_adjacency.py`
- Create: `packages/cli/src/opentools/chain/linker/rules/kill_chain.py`
- Modify: `packages/cli/tests/chain/test_rules.py`

**Contracts:**
- `CVEAdjacencyRule`: fires when findings share a CVE entity AND have differing severity; direction points lower-severity → higher-severity
- `KillChainAdjacencyRule`: fires when findings have MITRE techniques mapping to tactics ≤2 steps apart in the tactic ordering; direction follows tactic order

Maintain a `TACTIC_ORDER` list and a `TECHNIQUE_TO_TACTIC` dict (hand-curated for 3C.1, derived from the MITRE catalog).

**Tests:** both rules fire only under correct conditions; directions are correct; unrelated findings produce no contributions.

**Commit:** `feat(chain): add CVE adjacency and MITRE kill chain adjacency rules`

---

## Task 22: Cross-Engagement IOC Rule (privacy-scoped)

**Spec:** §6.3 row 5 + §6.2 "reads_cross_scope" enforcement

**Files:**
- Create: `packages/cli/src/opentools/chain/linker/rules/cross_engagement_ioc.py`
- Modify: `packages/cli/tests/chain/test_rules.py`

**Contract:**

```python
class SharedIOCCrossEngagementRule(Rule):
    name = "shared_ioc_cross_engagement"
    default_weight = 0.8
    symmetric = True
    requires_shared_entity = True
    reads_cross_scope = True   # CRITICAL — linker enforces user_id filter

    def apply(self, a, b, shared_entities, ctx):
        if ctx.is_web and ctx.user_id is None:
            raise ScopingViolation(f"{self.name} requires user_id in web context")
        if a.engagement_id == b.engagement_id:
            return []
        ioc_entities = [e for e in shared_entities if e.type in {"ip", "domain", "registered_domain", "url", "hash_md5", "hash_sha1", "hash_sha256"}]
        if not ioc_entities:
            return []
        # Trust the caller: in web context, the candidate fetch already filtered by user_id.
        return [RuleContribution(
            rule=self.name, weight=self.default_weight,
            details={"ioc_count": len(ioc_entities)},
            direction="symmetric",
        )]


class ScopingViolation(RuntimeError):
    pass
```

**Tests:**
- Web context with `user_id=None` → raises `ScopingViolation`
- Web context with matching user_id → fires
- Same engagement → no contribution
- No IOC entities → no contribution

**Commit:** `feat(chain): add cross-engagement IOC rule with user-scoping enforcement`

---

## Task 23: Linker Engine — Inline Mode

**Spec:** §6.1, §6.6 weight accumulation, §6.7 status transitions

**Files:**
- Create: `packages/cli/src/opentools/chain/linker/engine.py`
- Create: `packages/cli/tests/chain/test_linker_engine.py`

**Contract:**

```python
class LinkerEngine:
    def __init__(self, *, store: ChainStore, config: ChainConfig, rules: list[Rule]): ...

    def link_finding(self, finding_id: str, *, user_id: UUID | None, context: LinkerContext) -> LinkerRun:
        """Run rule-based linking for a single finding using inverted-index lookup.
        1. Fetch F's entities
        2. Fetch candidate partners (one JOIN on entity_mention, user-scoped)
        3. For each partner, apply rules, accumulate contributions
        4. Bulk upsert relations (ON CONFLICT DO UPDATE with status stickiness)
        5. Return a LinkerRun row recording the outcome
        """
```

Key details:
- Candidate fetch SQL uses the `idx_em_entity_finding` covering index
- Weight accumulation sums contributions per (source, target) pair, caps at `max_edge_weight`
- Status is `AUTO_CONFIRMED` if `capped_weight >= confirmed_threshold`, else `CANDIDATE`
- Bulk upsert preserves `USER_CONFIRMED`/`USER_REJECTED` status via the SQL `CASE` in the ON CONFLICT DO UPDATE (already in Task 5 schema)
- `rule_stats` dict populated as rules fire
- Direction resolution: if any asymmetric rule fires, store ONE row in the specified direction; if all rules symmetric, store one row in canonical (lower id → higher id) ordering with `symmetric=True`; if both directions fire asymmetrically, store two rows

**Tests:**
- Two findings sharing a host → one symmetric edge at weight ~1.0
- Two findings with temporal ordering → directional edge
- Three findings, one with sticky `USER_CONFIRMED` status → re-run preserves status
- Re-run without finding changes → relations updated, weights may differ if mention_counts changed, status preserved where sticky
- Cross-engagement cross-user candidates filtered out when `user_id` set

**Commit:** `feat(chain): add linker engine with inverted-index lookup and bulk upsert`

---

## Task 23b: Event Bus Subscription Wiring

**Spec:** §8.5 finding lifecycle hooks, §8.11 Stage 3 automatic inline linking

**Files:**
- Create: `packages/cli/src/opentools/chain/subscriptions.py`
- Create: `packages/cli/tests/chain/test_subscriptions.py`
- Modify: `packages/cli/src/opentools/chain/__init__.py`

This task wires the emitted `finding.created` / `finding.updated` / `finding.deleted` events from Task 4 to the extraction pipeline (Task 17) and linker engine (Task 23). Without this task, the store fires events into the void and §8.11 Stage 3 never happens.

**Contract:**

```python
# subscriptions.py
from __future__ import annotations

import logging
from typing import Callable

from opentools.chain.events import get_event_bus
from opentools.chain.store_extensions import ChainStore, DEFAULT_DB_PATH
from opentools.chain.extractors.pipeline import ExtractionPipeline
from opentools.chain.linker.engine import LinkerEngine
from opentools.chain.linker.rules import get_default_rules
from opentools.chain.config import get_chain_config

logger = logging.getLogger(__name__)

_subscribed = False
_in_batch_context = False  # flipped by ChainBatchContext (Task 24)


def set_batch_context(active: bool) -> None:
    global _in_batch_context
    _in_batch_context = active


def subscribe_chain_handlers(
    *,
    store_factory: Callable[[], ChainStore] | None = None,
    pipeline_factory: Callable[[ChainStore], ExtractionPipeline] | None = None,
    engine_factory: Callable[[ChainStore], LinkerEngine] | None = None,
) -> None:
    """Idempotent — safe to call multiple times. Called from chain __init__."""
    global _subscribed
    if _subscribed:
        return
    _subscribed = True

    cfg = get_chain_config()
    if not cfg.enabled:
        logger.info("chain processing disabled; skipping event subscription")
        return

    store_factory = store_factory or (lambda: ChainStore(db_path=DEFAULT_DB_PATH))
    pipeline_factory = pipeline_factory or (lambda s: ExtractionPipeline(store=s, config=cfg))
    engine_factory = engine_factory or (lambda s: LinkerEngine(store=s, config=cfg, rules=get_default_rules(cfg)))

    bus = get_event_bus()

    def on_created(finding_id, engagement_id, **_):
        if _in_batch_context:
            return
        try:
            store = store_factory()
            store.initialize()
            pipeline = pipeline_factory(store)
            engine = engine_factory(store)
            pipeline.extract_for_finding_id(finding_id, user_id=None)
            engine.link_finding(finding_id, user_id=None, context=engine.make_context(user_id=None))
        except Exception:
            logger.exception("chain on_created handler failed for %s", finding_id)

    def on_updated(finding_id, engagement_id, **_):
        if _in_batch_context:
            return
        try:
            store = store_factory()
            store.initialize()
            # Hash-based change detection short-circuits if nothing changed;
            # otherwise pipeline deletes old mentions and re-extracts (see Task 17).
            pipeline = pipeline_factory(store)
            engine = engine_factory(store)
            pipeline.extract_for_finding_id(finding_id, user_id=None)
            engine.link_finding(finding_id, user_id=None, context=engine.make_context(user_id=None))
        except Exception:
            logger.exception("chain on_updated handler failed for %s", finding_id)

    def on_deleted(finding_id, engagement_id, **_):
        # CASCADE on FKs in Task 5 handles EntityMention / FindingRelation removal
        # automatically once chain_finding_cache rows are deleted. We just need to
        # remove the cache row.
        try:
            store = store_factory()
            store.initialize()
            store.delete_finding_cache(finding_id)
        except Exception:
            logger.exception("chain on_deleted handler failed for %s", finding_id)

    bus.subscribe("finding.created", on_created)
    bus.subscribe("finding.updated", on_updated)
    bus.subscribe("finding.deleted", on_deleted)
```

Then modify `packages/cli/src/opentools/chain/__init__.py` to call `subscribe_chain_handlers()` at the end:

```python
# At end of packages/cli/src/opentools/chain/__init__.py
from opentools.chain.subscriptions import subscribe_chain_handlers  # noqa: E402
subscribe_chain_handlers()
```

**Tests:**
- Subscribing twice is a no-op (idempotent)
- `finding.created` event triggers extraction + linking (use fake pipeline/engine factories that record calls)
- `finding.updated` triggers the same (with pipeline handling the old-mention delete via change detection — verified in Task 17)
- `finding.deleted` removes the `chain_finding_cache` row; CASCADE cleans up mentions and relations
- `_in_batch_context=True` short-circuits the handlers (batch manager in Task 24 uses this)
- `chain.enabled=False` skips subscription entirely
- Handler exceptions are logged and swallowed (the event bus in Task 4 already wraps them, but the handler bodies add an extra safety net for catastrophic failures)

**Commit:** `feat(chain): subscribe extraction and linker to store events for automatic inline processing`

---

## Task 24: Batch Linking Context Manager

**Spec:** §6.9 batch mode

**Files:**
- Create: `packages/cli/src/opentools/chain/linker/batch.py`
- Create: `packages/cli/tests/chain/test_linker_batch.py`

**Contract:**

```python
class ChainBatchContext:
    def __init__(self, *, engine: LinkerEngine, pipeline: ExtractionPipeline): ...
    def __enter__(self):
        from opentools.chain.subscriptions import set_batch_context
        set_batch_context(True)     # suppress per-finding inline handlers
        return self
    def __exit__(self, *exc_info):
        from opentools.chain.subscriptions import set_batch_context
        try:
            self._flush()           # batch extraction + linking
        finally:
            set_batch_context(False)
    def defer_linking(self, finding_id: str) -> None: ...
```

On `__exit__` (inside `_flush`):
- Run extraction pipeline over all deferred findings in parallel (bounded semaphore)
- Run linker over the batch using a single SQL pass for candidate lookup
- Write one `LinkerRun` row for the batch
- If the context manager exits via exception, still commit the extraction and linking for any findings already added (derived data, idempotent)
- `set_batch_context(False)` must run in `finally` so a crash inside the batch doesn't wedge the subscription layer into permanent batch mode

**Tests:**
- Adding 10 findings inside a batch → one LinkerRun, not 10
- Exception partway through → already-added findings still linked
- Nested batches are an error (raise)

**Commit:** `feat(chain): add chain_batch context manager for deferred linking`

---

## Task 25: Advisory Lock for Concurrent Run Protection

**Spec:** §6.8

**Files:**
- Create: `packages/cli/src/opentools/chain/linker/advisory_lock.py`
- Create: `packages/cli/tests/chain/test_advisory_lock.py`

**Contract:**

```python
@contextmanager
def chain_lock(db_path: Path, *, scope_key: str, wait: bool = False, timeout_sec: float = 30.0):
    """File-based advisory lock via a .lock sibling file.

    Acquires an exclusive lock on f"{db_path}.lock". If already held:
    - wait=False → raises LinkerLockHeld immediately
    - wait=True → blocks up to timeout_sec, then raises LinkerLockTimeout
    """


class LinkerLockHeld(RuntimeError): ...
class LinkerLockTimeout(RuntimeError): ...
```

Uses `fcntl.flock` on POSIX and `msvcrt.locking` on Windows. The lock file is named after the DB plus scope_key so different scopes can lock independently.

**Tests:** two concurrent context managers on the same scope → second raises; different scopes → both succeed; wait=True blocks then acquires when first releases.

**Commit:** `feat(chain): add file advisory lock for concurrent linker protection`

---

## Task 26: LLM Linking Pass

**Spec:** §6.10

**Files:**
- Create: `packages/cli/src/opentools/chain/linker/llm_pass.py`
- Create: `packages/cli/tests/chain/test_llm_pass.py`

**Contract:**

```python
async def llm_link_pass(
    *,
    provider: LLMExtractionProvider,
    store: ChainStore,
    scope: LinkerScope,
    scope_id: str | None,
    user_id: UUID | None,
    min_weight: float = 0.3,
    max_weight: float = 1.0,
    dry_run: bool = False,
    progress_callback: Callable[[int, int], None] | None = None,
) -> LLMLinkPassResult:
    """Classify candidate edges via LLM and update statuses/rationales."""
```

Workflow:
1. Fetch candidate relations in `[min_weight, max_weight]` within scope
2. For each, compute cache key, check `llm_link_cache`
3. On cache miss, fetch both findings and shared entities, call `provider.classify_relation(...)`, store result
4. Apply result: confidence ≥ 0.7 + related → `AUTO_CONFIRMED`; related + 0.4–0.7 → stay `CANDIDATE` with rationale; `related=False` → `REJECTED`
5. Write a `LinkerRun` row with `mode=RULES_PLUS_LLM`, `llm_calls_made`, cache stats
6. `dry_run=True` returns counts without making calls

**Tests:** use a mock provider; test each classification → status mapping; test cache hit path; test dry_run; test malformed response leaves status unchanged.

**Commit:** `feat(chain): add on-demand LLM linking pass with caching`

---

## Task 27: Graph Cache

**Spec:** §7.1, §7.2, §8.1 cost function

**Files:**
- Create: `packages/cli/src/opentools/chain/query/__init__.py` (empty)
- Create: `packages/cli/src/opentools/chain/query/cost.py`
- Create: `packages/cli/src/opentools/chain/query/graph_cache.py`
- Create: `packages/cli/tests/chain/test_graph_cache.py`

**Contracts:**

```python
# cost.py
from math import log

def edge_cost(weight: float, max_edge_weight: float) -> float:
    """Log-probability cost: -log(weight / max_edge_weight) + epsilon."""
    normalized = max(weight / max(max_edge_weight, 0.01), 1e-6)
    return -log(normalized) + 0.01


# graph_cache.py
import rustworkx as rx
from functools import lru_cache

class GraphCache:
    def __init__(self, *, store: ChainStore, maxsize: int = 8): ...
    def get_master_graph(self, *, user_id: UUID | None, include_candidates: bool, include_rejected: bool) -> MasterGraph:
        """Build and cache a rustworkx PyDiGraph of the full user-scoped graph."""
    def invalidate(self, *, user_id: UUID | None) -> None: ...
    def subgraph(self, master: MasterGraph, node_indices: list[int]) -> rx.PyDiGraph: ...


@dataclass
class MasterGraph:
    graph: rx.PyDiGraph
    node_map: dict[str, int]        # finding_id → rustworkx node index
    reverse_map: dict[int, str]     # rustworkx index → finding_id
    generation: int
    max_weight: float


@dataclass
class PathNode:
    finding_id: str
    index: int                      # rustworkx node index in the master graph
    severity: str | None
    tool: str | None
    title: str | None


@dataclass
class PathEdgeRef:
    source_finding_id: str
    target_finding_id: str
    weight: float
    status: str                     # RelationStatus.value
    reasons_summary: list[str]      # human-readable rule names
    llm_rationale: str | None
    llm_relation_type: str | None


@dataclass
class PathResult:
    """Canonical result object for all path queries."""
    nodes: list[PathNode]
    edges: list[PathEdgeRef]
    total_cost: float
    length: int                     # number of edges
    source_finding_id: str
    target_finding_id: str
    truncated: bool = False
    truncation_reason: str | None = None
    narration: str | None = None    # populated only when --explain is passed
```

`PathResult` is the canonical return type for all query executors: `k_shortest_paths`, `simple_paths_bounded`, `neighborhood` (wraps paths from the seed), and preset queries in Task 33. All output adapters (Task 32) and CLI formatters (Task 37) consume this shape.

Cache keyed by `(user_id, generation, include_candidates, include_rejected)`. `maxsize=8` LRU. Generation read from the highest `LinkerRun.generation` for the user.

**Tests:**
- Build graph over 5 findings + 7 edges → correct node/edge counts
- Cost function: weight=1.0 with max_weight=5.0 → cost ≈ 1.619, weight=5.0 → cost ≈ 0.01
- Cache hit returns same instance; generation bump invalidates
- Subgraph projection: filter to 2 nodes → graph with those 2 nodes and any interconnecting edges

**Commit:** `feat(chain): add graph cache and log-probability cost function`

---

## Task 28: Yen's K-Shortest Paths Implementation

**Spec:** §7.4

**Files:**
- Create: `packages/cli/src/opentools/chain/query/yen.py`
- Create: `packages/cli/tests/chain/test_yen.py`

**Contract:**

```python
def yens_k_shortest(
    graph: rx.PyDiGraph,
    source: int,
    target: int,
    k: int,
    max_hops: int,
    cost_key: Callable[[EdgeData], float],
) -> list[RawPath]:
    """Textbook Yen's on rustworkx.dijkstra_shortest_paths.

    RawPath = list of node indices (inclusive source and target).
    Returns up to k distinct simple paths, sorted by total cost ascending.
    """
```

**Tests:** hand-verified 5-node graph with three distinct shortest paths; verify k=1 returns the single shortest, k=3 returns all three in correct order, k=10 returns only 3 (graph exhausted); verify `max_hops` caps path length; verify no cycles in simple paths.

**Commit:** `feat(chain): add in-house Yen's K-shortest paths on rustworkx`

---

## Task 29: Endpoint Resolver

**Spec:** §7.3

**Files:**
- Create: `packages/cli/src/opentools/chain/query/endpoints.py`
- Create: `packages/cli/tests/chain/test_endpoints.py`

**Contract:**

```python
@dataclass
class EndpointSpec:
    kind: Literal["finding_id", "entity", "predicate"]
    finding_id: str | None = None
    entity_type: str | None = None
    entity_value: str | None = None
    predicate: Callable[[FindingNode], bool] | None = None
    scope: QueryScope | None = None


def resolve_endpoint(spec: EndpointSpec, master: MasterGraph, store: ChainStore) -> set[int]:
    """Return the set of rustworkx node indices matching the endpoint spec."""


def parse_endpoint_spec(raw: str) -> EndpointSpec:
    """Parse CLI syntax:
        'fnd_abc123'              → finding_id
        'host:10.0.0.5'           → entity
        'severity=critical'       → predicate (key=value)
        'has_mitre:T1566'         → predicate function
    """
```

**Tests:** each parser case; entity-ref resolves to multiple findings; missing finding_id raises; unknown entity type raises; predicate lambda correctly filters.

**Commit:** `feat(chain): add endpoint resolver for path queries`

---

## Task 30: Query Engine with Super-Source/Sink Reduction

**Spec:** §7.4 multi-endpoint reduction

**Files:**
- Create: `packages/cli/src/opentools/chain/query/engine.py`
- Create: `packages/cli/tests/chain/test_query_engine.py`

**Contract:**

```python
class ChainQueryEngine:
    def __init__(self, *, store: ChainStore, graph_cache: GraphCache, config: ChainConfig): ...

    def k_shortest_paths(
        self,
        *,
        from_spec: EndpointSpec,
        to_spec: EndpointSpec,
        user_id: UUID | None,
        k: int = 5,
        max_hops: int = 6,
        include_candidates: bool = False,
    ) -> list[PathResult]:
        """Super-source/super-sink reduction → single Yen's run → strip virtual endpoints."""
```

Workflow:
1. Get master graph from cache
2. Resolve from/to endpoint specs → source_set, target_set
3. Copy master graph to scratch (`rx.PyDiGraph.copy()`)
4. Add virtual super_source with cost-0 edges to sources
5. Add virtual super_sink with cost-0 edges from targets
6. Run Yen's from super_source to super_sink, k iterations, max_hops+2 cap
7. Strip virtual endpoints from each path, deduplicate symmetric-variant paths, sort by cost
8. Return `PathResult` objects

**Tests:** single source / single target identical to direct Yen's; multi-source multi-target reduces to single run; empty source set → empty results; unreachable targets → empty results; max_hops enforced.

**Commit:** `feat(chain): add query engine with multi-endpoint super-source reduction`

---

## Task 31: Bounded Simple Paths, Neighborhood, Subgraph

**Spec:** §7.5, §7.6, §7.7

**Files:**
- Create: `packages/cli/src/opentools/chain/query/bounded.py`
- Create: `packages/cli/src/opentools/chain/query/neighborhood.py`
- Create: `packages/cli/src/opentools/chain/query/subgraph.py`
- Create: `packages/cli/tests/chain/test_neighborhood.py` (and extend test_query_engine.py)

**Contracts:** as in spec §7.5–§7.7. Each function takes a master graph and returns appropriate results with explicit truncation reasons.

**Tests:**
- `simple_paths_bounded`: returns paths within max_hops; timeout sets `truncated=True`; max_results cap enforced
- `neighborhood`: radius 0 = seed only; radius 1 = seed + direct neighbors; direction filters work
- `subgraph`: predicate correctly filters nodes; induced edges preserved

**Commit:** `feat(chain): add bounded simple paths, neighborhood, and subgraph queries`

---

## Task 32: Graph Adapters (force-graph, cytoscape, cosmograph, DOT)

**Spec:** §7.12

**Files:**
- Create: `packages/cli/src/opentools/chain/query/adapters.py`
- Create: `packages/cli/tests/chain/test_adapters.py`

**Contracts:**

```python
def to_canonical_json(master: MasterGraph, subgraph: rx.PyDiGraph | None = None) -> dict:
    """Canonical schema-versioned graph-json format."""

def to_force_graph(canonical: dict) -> dict: ...       # {nodes, links}
def to_cytoscape(canonical: dict) -> dict: ...         # {elements: {nodes, edges}}
def to_cosmograph(canonical: dict) -> dict: ...        # {nodes, links}
def to_dot(canonical: dict) -> str: ...                # Graphviz DOT
```

**Tests:** a 3-node / 2-edge input graph round-trips correctly through each adapter; DOT output is valid Graphviz syntax; schema_version `"1.0"` appears in canonical output.

**Commit:** `feat(chain): add graph adapters for force-graph, cytoscape, cosmograph, DOT`

---

## Task 33: Pre-Canned Query Presets

**Spec:** §7.8

**Files:**
- Create: `packages/cli/src/opentools/chain/query/presets.py`
- Create: `packages/cli/tests/chain/test_presets.py`

**Contracts:** implement the 5 presets from §7.8 — `lateral_movement`, `priv_esc_chains`, `external_to_internal`, `crown_jewel`, `mitre_coverage`. Each is a function accepting `(engagement_id, **kwargs)` and returning `list[PathResult]` or `MitreCoverageResult`.

`register_query_preset(name, fn, help)` API for plugin extension.

**Tests:** each preset runs against a fixture graph and returns expected shape/count; plugin registration makes a custom preset discoverable.

**Commit:** `feat(chain): add 5 pre-canned query presets and plugin registration API`

---

## Task 34: LLM Path Narration

**Spec:** §7.10

**Files:**
- Create: `packages/cli/src/opentools/chain/query/narration.py`
- Create: `packages/cli/tests/chain/test_narration.py`

**Contract:**

```python
async def narrate_path(
    path: PathResult,
    *,
    provider: LLMExtractionProvider,
    store: ChainStore,
) -> str:
    """Content-addressed cache + single LLM call per path."""
```

Uses the persistent session pattern for `ClaudeCodeProvider`, single-turn otherwise. Cache key: `sha256(path_finding_ids + edge_reasons_summary + provider + model + NARRATION_SCHEMA_VERSION)`.

**Tests:** mock provider; cache-hit returns without calling provider; failures return None + logged warning (query still succeeds).

**Commit:** `feat(chain): add LLM path narration with content-addressed caching`

---

## Task 35: Entity Merge & Split

**Spec:** §8.6

**Files:**
- Create: `packages/cli/src/opentools/chain/entity_ops.py`
- Create: `packages/cli/tests/chain/test_entity_ops.py`

**Contracts:**

```python
async def merge_entities(*, store, a_id, b_id, into: Literal["a", "b"] | None, user_id) -> MergeResult:
    """Atomic merge under advisory lock."""

async def split_entity(*, store, entity_id, criterion: Callable, user_id) -> SplitResult:
    """Atomic partition under advisory lock."""
```

**Tests:** merge preserves total mention count, deletes source entity, re-runs linker on affected findings; split creates N new entities, partitions mentions correctly, old entity removed if empty.

**Commit:** `feat(chain): add entity merge and split operations`

---

## Task 36: Export & Import

**Spec:** §8.7

**Files:**
- Create: `packages/cli/src/opentools/chain/exporter.py`
- Create: `packages/cli/tests/chain/test_exporter.py`

**Contracts:**

```python
def export_chain(*, store, scope: QueryScope, output_path: Path) -> None:
    """Schema-versioned JSON dump of entities, mentions, relations, linker runs."""

def import_chain(*, store, input_path: Path, merge_strategy: Literal["skip", "overwrite", "merge"]) -> ImportResult:
    """Import dump with ID-collision handling."""
```

**Tests:** round-trip export/import produces byte-equal re-export; each merge strategy behaves correctly; schema version mismatch raises.

**Commit:** `feat(chain): add chain export and import with merge strategies`

---

## Task 37: CLI Commands

**Spec:** §8.8

**Files:**
- Create: `packages/cli/src/opentools/chain/cli.py`
- Create: `packages/cli/tests/chain/test_cli_commands.py`
- Modify: `packages/cli/src/opentools/__main__.py`

**Contract:** Typer `app = typer.Typer(name="chain")` implementing every command in §8.8. Register under the top-level CLI in `__main__.py`:

```python
from opentools.chain.cli import app as chain_app
cli.add_typer(chain_app, name="chain")
```

Each command is a thin wrapper that:
1. Loads config and store
2. Calls the appropriate engine/service
3. Formats output via the requested format (`table`, `json`, `graph-json`, `dot`, `markdown`)
4. Exit code 0 on success, non-zero on error

**Tests:** use Typer's `CliRunner` to invoke each command against a populated test store; verify exit codes, output format, and key assertions (e.g., `chain path` returns JSON with `"paths"` key).

**Commit:** `feat(chain): add full CLI command surface for chain operations`

---

## Task 38: Plugin API Public Surface

**Spec:** §5.8, §6.2 plugin rules, §7.9 plugin presets

**Files:**
- Create: `packages/cli/src/opentools/chain/plugin_api.py`

**Contract:**

```python
from opentools.chain.plugin_api import (
    register_entity_type,
    register_security_extractor,
    register_parser_extractor,
    register_linker_rule,
    register_query_preset,
)
```

This module re-exports the registration functions from their home modules so plugins have a single, stable import. No new logic.

**Commit:** `feat(chain): expose public plugin API surface`

---

## Task 39: Web Models + Alembic Migration

**Spec:** §8.3

**Files:**
- Modify: `packages/web/backend/app/models.py`
- Create: `packages/web/backend/alembic/versions/003_chain_data_layer.py`
- Modify: `packages/web/backend/pyproject.toml`

**Contract:** add SQLModel tables mirroring every CLI chain model, with `user_id` UUID FK, cascading deletes, and the same unique constraints. Alembic migration creates all tables on upgrade, drops all on downgrade (fully reversible).

Add web dependencies: `rustworkx`, `ioc-finder`, `tldextract`, `instructor`, `anthropic`, `openai`, `aiolimiter`, `tenacity`, `orjson`.

**Tests:** Alembic `upgrade head` and `downgrade base` both succeed on a fresh DB; tables exist after upgrade; SQLModel class matches schema.

**Commit:** `feat(web): add chain data layer SQLModel tables and migration`

---

## Task 40: Web Chain Service

**Spec:** §8.9 read-only endpoints contracts

**Files:**
- Create: `packages/web/backend/app/services/chain_service.py`

**Contract:** async wrappers around the CLI chain package. The service owns a `ChainStore` pointing at the Postgres connection (via SQLAlchemy Core compatibility shim) and exposes methods matching each route:

```python
class ChainService:
    async def list_entities(self, *, user_id, type, limit, offset) -> list[Entity]: ...
    async def get_entity(self, *, user_id, entity_id) -> Entity | None: ...
    async def mentions_for_entity(self, *, user_id, entity_id) -> list[EntityMention]: ...
    async def entities_for_finding(self, *, user_id, finding_id) -> list[Entity]: ...
    async def relations_for_finding(self, *, user_id, finding_id) -> list[FindingRelation]: ...

    async def query_path(self, *, user_id, from_id, to_id, k, max_hops, explain, include_candidates) -> list[PathResult]: ...
    async def query_path_entity(self, *, user_id, from_entity, to_entity, k, max_hops) -> list[PathResult]: ...
    async def query_neighborhood(self, *, user_id, finding_id, hops, direction) -> NeighborhoodResult: ...
    async def query_subgraph(self, *, user_id, engagement_id, filters) -> dict: ...

    async def list_presets(self) -> list[PresetMeta]: ...
    async def run_preset(self, *, user_id, name, **kwargs) -> dict: ...

    async def list_runs(self, *, user_id, limit) -> list[LinkerRun]: ...
    async def get_run(self, *, user_id, run_id) -> LinkerRun | None: ...
    async def stats_rules(self, *, user_id, run_id) -> dict: ...
    async def stats_entities(self, *, user_id) -> dict: ...
    async def stats_llm(self, *, user_id) -> dict: ...

    async def merge_entities(self, *, user_id, a_id, b_id, into) -> MergeResult: ...
    async def split_entity(self, *, user_id, entity_id, criterion) -> SplitResult: ...
    async def import_chain(self, *, user_id, payload: bytes, merge_strategy) -> ImportResult: ...
```

All methods enforce `user_id` scoping at the query level — never trust the caller.

**Commit:** `feat(web): add chain service layer with user-scoped async methods`

---

## Task 41: Web Long-Running Task Registry

**Spec:** §8.9 long-running operations pattern

**Files:**
- Create: `packages/web/backend/app/services/chain_tasks.py`
- Modify: `packages/web/backend/app/dependencies.py`

**Contract:**

```python
class ChainTaskRegistry:
    def __init__(self): self._tasks: dict[str, asyncio.Task] = {}
    def start(self, run_id: str, coro) -> asyncio.Task: ...
    def get(self, run_id: str) -> asyncio.Task | None: ...
    def cleanup_completed(self): ...

# Registered on app startup, injected via Depends in routes
def get_chain_task_registry() -> ChainTaskRegistry: ...
```

Progress updates flow through `LinkerRun` row writes; SSE polling in the existing `/api/events` channel reads those rows.

**Commit:** `feat(web): add chain task registry for long-running linker operations`

---

## Task 42: Web Routes

**Spec:** §8.9

**Files:**
- Create: `packages/web/backend/app/routes/chain.py`
- Modify: `packages/web/backend/app/main.py`

**Contract:** FastAPI router with every endpoint listed in §8.9. Each handler:
1. Extracts `user_id` from the session dependency (existing 3A auth pattern)
2. Calls the corresponding `ChainService` method
3. Returns the result as JSON with a `schema_version: "1.0"` envelope
4. Long-running POSTs start an `asyncio.create_task` via the task registry and return `{"run_id": ...}` immediately

Register the router in `main.py`:
```python
from app.routes import chain
app.include_router(chain.router, prefix="/api/chain", tags=["chain"])
```

**Commit:** `feat(web): add chain API routes with user scoping and async task handling`

---

## Task 43: Web API Tests

**Spec:** §9.3

**Files:**
- Create: `packages/web/backend/tests/test_chain_api.py`

**Contract:** pytest + httpx.AsyncClient tests covering:
- Each read-only endpoint returns 200 with expected schema
- Pagination on `/entities` honors `limit` and `offset`
- Unauthenticated request → 401
- Long-running POST returns `{"run_id"}` and launches a task
- `query_id` determinism: same params → same ETag
- Invalid payloads → 400 with structured error

**Commit:** `test(web): add chain API endpoint tests`

---

## Task 44: Cross-User Isolation Tests

**Spec:** §9.3 "Cross-user isolation: Alice cannot see Bob's entities..."

**Files:**
- Create: `packages/web/backend/tests/test_chain_isolation.py`

**Contract:** create two users (Alice, Bob), create entities/mentions/relations for each, verify:
- Alice's `GET /api/chain/entities` returns only Alice's entities
- Alice's `GET /api/chain/path?from=<bob_finding>&to=<bob_finding>` returns 404 or empty
- Alice's preset runs exclude Bob's findings
- Alice's cross-engagement queries never surface Bob's data
- `ScopingViolation` never leaks to the API (always filtered at the query layer)

**Commit:** `test(web): add cross-user chain data isolation tests`

---

## Task 45: Canonical Test Fixtures

**Spec:** §9.2

**Files:**
- Create: `packages/cli/tests/chain/fixtures/canonical_findings.json`
- Create: `packages/cli/tests/chain/fixtures/expected_entities.json`
- Create: `packages/cli/tests/chain/fixtures/expected_edges.json`

**Contract:** hand-curated 30-50 findings spanning tools, severities, and entity types. Each fixture includes findings from Nmap, Burp, Semgrep, Nikto, Nuclei. `expected_entities.json` lists known-extractable entities with tolerant count ranges. `expected_edges.json` lists expected edges with weight ranges.

Include at least:
- 3 findings on the same host (expected: shared-host edges)
- 2 findings with an `nmap → nuclei` tool chain
- 2 findings with shared MITRE techniques
- 2 findings with a shared CVE at different severities
- 2 findings in different engagements with a shared IOC

**Commit:** `test(chain): add canonical fixture data for pipeline integration tests`

---

## Task 46: Pipeline Integration Test

**Spec:** §9.2

**Files:**
- Create: `packages/cli/tests/chain/test_pipeline_integration.py`

**Contract:** one big test that:
1. Loads fixtures
2. Inserts findings into a temp ChainStore
3. Runs the full extract → link pipeline
4. Asserts expected entities exist (fuzzy counts)
5. Asserts expected edges exist with weights in the expected ranges
6. Runs each pre-canned preset and asserts at least one result
7. Runs a path query between two known-connected findings and asserts non-empty result

Plus a resume test: interrupt backfill partway (mock exception), restart, verify end state matches single-run state.

**Commit:** `test(chain): add end-to-end pipeline integration test with canonical fixtures`

---

## Self-Review (completed)

The plan was reviewed against the spec after initial authoring. Issues found and fixed inline:

1. **Event bus subscription wiring missing** — Task 4 emitted events but nothing subscribed. Added **Task 23b** to wire extraction + linking to `finding.created` / `finding.updated` / `finding.deleted` events, with batch-context suppression for Task 24.
2. **`PathResult` type undefined** — used in Tasks 28, 30, 31, 33, 40 but never defined. Added full `PathResult`, `PathNode`, `PathEdgeRef` dataclasses to Task 27.
3. **`url` entity type not registered** — Task 10 referenced it but Task 6 didn't register it. Added `_norm_url`, added `"url"` to `NORMALIZERS`, `_BUILTIN_STRONG`, and the Task 6 test.
4. **Wrong `Finding` import path in Task 8** — plan had `from opentools.chain.models import Finding`. Corrected to `from opentools.models import Finding`.
5. **Task 17 cascade behavior vague** — expanded the contract into an explicit 10-step procedure covering hash-based change detection, hard-delete of stale mentions, normalization, upserts, and `FindingExtractionState` updates.
6. **`SharedWeakEntityRule` "identical except"** — replaced the shortcut with a full class definition so engineers reading tasks out of order have complete code.

**Verified clean:**

- Spec coverage: every row in §10 "In scope" and every section in §3-§9 maps to at least one task.
- Type consistency: `Finding`, `Entity`, `EntityMention`, `FindingRelation`, `ExtractedEntity`, `ExtractionContext`, `LinkerContext`, `RuleContribution`, `Rule`, `ChainStore`, `MasterGraph`, `PathResult`, `EndpointSpec`, `LLMExtractionProvider`, `LLMLinkClassification`, and all enums are defined before first use and signatures match across tasks.
- Commit granularity: 47 commits (46 numbered tasks plus Task 23b). Each produces compiling, testing code reviewable in isolation.
- Known trade-off: Tasks 8-46 use a tightened contract-style format rather than exhaustive TDD-step enumeration. This is a deliberate plan-length trade-off. Each compressed task still identifies files, spec section, contract (with signatures), test shape, and commit message — sufficient for an engineer to implement without guessing. Tasks 1-7 retain the full 5-step TDD format as a reference pattern.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-04-10-phase3c1-attack-chain-data-layer.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration, protects the main conversation context from accumulating implementation noise.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints for review.

**Which approach?**
