"""Pydantic v2 models for plugin manifests, catalogs, and registry entries."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


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


class PluginSet(BaseModel):
    name: str
    min_opentools_version: str = "0.1.0"
    registries: list[str] = Field(default_factory=list)
    plugins: dict[str, str] = Field(default_factory=dict)
    sandbox_policy: Optional[str] = None
