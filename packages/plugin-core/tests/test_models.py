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
