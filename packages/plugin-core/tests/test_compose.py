"""Tests for per-plugin Docker Compose project generation."""

import pytest


class TestComposeGenerator:
    def test_single_container_basic(self):
        from opentools_plugin_core.compose import generate_compose
        from opentools_plugin_core.models import PluginManifest

        manifest_dict = {
            "name": "wifi-hacking", "version": "1.0.0", "description": "WiFi tools",
            "author": {"name": "tester"}, "license": "MIT",
            "min_opentools_version": "0.3.0", "tags": ["wifi"], "domain": "pentest",
            "provides": {"skills": [], "recipes": [], "containers": [{
                "name": "aircrack-mcp", "compose_fragment": "containers/aircrack-mcp.yaml",
                "image": "ghcr.io/someone/aircrack-mcp:1.2.0", "profile": "pentest",
            }]},
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
            provides={"containers": [{"name": "test-mcp", "compose_fragment": "c.yaml", "image": "test:1.0"}]},
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
            provides={"containers": [{"name": "svc", "compose_fragment": "c.yaml", "image": "img:1.0"}]},
        )
        compose = generate_compose(manifest, hub_network="hub_default")
        assert "networks" in compose
        assert compose["networks"]["plugin-net"]["name"] == "opentools-plugin-my-plugin"

    def test_hub_network_external(self):
        from opentools_plugin_core.compose import generate_compose
        from opentools_plugin_core.models import PluginManifest

        manifest = PluginManifest(
            name="p", version="1.0.0", description="T",
            author={"name": "t"}, domain="pentest", tags=[],
            provides={"containers": [{"name": "s", "compose_fragment": "c.yaml", "image": "i:1"}]},
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
            provides={"containers": [{"name": "svc", "compose_fragment": "c.yaml", "image": "i:1"}]},
        )
        compose = generate_compose(manifest, hub_network="hub")
        labels = compose["services"]["svc"]["labels"]
        assert labels["com.opentools.plugin"] == "labeled"
        assert labels["com.opentools.version"] == "2.0.0"

    def test_no_containers_returns_none(self):
        from opentools_plugin_core.compose import generate_compose
        from opentools_plugin_core.models import PluginManifest

        manifest = PluginManifest(
            name="no-containers", version="1.0.0", description="T",
            author={"name": "t"}, domain="pentest", tags=[],
        )
        compose = generate_compose(manifest, hub_network="hub")
        assert compose is None
