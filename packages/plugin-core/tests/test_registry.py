"""Tests for registry client: catalog fetch, ETag, multi-registry, offline."""

import json
import pytest


@pytest.fixture
def sample_catalog_json():
    return json.dumps({
        "generated_at": "2026-04-15T12:00:00Z",
        "schema_version": "1.0.0",
        "plugins": [
            {"name": "wifi-hacking", "description": "WiFi tools", "author": "someone",
             "trust_tier": "verified", "domain": "pentest", "tags": ["wifi"],
             "latest_version": "1.0.0", "repo": "https://github.com/someone/x",
             "min_opentools_version": "0.3.0",
             "provides": {"skills": [], "recipes": [], "containers": []},
             "requires": {}, "yanked_versions": []},
            {"name": "cloud-recon", "description": "Cloud scanning", "author": "another",
             "trust_tier": "unverified", "domain": "cloud", "tags": ["aws", "cloud"],
             "latest_version": "0.5.0", "repo": "https://github.com/another/y",
             "min_opentools_version": "0.3.0",
             "provides": {"skills": [], "recipes": [], "containers": []},
             "requires": {}, "yanked_versions": []},
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
        assert client.load_cached_catalog() is None


class TestSearch:
    def test_search_by_name(self, tmp_opentools_home, sample_catalog_json):
        from opentools_plugin_core.registry import RegistryClient
        (tmp_opentools_home / "registry-cache" / "catalog.json").write_text(sample_catalog_json)
        client = RegistryClient(cache_dir=tmp_opentools_home / "registry-cache")
        results = client.search("wifi")
        assert len(results) == 1
        assert results[0].name == "wifi-hacking"

    def test_search_by_tag(self, tmp_opentools_home, sample_catalog_json):
        from opentools_plugin_core.registry import RegistryClient
        (tmp_opentools_home / "registry-cache" / "catalog.json").write_text(sample_catalog_json)
        client = RegistryClient(cache_dir=tmp_opentools_home / "registry-cache")
        results = client.search("aws")
        assert len(results) == 1
        assert results[0].name == "cloud-recon"

    def test_search_by_domain(self, tmp_opentools_home, sample_catalog_json):
        from opentools_plugin_core.registry import RegistryClient
        (tmp_opentools_home / "registry-cache" / "catalog.json").write_text(sample_catalog_json)
        client = RegistryClient(cache_dir=tmp_opentools_home / "registry-cache")
        results = client.search("", domain="cloud")
        assert len(results) == 1

    def test_search_no_match(self, tmp_opentools_home, sample_catalog_json):
        from opentools_plugin_core.registry import RegistryClient
        (tmp_opentools_home / "registry-cache" / "catalog.json").write_text(sample_catalog_json)
        client = RegistryClient(cache_dir=tmp_opentools_home / "registry-cache")
        assert client.search("nonexistent-plugin-xyz") == []


class TestLookup:
    def test_lookup_by_name(self, tmp_opentools_home, sample_catalog_json):
        from opentools_plugin_core.registry import RegistryClient
        (tmp_opentools_home / "registry-cache" / "catalog.json").write_text(sample_catalog_json)
        client = RegistryClient(cache_dir=tmp_opentools_home / "registry-cache")
        entry = client.lookup("wifi-hacking")
        assert entry is not None
        assert entry.name == "wifi-hacking"

    def test_lookup_nonexistent(self, tmp_opentools_home, sample_catalog_json):
        from opentools_plugin_core.registry import RegistryClient
        (tmp_opentools_home / "registry-cache" / "catalog.json").write_text(sample_catalog_json)
        client = RegistryClient(cache_dir=tmp_opentools_home / "registry-cache")
        assert client.lookup("nope") is None
