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
        with pytest.raises(ValueError, match="hash mismatch"):
            cache.store("0000" * 16, b"some data")

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
