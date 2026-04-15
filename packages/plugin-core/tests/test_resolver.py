"""Tests for dependency resolver: tree, conflicts, cycles."""

import pytest


class TestResolver:
    def test_no_dependencies(self):
        from opentools_plugin_core.resolver import resolve
        catalog = {"wifi-hacking": {"requires_plugins": [], "provides_containers": ["aircrack-mcp"], "provides_skills": ["wifi-pentest"]}}
        plan = resolve("wifi-hacking", catalog, installed=set())
        assert plan == ["wifi-hacking"]

    def test_linear_dependency(self):
        from opentools_plugin_core.resolver import resolve
        catalog = {
            "wifi-hacking": {"requires_plugins": [{"name": "network-utils", "version": ">=1.0.0"}], "provides_containers": [], "provides_skills": []},
            "network-utils": {"requires_plugins": [], "provides_containers": [], "provides_skills": []},
        }
        plan = resolve("wifi-hacking", catalog, installed=set())
        assert plan.index("network-utils") < plan.index("wifi-hacking")

    def test_diamond_dependency(self):
        from opentools_plugin_core.resolver import resolve
        catalog = {
            "top": {"requires_plugins": [{"name": "left", "version": ">=1.0"}, {"name": "right", "version": ">=1.0"}], "provides_containers": [], "provides_skills": []},
            "left": {"requires_plugins": [{"name": "base", "version": ">=1.0"}], "provides_containers": [], "provides_skills": []},
            "right": {"requires_plugins": [{"name": "base", "version": ">=1.0"}], "provides_containers": [], "provides_skills": []},
            "base": {"requires_plugins": [], "provides_containers": [], "provides_skills": []},
        }
        plan = resolve("top", catalog, installed=set())
        assert "base" in plan
        assert plan.count("base") == 1
        assert plan.index("base") < plan.index("left")
        assert plan.index("base") < plan.index("right")

    def test_circular_dependency_detected(self):
        from opentools_plugin_core.resolver import resolve
        from opentools_plugin_core.errors import DependencyResolveError
        catalog = {
            "a": {"requires_plugins": [{"name": "b", "version": ">=1.0"}], "provides_containers": [], "provides_skills": []},
            "b": {"requires_plugins": [{"name": "a", "version": ">=1.0"}], "provides_containers": [], "provides_skills": []},
        }
        with pytest.raises(DependencyResolveError, match="[Cc]ircular"):
            resolve("a", catalog, installed=set())

    def test_missing_dependency_error(self):
        from opentools_plugin_core.resolver import resolve
        from opentools_plugin_core.errors import DependencyResolveError
        catalog = {"needs-missing": {"requires_plugins": [{"name": "ghost", "version": ">=1.0"}], "provides_containers": [], "provides_skills": []}}
        with pytest.raises(DependencyResolveError, match="ghost"):
            resolve("needs-missing", catalog, installed=set())

    def test_already_installed_skipped(self):
        from opentools_plugin_core.resolver import resolve
        catalog = {
            "wifi-hacking": {"requires_plugins": [{"name": "network-utils", "version": ">=1.0.0"}], "provides_containers": [], "provides_skills": []},
            "network-utils": {"requires_plugins": [], "provides_containers": [], "provides_skills": []},
        }
        plan = resolve("wifi-hacking", catalog, installed={"network-utils"})
        assert "network-utils" not in plan
        assert "wifi-hacking" in plan

    def test_conflict_detection(self):
        from opentools_plugin_core.resolver import detect_conflicts
        installed_provides = {"containers": {"nmap-mcp": "existing-plugin"}}
        new_provides = {"containers": ["nmap-mcp"], "skills": [], "recipes": []}
        conflicts = detect_conflicts("new-plugin", new_provides, installed_provides)
        assert len(conflicts) >= 1
        assert any("nmap-mcp" in c for c in conflicts)
