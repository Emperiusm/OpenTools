# packages/cli/tests/test_scanner/test_profiles.py
"""Tests for scan profile models and YAML loading."""

import pytest

from opentools.scanner.models import (
    ExecutionTier,
    RetryPolicy,
    TargetType,
    TaskIsolation,
    TaskType,
)
from opentools.scanner.profiles import (
    DEFAULT_PROFILES,
    ProfilePhase,
    ProfileTool,
    ReactiveEdgeTemplate,
    ScanProfile,
    load_builtin_profile,
    load_profile_yaml,
    list_builtin_profiles,
)


class TestProfileTool:
    def test_defaults(self):
        pt = ProfileTool(
            tool="semgrep",
            task_type=TaskType.SHELL,
        )
        assert pt.tool == "semgrep"
        assert pt.task_type == TaskType.SHELL
        assert pt.priority == 50
        assert pt.tier == ExecutionTier.NORMAL
        assert pt.optional is False
        assert pt.condition is None
        assert pt.isolation == TaskIsolation.NONE

    def test_full_config(self):
        pt = ProfileTool(
            tool="nuclei",
            task_type=TaskType.SHELL,
            command_template="nuclei -u {target} -t {templates}",
            parser="nuclei",
            priority=30,
            tier=ExecutionTier.NORMAL,
            resource_group="shell",
            retry_policy=RetryPolicy(max_retries=3),
            cache_key_template="{tool}:{target_hash}",
            optional=False,
            condition="language in ['python', 'java']",
            preferred_output_format="json",
        )
        assert pt.command_template == "nuclei -u {target} -t {templates}"
        assert pt.retry_policy.max_retries == 3

    def test_mcp_tool(self):
        pt = ProfileTool(
            tool="codebadger",
            task_type=TaskType.MCP_CALL,
            mcp_server="codebadger",
            mcp_tool="generate_cpg",
            mcp_args_template={"path": "{target}"},
            priority=40,
        )
        assert pt.mcp_server == "codebadger"
        assert pt.mcp_tool == "generate_cpg"

    def test_serialization(self):
        pt = ProfileTool(
            tool="semgrep",
            task_type=TaskType.SHELL,
            command_template="semgrep --config auto {target}",
        )
        restored = ProfileTool.model_validate_json(pt.model_dump_json())
        assert restored == pt


class TestReactiveEdgeTemplate:
    def test_basic(self):
        ret = ReactiveEdgeTemplate(
            evaluator="builtin:open_ports_to_vuln_scan",
            trigger_tool="nmap",
            max_spawns=20,
            max_spawns_per_trigger=5,
        )
        assert ret.evaluator == "builtin:open_ports_to_vuln_scan"
        assert ret.trigger_tool == "nmap"
        assert ret.max_spawns == 20

    def test_with_condition(self):
        ret = ReactiveEdgeTemplate(
            evaluator="builtin:high_severity_to_deep_dive",
            trigger_tool="*",
            condition="severity in ['critical', 'high']",
            max_spawns=10,
        )
        assert ret.condition is not None


class TestProfilePhase:
    def test_basic_phase(self):
        phase = ProfilePhase(
            name="discovery",
            tools=[
                ProfileTool(tool="whatweb", task_type=TaskType.SHELL),
                ProfileTool(tool="waybackurls", task_type=TaskType.SHELL),
            ],
            parallel=True,
        )
        assert phase.name == "discovery"
        assert len(phase.tools) == 2
        assert phase.parallel is True

    def test_sequential_phase(self):
        phase = ProfilePhase(
            name="decompile",
            tools=[
                ProfileTool(tool="jadx", task_type=TaskType.SHELL),
            ],
            parallel=False,
        )
        assert phase.parallel is False


class TestScanProfile:
    def test_basic_profile(self):
        profile = ScanProfile(
            id="source-quick",
            name="Source Quick Scan",
            description="Fast static analysis of source code",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="static-analysis",
                    tools=[
                        ProfileTool(tool="semgrep", task_type=TaskType.SHELL),
                        ProfileTool(tool="gitleaks", task_type=TaskType.SHELL),
                    ],
                ),
            ],
        )
        assert profile.id == "source-quick"
        assert len(profile.phases) == 1
        assert len(profile.phases[0].tools) == 2

    def test_profile_with_inheritance(self):
        profile = ScanProfile(
            id="source-full",
            name="Source Full Scan",
            description="Comprehensive source code analysis",
            target_types=[TargetType.SOURCE_CODE],
            extends="source-quick",
            add_tools=[
                ProfileTool(tool="codebadger", task_type=TaskType.MCP_CALL),
            ],
            remove_tools=["gitleaks"],
        )
        assert profile.extends == "source-quick"
        assert len(profile.add_tools) == 1
        assert "gitleaks" in profile.remove_tools

    def test_profile_serialization(self):
        profile = ScanProfile(
            id="test",
            name="Test Profile",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[],
        )
        restored = ScanProfile.model_validate_json(profile.model_dump_json())
        assert restored == profile


class TestDefaultProfiles:
    def test_all_target_types_mapped(self):
        for tt in TargetType:
            assert tt in DEFAULT_PROFILES, f"Missing default profile for {tt}"

    def test_mappings_are_strings(self):
        for tt, profile_name in DEFAULT_PROFILES.items():
            assert isinstance(profile_name, str)


class TestBuiltinProfileLoading:
    def test_list_builtin_profiles(self):
        profiles = list_builtin_profiles()
        assert len(profiles) >= 8
        expected = {
            "source-quick", "source-full", "web-quick", "web-full",
            "binary-triage", "network-recon", "container-audit", "apk-analysis",
        }
        assert expected.issubset(set(profiles))

    def test_load_source_quick(self):
        profile = load_builtin_profile("source-quick")
        assert profile.id == "source-quick"
        assert TargetType.SOURCE_CODE in profile.target_types
        assert len(profile.phases) >= 1
        tool_names = [t.tool for phase in profile.phases for t in phase.tools]
        assert "semgrep" in tool_names
        assert "gitleaks" in tool_names

    def test_load_web_full(self):
        profile = load_builtin_profile("web-full")
        assert profile.id == "web-full"
        assert TargetType.URL in profile.target_types
        tool_names = [t.tool for phase in profile.phases for t in phase.tools]
        assert "nuclei" in tool_names

    def test_load_binary_triage(self):
        profile = load_builtin_profile("binary-triage")
        assert profile.id == "binary-triage"
        assert TargetType.BINARY in profile.target_types

    def test_load_network_recon(self):
        profile = load_builtin_profile("network-recon")
        assert profile.id == "network-recon"
        assert TargetType.NETWORK in profile.target_types
        # Should have reactive edges defined
        assert len(profile.reactive_edges) >= 1

    def test_load_nonexistent_raises(self):
        with pytest.raises(FileNotFoundError):
            load_builtin_profile("nonexistent-profile")

    def test_load_profile_from_yaml_string(self):
        yaml_str = """
id: custom-test
name: Custom Test
description: A custom test profile
target_types:
  - source_code
phases:
  - name: analysis
    tools:
      - tool: semgrep
        task_type: shell
        command_template: "semgrep --config auto {target}"
"""
        profile = load_profile_yaml(yaml_str)
        assert profile.id == "custom-test"
        assert len(profile.phases) == 1
        assert profile.phases[0].tools[0].tool == "semgrep"

    def test_load_all_builtin_profiles_valid(self):
        """Every builtin profile YAML must parse into a valid ScanProfile."""
        for name in list_builtin_profiles():
            profile = load_builtin_profile(name)
            assert profile.id == name, f"Profile {name} has mismatched id: {profile.id}"
            assert len(profile.target_types) >= 1
            assert len(profile.phases) >= 1
