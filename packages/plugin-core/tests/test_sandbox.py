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
        violations = check_volumes(["~/.ssh/:/root/.ssh/"])
        assert len(violations) >= 1

    def test_proc_sys_blocked(self):
        from opentools_plugin_core.sandbox import check_volumes
        for path in ["/proc:/proc", "/sys:/sys"]:
            violations = check_volumes([path])
            assert len(violations) >= 1, f"{path} should be blocked"


class TestCapabilityCheck:
    def test_undeclared_capability_flagged(self):
        from opentools_plugin_core.sandbox import check_capabilities
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
