import pytest
from unittest.mock import patch, MagicMock
from opentools.preflight import PreflightRunner, SKILL_DEPENDENCIES
from opentools.models import ToolConfig, ToolkitConfig, ToolStatus, ToolCheckResult


@pytest.fixture
def sample_config():
    return ToolkitConfig(
        mcp_servers={
            "codebadger": ToolConfig(
                name="codebadger", type="mcp_server",
                path_or_command="http://localhost:4242/mcp",
                health_check="http://localhost:4242/health",
            ),
        },
        cli_tools={
            "webcrack": ToolConfig(
                name="webcrack", type="cli_tool",
                path_or_command="webcrack",
            ),
        },
        containers={
            "nmap-mcp": ToolConfig(
                name="nmap-mcp", type="docker_container",
                path_or_command="nmap-mcp",
            ),
        },
        api_keys={"SHODAN_API_KEY": False, "VIRUSTOTAL_API_KEY": True},
    )


def test_check_all_returns_report(sample_config):
    runner = PreflightRunner(sample_config)
    with patch("opentools.preflight.shutil.which", return_value=None):
        with patch("opentools.preflight.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            report = runner.check_all()
    assert report.platform == "win32"
    assert len(report.tools) > 0
    assert report.summary.total > 0


def test_check_cli_tool_found_on_path(sample_config):
    runner = PreflightRunner(sample_config)
    runner._docker_available = False
    with patch("opentools.preflight.shutil.which", return_value="/usr/bin/webcrack"):
        result = runner.check_tool("webcrack")
    assert result.status == ToolStatus.AVAILABLE
    assert "PATH" in result.message


def test_check_cli_tool_not_found(sample_config):
    runner = PreflightRunner(sample_config)
    runner._docker_available = False
    with patch("opentools.preflight.shutil.which", return_value=None):
        result = runner.check_tool("webcrack")
    assert result.status == ToolStatus.MISSING


def test_api_key_status(sample_config):
    runner = PreflightRunner(sample_config)
    runner._docker_available = False
    with patch("opentools.preflight.shutil.which", return_value=None):
        report = runner.check_all()
    api_results = {t.name: t for t in report.tools if t.category == "api_key"}
    assert api_results["SHODAN_API_KEY"].status == ToolStatus.NOT_CONFIGURED
    assert api_results["VIRUSTOTAL_API_KEY"].status == ToolStatus.AVAILABLE


def test_check_skill_filters_tools(sample_config):
    runner = PreflightRunner(sample_config)
    runner._docker_available = False
    report = runner.check_skill("pentest")
    assert report.skill == "pentest"
    tool_names = {t.name for t in report.tools}
    assert "codebadger" in tool_names  # codebadger is required for pentest


def test_skill_dependencies_complete():
    """Verify all 6 skills have dependency entries."""
    expected = {"pentest", "reverse-engineering", "hardware-re", "forensics", "cloud-security", "mobile"}
    assert set(SKILL_DEPENDENCIES.keys()) == expected
