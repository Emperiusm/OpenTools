import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from opentools.containers import ContainerManager
from opentools.models import ToolkitConfig, ToolConfig


@pytest.fixture
def container_config(tmp_path):
    return ToolkitConfig(
        docker_hub_path=tmp_path,
        containers={
            "nmap-mcp": ToolConfig(
                name="nmap-mcp", type="docker_container",
                path_or_command="nmap-mcp", profiles=["pentest"],
            ),
            "nuclei-mcp": ToolConfig(
                name="nuclei-mcp", type="docker_container",
                path_or_command="nuclei-mcp", profiles=["pentest"],
            ),
        },
    )


def _mock_compose_ps_output():
    """Sample docker compose ps --format json output."""
    return (
        json.dumps({"Name": "nmap-mcp", "State": "running", "Health": "", "Service": "nmap-mcp"}) + "\n"
        + json.dumps({"Name": "nuclei-mcp", "State": "exited", "Health": "", "Service": "nuclei-mcp", "ExitCode": 1})
    ).encode()


def test_status_parses_compose_output(container_config):
    mgr = ContainerManager(container_config)
    mock_result = MagicMock(returncode=0, stdout=_mock_compose_ps_output())
    with patch.object(mgr, "_compose_run", return_value=mock_result):
        statuses = mgr.status()
    assert len(statuses) == 2
    names = {s.name for s in statuses}
    assert names == {"nmap-mcp", "nuclei-mcp"}
    running = [s for s in statuses if s.state == "running"]
    assert len(running) == 1


def test_start_calls_compose_up(container_config):
    mgr = ContainerManager(container_config)
    mock_result = MagicMock(returncode=0, stdout=b"", stderr=b"")
    with patch.object(mgr, "_compose_run", return_value=mock_result) as mock_run:
        result = mgr.start(["nmap-mcp"], wait=False)
    assert result.success
    assert "nmap-mcp" in result.started
    mock_run.assert_called_once_with(["up", "-d", "nmap-mcp"])


def test_stop_calls_compose_stop(container_config):
    mgr = ContainerManager(container_config)
    mock_result = MagicMock(returncode=0, stdout=b"", stderr=b"")
    with patch.object(mgr, "_compose_run", return_value=mock_result) as mock_run:
        result = mgr.stop(["nmap-mcp"])
    assert result.success
    mock_run.assert_called_once_with(["stop", "nmap-mcp"])


def test_no_hub_path_returns_failure():
    config = ToolkitConfig()  # no docker_hub_path
    mgr = ContainerManager(config)
    result = mgr.start(["nmap-mcp"])
    assert not result.success
    assert "docker_hub_path" in result.errors.get("all", "")


def test_logs_returns_output(container_config):
    mgr = ContainerManager(container_config)
    mock_result = MagicMock(returncode=0, stdout=b"some log output\n")
    with patch.object(mgr, "_compose_run", return_value=mock_result):
        output = mgr.logs("nmap-mcp", tail=10)
    assert "some log output" in output
