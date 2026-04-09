import os
from pathlib import Path
import pytest
from opentools.config import resolve_env_vars, ConfigLoader


def test_resolve_env_vars_with_set_var(monkeypatch):
    monkeypatch.setenv("MY_TOOL", "/custom/path")
    result = resolve_env_vars("${MY_TOOL:-/default/path}")
    assert result == "/custom/path"


def test_resolve_env_vars_with_default():
    result = resolve_env_vars("${NONEXISTENT_VAR_12345:-/default/path}")
    assert result == "/default/path"


def test_resolve_env_vars_no_default_no_env():
    result = resolve_env_vars("${NONEXISTENT_VAR_12345}")
    assert result == "${NONEXISTENT_VAR_12345}"


def test_resolve_env_vars_plain_string():
    result = resolve_env_vars("docker exec nmap-mcp nmap")
    assert result == "docker exec nmap-mcp nmap"


def test_config_loader_loads_tools_yaml(tmp_path):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / "tools.yaml").write_text(
        'docker_hub: "/tmp/hub"\n'
        'cli_tools:\n'
        '  webcrack:\n'
        '    path: "webcrack"\n'
        '    description: "JS deobfuscator"\n'
        '    used_by: [reverse-engineering]\n'
    )
    (config_dir / "mcp-servers.yaml").write_text(
        'servers: {}\nskill_dependencies: {}\n'
    )
    (config_dir / "profiles.yaml").write_text(
        'profile:\n  name: default\n  platform: auto\n'
    )
    loader = ConfigLoader(tmp_path)
    config = loader.load()
    assert "webcrack" in config.cli_tools
    assert config.cli_tools["webcrack"].path_or_command == "webcrack"


def test_config_loader_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        loader = ConfigLoader(tmp_path)
        loader.load()
