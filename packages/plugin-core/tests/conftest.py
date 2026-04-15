"""Shared fixtures for plugin-core tests."""

from pathlib import Path
import pytest


@pytest.fixture
def tmp_opentools_home(tmp_path: Path) -> Path:
    """Create a temporary ~/.opentools structure."""
    home = tmp_path / ".opentools"
    (home / "plugins").mkdir(parents=True)
    (home / "staging").mkdir()
    (home / "cache").mkdir()
    (home / "registry-cache").mkdir()
    return home


@pytest.fixture
def sample_manifest_dict() -> dict:
    """Minimal valid manifest as a dict."""
    return {
        "name": "test-plugin",
        "version": "1.0.0",
        "description": "A test plugin",
        "author": {"name": "tester"},
        "license": "MIT",
        "min_opentools_version": "0.3.0",
        "tags": ["test"],
        "domain": "pentest",
        "provides": {
            "skills": [{"path": "skills/test-skill/SKILL.md"}],
            "recipes": [],
            "containers": [],
        },
    }
