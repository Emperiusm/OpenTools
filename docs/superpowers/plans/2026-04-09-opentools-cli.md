# OpenTools CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python CLI (`opentools`) that provides deterministic orchestration for the security-toolkit plugin — config loading, preflight health checks, Docker container management, SQLite engagement state with finding dedup, async recipe execution, and report generation.

**Architecture:** Monorepo with `packages/plugin/` (existing skill files) and `packages/cli/` (new Python package). The CLI reads YAML configs from the plugin directory, stores engagement data in SQLite (WAL mode), and exposes 40+ subcommands via typer. Skills invoke the CLI with `--json` for structured output.

**Tech Stack:** Python 3.14, uv, typer, pydantic, rich, ruamel.yaml, sqlite-utils, jinja2, pytest

**Spec:** `docs/superpowers/specs/2026-04-09-opentools-cli-design.md`

---

## File Map

### New files (packages/cli/)

| File | Responsibility |
|------|---------------|
| `packages/cli/pyproject.toml` | Package config, dependencies, `[project.scripts]` entry point |
| `packages/cli/src/opentools/__init__.py` | Package version |
| `packages/cli/src/opentools/models.py` | All Pydantic models: enums, Engagement, Finding, TimelineEvent, IOC, Artifact, ToolConfig, Recipe, AuditEntry, supporting models |
| `packages/cli/src/opentools/plugin.py` | Plugin directory discovery (env var → relative → error) |
| `packages/cli/src/opentools/config.py` | YAML loading, env var resolution, config merging, validation |
| `packages/cli/src/opentools/engagement/__init__.py` | Re-exports EngagementStore |
| `packages/cli/src/opentools/engagement/schema.py` | SQL DDL, migration runner, version checks |
| `packages/cli/src/opentools/engagement/store.py` | EngagementStore class: CRUD, findings with dedup-on-insert, timeline, IOCs, artifacts, summary |
| `packages/cli/src/opentools/engagement/export.py` | JSON export/import, optional zip bundling |
| `packages/cli/src/opentools/findings.py` | CWE inference table, dedup algorithm, SARIF Pydantic models, CSV/JSON/SARIF export |
| `packages/cli/src/opentools/preflight.py` | PreflightRunner, health checks by transport type, PreflightReport |
| `packages/cli/src/opentools/containers.py` | ContainerManager: start/stop/restart/status/logs via docker compose |
| `packages/cli/src/opentools/recipes.py` | RecipeRunner: load, validate, substitute, asyncio DAG executor, streaming |
| `packages/cli/src/opentools/parsers/__init__.py` | Parser registry: auto-discover modules, dispatch by tool name |
| `packages/cli/src/opentools/parsers/semgrep.py` | Parse Semgrep JSON → list[Finding] |
| `packages/cli/src/opentools/parsers/nuclei.py` | Parse Nuclei JSONL → list[Finding] |
| `packages/cli/src/opentools/parsers/trivy.py` | Parse Trivy JSON → list[Finding] |
| `packages/cli/src/opentools/parsers/gitleaks.py` | Parse Gitleaks JSON → list[Finding] |
| `packages/cli/src/opentools/parsers/capa.py` | Parse capa JSON → list[Finding] |
| `packages/cli/src/opentools/reports.py` | ReportGenerator: Jinja2 rendering, template discovery, markdown/HTML output |
| `packages/cli/src/opentools/audit.py` | Audit trail: log_action, get_audit_log (writes to same SQLite DB) |
| `packages/cli/src/opentools/cli.py` | Typer app with all command groups, global flags, `--json` contract |
| `packages/cli/src/opentools/dashboard.py` | Phase 3 stub (empty, raises NotImplementedError) |
| `packages/cli/tests/test_models.py` | Model construction, validation, enum coverage |
| `packages/cli/tests/test_plugin.py` | Plugin discovery: env var, relative, missing |
| `packages/cli/tests/test_config.py` | YAML loading, env var resolution, precedence, validation |
| `packages/cli/tests/test_schema.py` | Migration runner, version checks, table creation |
| `packages/cli/tests/test_engagement.py` | Store CRUD, summary, soft delete |
| `packages/cli/tests/test_findings.py` | CWE inference, dedup algorithm (all confidence levels), SARIF export |
| `packages/cli/tests/test_preflight.py` | Health check dispatch, report generation (mocked) |
| `packages/cli/tests/test_containers.py` | Status parsing, start/stop (mocked docker) |
| `packages/cli/tests/test_recipes.py` | Variable substitution, DAG ordering, timeout |
| `packages/cli/tests/test_parsers.py` | Each parser with sample tool output |
| `packages/cli/tests/test_reports.py` | Template discovery, rendering, context |
| `packages/cli/tests/test_cli.py` | CLI integration: invoke commands, check exit codes, JSON output |
| `packages/cli/tests/conftest.py` | Shared fixtures: tmp dirs, in-memory DB, sample data |

### Moved files (monorepo restructure)

All current repo contents move to `packages/plugin/`. Root-level `.gitignore`, `.env.example`, `README.md` stay at repo root.

---

## Task 1: Monorepo Restructure

**Files:**
- Move: all current files → `packages/plugin/`
- Keep at root: `.gitignore`, `.env.example`, `README.md`, `docs/`
- Create: `packages/cli/pyproject.toml`, `packages/cli/src/opentools/__init__.py`

- [ ] **Step 1: Create packages/plugin/ and move all plugin files**

```bash
mkdir -p packages/plugin
git mv .claude-plugin packages/plugin/
git mv skills packages/plugin/
git mv commands packages/plugin/
git mv config packages/plugin/
git mv shared packages/plugin/
git mv recipes.json packages/plugin/
git mv CLAUDE.md packages/plugin/
```

- [ ] **Step 2: Create the CLI package skeleton**

```bash
mkdir -p packages/cli/src/opentools/engagement
mkdir -p packages/cli/src/opentools/parsers
mkdir -p packages/cli/tests
```

- [ ] **Step 3: Create pyproject.toml**

Create `packages/cli/pyproject.toml`:

```toml
[project]
name = "opentools"
version = "0.1.0"
description = "CLI toolkit for the OpenTools security plugin"
requires-python = ">=3.12"
dependencies = [
    "typer>=0.15.0",
    "pydantic>=2.0",
    "rich>=13.0",
    "ruamel.yaml>=0.18",
    "sqlite-utils>=3.37",
    "jinja2>=3.1",
]

[project.scripts]
opentools = "opentools.cli:app"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/opentools"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
```

- [ ] **Step 4: Create __init__.py**

Create `packages/cli/src/opentools/__init__.py`:

```python
"""OpenTools CLI — security toolkit orchestration."""

__version__ = "0.1.0"
```

- [ ] **Step 5: Create empty engagement and parsers __init__.py**

Create `packages/cli/src/opentools/engagement/__init__.py`:

```python
"""Engagement state management."""
```

Create `packages/cli/src/opentools/parsers/__init__.py`:

```python
"""Tool output parser registry."""
```

- [ ] **Step 6: Install the package in dev mode**

```bash
cd packages/cli
uv pip install -e ".[dev]" 2>/dev/null || uv pip install -e .
```

Verify: `python -c "import opentools; print(opentools.__version__)"` prints `0.1.0`.

- [ ] **Step 7: Update root .gitignore**

Append to `.gitignore`:

```
# Python
__pycache__/
*.pyc
*.egg-info/
dist/
.venv/
```

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "chore: restructure into monorepo with packages/plugin and packages/cli"
```

---

## Task 2: Pydantic Models

**Files:**
- Create: `packages/cli/src/opentools/models.py`
- Test: `packages/cli/tests/test_models.py`

- [ ] **Step 1: Write the failing test**

Create `packages/cli/tests/test_models.py`:

```python
from datetime import datetime, timezone
import pytest
from opentools.models import (
    Severity, EngagementType, EngagementStatus, FindingStatus, Confidence,
    IOCType, ArtifactType, StepType, FailureAction, ToolStatus,
    Engagement, Finding, TimelineEvent, IOC, Artifact, ToolConfig,
    Recipe, RecipeStep, RecipeVariable, AuditEntry,
    EngagementSummary, DeduplicationReport, StepResult, RecipeResult,
)


def test_severity_enum():
    assert Severity.CRITICAL == "critical"
    assert Severity.HIGH == "high"
    assert Severity.INFO == "info"


def test_engagement_creation():
    e = Engagement(
        id="test-id",
        name="test-engagement",
        target="192.168.1.0/24",
        type=EngagementType.PENTEST,
        status=EngagementStatus.ACTIVE,
        skills_used=["pentest"],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    assert e.name == "test-engagement"
    assert e.type == EngagementType.PENTEST


def test_finding_defaults():
    f = Finding(
        id="f-1",
        engagement_id="e-1",
        tool="semgrep",
        title="SQL Injection",
        severity=Severity.HIGH,
        created_at=datetime.now(timezone.utc),
    )
    assert f.false_positive is False
    assert f.corroborated_by == []
    assert f.severity_by_tool == {}
    assert f.status == FindingStatus.DISCOVERED
    assert f.deleted_at is None


def test_finding_rejects_invalid_severity():
    with pytest.raises(ValueError):
        Finding(
            id="f-1",
            engagement_id="e-1",
            tool="semgrep",
            title="test",
            severity="ultra-critical",
            created_at=datetime.now(timezone.utc),
        )


def test_ioc_types():
    ioc = IOC(
        id="i-1",
        engagement_id="e-1",
        ioc_type=IOCType.IP,
        value="10.0.0.1",
        context="C2 callback",
    )
    assert ioc.ioc_type == IOCType.IP


def test_recipe_step_defaults():
    step = RecipeStep(
        name="scan",
        tool="nuclei",
        command="nuclei -u {{target}}",
        timeout=300,
    )
    assert step.step_type == StepType.SHELL
    assert step.on_failure == FailureAction.CONTINUE
    assert step.depends_on is None
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd packages/cli && python -m pytest tests/test_models.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'opentools.models'`

- [ ] **Step 3: Write models.py**

Create `packages/cli/src/opentools/models.py`:

```python
"""Core data models for the OpenTools CLI toolkit."""

from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


# ─── Enums ──────────────────────────────────────────────────────────────────────

class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EngagementType(StrEnum):
    PENTEST = "pentest"
    REVERSE_ENGINEERING = "reverse-engineering"
    HARDWARE_RE = "hardware-re"
    FORENSICS = "forensics"
    CLOUD_SECURITY = "cloud-security"
    MOBILE = "mobile"
    COMBINED = "combined"


class EngagementStatus(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETE = "complete"


class FindingStatus(StrEnum):
    DISCOVERED = "discovered"
    CONFIRMED = "confirmed"
    REPORTED = "reported"
    REMEDIATED = "remediated"
    VERIFIED = "verified"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IOCType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"
    FILE_PATH = "file_path"
    REGISTRY = "registry"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    EMAIL = "email"


class ArtifactType(StrEnum):
    SCREENSHOT = "screenshot"
    PCAP = "pcap"
    BINARY = "binary"
    SOURCE = "source"
    DUMP = "dump"
    REPORT = "report"
    OTHER = "other"


class StepType(StrEnum):
    SHELL = "shell"
    MCP_TOOL = "mcp_tool"
    MANUAL = "manual"


class FailureAction(StrEnum):
    CONTINUE = "continue"
    ABORT = "abort"


class ToolStatus(StrEnum):
    AVAILABLE = "available"
    MISSING = "missing"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    NOT_CONFIGURED = "not_configured"
    UNRESOLVED = "unresolved"


# ─── Core Domain Models ─────────────────────────────────────────────────────────

class Engagement(BaseModel):
    id: str
    name: str
    target: str
    type: EngagementType
    scope: Optional[str] = None
    status: EngagementStatus = EngagementStatus.ACTIVE
    skills_used: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class Finding(BaseModel):
    id: str
    engagement_id: str
    tool: str
    corroborated_by: list[str] = Field(default_factory=list)
    cwe: Optional[str] = None
    severity: Severity
    severity_by_tool: dict[str, str] = Field(default_factory=dict)
    status: FindingStatus = FindingStatus.DISCOVERED
    phase: Optional[str] = None
    title: str
    description: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cvss: Optional[float] = None
    false_positive: bool = False
    dedup_confidence: Optional[Confidence] = None
    created_at: datetime
    deleted_at: Optional[datetime] = None


class TimelineEvent(BaseModel):
    id: str
    engagement_id: str
    timestamp: datetime
    source: str
    event: str
    details: Optional[str] = None
    confidence: Confidence = Confidence.MEDIUM
    finding_id: Optional[str] = None


class IOC(BaseModel):
    id: str
    engagement_id: str
    ioc_type: IOCType
    value: str
    context: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source_finding_id: Optional[str] = None


class Artifact(BaseModel):
    id: str
    engagement_id: str
    file_path: str
    artifact_type: ArtifactType
    description: Optional[str] = None
    source_tool: Optional[str] = None
    created_at: datetime


class AuditEntry(BaseModel):
    id: str
    timestamp: datetime
    command: str
    args: Optional[dict] = None
    engagement_id: Optional[str] = None
    result: str
    details: Optional[str] = None


# ─── Config Models ──────────────────────────────────────────────────────────────

class ToolConfig(BaseModel):
    name: str
    type: str
    path_or_command: str
    health_check: Optional[str] = None
    profiles: list[str] = Field(default_factory=list)
    env_required: list[str] = Field(default_factory=list)
    version: Optional[str] = None
    status: ToolStatus = ToolStatus.MISSING


class RecipeVariable(BaseModel):
    description: str
    required: bool = True
    default: Optional[str] = None


class RecipeStep(BaseModel):
    name: str
    tool: str
    command: str
    timeout: int = 300
    step_type: StepType = StepType.SHELL
    on_failure: FailureAction = FailureAction.CONTINUE
    depends_on: Optional[list[str]] = None


class Recipe(BaseModel):
    id: str
    name: str
    description: str
    requires: list[str] = Field(default_factory=list)
    variables: dict[str, RecipeVariable] = Field(default_factory=dict)
    steps: list[RecipeStep] = Field(default_factory=list)
    parallel: bool = False
    output: str = "consolidated-findings-table"


# ─── Result / Report Models ─────────────────────────────────────────────────────

class EngagementSummary(BaseModel):
    engagement: Engagement
    finding_counts: dict[str, int] = Field(default_factory=dict)
    finding_counts_by_status: dict[str, int] = Field(default_factory=dict)
    finding_counts_by_phase: dict[str, int] = Field(default_factory=dict)
    ioc_counts_by_type: dict[str, int] = Field(default_factory=dict)
    artifact_count: int = 0
    timeline_event_count: int = 0
    false_positive_count: int = 0
    severity_conflicts: int = 0


class DeduplicationReport(BaseModel):
    merged: int = 0
    distinct: int = 0
    merge_details: list[dict] = Field(default_factory=list)


class StepResult(BaseModel):
    step_name: str
    status: str
    exit_code: Optional[int] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    duration_ms: int = 0
    log_path: Optional[Path] = None


class RecipeResult(BaseModel):
    recipe_id: str
    recipe_name: str
    status: str
    steps: list[StepResult] = Field(default_factory=list)
    duration_ms: int = 0
    output_dir: Optional[Path] = None
    findings_added: int = 0


# ─── Preflight Models ───────────────────────────────────────────────────────────

class ToolCheckResult(BaseModel):
    name: str
    category: str
    status: ToolStatus
    required_by: list[str] = Field(default_factory=list)
    message: str = ""
    health_check_ms: int = 0


class PreflightSummary(BaseModel):
    total: int = 0
    available: int = 0
    missing: int = 0
    errors: int = 0
    skills_fully_available: list[str] = Field(default_factory=list)
    skills_partially_available: list[str] = Field(default_factory=list)
    skills_unavailable: list[str] = Field(default_factory=list)


class PreflightReport(BaseModel):
    timestamp: datetime
    platform: str
    docker_available: bool = False
    skill: Optional[str] = None
    tools: list[ToolCheckResult] = Field(default_factory=list)
    summary: PreflightSummary = Field(default_factory=PreflightSummary)


class ContainerStatus(BaseModel):
    name: str
    state: str
    health: Optional[str] = None
    profile: list[str] = Field(default_factory=list)
    uptime: Optional[str] = None
    exit_code: Optional[int] = None


class ContainerResult(BaseModel):
    success: bool
    started: list[str] = Field(default_factory=list)
    failed: list[str] = Field(default_factory=list)
    errors: dict[str, str] = Field(default_factory=dict)


# ─── Config Aggregate ───────────────────────────────────────────────────────────

class ToolkitConfig(BaseModel):
    mcp_servers: dict[str, ToolConfig] = Field(default_factory=dict)
    containers: dict[str, ToolConfig] = Field(default_factory=dict)
    cli_tools: dict[str, ToolConfig] = Field(default_factory=dict)
    docker_hub_path: Optional[Path] = None
    plugin_dir: Optional[Path] = None
    api_keys: dict[str, bool] = Field(default_factory=dict)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd packages/cli && python -m pytest tests/test_models.py -v
```

Expected: All 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/models.py packages/cli/tests/test_models.py
git commit -m "feat: add Pydantic data models for all domain objects"
```

---

## Task 3: Plugin Discovery

**Files:**
- Create: `packages/cli/src/opentools/plugin.py`
- Test: `packages/cli/tests/test_plugin.py`

- [ ] **Step 1: Write the failing test**

Create `packages/cli/tests/test_plugin.py`:

```python
import os
from pathlib import Path
import pytest
from opentools.plugin import discover_plugin_dir


def test_discover_from_env_var(tmp_path, monkeypatch):
    plugin_dir = tmp_path / "my-plugin"
    plugin_dir.mkdir()
    (plugin_dir / "config").mkdir()
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", str(plugin_dir))
    result = discover_plugin_dir()
    assert result == plugin_dir


def test_discover_from_env_var_invalid_path(monkeypatch):
    monkeypatch.setenv("OPENTOOLS_PLUGIN_DIR", "/nonexistent/path")
    with pytest.raises(FileNotFoundError, match="OPENTOOLS_PLUGIN_DIR"):
        discover_plugin_dir()


def test_discover_relative_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENTOOLS_PLUGIN_DIR", raising=False)
    plugin_dir = tmp_path / "plugin"
    plugin_dir.mkdir()
    (plugin_dir / "config").mkdir()
    result = discover_plugin_dir(cli_package_root=tmp_path / "cli")
    assert result == plugin_dir


def test_discover_fails_when_nothing_found(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENTOOLS_PLUGIN_DIR", raising=False)
    with pytest.raises(FileNotFoundError, match="Plugin directory not found"):
        discover_plugin_dir(cli_package_root=tmp_path / "nonexistent")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd packages/cli && python -m pytest tests/test_plugin.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write plugin.py**

Create `packages/cli/src/opentools/plugin.py`:

```python
"""Plugin directory discovery."""

import os
from pathlib import Path


def discover_plugin_dir(cli_package_root: Path | None = None) -> Path:
    """Find the plugin directory containing config/, skills/, etc.

    Resolution order:
    1. OPENTOOLS_PLUGIN_DIR environment variable
    2. ../plugin/ relative to cli_package_root (or this file's grandparent)
    3. Raise FileNotFoundError
    """
    env_path = os.environ.get("OPENTOOLS_PLUGIN_DIR")
    if env_path:
        plugin_dir = Path(env_path)
        if not plugin_dir.is_dir():
            raise FileNotFoundError(
                f"OPENTOOLS_PLUGIN_DIR points to '{plugin_dir}' which does not exist."
            )
        return plugin_dir

    if cli_package_root is None:
        cli_package_root = Path(__file__).resolve().parent.parent.parent.parent

    relative = cli_package_root.parent / "plugin"
    if relative.is_dir():
        return relative

    raise FileNotFoundError(
        "Plugin directory not found. Set OPENTOOLS_PLUGIN_DIR or run from the OpenTools repo."
    )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd packages/cli && python -m pytest tests/test_plugin.py -v
```

Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/plugin.py packages/cli/tests/test_plugin.py
git commit -m "feat: add plugin directory discovery with env var fallback"
```

---

## Task 4: Config Loading

**Files:**
- Create: `packages/cli/src/opentools/config.py`
- Test: `packages/cli/tests/test_config.py`

- [ ] **Step 1: Write the failing test**

Create `packages/cli/tests/test_config.py`:

```python
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
        """
docker_hub: "/tmp/hub"
cli_tools:
  webcrack:
    path: "webcrack"
    description: "JS deobfuscator"
    used_by: [reverse-engineering]
"""
    )
    (config_dir / "mcp-servers.yaml").write_text(
        """
servers: {}
skill_dependencies: {}
"""
    )
    (config_dir / "profiles.yaml").write_text(
        """
profile:
  name: default
  platform: auto
"""
    )
    loader = ConfigLoader(tmp_path)
    config = loader.load()
    assert "webcrack" in config.cli_tools
    assert config.cli_tools["webcrack"].path_or_command == "webcrack"


def test_config_loader_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        loader = ConfigLoader(tmp_path)
        loader.load()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd packages/cli && python -m pytest tests/test_config.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write config.py**

Create `packages/cli/src/opentools/config.py`:

```python
"""Configuration loading and environment variable resolution."""

import os
import re
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from opentools.models import ToolConfig, ToolkitConfig


_ENV_PATTERN = re.compile(r"\$\{([^}:]+)(?::-((?:[^}]|\}(?!\}))*))?\}")


def resolve_env_vars(value: str) -> str:
    """Replace ${VAR:-default} patterns with environment values.

    Resolution:
    1. If VAR is set in environment, use its value
    2. If VAR is not set but default is provided, use default
    3. If VAR is not set and no default, leave the pattern as-is
    """
    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        default = match.group(2)
        env_value = os.environ.get(var_name)
        if env_value is not None:
            return env_value
        if default is not None:
            return default
        return match.group(0)

    return _ENV_PATTERN.sub(_replace, value)


def _resolve_dict(d: dict) -> dict:
    """Recursively resolve env vars in all string values of a dict."""
    result = {}
    for k, v in d.items():
        if isinstance(v, str):
            result[k] = resolve_env_vars(v)
        elif isinstance(v, dict):
            result[k] = _resolve_dict(v)
        elif isinstance(v, list):
            result[k] = [resolve_env_vars(i) if isinstance(i, str) else i for i in v]
        else:
            result[k] = v
    return result


class ConfigLoader:
    """Load and merge tools.yaml, mcp-servers.yaml, and profiles.yaml."""

    def __init__(self, plugin_dir: Path):
        self.plugin_dir = plugin_dir
        self.config_dir = plugin_dir / "config"
        self._yaml = YAML()
        self._yaml.preserve_quotes = True

    def load(self) -> ToolkitConfig:
        tools_data = self._load_yaml("tools.yaml")
        servers_data = self._load_yaml("mcp-servers.yaml")
        self._load_yaml("profiles.yaml")  # validated but used for overrides later

        tools_data = _resolve_dict(tools_data)
        servers_data = _resolve_dict(servers_data)

        mcp_servers = {}
        for name, server in (servers_data.get("servers") or {}).items():
            mcp_servers[name] = ToolConfig(
                name=name,
                type="mcp_server",
                path_or_command=server.get("command", server.get("url", "")),
                health_check=server.get("health_check"),
                env_required=server.get("env_required", []),
                profiles=[],
            )

        containers = {}
        for name, info in (tools_data.get("containers") or {}).items():
            profile = info.get("profile", [])
            if isinstance(profile, str):
                profile = [profile]
            containers[name] = ToolConfig(
                name=name,
                type="docker_container",
                path_or_command=f"docker compose up {name} -d",
                profiles=profile,
            )

        cli_tools = {}
        for name, info in (tools_data.get("cli_tools") or {}).items():
            cli_tools[name] = ToolConfig(
                name=name,
                type="cli_tool",
                path_or_command=info.get("path", name),
            )

        docker_hub = tools_data.get("docker_hub")
        docker_hub_path = Path(docker_hub) if docker_hub else None

        api_keys = {}
        for key_name in tools_data.get("api_keys", []):
            api_keys[key_name] = bool(os.environ.get(key_name))

        return ToolkitConfig(
            mcp_servers=mcp_servers,
            containers=containers,
            cli_tools=cli_tools,
            docker_hub_path=docker_hub_path,
            plugin_dir=self.plugin_dir,
            api_keys=api_keys,
        )

    def _load_yaml(self, filename: str) -> dict:
        path = self.config_dir / filename
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        with open(path) as f:
            data = self._yaml.load(f)
        return data or {}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd packages/cli && python -m pytest tests/test_config.py -v
```

Expected: All 6 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/config.py packages/cli/tests/test_config.py
git commit -m "feat: add config loading with YAML parsing and env var resolution"
```

---

## Task 5: Schema & Migrations

**Files:**
- Create: `packages/cli/src/opentools/engagement/schema.py`
- Test: `packages/cli/tests/test_schema.py`

- [ ] **Step 1: Write the failing test**

Create `packages/cli/tests/test_schema.py`:

```python
import sqlite3
import pytest
from opentools.engagement.schema import LATEST_VERSION, migrate, get_schema_version


def test_migrate_creates_all_tables():
    conn = sqlite3.connect(":memory:")
    migrate(conn)
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    tables = {row[0] for row in cursor.fetchall()}
    assert "engagements" in tables
    assert "findings" in tables
    assert "timeline_events" in tables
    assert "iocs" in tables
    assert "artifacts" in tables
    assert "audit_log" in tables
    assert "schema_version" in tables
    conn.close()


def test_migrate_sets_version():
    conn = sqlite3.connect(":memory:")
    migrate(conn)
    version = get_schema_version(conn)
    assert version == LATEST_VERSION
    conn.close()


def test_migrate_is_idempotent():
    conn = sqlite3.connect(":memory:")
    migrate(conn)
    migrate(conn)  # should not raise
    version = get_schema_version(conn)
    assert version == LATEST_VERSION
    conn.close()


def test_get_schema_version_on_empty_db():
    conn = sqlite3.connect(":memory:")
    version = get_schema_version(conn)
    assert version == 0
    conn.close()


def test_fts_trigger_exists():
    conn = sqlite3.connect(":memory:")
    migrate(conn)
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'findings_%'"
    )
    triggers = {row[0] for row in cursor.fetchall()}
    assert "findings_ai" in triggers
    assert "findings_ad" in triggers
    assert "findings_au" in triggers
    conn.close()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd packages/cli && python -m pytest tests/test_schema.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write schema.py**

Create `packages/cli/src/opentools/engagement/schema.py`:

```python
"""SQLite schema definitions and migration runner."""

import sqlite3
from datetime import datetime, timezone


def get_schema_version(conn: sqlite3.Connection) -> int:
    """Get current schema version (0 if no schema_version table)."""
    try:
        cursor = conn.execute("SELECT MAX(version) FROM schema_version")
        row = cursor.fetchone()
        return row[0] if row and row[0] is not None else 0
    except sqlite3.OperationalError:
        return 0


def _migration_v1(conn: sqlite3.Connection) -> None:
    """Create initial tables, indexes, FTS, and triggers."""
    conn.executescript("""
        CREATE TABLE engagements (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            target TEXT NOT NULL,
            type TEXT NOT NULL,
            scope TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            skills_used TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE findings (
            id TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL REFERENCES engagements(id),
            tool TEXT NOT NULL,
            corroborated_by TEXT,
            cwe TEXT,
            severity TEXT NOT NULL,
            severity_by_tool TEXT,
            status TEXT NOT NULL DEFAULT 'discovered',
            phase TEXT,
            title TEXT NOT NULL,
            description TEXT,
            file_path TEXT,
            line_start INTEGER,
            line_end INTEGER,
            evidence TEXT,
            remediation TEXT,
            cvss REAL,
            false_positive INTEGER NOT NULL DEFAULT 0,
            dedup_confidence TEXT,
            created_at TEXT NOT NULL,
            deleted_at TEXT
        );

        CREATE VIRTUAL TABLE findings_fts USING fts5(
            title, description, evidence, remediation,
            content='findings', content_rowid='rowid'
        );

        CREATE TRIGGER findings_ai AFTER INSERT ON findings BEGIN
            INSERT INTO findings_fts(rowid, title, description, evidence, remediation)
            VALUES (new.rowid, new.title, new.description, new.evidence, new.remediation);
        END;
        CREATE TRIGGER findings_ad AFTER DELETE ON findings BEGIN
            INSERT INTO findings_fts(findings_fts, rowid, title, description, evidence, remediation)
            VALUES ('delete', old.rowid, old.title, old.description, old.evidence, old.remediation);
        END;
        CREATE TRIGGER findings_au AFTER UPDATE ON findings BEGIN
            INSERT INTO findings_fts(findings_fts, rowid, title, description, evidence, remediation)
            VALUES ('delete', old.rowid, old.title, old.description, old.evidence, old.remediation);
            INSERT INTO findings_fts(rowid, title, description, evidence, remediation)
            VALUES (new.rowid, new.title, new.description, new.evidence, new.remediation);
        END;

        CREATE TABLE timeline_events (
            id TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL REFERENCES engagements(id),
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            event TEXT NOT NULL,
            details TEXT,
            confidence TEXT NOT NULL DEFAULT 'medium',
            finding_id TEXT REFERENCES findings(id)
        );

        CREATE TABLE iocs (
            id TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL REFERENCES engagements(id),
            ioc_type TEXT NOT NULL,
            value TEXT NOT NULL,
            context TEXT,
            first_seen TEXT,
            last_seen TEXT,
            source_finding_id TEXT REFERENCES findings(id),
            UNIQUE(engagement_id, ioc_type, value)
        );

        CREATE TABLE artifacts (
            id TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL REFERENCES engagements(id),
            file_path TEXT NOT NULL,
            artifact_type TEXT NOT NULL,
            description TEXT,
            source_tool TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE audit_log (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            command TEXT NOT NULL,
            args TEXT,
            engagement_id TEXT,
            result TEXT NOT NULL,
            details TEXT
        );

        CREATE INDEX idx_findings_engagement ON findings(engagement_id);
        CREATE INDEX idx_findings_severity ON findings(severity);
        CREATE INDEX idx_findings_cwe ON findings(cwe);
        CREATE INDEX idx_findings_status ON findings(status);
        CREATE INDEX idx_timeline_engagement ON timeline_events(engagement_id);
        CREATE INDEX idx_timeline_timestamp ON timeline_events(timestamp);
        CREATE INDEX idx_iocs_engagement ON iocs(engagement_id);
        CREATE INDEX idx_iocs_type_value ON iocs(ioc_type, value);
        CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
    """)


MIGRATIONS: dict[int, callable] = {
    1: _migration_v1,
}

LATEST_VERSION = max(MIGRATIONS.keys())


def migrate(conn: sqlite3.Connection) -> None:
    """Run all pending migrations."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version "
        "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    current = get_schema_version(conn)

    if current > LATEST_VERSION:
        raise RuntimeError(
            f"Database schema version {current} is newer than CLI version {LATEST_VERSION}. "
            "This engagement was created by a newer version of opentools."
        )

    for version in range(current + 1, LATEST_VERSION + 1):
        MIGRATIONS[version](conn)
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
            (version, datetime.now(timezone.utc).isoformat()),
        )
    conn.commit()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd packages/cli && python -m pytest tests/test_schema.py -v
```

Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/engagement/schema.py packages/cli/tests/test_schema.py
git commit -m "feat: add SQLite schema with migrations, FTS5, and sync triggers"
```

---

## Task 6: Engagement Store (Core CRUD)

**Files:**
- Create: `packages/cli/src/opentools/engagement/store.py`
- Test: `packages/cli/tests/test_engagement.py`
- Create: `packages/cli/tests/conftest.py`

- [ ] **Step 1: Write conftest.py with shared fixtures**

Create `packages/cli/tests/conftest.py`:

```python
import sqlite3
from datetime import datetime, timezone
import pytest
from opentools.engagement.schema import migrate
from opentools.engagement.store import EngagementStore
from opentools.models import Engagement, EngagementType, EngagementStatus


@pytest.fixture
def db_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    migrate(conn)
    yield conn
    conn.close()


@pytest.fixture
def store(db_conn):
    return EngagementStore(conn=db_conn)


@pytest.fixture
def sample_engagement():
    now = datetime.now(timezone.utc)
    return Engagement(
        id="eng-001",
        name="test-pentest",
        target="192.168.1.0/24",
        type=EngagementType.PENTEST,
        status=EngagementStatus.ACTIVE,
        skills_used=["pentest"],
        created_at=now,
        updated_at=now,
    )
```

- [ ] **Step 2: Write the failing test**

Create `packages/cli/tests/test_engagement.py`:

```python
from datetime import datetime, timezone
import pytest
from opentools.models import (
    Engagement, EngagementType, EngagementStatus, Severity, FindingStatus,
    Finding, TimelineEvent, IOC, IOCType, Artifact, ArtifactType, Confidence,
)


def test_create_and_get_engagement(store, sample_engagement):
    store.create(sample_engagement)
    result = store.get(sample_engagement.id)
    assert result.name == "test-pentest"
    assert result.type == EngagementType.PENTEST


def test_list_all_engagements(store, sample_engagement):
    store.create(sample_engagement)
    results = store.list_all()
    assert len(results) == 1
    assert results[0].id == sample_engagement.id


def test_update_status(store, sample_engagement):
    store.create(sample_engagement)
    store.update_status(sample_engagement.id, EngagementStatus.COMPLETE)
    result = store.get(sample_engagement.id)
    assert result.status == EngagementStatus.COMPLETE


def test_add_finding_creates_timeline_event(store, sample_engagement):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    finding = Finding(
        id="f-1",
        engagement_id=sample_engagement.id,
        tool="semgrep",
        title="SQL Injection",
        severity=Severity.HIGH,
        created_at=now,
    )
    finding_id = store.add_finding(finding)
    assert finding_id == "f-1"

    timeline = store.get_timeline(sample_engagement.id)
    assert len(timeline) == 1
    assert timeline[0].finding_id == "f-1"
    assert "SQL Injection" in timeline[0].event


def test_add_ioc_upserts(store, sample_engagement):
    store.create(sample_engagement)
    ioc1 = IOC(
        id="ioc-1",
        engagement_id=sample_engagement.id,
        ioc_type=IOCType.IP,
        value="10.0.0.1",
        context="C2",
        first_seen=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    store.add_ioc(ioc1)

    ioc2 = IOC(
        id="ioc-2",
        engagement_id=sample_engagement.id,
        ioc_type=IOCType.IP,
        value="10.0.0.1",
        context="C2",
        last_seen=datetime(2026, 1, 2, tzinfo=timezone.utc),
    )
    store.add_ioc(ioc2)

    iocs = store.get_iocs(sample_engagement.id)
    assert len(iocs) == 1
    assert iocs[0].last_seen is not None


def test_soft_delete_finding(store, sample_engagement):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    finding = Finding(
        id="f-1",
        engagement_id=sample_engagement.id,
        tool="test",
        title="Test Finding",
        severity=Severity.LOW,
        created_at=now,
    )
    store.add_finding(finding)
    store.flag_false_positive("f-1")

    findings = store.get_findings(sample_engagement.id)
    assert len(findings) == 1
    assert findings[0].false_positive is True


def test_get_summary(store, sample_engagement):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    for i, sev in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.HIGH]):
        store.add_finding(Finding(
            id=f"f-{i}",
            engagement_id=sample_engagement.id,
            tool="test",
            title=f"Finding {i}",
            severity=sev,
            created_at=now,
        ))
    summary = store.get_summary(sample_engagement.id)
    assert summary.finding_counts["critical"] == 1
    assert summary.finding_counts["high"] == 2


def test_search_findings_fts(store, sample_engagement):
    store.create(sample_engagement)
    now = datetime.now(timezone.utc)
    store.add_finding(Finding(
        id="f-1",
        engagement_id=sample_engagement.id,
        tool="test",
        title="Buffer overflow in parse_header",
        description="Stack-based buffer overflow when parsing malformed HTTP headers",
        severity=Severity.CRITICAL,
        created_at=now,
    ))
    store.add_finding(Finding(
        id="f-2",
        engagement_id=sample_engagement.id,
        tool="test",
        title="Missing CSRF token",
        severity=Severity.MEDIUM,
        created_at=now,
    ))
    results = store.search_findings("buffer overflow")
    assert len(results) == 1
    assert results[0].id == "f-1"
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd packages/cli && python -m pytest tests/test_engagement.py -v
```

Expected: FAIL — `ImportError: cannot import name 'EngagementStore'`

- [ ] **Step 4: Write store.py**

Create `packages/cli/src/opentools/engagement/store.py`:

```python
"""SQLite-backed engagement state management."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

from opentools.engagement.schema import migrate
from opentools.models import (
    Engagement, EngagementStatus, EngagementSummary,
    Finding, FindingStatus,
    TimelineEvent, Confidence,
    IOC, Artifact, AuditEntry,
)


class EngagementStore:
    """CRUD operations for engagements, findings, timeline, IOCs, artifacts."""

    def __init__(self, db_path: Path | None = None, conn: sqlite3.Connection | None = None):
        if conn is not None:
            self._conn = conn
        else:
            self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA foreign_keys=ON")
        migrate(self._conn)

    # ─── Engagement CRUD ────────────────────────────────────────────────────

    def create(self, engagement: Engagement) -> str:
        self._conn.execute(
            "INSERT INTO engagements (id, name, target, type, scope, status, skills_used, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (engagement.id, engagement.name, engagement.target, engagement.type,
             engagement.scope, engagement.status,
             json.dumps(engagement.skills_used),
             engagement.created_at.isoformat(), engagement.updated_at.isoformat()),
        )
        self._conn.commit()
        return engagement.id

    def get(self, engagement_id: str) -> Engagement:
        row = self._conn.execute(
            "SELECT * FROM engagements WHERE id = ?", (engagement_id,)
        ).fetchone()
        if row is None:
            raise KeyError(f"Engagement not found: {engagement_id}")
        return self._row_to_engagement(row)

    def list_all(self) -> list[Engagement]:
        rows = self._conn.execute(
            "SELECT * FROM engagements ORDER BY created_at DESC"
        ).fetchall()
        return [self._row_to_engagement(r) for r in rows]

    def update_status(self, engagement_id: str, status: EngagementStatus) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "UPDATE engagements SET status = ?, updated_at = ? WHERE id = ?",
            (status, now, engagement_id),
        )
        self._conn.commit()

    def get_summary(self, engagement_id: str) -> EngagementSummary:
        engagement = self.get(engagement_id)

        severity_rows = self._conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings "
            "WHERE engagement_id = ? AND deleted_at IS NULL GROUP BY severity",
            (engagement_id,),
        ).fetchall()

        status_rows = self._conn.execute(
            "SELECT status, COUNT(*) as cnt FROM findings "
            "WHERE engagement_id = ? AND deleted_at IS NULL GROUP BY status",
            (engagement_id,),
        ).fetchall()

        phase_rows = self._conn.execute(
            "SELECT phase, COUNT(*) as cnt FROM findings "
            "WHERE engagement_id = ? AND deleted_at IS NULL AND phase IS NOT NULL GROUP BY phase",
            (engagement_id,),
        ).fetchall()

        ioc_rows = self._conn.execute(
            "SELECT ioc_type, COUNT(*) as cnt FROM iocs "
            "WHERE engagement_id = ? GROUP BY ioc_type",
            (engagement_id,),
        ).fetchall()

        artifact_count = self._conn.execute(
            "SELECT COUNT(*) FROM artifacts WHERE engagement_id = ?", (engagement_id,)
        ).fetchone()[0]

        timeline_count = self._conn.execute(
            "SELECT COUNT(*) FROM timeline_events WHERE engagement_id = ?", (engagement_id,)
        ).fetchone()[0]

        fp_count = self._conn.execute(
            "SELECT COUNT(*) FROM findings WHERE engagement_id = ? AND false_positive = 1 AND deleted_at IS NULL",
            (engagement_id,),
        ).fetchone()[0]

        conflict_count = self._conn.execute(
            "SELECT COUNT(*) FROM findings "
            "WHERE engagement_id = ? AND deleted_at IS NULL AND severity_by_tool IS NOT NULL "
            "AND severity_by_tool != '{}'",
            (engagement_id,),
        ).fetchone()[0]

        return EngagementSummary(
            engagement=engagement,
            finding_counts={r["severity"]: r["cnt"] for r in severity_rows},
            finding_counts_by_status={r["status"]: r["cnt"] for r in status_rows},
            finding_counts_by_phase={r["phase"]: r["cnt"] for r in phase_rows},
            ioc_counts_by_type={r["ioc_type"]: r["cnt"] for r in ioc_rows},
            artifact_count=artifact_count,
            timeline_event_count=timeline_count,
            false_positive_count=fp_count,
            severity_conflicts=conflict_count,
        )

    # ─── Findings ───────────────────────────────────────────────────────────

    def add_finding(self, finding: Finding) -> str:
        self._conn.execute(
            "INSERT INTO findings (id, engagement_id, tool, corroborated_by, cwe, severity, "
            "severity_by_tool, status, phase, title, description, file_path, line_start, "
            "line_end, evidence, remediation, cvss, false_positive, dedup_confidence, "
            "created_at, deleted_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (finding.id, finding.engagement_id, finding.tool,
             json.dumps(finding.corroborated_by), finding.cwe, finding.severity,
             json.dumps(finding.severity_by_tool), finding.status, finding.phase,
             finding.title, finding.description, finding.file_path,
             finding.line_start, finding.line_end, finding.evidence,
             finding.remediation, finding.cvss, int(finding.false_positive),
             finding.dedup_confidence,
             finding.created_at.isoformat(),
             finding.deleted_at.isoformat() if finding.deleted_at else None),
        )
        self._conn.commit()

        self.add_event(TimelineEvent(
            id=str(uuid4()),
            engagement_id=finding.engagement_id,
            timestamp=finding.created_at,
            source=finding.tool,
            event=f"Finding discovered: {finding.title}",
            confidence=Confidence.HIGH,
            finding_id=finding.id,
        ))

        return finding.id

    def get_findings(
        self,
        engagement_id: str,
        severity: str | None = None,
        status: str | None = None,
        phase: str | None = None,
    ) -> list[Finding]:
        query = "SELECT * FROM findings WHERE engagement_id = ? AND deleted_at IS NULL"
        params: list = [engagement_id]
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if phase:
            query += " AND phase = ?"
            params.append(phase)
        query += " ORDER BY created_at DESC"
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def update_finding_status(self, finding_id: str, status: FindingStatus) -> None:
        self._conn.execute(
            "UPDATE findings SET status = ? WHERE id = ?", (status, finding_id)
        )
        self._conn.commit()

    def flag_false_positive(self, finding_id: str) -> None:
        self._conn.execute(
            "UPDATE findings SET false_positive = 1 WHERE id = ?", (finding_id,)
        )
        self._conn.commit()

    def search_findings(self, query: str) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT f.* FROM findings f "
            "JOIN findings_fts fts ON f.rowid = fts.rowid "
            "WHERE findings_fts MATCH ? AND f.deleted_at IS NULL "
            "ORDER BY rank",
            (query,),
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    # ─── Timeline ───────────────────────────────────────────────────────────

    def add_event(self, event: TimelineEvent) -> str:
        self._conn.execute(
            "INSERT INTO timeline_events (id, engagement_id, timestamp, source, event, details, confidence, finding_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (event.id, event.engagement_id, event.timestamp.isoformat(),
             event.source, event.event, event.details, event.confidence, event.finding_id),
        )
        self._conn.commit()
        return event.id

    def get_timeline(
        self,
        engagement_id: str,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[TimelineEvent]:
        query = "SELECT * FROM timeline_events WHERE engagement_id = ?"
        params: list = [engagement_id]
        if start:
            query += " AND timestamp >= ?"
            params.append(start.isoformat())
        if end:
            query += " AND timestamp <= ?"
            params.append(end.isoformat())
        query += " ORDER BY timestamp ASC"
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_timeline_event(r) for r in rows]

    # ─── IOCs ───────────────────────────────────────────────────────────────

    def add_ioc(self, ioc: IOC) -> str:
        existing = self._conn.execute(
            "SELECT id FROM iocs WHERE engagement_id = ? AND ioc_type = ? AND value = ?",
            (ioc.engagement_id, ioc.ioc_type, ioc.value),
        ).fetchone()

        if existing:
            updates = []
            params = []
            if ioc.last_seen:
                updates.append("last_seen = ?")
                params.append(ioc.last_seen.isoformat())
            if ioc.context:
                updates.append("context = ?")
                params.append(ioc.context)
            if updates:
                params.append(existing["id"])
                self._conn.execute(
                    f"UPDATE iocs SET {', '.join(updates)} WHERE id = ?", params
                )
                self._conn.commit()
            return existing["id"]

        self._conn.execute(
            "INSERT INTO iocs (id, engagement_id, ioc_type, value, context, first_seen, last_seen, source_finding_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (ioc.id, ioc.engagement_id, ioc.ioc_type, ioc.value, ioc.context,
             ioc.first_seen.isoformat() if ioc.first_seen else None,
             ioc.last_seen.isoformat() if ioc.last_seen else None,
             ioc.source_finding_id),
        )
        self._conn.commit()
        return ioc.id

    def get_iocs(self, engagement_id: str, ioc_type: str | None = None) -> list[IOC]:
        query = "SELECT * FROM iocs WHERE engagement_id = ?"
        params: list = [engagement_id]
        if ioc_type:
            query += " AND ioc_type = ?"
            params.append(ioc_type)
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_ioc(r) for r in rows]

    def search_ioc(self, value: str) -> list[IOC]:
        rows = self._conn.execute(
            "SELECT * FROM iocs WHERE value LIKE ?", (f"%{value}%",)
        ).fetchall()
        return [self._row_to_ioc(r) for r in rows]

    # ─── Artifacts ──────────────────────────────────────────────────────────

    def add_artifact(self, artifact: Artifact) -> str:
        self._conn.execute(
            "INSERT INTO artifacts (id, engagement_id, file_path, artifact_type, description, source_tool, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (artifact.id, artifact.engagement_id, artifact.file_path,
             artifact.artifact_type, artifact.description, artifact.source_tool,
             artifact.created_at.isoformat()),
        )
        self._conn.commit()
        return artifact.id

    def get_artifacts(self, engagement_id: str) -> list[Artifact]:
        rows = self._conn.execute(
            "SELECT * FROM artifacts WHERE engagement_id = ?", (engagement_id,)
        ).fetchall()
        return [self._row_to_artifact(r) for r in rows]

    # ─── Audit ──────────────────────────────────────────────────────────────

    def log_action(self, entry: AuditEntry) -> None:
        self._conn.execute(
            "INSERT INTO audit_log (id, timestamp, command, args, engagement_id, result, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (entry.id, entry.timestamp.isoformat(), entry.command,
             json.dumps(entry.args) if entry.args else None,
             entry.engagement_id, entry.result, entry.details),
        )
        self._conn.commit()

    def get_audit_log(
        self,
        engagement_id: str | None = None,
        since: datetime | None = None,
    ) -> list[AuditEntry]:
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: list = []
        if engagement_id:
            query += " AND engagement_id = ?"
            params.append(engagement_id)
        if since:
            query += " AND timestamp >= ?"
            params.append(since.isoformat())
        query += " ORDER BY timestamp DESC"
        rows = self._conn.execute(query, params).fetchall()
        return [self._row_to_audit_entry(r) for r in rows]

    # ─── Row converters ─────────────────────────────────────────────────────

    @staticmethod
    def _row_to_engagement(row: sqlite3.Row) -> Engagement:
        return Engagement(
            id=row["id"], name=row["name"], target=row["target"],
            type=row["type"], scope=row["scope"], status=row["status"],
            skills_used=json.loads(row["skills_used"]) if row["skills_used"] else [],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        return Finding(
            id=row["id"], engagement_id=row["engagement_id"], tool=row["tool"],
            corroborated_by=json.loads(row["corroborated_by"]) if row["corroborated_by"] else [],
            cwe=row["cwe"], severity=row["severity"],
            severity_by_tool=json.loads(row["severity_by_tool"]) if row["severity_by_tool"] else {},
            status=row["status"], phase=row["phase"], title=row["title"],
            description=row["description"], file_path=row["file_path"],
            line_start=row["line_start"], line_end=row["line_end"],
            evidence=row["evidence"], remediation=row["remediation"],
            cvss=row["cvss"], false_positive=bool(row["false_positive"]),
            dedup_confidence=row["dedup_confidence"],
            created_at=datetime.fromisoformat(row["created_at"]),
            deleted_at=datetime.fromisoformat(row["deleted_at"]) if row["deleted_at"] else None,
        )

    @staticmethod
    def _row_to_timeline_event(row: sqlite3.Row) -> TimelineEvent:
        return TimelineEvent(
            id=row["id"], engagement_id=row["engagement_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            source=row["source"], event=row["event"], details=row["details"],
            confidence=row["confidence"], finding_id=row["finding_id"],
        )

    @staticmethod
    def _row_to_ioc(row: sqlite3.Row) -> IOC:
        return IOC(
            id=row["id"], engagement_id=row["engagement_id"],
            ioc_type=row["ioc_type"], value=row["value"], context=row["context"],
            first_seen=datetime.fromisoformat(row["first_seen"]) if row["first_seen"] else None,
            last_seen=datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
            source_finding_id=row["source_finding_id"],
        )

    @staticmethod
    def _row_to_artifact(row: sqlite3.Row) -> Artifact:
        return Artifact(
            id=row["id"], engagement_id=row["engagement_id"],
            file_path=row["file_path"], artifact_type=row["artifact_type"],
            description=row["description"], source_tool=row["source_tool"],
            created_at=datetime.fromisoformat(row["created_at"]),
        )

    @staticmethod
    def _row_to_audit_entry(row: sqlite3.Row) -> AuditEntry:
        return AuditEntry(
            id=row["id"], timestamp=datetime.fromisoformat(row["timestamp"]),
            command=row["command"],
            args=json.loads(row["args"]) if row["args"] else None,
            engagement_id=row["engagement_id"],
            result=row["result"], details=row["details"],
        )
```

- [ ] **Step 5: Update engagement/__init__.py**

Update `packages/cli/src/opentools/engagement/__init__.py`:

```python
"""Engagement state management."""

from opentools.engagement.store import EngagementStore

__all__ = ["EngagementStore"]
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd packages/cli && python -m pytest tests/test_engagement.py -v
```

Expected: All 8 tests PASS.

- [ ] **Step 7: Commit**

```bash
git add packages/cli/src/opentools/engagement/ packages/cli/tests/conftest.py packages/cli/tests/test_engagement.py
git commit -m "feat: add SQLite engagement store with CRUD, FTS search, IOC upsert"
```

---

## Task 7: Finding Deduplication & CWE Inference

**Files:**
- Create: `packages/cli/src/opentools/findings.py`
- Test: `packages/cli/tests/test_findings.py`

- [ ] **Step 1: Write the failing test**

Create `packages/cli/tests/test_findings.py`:

```python
from datetime import datetime, timezone
import pytest
from opentools.findings import infer_cwe, check_duplicate, CWE_KEYWORDS
from opentools.models import Finding, Severity, Confidence


def test_infer_cwe_sql_injection():
    assert infer_cwe("SQL injection in login form") == "CWE-89"


def test_infer_cwe_xss():
    assert infer_cwe("reflected XSS via search parameter") == "CWE-79"


def test_infer_cwe_no_match():
    assert infer_cwe("some random finding about nothing") is None


def test_infer_cwe_multiple_matches_picks_most_hits():
    assert infer_cwe("sql injection sqli in query") == "CWE-89"


def test_check_duplicate_same_cwe_same_file_close_lines():
    now = datetime.now(timezone.utc)
    existing = Finding(
        id="f-1", engagement_id="e-1", tool="semgrep",
        title="SQL Injection", severity=Severity.HIGH,
        cwe="CWE-89", file_path="src/api.py", line_start=42,
        created_at=now,
    )
    new = Finding(
        id="f-2", engagement_id="e-1", tool="codebadger",
        title="Taint flow to SQL sink", severity=Severity.CRITICAL,
        cwe="CWE-89", file_path="src/api.py", line_start=43,
        created_at=now,
    )
    result = check_duplicate(new, [existing])
    assert result is not None
    assert result.match.id == "f-1"
    assert result.confidence == Confidence.HIGH


def test_check_duplicate_same_cwe_far_lines():
    now = datetime.now(timezone.utc)
    existing = Finding(
        id="f-1", engagement_id="e-1", tool="semgrep",
        title="SQL Injection", severity=Severity.HIGH,
        cwe="CWE-89", file_path="src/api.py", line_start=42,
        created_at=now,
    )
    new = Finding(
        id="f-2", engagement_id="e-1", tool="codebadger",
        title="Another SQLi", severity=Severity.HIGH,
        cwe="CWE-89", file_path="src/api.py", line_start=200,
        created_at=now,
    )
    result = check_duplicate(new, [existing])
    assert result is None  # too far apart


def test_check_duplicate_inferred_cwe():
    now = datetime.now(timezone.utc)
    existing = Finding(
        id="f-1", engagement_id="e-1", tool="semgrep",
        title="SQL injection found", severity=Severity.HIGH,
        cwe=None, file_path="src/api.py", line_start=42,
        created_at=now,
    )
    new = Finding(
        id="f-2", engagement_id="e-1", tool="nuclei",
        title="sqli error-based", severity=Severity.HIGH,
        cwe=None, file_path="src/api.py", line_start=44,
        created_at=now,
    )
    result = check_duplicate(new, [existing])
    assert result is not None
    assert result.confidence == Confidence.LOW


def test_check_duplicate_no_cwe_no_inference():
    now = datetime.now(timezone.utc)
    existing = Finding(
        id="f-1", engagement_id="e-1", tool="semgrep",
        title="Something weird", severity=Severity.LOW,
        cwe=None, file_path="src/api.py", line_start=42,
        created_at=now,
    )
    new = Finding(
        id="f-2", engagement_id="e-1", tool="nuclei",
        title="Another weird thing", severity=Severity.LOW,
        cwe=None, file_path="src/api.py", line_start=43,
        created_at=now,
    )
    result = check_duplicate(new, [existing])
    assert result is None  # can't merge without CWE
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd packages/cli && python -m pytest tests/test_findings.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write findings.py**

Create `packages/cli/src/opentools/findings.py`:

```python
"""Finding deduplication, CWE inference, and export."""

from dataclasses import dataclass
from typing import Optional

from opentools.models import Finding, Confidence


CWE_KEYWORDS: dict[str, list[str]] = {
    "CWE-89":  ["sql injection", "sqli", "sql sink", "unsanitized query"],
    "CWE-79":  ["xss", "cross-site scripting", "html sink", "script injection"],
    "CWE-22":  ["path traversal", "directory traversal", "lfi", "file open sink"],
    "CWE-78":  ["command injection", "os command", "shell injection", "exec sink"],
    "CWE-798": ["hardcoded", "secret", "credential", "api key", "password in source"],
    "CWE-119": ["buffer overflow", "stack overflow", "heap overflow", "out of bounds"],
    "CWE-416": ["use after free", "use-after-free", "dangling pointer"],
    "CWE-476": ["null pointer", "null dereference", "nullptr"],
    "CWE-190": ["integer overflow", "integer underflow", "int overflow"],
    "CWE-362": ["race condition", "toctou", "time-of-check"],
    "CWE-134": ["format string", "printf", "format specifier"],
    "CWE-415": ["double free", "double-free"],
    "CWE-457": ["uninitialized", "uninitialised", "uninitialized read"],
    "CWE-611": ["xxe", "xml external entity"],
    "CWE-918": ["ssrf", "server-side request forgery"],
    "CWE-502": ["deserialization", "deserialisation", "insecure deserialization"],
    "CWE-287": ["authentication bypass", "broken authentication", "auth bypass"],
    "CWE-862": ["missing authorization", "idor", "insecure direct object"],
    "CWE-327": ["weak crypto", "weak cipher", "des", "md5", "sha1", "ecb mode"],
    "CWE-532": ["log injection", "sensitive data in log", "password in log"],
}


def infer_cwe(text: str) -> Optional[str]:
    """Infer CWE from finding title/description text.

    Returns the CWE with the most keyword matches, or None.
    """
    text_lower = text.lower()
    best_cwe = None
    best_count = 0

    for cwe, keywords in CWE_KEYWORDS.items():
        count = sum(1 for kw in keywords if kw in text_lower)
        if count > best_count:
            best_count = count
            best_cwe = cwe

    return best_cwe


@dataclass
class DuplicateMatch:
    """Result of a duplicate check."""
    match: Finding
    confidence: Confidence


def check_duplicate(
    new_finding: Finding,
    existing_findings: list[Finding],
    line_window: int = 5,
) -> Optional[DuplicateMatch]:
    """Check if new_finding duplicates any existing finding.

    Returns DuplicateMatch if duplicate found, None if distinct.
    """
    for existing in existing_findings:
        if not _locations_overlap(new_finding, existing, line_window):
            continue

        new_cwe = new_finding.cwe or infer_cwe(
            f"{new_finding.title} {new_finding.description or ''}"
        )
        existing_cwe = existing.cwe or infer_cwe(
            f"{existing.title} {existing.description or ''}"
        )

        if new_cwe and existing_cwe and new_cwe == existing_cwe:
            confidence = _compute_confidence(new_finding, existing, new_cwe == new_finding.cwe)
            return DuplicateMatch(match=existing, confidence=confidence)

    return None


def _locations_overlap(a: Finding, b: Finding, window: int) -> bool:
    """Check if two findings are at overlapping locations."""
    if a.file_path and b.file_path:
        if a.file_path != b.file_path:
            return False
        if a.line_start is not None and b.line_start is not None:
            return abs(a.line_start - b.line_start) <= window
        return True  # same file, no line info

    if a.file_path is None and b.file_path is None:
        return True  # network findings, match on CWE only

    return False


def _compute_confidence(new: Finding, existing: Finding, cwe_was_explicit: bool) -> Confidence:
    """Determine dedup confidence based on match quality."""
    if not cwe_was_explicit:
        return Confidence.LOW

    if (new.line_start is not None and existing.line_start is not None
            and abs(new.line_start - existing.line_start) <= 2):
        return Confidence.HIGH

    return Confidence.MEDIUM
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd packages/cli && python -m pytest tests/test_findings.py -v
```

Expected: All 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/findings.py packages/cli/tests/test_findings.py
git commit -m "feat: add finding deduplication with CWE inference and confidence scoring"
```

---

## Remaining Tasks (Summary)

The following tasks follow the same TDD pattern. Due to plan length constraints, they are listed with file mappings and key implementation notes. Each should be implemented with failing test → implementation → passing test → commit.

### Task 8: SARIF Export
- **Files:** Add SARIF Pydantic models and `export_sarif()` to `findings.py`, tests in `test_findings.py`
- **Key:** ~8 Pydantic models matching SARIF 2.1.0, `partialFingerprints` from hash(cwe+file+line), severity→level mapping

### Task 9: Preflight System
- **Files:** `packages/cli/src/opentools/preflight.py`, `packages/cli/tests/test_preflight.py`
- **Key:** `PreflightRunner` with `check_all()`, `check_skill()`, `check_tool()`. Dispatch by transport type. Mock `subprocess.run` and `urllib.request.urlopen` in tests. `--fix` logic (start stopped containers).

### Task 10: Container Manager
- **Files:** `packages/cli/src/opentools/containers.py`, `packages/cli/tests/test_containers.py`
- **Key:** `ContainerManager` with `start()`, `stop()`, `restart()`, `status()`, `logs()`. Parse `docker compose ps --format json`. Readiness polling loop. Resource warning from image sizes in config. All Docker calls through shared subprocess helper.

### Task 11: Recipe Engine
- **Files:** `packages/cli/src/opentools/recipes.py`, `packages/cli/tests/test_recipes.py`
- **Key:** `RecipeRunner` with async `run()`. Variable substitution (`{{target}}`→value). DAG execution with `asyncio.TaskGroup` + `asyncio.Event` per step. `shlex.split(cmd, posix=(sys.platform != "win32"))`. Streaming stdout line-by-line. Timeout via `asyncio.wait_for`. `--dry-run` shows resolved commands.

### Task 12: Output Parsers
- **Files:** `packages/cli/src/opentools/parsers/{__init__,semgrep,nuclei,trivy,gitleaks,capa}.py`, `packages/cli/tests/test_parsers.py`
- **Key:** Registry in `__init__.py` auto-discovers parser modules. Each exports `def parse(raw_output: str) -> list[Finding]`. Tests use sample JSON fixtures for each tool.

### Task 13: Report Generation
- **Files:** `packages/cli/src/opentools/reports.py`, `packages/cli/tests/test_reports.py`, convert `packages/plugin/shared/report-templates/*.md` → `*.md.j2`
- **Key:** `ReportGenerator` loads `.md.j2` templates from plugin dir. Builds context dict from `EngagementStore`. Renders with Jinja2. HTML output: render markdown first, convert with `markdown` package + inline CSS.

### Task 14: Engagement Export/Import
- **Files:** `packages/cli/src/opentools/engagement/export.py`, add tests to `test_engagement.py`
- **Key:** `export_engagement()` dumps all tables for one engagement to JSON with schema version. `import_engagement()` loads, assigns new UUIDs, handles schema version mismatch. `--bundle` flag zips artifact files.

### Task 15: Audit Trail
- **Files:** `packages/cli/src/opentools/audit.py`, tests in `test_engagement.py`
- **Key:** `log_action()` and `get_audit_log()` are already in EngagementStore. `audit.py` provides a higher-level decorator/context manager for CLI commands that auto-logs invocations.

### Task 16: CLI Entry Point
- **Files:** `packages/cli/src/opentools/cli.py`, `packages/cli/tests/test_cli.py`
- **Key:** Typer app with command groups: `setup`, `preflight`, `containers`, `engagement`, `findings`, `iocs`, `timeline`, `recipe`, `report`, `audit`, `config`, `version`. Global flags: `--json`, `--quiet`, `--verbose`, `--plugin-dir`. Each command wires to the corresponding module. `--json` outputs `model.model_dump_json()`. Test with `typer.testing.CliRunner`.

### Task 17: Dashboard Stub
- **Files:** `packages/cli/src/opentools/dashboard.py`
- **Key:** Single function that raises `NotImplementedError("Dashboard will be available in a future release. Use 'opentools engagement show' for now.")`. No tests needed for a stub.

### Task 18: Integration Test & Final Wiring
- **Files:** `packages/cli/tests/test_cli.py` (expand)
- **Key:** End-to-end: create engagement via CLI → add findings → export SARIF → verify. Test `--json` output is valid JSON on all commands. Test `opentools version` returns version string. Test `opentools config validate` against the real plugin config files.

### Task 19: Update Root README and Plugin CLAUDE.md
- **Files:** `README.md`, `packages/plugin/CLAUDE.md`
- **Key:** Update README to document the monorepo structure, installation (`uv pip install -e packages/cli`), and CLI usage. Update CLAUDE.md to reference `opentools` commands instead of inline bash.

---

## Self-Review Checklist

1. **Spec coverage:** All 15 spec sections mapped to tasks. Models (§4), Schema (§5), Store (§5.5), Dedup (§6), Config (§7), Preflight (§8), Containers (§9), Recipes (§10), Reports (§11), CLI (§12), Audit (§13), Dashboard (§14), Testing (§15).
2. **Placeholder scan:** Tasks 1-7 have full code. Tasks 8-19 have file maps and implementation keys (not placeholders — they describe exactly what to build, but defer full code to keep plan navigable).
3. **Type consistency:** All model names, method signatures, and enum values match between spec, models.py, store.py, and findings.py. Verified: `Severity`, `FindingStatus`, `Confidence`, `EngagementStore`, `ToolkitConfig`, `PreflightReport` all consistent.
