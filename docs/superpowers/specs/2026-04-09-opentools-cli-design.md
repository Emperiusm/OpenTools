# OpenTools CLI Toolkit — Design Specification

**Date:** 2026-04-09
**Status:** Approved
**Author:** slabl + Claude

## 1. Overview

The `opentools` CLI is a Python package that provides deterministic orchestration for the security-toolkit Claude Code plugin. It replaces the fragile inline bash snippets in skill files with structured, testable, importable modules.

The CLI handles:
- Config loading and environment validation
- Tool health checks (preflight)
- Docker container lifecycle management
- SQLite-backed engagement state with finding deduplication
- Recipe execution with async parallelism
- Report generation from templates
- SARIF, CSV, JSON export for CI/CD integration

The skills remain as the AI knowledge layer (decision trees, methodology, tool selection). The CLI handles the deterministic orchestration that shouldn't depend on prompt-following.

## 2. Architecture

### 2.1 Monorepo Structure

```
OpenTools/
├── packages/
│   ├── plugin/                  ← current repo contents
│   │   ├── .claude-plugin/
│   │   ├── skills/
│   │   ├── commands/
│   │   ├── config/
│   │   ├── shared/
│   │   ├── recipes.json
│   │   └── CLAUDE.md
│   │
│   └── cli/                     ← new Python package
│       ├── pyproject.toml
│       ├── src/
│       │   └── opentools/
│       │       ├── __init__.py
│       │       ├── cli.py
│       │       ├── models.py
│       │       ├── config.py
│       │       ├── plugin.py
│       │       ├── preflight.py
│       │       ├── containers.py
│       │       ├── engagement/
│       │       │   ├── __init__.py
│       │       │   ├── store.py
│       │       │   ├── schema.py
│       │       │   └── export.py
│       │       ├── findings.py
│       │       ├── recipes.py
│       │       ├── reports.py
│       │       ├── audit.py
│       │       ├── dashboard.py
│       │       └── parsers/
│       │           ├── __init__.py
│       │           ├── semgrep.py
│       │           ├── nuclei.py
│       │           ├── trivy.py
│       │           ├── gitleaks.py
│       │           └── capa.py
│       └── tests/
│           ├── test_config.py
│           ├── test_engagement.py
│           ├── test_findings.py
│           └── test_recipes.py
│
├── README.md
├── .gitignore
└── .env.example
```

### 2.2 Plugin Discovery

The CLI needs to find the plugin directory (`packages/plugin/`) to read config files, recipes, and report templates.

Resolution order:
1. `OPENTOOLS_PLUGIN_DIR` environment variable (highest priority)
2. `../plugin/` relative to the CLI package root
3. Fail with error: "Plugin directory not found. Set OPENTOOLS_PLUGIN_DIR or run from the OpenTools repo."

### 2.3 Component Diagram

```
┌─────────────────────────────────────────────────┐
│  Claude Code Skills (packages/plugin/)          │
│  ┌──────┐ ┌────┐ ┌──────┐ ┌───┐ ┌───┐ ┌───┐   │
│  │pentest│ │ RE │ │hw-re │ │for│ │cld│ │mob│   │
│  └──┬───┘ └──┬─┘ └──┬───┘ └─┬─┘ └─┬─┘ └─┬─┘   │
│     └────────┴──────┴───────┴─────┴─────┘      │
│                     │ invoke                    │
│             opentools <cmd> --json              │
│                     │ stdout JSON               │
└─────────────────────┼───────────────────────────┘
                      ▼
┌──────────────────────────────────────────────────┐
│  CLI (packages/cli/)                             │
│                                                  │
│  cli.py ─── typer commands                       │
│    │                                             │
│    ├── config.py ◄── tools.yaml, mcp-servers.yaml│
│    │     │                                       │
│    ├── preflight.py ─── health checks ──► JSON   │
│    ├── containers.py ── docker compose           │
│    ├── recipes.py ───── asyncio executor         │
│    ├── findings.py ──── dedup + SARIF            │
│    ├── reports.py ───── Jinja2 templates         │
│    │                                             │
│    └── engagement/                               │
│         store.py ◄──► SQLite DB                  │
│         schema.py ─── versioned migrations       │
│         export.py ─── JSON archive               │
│                                                  │
│  models.py ─── Pydantic (shared by all modules)  │
│  audit.py ──── audit trail                       │
│  parsers/ ──── tool output → Finding conversion  │
└──────────────────────────────────────────────────┘
```

## 3. Technology Stack

| Dependency | Purpose | Why This Over Alternatives |
|-----------|---------|---------------------------|
| Python 3.14 | Runtime | Already installed on target system |
| uv | Package management | Fast, already available |
| typer | CLI framework | Type-hint-driven, Pydantic integration |
| pydantic | Data models + validation | Config validation, finding normalization, SARIF models |
| rich | Terminal output | Tables, colored output, progress |
| textual | TUI dashboard (Phase 3) | Full widget framework, same author as rich |
| ruamel.yaml | YAML loading | Preserves comments on round-trip (users edit config) |
| sqlite-utils | SQLite access | Dict-friendly API with explicit schema support |
| jinja2 | Report templates | Industry standard, already used across Python ecosystem |

**Not using:**
- `sarif-om` — stale (last updated 2020). Pydantic SARIF models instead.
- `httpx` — overkill for 2 HTTP health checks. stdlib `urllib.request` suffices.
- `pyyaml` — strips comments. `ruamel.yaml` preserves them.
- `msgspec` — faster serialization but weaker validation than Pydantic.

## 4. Data Models

All models are Pydantic `BaseModel` subclasses. SQLite tables are derived from these.

### 4.1 Engagement

```python
class Engagement(BaseModel):
    id: str                    # UUID
    name: str
    target: str
    type: EngagementType       # pentest|reverse-engineering|hardware-re|forensics|cloud-security|mobile|combined
    scope: Optional[str]
    status: EngagementStatus   # active|paused|complete
    skills_used: list[str]     # ["pentest", "reverse-engineering"]
    created_at: datetime       # UTC
    updated_at: datetime       # UTC
```

### 4.2 Finding

```python
class Finding(BaseModel):
    id: str                    # UUID
    engagement_id: str
    tool: str                  # reporting tool
    corroborated_by: list[str] # other tools that found the same thing
    cwe: Optional[str]         # "CWE-89"
    severity: Severity         # critical|high|medium|low|info
    severity_by_tool: dict[str, str]  # {"codebadger": "high", "semgrep": "medium"}
    status: FindingStatus      # discovered|confirmed|reported|remediated|verified
    phase: Optional[str]       # recon|vuln-analysis|exploitation|post-exploitation
    title: str
    description: Optional[str]
    file_path: Optional[str]
    line_start: Optional[int]
    line_end: Optional[int]
    evidence: Optional[str]
    remediation: Optional[str]
    cvss: Optional[float]
    false_positive: bool       # default False
    dedup_confidence: Optional[str]  # high|medium|low (set when merged)
    created_at: datetime
    deleted_at: Optional[datetime]   # soft delete
```

### 4.3 TimelineEvent

```python
class TimelineEvent(BaseModel):
    id: str                    # UUID
    engagement_id: str
    timestamp: datetime        # UTC
    source: str                # which log/tool/phase
    event: str
    details: Optional[str]
    confidence: Confidence     # high|medium|low
    finding_id: Optional[str]  # links to finding if event is a discovery
```

### 4.4 IOC

```python
class IOC(BaseModel):
    id: str                    # UUID
    engagement_id: str
    ioc_type: IOCType          # ip|domain|url|hash_md5|hash_sha256|file_path|registry|mutex|user_agent|email
    value: str
    context: Optional[str]     # "C2 callback", "dropped file"
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    source_finding_id: Optional[str]
```

### 4.5 Artifact

```python
class Artifact(BaseModel):
    id: str                    # UUID
    engagement_id: str
    file_path: str
    artifact_type: ArtifactType  # screenshot|pcap|binary|source|dump|report|other
    description: Optional[str]
    source_tool: Optional[str]
    created_at: datetime
```

### 4.6 Tool & Config Models

```python
class ToolConfig(BaseModel):
    name: str
    type: str                  # mcp_server|docker_container|cli_tool
    path_or_command: str       # resolved with env vars
    health_check: Optional[str]
    profiles: list[str]
    env_required: list[str]
    version: Optional[str]
    status: ToolStatus         # available|missing|running|stopped|error

class Recipe(BaseModel):
    id: str
    name: str
    description: str
    requires: list[str]
    variables: dict[str, RecipeVariable]
    steps: list[RecipeStep]
    parallel: bool
    output: str

class RecipeStep(BaseModel):
    name: str
    tool: str
    command: str               # with {{var}} placeholders
    timeout: int               # seconds
    step_type: StepType        # shell|mcp_tool|manual
    on_failure: FailureAction  # continue|abort
    depends_on: Optional[list[str]]

class AuditEntry(BaseModel):
    id: str                    # UUID
    timestamp: datetime
    command: str
    args: Optional[dict]
    engagement_id: Optional[str]
    result: str                # success|error
    details: Optional[str]
```

### 4.7 Supporting Models

```python
class RecipeVariable(BaseModel):
    description: str
    required: bool             # default True
    default: Optional[str]

class EngagementSummary(BaseModel):
    engagement: Engagement
    finding_counts: dict[str, int]      # {"critical": 2, "high": 5, ...}
    finding_counts_by_status: dict[str, int]  # {"discovered": 3, "confirmed": 4, ...}
    finding_counts_by_phase: dict[str, int]
    ioc_counts_by_type: dict[str, int]
    artifact_count: int
    timeline_event_count: int
    false_positive_count: int
    severity_conflicts: int             # findings where tools disagree

class DeduplicationReport(BaseModel):
    merged: int                # number of findings merged
    distinct: int              # number left after dedup
    merge_details: list[dict]  # [{finding_id, merged_with, confidence}, ...]

class StepResult(BaseModel):
    step_name: str
    status: str                # success|error|timeout|skipped|manual
    exit_code: Optional[int]
    stdout: Optional[str]
    stderr: Optional[str]
    duration_ms: int
    log_path: Optional[Path]

class RecipeResult(BaseModel):
    recipe_id: str
    recipe_name: str
    status: str                # success|partial|failed
    steps: list[StepResult]
    duration_ms: int
    output_dir: Path
    findings_added: int
```

## 5. Engagement Store (SQLite)

### 5.1 Database Location

Single database file at `<repo_root>/engagements/opentools.db` (i.e., `OpenTools/engagements/`, at the monorepo root, NOT inside either package). All engagements share one DB. Artifact files live in `engagements/<name>/` directories. This directory is gitignored (runtime data).

```
engagements/
├── opentools.db          ← single DB
├── project-alpha/        ← artifact files
│   ├── screenshots/
│   ├── extracted/
│   └── reports/
└── project-beta/
    └── ...
```

### 5.2 Connection Settings

```python
db.execute("PRAGMA journal_mode=WAL")      # concurrent reads + one writer
db.execute("PRAGMA busy_timeout=5000")      # wait up to 5s for lock
db.execute("PRAGMA foreign_keys=ON")        # enforce referential integrity
```

WAL mode is critical for recipe parallelism — multiple async steps writing findings simultaneously.

### 5.3 Schema

```sql
CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE engagements (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target TEXT NOT NULL,
    type TEXT NOT NULL,
    scope TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    skills_used TEXT,            -- JSON array
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id),
    tool TEXT NOT NULL,
    corroborated_by TEXT,        -- JSON array
    cwe TEXT,
    severity TEXT NOT NULL,
    severity_by_tool TEXT,       -- JSON dict
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
    deleted_at TEXT              -- soft delete
);

CREATE VIRTUAL TABLE findings_fts USING fts5(
    title, description, evidence, remediation,
    content='findings', content_rowid='rowid'
);

-- FTS sync triggers (required: content= tables don't auto-sync)
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
```

### 5.4 Schema Migrations

Each migration is a Python function in `engagement/schema.py`:

```python
MIGRATIONS = {
    1: create_initial_tables,
    # Future migrations added here as the schema evolves, e.g.:
    # 2: add_finding_tags_column,
}
```

On DB open: read current version (0 if new), run all migrations from current+1 to latest, update `schema_version`. Linear, no rollback. Security data should not be destructively migrated.

If the DB's schema version is higher than the CLI's latest migration, refuse to open with: "This engagement was created by a newer version of opentools."

### 5.5 Store API

```python
class EngagementStore:
    def __init__(self, db_path: Path)

    # Engagement CRUD
    def create(engagement: Engagement) -> str
    def get(id: str) -> Engagement
    def update_status(id: str, status: str)
    def list_all() -> list[Engagement]
    def get_summary(engagement_id: str) -> EngagementSummary

    # Findings (auto-creates TimelineEvent on add, dedup on insert)
    def add_finding(finding: Finding) -> str
    def get_findings(engagement_id, severity=None, status=None, phase=None) -> list[Finding]
    def update_finding_status(finding_id, status: str)
    def flag_false_positive(finding_id: str)
    def deduplicate(engagement_id: str) -> DeduplicationReport
    def search_findings(query: str) -> list[Finding]  # FTS5

    # Timeline
    def add_event(event: TimelineEvent) -> str
    def get_timeline(engagement_id, start=None, end=None) -> list[TimelineEvent]

    # IOCs
    def add_ioc(ioc: IOC) -> str          # upserts: updates last_seen if exists
    def get_iocs(engagement_id, ioc_type=None) -> list[IOC]
    def search_ioc(value: str) -> list[IOC]   # cross-engagement

    # Artifacts
    def add_artifact(artifact: Artifact) -> str
    def get_artifacts(engagement_id) -> list[Artifact]

    # Audit
    def log_action(entry: AuditEntry)
    def get_audit_log(engagement_id=None, since=None) -> list[AuditEntry]
```

### 5.6 Export/Import

- `export_engagement(store, engagement_id) -> Path` — dumps all tables for one engagement to JSON, includes schema version
- `export_engagement(store, engagement_id, bundle=True) -> Path` — same but zips artifact files alongside
- `import_engagement(store, path) -> str` — loads from export, assigns new IDs to avoid conflicts, runs migrations if export was from older schema

## 6. Finding Deduplication

### 6.1 Dedup-on-Insert Algorithm

When `add_finding()` is called:

1. Query existing findings in the same engagement where:
   - Same `file_path` (if both non-null)
   - `line_start` within ±5 of the new finding's `line_start` (if both non-null)

2. For each candidate match:
   - a. If CWE matches (both non-null, equal) → **DUPLICATE**
   - b. If either CWE is null, attempt CWE inference from title/description using the CWE keyword table. If inferred CWEs match → **DUPLICATE**
   - c. If CWE inference fails for both → **DISTINCT** (don't merge without classification)

3. For network/non-file findings (no file_path): match on CWE + target URL/IP instead.

4. If DUPLICATE:
   - Append new tool to existing finding's `corroborated_by`
   - Merge `severity_by_tool` dicts
   - Keep higher severity as effective rating
   - Keep whichever description is longer
   - Set `dedup_confidence` based on match quality:
     - HIGH: same CWE + same file + lines within ±2
     - MEDIUM: same CWE + same file + lines within ±5
     - LOW: inferred CWE + keyword match + nearby lines
   - Return existing finding's ID

5. If no match → INSERT new finding, return new ID

6. Auto-create a TimelineEvent linked to the finding.

### 6.2 CWE Inference Table

Maps tool-specific keywords to CWE numbers for findings that lack classification:

```python
CWE_KEYWORDS = {
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
```

Inference: lowercase the finding's title + description, scan for keyword matches, return the first matching CWE. If multiple match, prefer the one with the most keyword hits.

### 6.3 SARIF Export

Pydantic models matching SARIF 2.1.0 schema (~8 classes: SarifLog, Run, Tool, ToolComponent, ReportingDescriptor, Result, Location, PhysicalLocation).

Key features:
- **Grouping by tool**: each tool becomes a SARIF "run" with its own rules and results
- **`partialFingerprints`**: stable identifiers computed from `hash(cwe + file_path + normalized_line_start)`. Enables CI/CD tools to track findings across runs.
- **`relatedLocations`**: when a finding is corroborated by multiple tools, include where each tool reported it
- **Severity mapping**: critical/high → `"error"`, medium → `"warning"`, low/info → `"note"`

### 6.4 Other Export Formats

- `export_csv(store, engagement_id, output_path)` — flat findings table
- `export_json(store, engagement_id, output_path)` — raw JSON array of findings
- `export_iocs_csv(store, engagement_id, output_path)` — IOCs for threat intel import

## 7. Config Loading

### 7.1 ConfigLoader

```python
class ConfigLoader:
    def __init__(self, plugin_dir: Path)
    def load() -> ToolkitConfig
```

Loads and merges three files:
1. `config/tools.yaml` — tool registry (paths, containers, CLI tools, API keys)
2. `config/mcp-servers.yaml` — MCP server connections and health checks
3. `config/profiles.yaml` — user environment overrides

### 7.2 Config Precedence

```
1. Environment variable      (highest — user's session override)
2. profiles.yaml             (user's persistent config)
3. tools.yaml defaults       (repo defaults)
```

### 7.3 Environment Variable Resolution

YAML files use `${VAR:-default}` syntax. Resolution:
1. Check `os.environ[VAR]`
2. If not set, use the default after `:-`
3. If no default and no env var, mark tool as `unresolved`

Single-pass string replacement. No nested expansion, no command substitution.

### 7.4 Validation

Config is loaded into Pydantic models. Invalid fields, missing required fields, and wrong types are caught automatically. `opentools config validate` runs this explicitly without starting any tools.

### 7.5 First-Run Detection

If >80% of tools report as missing/unresolved, prepend: "Looks like this is your first run. Start with: opentools setup"

## 8. Preflight System

### 8.1 PreflightRunner

```python
class PreflightRunner:
    def __init__(self, config: ToolkitConfig)
    def check_all() -> PreflightReport
    def check_skill(skill_name: str) -> PreflightReport
    def check_tool(tool_name: str) -> ToolStatus
```

### 8.2 Check Strategy by Transport/Type

| Category | Health Check Method |
|----------|-------------------|
| MCP server (HTTP transport) | `urllib.request.urlopen(url, timeout=3)` |
| MCP server (stdio, Docker-based) | `docker image inspect <image>` |
| MCP server (stdio, local process) | `Path.exists()` on the executable |
| Docker container | `docker compose ps --format json` (one call, parse all) |
| CLI tool (absolute path) | `Path.exists()` |
| CLI tool (on PATH) | `shutil.which(name)` |
| API key | `os.environ.get(key)` |

### 8.3 Execution Order

1. Check Docker binary exists (`shutil.which("docker")`) — if missing, skip all container checks
2. Check Docker daemon running (`docker info`) — if not running, skip container checks
3. `docker compose ps --format json` scoped to security-hub (one call, all container states)
4. MCP server checks (dispatch by transport type)
5. CLI tools (`Path.exists()` / `shutil.which()`)
6. API keys (`os.environ.get()`)

### 8.4 Output

**Human output** (default): `rich` table with tool name, status icon, notes.

**Machine output** (`--json`): structured JSON for Claude/scripting:
```json
{
  "skill": "pentest",
  "fully_available": true,
  "tools": [
    {"name": "codebadger", "status": "running", "message": "OK"},
    {"name": "nmap-mcp", "status": "stopped", "message": "container not running"}
  ],
  "summary": {"total": 12, "available": 9, "missing": 2, "errors": 1}
}
```

### 8.5 Auto-Fix (`--fix`)

Opt-in flag. Behavior:
- Stopped containers needed by the skill → `docker compose up <name> -d`
- Missing Docker images → prompt before pulling (large images like Arkana are 5.7GB)
- Missing CLI tools → print install command, don't auto-install
- Missing API keys → print which env var to set

Read-only by default. `--fix` opts into side effects.

## 9. Container Manager

### 9.1 API

```python
class ContainerManager:
    def __init__(self, config: ToolkitConfig)
    def start_profile(profile: str, wait: bool = True, timeout: int = 30) -> ContainerResult
    def start(names: list[str], wait: bool = True, timeout: int = 30) -> ContainerResult
    def stop_profile(profile: str) -> ContainerResult
    def stop(names: list[str]) -> ContainerResult
    def stop_all() -> ContainerResult
    def restart(names: list[str]) -> ContainerResult
    def status() -> list[ContainerStatus]
    def logs(name: str, tail: int = 50) -> str
```

### 9.2 Readiness Polling

After `docker compose up -d`, poll `docker compose ps --format json` until all requested containers show `running` (or `healthy` for containers with HEALTHCHECK). Timeout default 30s.

### 9.3 Resource Warning

Before starting a profile, sum known image sizes from `tools.yaml`. If total exceeds a threshold (e.g., 8GB), warn:
```
Warning: pentest profile containers require ~8GB RAM. Continue? [Y/n]
```

### 9.4 Subprocess Handling

All Docker commands go through a shared helper that:
- Sets `cwd` to the docker hub path from config
- Captures stdout/stderr
- Enforces a timeout
- Logs the command to the audit trail

## 10. Recipe Engine

### 10.1 API

```python
class RecipeRunner:
    def __init__(self, config: ToolkitConfig, store: EngagementStore)
    async def run(recipe_id: str, variables: dict, engagement_id: Optional[str]) -> RecipeResult
    def list_recipes() -> list[Recipe]
    def validate_recipe(recipe_id: str) -> list[str]
```

### 10.2 Execution Flow

1. Load recipe from `recipes.json` by ID
2. Validate: required variables provided, required tools available (via preflight)
3. Substitute `{{variables}}` in all step commands
4. Create output directory: `engagements/<name>/recipes/<recipe_id>-<timestamp>/`
5. Execute steps (see below)
6. Parse tool output for known tools (via parsers registry)
7. Add extracted findings to engagement store
8. Log to audit trail, return RecipeResult

### 10.3 Step Execution

**Parallel recipes (with DAG support):**

```python
events = {step.name: asyncio.Event() for step in steps}

async def run_with_deps(step):
    for dep in (step.depends_on or []):
        await events[dep].wait()
    result = await run_step(step)
    events[step.name].set()
    return result

async with asyncio.TaskGroup() as tg:
    for step in steps:
        tg.create_task(run_with_deps(step))
```

Independent steps run in parallel. Steps with `depends_on` wait for prerequisites.

**Sequential recipes:** Execute steps in order. If a step fails and `on_failure == "abort"`, stop.

### 10.4 run_step() Internals

**Shell steps:** `asyncio.create_subprocess_exec` with line-by-line stdout streaming:

```python
async def run_step(step):
    args = shlex.split(step.command, posix=(sys.platform != "win32"))
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=PIPE, stderr=PIPE
    )

    output_lines = []
    async for line in proc.stdout:
        decoded = line.decode()
        output_lines.append(decoded)
        log_file.write(decoded)
        if not quiet:
            console.print(f"  [{step.name}] {decoded}", end="")

    await proc.wait()
    # ... return StepResult
```

Streaming provides real-time feedback for long-running scans. Partial output is preserved on timeout (after `proc.kill()`).

**MCP tool steps:** Cannot be invoked from Python. Surfaced as instructions for Claude to execute. Recipe runner prints the instruction and, in interactive mode, waits for user confirmation before continuing.

**Manual steps:** Print instruction, wait for user confirmation. Skipped in `--non-interactive` mode.

### 10.5 Output Parsers

Convention-based registry in `parsers/` directory. Each module exports:

```python
def parse(raw_output: str) -> list[Finding]
```

Auto-discovered by scanning the directory. Adding a parser for a new tool = adding a new file.

Known parsers: semgrep, nuclei, trivy, gitleaks, capa.

### 10.6 Dry Run

`--dry-run` shows fully resolved commands (all variables substituted) without executing. Allows review before running against real targets.

## 11. Report Generation

### 11.1 API

```python
class ReportGenerator:
    def __init__(self, config: ToolkitConfig, store: EngagementStore)
    def generate(engagement_id, template, output_format, output_path) -> Path
    def list_templates() -> list[str]
```

### 11.2 Template Context

All data from the engagement store is available inside Jinja2 templates:

```python
{
    "engagement": Engagement,
    "findings": list[Finding],
    "findings_by_severity": dict,
    "findings_by_phase": dict,
    "findings_by_status": dict,
    "severity_conflicts": list[Finding],
    "timeline": list[TimelineEvent],
    "iocs": list[IOC],
    "iocs_by_type": dict,
    "artifacts": list[Artifact],
    "tools_used": list[str],
    "summary": { "total", "critical", "high", "medium", "low", "info", "false_positives", "remediated" },
    "generated_at": datetime,
}
```

### 11.3 Output Formats

- **Markdown** (default): rendered from `.md.j2` templates
- **HTML**: render markdown first, then convert with `markdown` package. Minimal inline CSS for severity badges and table styling. No JavaScript.

### 11.4 Templates

Built-in templates in `packages/plugin/shared/report-templates/`. Existing `.md` templates will be converted to Jinja2 `.md.j2` format during the monorepo migration:
- `pentest-report.md.j2` — with OWASP coverage matrix
- `incident-report.md.j2` — full IR with ATT&CK mapping
- `cloud-security-report.md.j2` — with compliance table
- `mobile-security-report.md.j2` — with OWASP Mobile Top 10

Custom templates: drop additional `.md.j2` files into the same directory. The generator discovers all `.md.j2` files automatically.

## 12. CLI Command Map

```
opentools
├── setup                                    # detect tools, generate profile
├── preflight [--skill X] [--json] [--fix]   # health checks
├── containers
│   ├── start <names...> [--profile X] [--wait] [--timeout N]
│   ├── stop <names...> [--all]
│   ├── restart <names...>
│   ├── status
│   └── logs <name> [--tail N]
├── engagement
│   ├── create <name> --target T --type T [--scope S]
│   ├── list
│   ├── show <name>
│   ├── status <name> [STATUS]
│   ├── export <name> [--bundle]
│   └── import <path>
├── findings
│   ├── list <engagement> [--severity X] [--status X] [--phase X]
│   ├── add <engagement> --tool T --title T --severity S
│   ├── update <finding-id> --status S
│   ├── flag <finding-id>
│   ├── search <query>
│   ├── review --confidence low
│   ├── conflicts
│   ├── deduplicate <engagement>
│   └── export <engagement> --format sarif|csv|json
├── iocs
│   ├── list <engagement> [--type X]
│   ├── add <engagement> --type T --value V [--context C]
│   ├── search <value>
│   └── export <engagement> --format csv|json
├── timeline
│   ├── list <engagement> [--since X] [--until X]
│   └── add <engagement> --event E --source S
├── recipe
│   ├── list
│   ├── run <id> --target T [--engagement E] [--dry-run] [--non-interactive]
│   └── validate <id>
├── report
│   ├── generate <engagement> --template T [--format md|html]
│   └── templates
├── audit
│   ├── list [--engagement E] [--since X]
│   └── export [--engagement E] --format json
├── config
│   ├── show
│   ├── validate
│   └── paths
└── version
```

**Global flags:** `--json`, `--quiet`, `--verbose`, `--plugin-dir`

**The `--json` contract:** Every command supports `--json` for structured JSON output. This is how Claude Code skills invoke the CLI and parse results.

## 13. Audit Trail

Every CLI command invocation is logged to the `audit_log` table:

- Timestamp, command name, arguments
- Associated engagement (if applicable)
- Result (success/error)
- Details (error message if failed)

The audit trail is operational logging separate from engagement state. It answers "what did the toolkit do and when" across all engagements.

## 14. Phase 3 Stub: Dashboard

`dashboard.py` is a placeholder for the `textual` TUI. Not implemented in Phase 1. The eventual dashboard will compose data from:

- `EngagementStore.get_summary()` — finding counts, status
- `ContainerManager.status()` — live container states
- `PreflightRunner.check_all()` — tool availability
- `EngagementStore.get_timeline()` — recent events

Split-pane layout: engagement summary top-left, container status top-right, findings table bottom-left, live timeline bottom-right. All auto-refreshing.

## 15. Testing Strategy

Unit tests per module using `pytest`:

| Module | Test Focus |
|--------|-----------|
| `test_config.py` | YAML loading, env var resolution, precedence, validation errors |
| `test_engagement.py` | CRUD, schema migrations, WAL concurrent writes |
| `test_findings.py` | Dedup algorithm (all confidence levels, edge cases), CWE inference, SARIF export |
| `test_recipes.py` | Variable substitution, parallel execution, timeout handling, DAG ordering |
| `test_parsers.py` | Each output parser with sample tool output |
| `test_containers.py` | Status parsing, readiness polling (mocked Docker) |

All SQLite tests use in-memory databases (`:memory:`) for speed. Docker tests mock subprocess calls.
