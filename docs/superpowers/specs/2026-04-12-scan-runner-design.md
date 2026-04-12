# Scan Runner Design Specification

**Date:** 2026-04-12
**Status:** Draft
**Scope:** Core scan orchestration engine for the OpenTools security toolkit

---

## Overview

The scan-runner is a task-graph-based security scan orchestration engine that dynamically selects tools based on target type, executes them with full concurrency control, parses and deduplicates findings across tools, and persists results into the engagement store. It supports two execution modes: **auto** (fully programmatic, no LLM cost) and **assisted** (Claude steers mid-scan, adds follow-up tools, and analyzes results).

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Surface model | Hybrid — CLI, web API, Claude skill share one engine | Follows existing RecipeRunner pattern; depth lives in the engine, each surface provides UX |
| Relationship to RecipeRunner | Sibling engines, shared infrastructure | Different concerns — scan-runner is a scan orchestrator, RecipeRunner is a generic step executor; forcing one to wrap the other would fight the abstraction |
| Tool selection | Auto-detect + named profiles + Claude analysis | Auto-detection covers common cases, profiles give repeatability, Claude adds intelligent steering |
| Execution model | Task graph (DAG) with reactive edges | Combines pipeline clarity with event-driven flexibility; DAG is auditable and visualizable |
| Engagement binding | Auto-create engagement, ephemeral option with importable output | Findings always have a home; ephemeral mode outputs structured JSON/SARIF for import later |
| Scan entity | First-class Scan model | Enables scan history, diffing, re-run, and audit trail |
| MCP execution | Built-in MCP client from day one | Uniform tool execution — auto mode gets full depth including CodeBadger, Arkana, GhydraMCP without Claude in the loop |

---

## 1. Data Model

### 1.1 Enums

```python
class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"           # assisted mode: waiting for Claude/user decision
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class ScanMode(StrEnum):
    AUTO = "auto"
    ASSISTED = "assisted"

class TargetType(StrEnum):
    SOURCE_CODE = "source_code"
    URL = "url"
    BINARY = "binary"
    DOCKER_IMAGE = "docker_image"
    APK = "apk"
    NETWORK = "network"

class TaskType(StrEnum):
    SHELL = "shell"
    DOCKER_EXEC = "docker_exec"
    MCP_CALL = "mcp_call"
    PREFLIGHT = "preflight"
    PROVISION = "provision"

class TaskStatus(StrEnum):
    PENDING = "pending"
    BLOCKED = "blocked"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

class ExecutionTier(StrEnum):
    FAST = "fast"               # <30s expected, scheduled immediately
    NORMAL = "normal"           # 30s-300s
    HEAVY = "heavy"             # >300s, high resource, limited concurrency

class EvidenceQuality(StrEnum):
    PROVEN = "proven"           # 1.0 — confirmed exploitability
    TRACED = "traced"           # 0.85 — data flow / taint trace
    STRUCTURED = "structured"   # 0.7 — structured rule match with context
    PATTERN = "pattern"         # 0.5 — pattern / regex match
    HEURISTIC = "heuristic"     # 0.3 — heuristic / guess

class LocationPrecision(StrEnum):
    EXACT_LINE = "exact_line"
    LINE_RANGE = "line_range"
    FUNCTION = "function"
    FILE = "file"
    ENDPOINT = "endpoint"
    HOST = "host"
```

### 1.2 Core Models

#### Scan

```python
class Scan(BaseModel):
    id: str
    engagement_id: str
    target: str
    target_type: TargetType
    resolved_path: str | None = None
    target_metadata: dict = {}              # SourceMetadata, etc.
    profile: str | None                     # named profile or None for auto-detect
    profile_snapshot: dict                  # frozen profile at scan time
    mode: ScanMode
    status: ScanStatus
    config: ScanConfig | None = None
    baseline_scan_id: str | None = None
    tools_planned: list[str] = []
    tools_completed: list[str] = []
    tools_failed: list[str] = []
    finding_count: int = 0
    estimated_duration_seconds: int | None = None
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
```

#### ScanConfig

```python
class ScanConfig(BaseModel):
    severity_threshold: Severity = Severity.INFO
    max_concurrent_tasks: int = 8
    max_duration_seconds: int | None = None     # scan-level timeout
    timeout_override: int | None = None         # per-task default
    tool_args: dict[str, dict] = {}             # per-tool argument overrides
    notifications: ScanNotification | None = None
    steering_frequency: str = "phase_boundary"  # every_task | phase_boundary | findings_only | manual

class ScanNotification(BaseModel):
    channels: list[NotificationChannel] = []

class NotificationChannel(BaseModel):
    type: str                   # "webhook", "desktop", "sse"
    url: str | None = None
    events: list[str] = ["scan_completed", "scan_failed", "critical_finding_discovered"]
```

#### ScanTask (DAG Nodes)

```python
class ScanTask(BaseModel):
    id: str
    scan_id: str
    name: str                           # human-readable: "nmap-port-scan"
    tool: str                           # tool registry name
    task_type: TaskType
    command: str | None = None          # for shell / docker_exec
    mcp_server: str | None = None       # for mcp_call
    mcp_tool: str | None = None
    mcp_args: dict | None = None
    depends_on: list[str] = []          # task IDs
    reactive_edges: list[ReactiveEdge] = []
    status: TaskStatus = TaskStatus.PENDING
    priority: int = 50                  # 0=highest, 100=lowest
    tier: ExecutionTier = ExecutionTier.NORMAL
    resource_group: str | None = None   # concurrency group
    retry_policy: RetryPolicy | None = None
    cache_key: str | None = None
    parser: str | None = None
    tool_version: str | None = None     # captured at execution time
    exit_code: int | None = None
    stdout: str | None = None
    stderr: str | None = None
    output_hash: str | None = None      # SHA-256 of stdout
    duration_ms: int | None = None
    cached: bool = False
    spawned_by: str | None = None       # task ID or "claude"
    spawned_reason: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None

class RetryPolicy(BaseModel):
    max_retries: int = 2
    backoff_seconds: float = 5.0
    retry_on: list[str] = ["timeout", "connection_error"]
```

#### ReactiveEdge

```python
class ReactiveEdge(BaseModel):
    id: str
    trigger_task_id: str
    evaluator: str                      # "builtin:open_ports_to_nuclei" or "claude"
    condition: str | None = None        # optional filter: "exit_code == 0"
    spawns: list[ScanTask] | None = None  # pre-defined tasks (builtin edges)
    max_spawns: int = 20                # hard cap per edge instance
    max_spawns_per_trigger: int = 5
    cooldown_seconds: float = 0
    budget_group: str | None = None
    min_upstream_confidence: float = 0.5
```

### 1.3 Finding Models

#### RawFinding (pre-dedup, per tool)

```python
class RawFinding(BaseModel):
    id: str
    scan_task_id: str
    scan_id: str
    tool: str
    raw_severity: str
    title: str
    canonical_title: str | None = None
    description: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    url: str | None = None
    evidence: str | None = None
    evidence_quality: EvidenceQuality
    evidence_hash: str
    cwe: str | None = None
    location_fingerprint: str
    location_precision: LocationPrecision
    parser_version: str
    parser_confidence: float
    raw_output_excerpt: str | None = None
    discovered_at: datetime
    causal_chain: list[str] | None = None   # upstream task IDs
```

#### DeduplicatedFinding (canonical per engagement)

```python
class DeduplicatedFinding(BaseModel):
    id: str
    engagement_id: str
    finding_id: str | None = None       # link to engagement-level Finding
    fingerprint: str
    raw_finding_ids: list[str] = []
    tools: list[str] = []
    corroboration_count: int = 1
    confidence_score: float
    severity_consensus: str
    canonical_title: str
    cwe: str | None = None
    location_fingerprint: str
    location_precision: LocationPrecision
    evidence_quality_best: EvidenceQuality
    previously_marked_fp: bool = False
    suppressed: bool = False
    suppression_rule_id: str | None = None
    status: FindingStatus = FindingStatus.DISCOVERED
    last_confirmed_scan_id: str | None = None
    last_confirmed_at: datetime | None = None
    first_seen_scan_id: str
    created_at: datetime
    updated_at: datetime
```

#### Finding Correlation

```python
class FindingCorrelation(BaseModel):
    id: str
    engagement_id: str
    scan_id: str
    finding_ids: list[str]
    correlation_type: str               # "same_endpoint", "same_cve", "attack_chain", "kill_chain"
    narrative: str
    severity: str
    kill_chain_phases: list[str] | None = None
    created_at: datetime
```

#### Remediation Group

```python
class RemediationGroup(BaseModel):
    id: str
    engagement_id: str
    scan_id: str
    action: str                         # "Upgrade lodash from 4.17.15 to 4.17.21"
    action_type: str                    # "dependency_upgrade", "code_fix", "config_change"
    finding_ids: list[str]
    findings_count: int
    max_severity: str
    effort_estimate: str | None = None  # "low", "medium", "high"
    created_at: datetime
```

### 1.4 Supporting Models

#### Suppression Rule

```python
class SuppressionRule(BaseModel):
    id: str
    scope: str                          # "global", "engagement", "scan"
    engagement_id: str | None = None
    rule_type: str                      # "path_pattern", "cwe", "severity_below", "tool"
    pattern: str
    reason: str
    created_by: str
    created_at: datetime
    expires_at: datetime | None = None
```

#### Finding Annotation

```python
class FindingAnnotation(BaseModel):
    id: str
    finding_fingerprint: str
    engagement_id: str | None = None
    annotation_type: str                # "false_positive", "severity_override", "note"
    value: str
    created_by: str                     # "user:web", "user:cli", "claude:assisted"
    created_at: datetime
```

#### Scan Attestation

```python
class ScanAttestation(BaseModel):
    scan_id: str
    findings_hash: str                  # SHA-256 of sorted canonical finding list
    profile_hash: str
    tool_versions: dict[str, str]
    signature: str                      # HMAC-SHA256 with configurable key
    created_at: datetime
```

#### Tool Effectiveness

```python
class ToolEffectiveness(BaseModel):
    tool: str
    target_type: str
    total_findings: int = 0
    confirmed_findings: int = 0
    false_positive_count: int = 0
    false_positive_rate: float = 0.0
    avg_duration_seconds: float = 0.0
    sample_count: int = 0
    updated_at: datetime
```

#### Scan Batch

```python
class ScanBatch(BaseModel):
    id: str
    scan_ids: list[str] = []
    max_parallel_scans: int = 2
    status: str = "pending"             # pending, running, completed, failed
    created_at: datetime
    completed_at: datetime | None = None
```

#### Existing Model Changes

The existing `Finding` model gains one field:

```python
class Finding(BaseModel):
    ...
    scan_id: str | None = None          # links to Scan that discovered it
```

---

## 2. Engine Architecture

### 2.1 Package Layout

```
packages/cli/src/opentools/scanner/
├── __init__.py
├── api.py              # ScanAPI — unified entry point for all surfaces
├── engine.py           # ScanEngine — DAG executor
├── planner.py          # ScanPlanner — target detection, profile resolution, graph building
├── profiles.py         # Profile definitions + auto-detect logic
├── models.py           # All scan-specific models
├── store.py            # ScanStoreProtocol + SqliteScanStore
├── executor/
│   ├── __init__.py
│   ├── base.py         # TaskExecutor protocol + TaskOutput
│   ├── shell.py        # ShellExecutor — subprocess with streaming
│   ├── docker.py       # DockerExecExecutor
│   ├── mcp.py          # McpExecutor — MCP client (stdio + HTTP)
│   └── pool.py         # AdaptiveResourcePool with priority heap
├── parsing/
│   ├── __init__.py
│   ├── router.py       # ParserRouter — builtin + plugin discovery
│   ├── normalization.py # NormalizationEngine — locations, CWEs, severities, titles
│   ├── dedup.py        # DedupEngine — bloom filter + precision-aware fuzzy match
│   ├── engagement_dedup.py # Cross-scan dedup within engagement
│   ├── confidence.py   # CorroborationScorer + ConfidenceDecay
│   ├── suppression.py  # SuppressionEngine
│   ├── correlation.py  # FindingCorrelationEngine — attack chains
│   ├── remediation.py  # RemediationGrouper
│   └── lifecycle.py    # FindingLifecycle — auto state transitions
├── reactive.py         # ReactiveEdge evaluators (builtin rules)
├── steering.py         # SteeringInterface + ClaudeSteering + SteeringThrottle
├── cache.py            # OutputCache + ScanCache (content fingerprint)
├── fp_memory.py        # False-positive memory
├── target.py           # TargetDetector + TargetValidator + SourceMetadata
├── diff.py             # ScanDiff — baseline comparison
├── export.py           # ScanResultExporter — JSON, SARIF, CSV, Markdown, HTML, STIX
├── importer.py         # ScanResultImporter — JSON and SARIF import
├── notifications.py    # Webhook, desktop, SSE notification dispatch
├── attestation.py      # ScanAttestation generation + verification
├── effectiveness.py    # ToolEffectivenessTracker — auto-tuning from history
├── trend.py            # TrendDetector — cross-engagement pattern detection
├── cwe.py              # CWEHierarchy — parent/child, OWASP mapping
├── cancellation.py     # CancellationToken
├── estimate.py         # ProgressEstimator — duration estimation from history
├── data/
│   ├── cwe_hierarchy.json
│   ├── cwe_owasp_map.json
│   ├── cwe_aliases.json
│   ├── title_normalization.json
│   ├── severity_maps.json
│   └── parser_confidence.json
└── profiles/
    ├── source_quick.yaml
    ├── source_full.yaml
    ├── web_quick.yaml
    ├── web_full.yaml
    ├── binary_triage.yaml
    ├── network_recon.yaml
    ├── container_audit.yaml
    └── apk_analysis.yaml
```

### 2.2 ScanEngine — DAG Executor

The core orchestrator. Maintains the task graph, schedules tasks respecting priority and concurrency, dispatches to executors, streams output to parsers, evaluates reactive edges, and handles cancellation/retry/caching.

```python
class ScanEngine:
    def __init__(
        self,
        resource_pool: AdaptiveResourcePool,
        executors: dict[TaskType, TaskExecutor],
        parser_router: ParserRouter,
        dedup_engine: DedupEngine,
        engagement_dedup: EngagementDedupEngine,
        corroboration_scorer: CorroborationScorer,
        suppression_engine: SuppressionEngine,
        correlation_engine: FindingCorrelationEngine,
        remediation_grouper: RemediationGrouper,
        lifecycle: FindingLifecycle,
        fp_memory: FPMemory,
        cache: OutputCache,
        scan_store: ScanStoreProtocol,
        event_bus: EventBus,
        cancellation: CancellationToken,
        estimator: ProgressEstimator,
        effectiveness: ToolEffectivenessTracker,
        trend_detector: TrendDetector,
        steering: SteeringInterface | None = None,
    ): ...

    async def run(self, plan: ScanPlan) -> ScanResult:
        """Execute the full scan DAG."""
        ...

    async def _schedule_loop(self) -> None:
        """Main loop: pick ready tasks from ready-set, respect concurrency, dispatch."""
        # Incremental readiness tracking:
        #   When task T completes, check only T's direct dependents
        #   If all deps satisfied → add to ready_set
        #   Scheduler pops highest-priority task from ready_set
        ...

    async def _execute_task(self, task: ScanTask) -> TaskOutput:
        """Check cache → acquire resource → dispatch to executor → stream to parser."""
        # 1. Cache check: if cache_key exists and matches, return cached findings
        # 2. Acquire resource from pool (priority-aware, blocks if full)
        # 3. Dispatch to appropriate executor (shell/docker/mcp)
        # 4. Stream output through: OutputBuffer → OutputValidator → Parser → pipeline
        # 5. Release resource
        # 6. Populate cache on success
        # 7. Handle retry on transient failure per RetryPolicy
        ...

    async def _evaluate_edges(self, task: ScanTask, output: TaskOutput) -> list[ScanTask]:
        """Run reactive edge evaluators, return new tasks."""
        # 1. Run builtin evaluators
        # 2. Dedup spawned tasks against existing graph (prevent double-spawn)
        # 3. Check budget caps (max_spawns, max_spawns_per_trigger)
        # 4. Check confidence threshold (min_upstream_confidence)
        # 5. Cycle detection: reject tasks that would create DAG cycles
        # 6. If steering is active and threshold met, invoke Claude
        # 7. Add new tasks to graph, update ready-set
        ...

    async def pause(self) -> None:
        """Stop scheduling new tasks. In-flight tasks run to completion."""
        ...

    async def resume(self) -> None:
        """Resume scheduling from where we left off."""
        ...
```

### 2.3 Task Executors

All executors implement the same protocol:

```python
class TaskExecutor(Protocol):
    async def execute(
        self, task: ScanTask, on_output: Callable[[bytes], None],
        cancellation: CancellationToken,
    ) -> TaskOutput: ...

class TaskOutput(BaseModel):
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    cached: bool = False
```

#### ShellExecutor

Async subprocess with streaming stdout, timeout, and cancellation. Uses `run_streaming()` from the shared infrastructure module.

#### DockerExecExecutor

Wraps `docker exec <container> <command>` with the same streaming/timeout/cancellation semantics.

#### McpExecutor

Built-in MCP client using the Python MCP SDK:

- **HTTP transport**: direct HTTP to servers with HTTP endpoints (e.g., CodeBadger on `localhost:4242`)
- **Stdio transport**: spawn server process, communicate via JSON-RPC over stdin/stdout
- **Connection pool**: one connection per server, reused across tasks within a scan
- **Lazy connections**: connect on first task dispatch to each server, not eagerly at scan start
- **Resilience**: auto-reconnect with exponential backoff (max 3 attempts), periodic health ping, clean teardown on scan end
- **Tool discovery**: verify tool exists via `tools/list` before invocation, cache tool list per-connection

### 2.4 Adaptive Resource Pool

Priority-aware concurrency control with system-load monitoring:

```python
class AdaptiveResourcePool:
    # Global limit: max_concurrent_tasks from ScanConfig (default 8)
    # Per-group limits:
    #   "shell": 6
    #   "docker": 4
    #   MCP servers: 1 each (single-connection)
    # Priority heap: highest-priority waiter gets the next available slot
    # Adaptive: monitors CPU/memory every 5s
    #   CPU > 90% or memory > 85% → reduce limit by 1
    #   CPU < 50% and memory < 60% and waiters queued → increase limit by 1
    #   Floor: 2 (always make progress)
    #   Ceiling: configured max
```

### 2.5 Cancellation

Cooperative cancellation propagated through the entire scan:

```python
class CancellationToken:
    async def cancel(self, reason: str) -> None: ...
    @property
    def is_cancelled(self) -> bool: ...
```

In-flight tasks receive SIGTERM → grace period → SIGKILL. MCP connections get clean disconnect. Reactive edges don't fire for cancelled tasks. Findings discovered before cancellation are persisted.

### 2.6 Output Streaming and Backpressure

```python
class OutputBuffer:
    memory_limit: int = 10 * 1024 * 1024    # 10MB in-memory
    # Above limit → spill to temp file, parser reads from file
    # Provides backpressure: if parser is slower than tool output, buffer absorbs the difference
    # If buffer fills AND disk spill exceeds 500MB → signal tool to slow down or abort
```

### 2.7 Liveness Monitoring

Periodic health checks on active resource groups during task execution:

- Docker containers: `docker inspect --format '{{.State.Running}}'` every 30s
- MCP servers: JSON-RPC `ping` every 30s
- If a resource dies mid-task, the task fails immediately instead of hanging until timeout

### 2.8 Speculative Provisioning

Preflight and provision tasks run concurrently at scan start, not sequentially. If preflight discovers a tool is missing, the engine cancels the corresponding provision task and removes downstream scan tasks from the graph. Zero wasted latency when everything is healthy.

### 2.9 Connection Pre-warming

When `ScanAPI.plan()` is called, infrastructure warming starts in the background:
- Docker containers begin starting
- MCP connections begin establishing
- Warming expires after 5 minutes if `execute()` isn't called

---

## 3. Profiles, Auto-Detect, and Reactive Edges

### 3.1 Target Detection

```python
class TargetDetector:
    def detect(self, target: str) -> DetectedTarget:
        # Resolution order (first match wins):
        # 1. Explicit override: --type source_code
        # 2. URL pattern: http(s)://... → URL
        # 3. CIDR/IP pattern → NETWORK
        # 4. Docker image pattern: image:tag, registry/image → DOCKER_IMAGE
        # 5. File extension: .apk → APK, .exe/.dll/.elf/.so/.dylib → BINARY
        # 6. Directory with source files → SOURCE_CODE
        # 7. GitHub URL → clone to temp dir, then SOURCE_CODE
        # 8. Ambiguous → raise

class DetectedTarget(BaseModel):
    target_type: TargetType
    resolved_path: str | None
    original_target: str
    metadata: dict

class SourceMetadata(BaseModel):
    languages: list[str]
    framework_hints: list[str]
    has_dockerfile: bool
    has_package_lock: bool
    estimated_loc: int
    content_hash: str
```

### 3.2 Target Validation

```python
class TargetValidator:
    # URL: HTTP HEAD, check status, follow redirects
    # Source: path exists, contains source files, not empty
    # Binary: magic bytes check (PE/ELF/Mach-O header)
    # Network: at least one host responds
    # APK: valid ZIP with AndroidManifest.xml
    # Docker: image exists locally or pullable
```

### 3.3 Scan Profiles

```python
class ScanProfile(BaseModel):
    id: str
    name: str
    description: str
    target_types: list[TargetType]
    extends: str | None = None          # parent profile for inheritance
    add_tools: list[ProfileTool] = []   # merged on top of parent
    remove_tools: list[str] = []        # tool names to exclude from parent
    phases: list[ProfilePhase] = []
    reactive_edges: list[ReactiveEdgeTemplate] = []
    default_config: ScanConfig | None = None
    override_config: ScanConfig | None = None

class ProfilePhase(BaseModel):
    name: str
    tools: list[ProfileTool]
    parallel: bool = True

class ProfileTool(BaseModel):
    tool: str
    task_type: TaskType
    command_template: str | None = None
    mcp_server: str | None = None
    mcp_tool: str | None = None
    mcp_args_template: dict | None = None
    parser: str | None = None
    priority: int = 50
    tier: ExecutionTier = ExecutionTier.NORMAL
    resource_group: str | None = None
    retry_policy: RetryPolicy | None = None
    cache_key_template: str | None = None
    optional: bool = False
    condition: str | None = None        # "language in ['python', 'java']"
    reactive_edges: list[ReactiveEdgeTemplate] | None = None
```

### 3.4 Built-in Profiles

| Profile | Target Type | Tools |
|---------|------------|-------|
| `source-quick` | source_code | semgrep, gitleaks |
| `source-full` | source_code | semgrep, gitleaks, codebadger (CPG + all detectors), trivy (conditional) |
| `web-quick` | url | whatweb, waybackurls, nuclei, nikto |
| `web-full` | url | whatweb, waybackurls, ffuf, nuclei, nikto, sqlmap, semgrep (optional) |
| `binary-triage` | binary | arkana (format detection, packing, entropy, triage, capa, strings, vulns), codebadger (conditional on decompiled source), yara, capa |
| `network-recon` | network | nmap, masscan + reactive edges for service-specific follow-up |
| `container-audit` | docker_image | trivy, gitleaks |
| `apk-analysis` | apk | jadx (decompile), then semgrep, gitleaks, codebadger |

Auto-detect maps `TargetType` to default profile:

```python
DEFAULT_PROFILES: dict[TargetType, str] = {
    TargetType.SOURCE_CODE: "source-full",
    TargetType.URL: "web-full",
    TargetType.BINARY: "binary-triage",
    TargetType.DOCKER_IMAGE: "container-audit",
    TargetType.APK: "apk-analysis",
    TargetType.NETWORK: "network-recon",
}
```

### 3.5 Adaptive Rule Selection

Tool-specific rulesets selected based on target metadata:

- **Semgrep**: language → rulesets (`p/python`, `p/java`), framework → rulesets (`p/django`, `p/react`)
- **Nuclei**: framework detected → template directories (`wordpress/`, `apache/`)
- **CodeBadger**: language → CPG frontend selection (`javasrc`, `pythonsrc`)

### 3.6 Reactive Edge Evaluators

Builtin evaluators codify common security workflows:

| Evaluator | Trigger | Action |
|-----------|---------|--------|
| `OpenPortsToVulnScan` | nmap finds open HTTP port | Spawn nuclei + nikto. Port 3306 → sqlmap. |
| `WebFrameworkToRuleset` | whatweb detects framework | Add framework-specific semgrep/nuclei rulesets |
| `PackingDetectedToUnpack` | Arkana detects packing | Spawn unpacking + re-analysis |
| `HighSeverityToDeepDive` | Critical/high finding | Spawn targeted deep analysis (full profiles only) |

All evaluators support: budget caps, dedup (no double-spawn), confidence thresholds, and conditional edge chains (spawned tasks can carry their own reactive edges).

### 3.7 Claude Steering — Assisted Mode

```python
class SteeringInterface(Protocol):
    async def on_task_completed(
        self, task: ScanTask, output: TaskOutput,
        findings_so_far: list[DeduplicatedFinding],
        graph_state: GraphSnapshot,
        threat_summary: ThreatSummary,
    ) -> SteeringDecision: ...

    async def on_scan_paused(self, reason: str, graph_state: GraphSnapshot) -> SteeringDecision: ...
    async def on_authorization_required(self, action_description: str, risk_level: str) -> bool: ...

class SteeringDecision(BaseModel):
    action: SteeringAction              # CONTINUE, ADD_TASKS, PAUSE, ABORT
    new_tasks: list[ScanTask] = []
    reasoning: str                      # audit trail
    authorization_required: bool = False
    research_requests: list[ResearchRequest] | None = None

class ResearchRequest(BaseModel):
    query_type: str                     # "cve_lookup", "threat_intel", "documentation"
    query: str
```

#### Rolling Threat Summary

Cumulative scan intelligence maintained for Claude's steering context:

```python
class ThreatSummary(BaseModel):
    attack_surface: AttackSurface
    findings_by_severity: dict[str, int]
    top_findings: list[FindingSummary]
    coverage_map: dict[str, CoverageStatus]
    uncovered_areas: list[str]
    technology_stack: list[str]
    causal_chains: list[CausalChain]

class AttackSurface(BaseModel):
    open_ports: list[PortInfo]
    endpoints_discovered: list[str]
    technologies: list[TechFingerprint]
    credentials_found: int
    external_services: list[str]
```

#### Steering Throttle

Controls when Claude is actually consulted to manage LLM cost:

| Frequency | Consult on |
|-----------|-----------|
| `every_task` | Every task completion (expensive, thorough) |
| `phase_boundary` | Phase transitions + critical/high findings (default) |
| `findings_only` | Only when findings are discovered |
| `manual` | Only when explicitly triggered |

Claude always sees critical/high findings and scan completion regardless of throttle setting.

---

## 4. Surface Integration

### 4.1 Unified Entry Point

```python
class ScanAPI:
    async def plan(self, target, profile, mode, engagement_id,
                   config_overrides, add_tools, remove_tools,
                   baseline_scan_id) -> ScanPlan: ...
    async def execute(self, plan, on_progress) -> ScanResult: ...
    async def execute_ephemeral(self, plan, on_progress) -> EphemeralResult: ...
    async def pause(self, scan_id) -> None: ...
    async def resume(self, scan_id) -> None: ...
    async def cancel(self, scan_id, reason) -> None: ...
    async def diff(self, scan_id, baseline_id) -> ScanDiff: ...
```

### 4.2 Progress Event Protocol

```python
class ProgressEventType(StrEnum):
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_PAUSED = "scan_paused"
    SCAN_RESUMED = "scan_resumed"
    TASK_QUEUED = "task_queued"
    TASK_STARTED = "task_started"
    TASK_PROGRESS = "task_progress"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    TASK_SKIPPED = "task_skipped"
    TASK_CACHED = "task_cached"
    TASK_RETRYING = "task_retrying"
    FINDING_DISCOVERED = "finding_discovered"
    FINDING_CORRELATED = "finding_correlated"
    EDGE_FIRED = "edge_fired"
    STEERING_DECISION = "steering_decision"
    THREAT_SUMMARY_UPDATED = "threat_summary_updated"
    RESOURCE_WARNING = "resource_warning"

class ProgressEvent(BaseModel):
    id: str                             # for SSE reconnection
    type: ProgressEventType
    timestamp: datetime
    scan_id: str
    sequence: int                       # monotonic ordering
    task_id: str | None = None
    data: dict
    tasks_total: int
    tasks_completed: int
    tasks_running: int
    findings_total: int
    elapsed_seconds: float
    estimated_remaining_seconds: float | None
```

Events are persisted to the scan store and fan out to multiple subscribers via EventBus. SSE reconnection replays from `Last-Event-ID`.

### 4.3 CLI Surface

New `opentools scan` subcommand group:

| Command | Purpose |
|---------|---------|
| `scan run <target>` | Plan and execute a scan |
| `scan plan <target>` | Show what would run without executing |
| `scan status <scan_id>` | Show scan status |
| `scan cancel <scan_id>` | Cancel a running scan |
| `scan resume <scan_id>` | Resume a failed/cancelled scan |
| `scan diff <scan_id> <baseline_id>` | Compare two scans |
| `scan history` | List past scans |
| `scan profiles` | List available profiles |
| `scan import <file>` | Import JSON/SARIF into engagement |
| `scan findings <scan_id>` | Show findings from running or completed scan |
| `scan steering-log <scan_id>` | Show Claude's steering decisions |
| `scan batch <targets_file>` | Batch scan multiple targets |

Key flags: `--profile`, `--mode auto|assisted`, `--engagement`, `--ephemeral`, `--output`, `--format json|sarif|csv|md|html|stix`, `--add-tool`, `--remove-tool`, `--baseline`, `--severity`, `--concurrency`, `--timeout`, `--dry-run`.

CLI progress display uses Rich live rendering with task progress table, live finding count, and streaming top findings.

### 4.4 Web API Surface

New FastAPI router at `/api/v1/scans`:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/scans` | POST | Create and start a scan |
| `/api/v1/scans` | GET | List scans (filterable by engagement) |
| `/api/v1/scans/batch` | POST | Queue multiple scans |
| `/api/v1/scans/profiles` | GET | List available profiles |
| `/api/v1/scans/import` | POST | Import findings from file |
| `/api/v1/scans/{id}` | GET | Get scan detail |
| `/api/v1/scans/{id}/tasks` | GET | Get task DAG with status |
| `/api/v1/scans/{id}/findings` | GET | Get deduplicated findings |
| `/api/v1/scans/{id}/stream` | GET | SSE event stream (with reconnection) |
| `/api/v1/scans/{id}/pause` | POST | Pause scan |
| `/api/v1/scans/{id}/resume` | POST | Resume scan |
| `/api/v1/scans/{id}/cancel` | POST | Cancel scan |
| `/api/v1/scans/{id}/diff/{baseline}` | GET | Diff two scans |
| `/api/v1/scans/{id}/steering-log` | GET | Get Claude steering log |

Web frontend subscribes to progress via SSE using the existing store pattern. SSE supports cursor-based reconnection via the `Last-Event-ID` header — events are replayed from the persisted event store.

### 4.5 Claude Skill Surface

New `/scan` command in the plugin. In auto mode, Claude runs `opentools scan run` and presents results. In assisted mode, the scan engine communicates with Claude via a structured JSON protocol over stdin/stdout — Claude reads progress events, makes steering decisions, and writes them back. Claude's `reasoning` field is persisted in the steering log for full audit trail.

Authorization gates: Claude presents authorization requests to the user before active exploitation tools (sqlmap, active injection testing). Engine pauses, user approves/rejects, engine resumes.

---

## 5. Finding Dedup Pipeline

### 5.1 Full Pipeline

```
Tool stdout (streaming bytes)
    → OutputBuffer (backpressure, 10MB memory, disk spillover)
    → OutputValidator (format check per tool — rejects malformed)
    → ParserRouter (builtin + plugin parsers, hot-loadable)
    → Parser (tool-specific, sets evidence_quality, yields RawFinding incrementally)
    → TitleNormalizer (canonical finding names from mapping table)
    → NormalizationEngine (locations, CWEs, severities — thread pool, cached)
    → SuppressionEngine (path patterns, CWE rules, severity thresholds)
    → DedupEngine (bloom filter fast-path, precision-aware fuzzy match)
    → EngagementDedupEngine (cross-scan reconciliation)
    → CorroborationScorer (evidence quality + tool diversity + effectiveness)
    → FindingLifecycle (auto-transition: discovered → confirmed)
    → FPMemory + ConfidenceDecay (flag known FPs, decay stale confidence)
    → CorrelationEngine (attack chains, kill chain, causal chains)
    → TrendDetector (cross-engagement pattern detection)
    → RemediationGrouper (group findings by shared fix)
    → ScanStore.save() (immediate, not batched)
    → EventBus.publish(FINDING_DISCOVERED)
    → LiveExporter (snapshot available at any point)
```

### 5.2 Normalization

Standardizes findings across tools for comparable dedup:

- **Paths**: resolve to relative, normalize separators (`C:\...\src\api\users.py` → `src/api/users.py`)
- **Line numbers**: overlap detection for ranges (semgrep line 42 vs codebadger lines 40-45)
- **URLs**: normalize scheme, trailing slash, query param order
- **CWEs**: alias resolution (`"sqli"` → `CWE-89`) with fallback inference from title
- **Severities**: per-tool mapping to canonical scale (semgrep `ERROR` → `high`)
- **Titles**: regex-based canonical title mapping across tools
- **Location cache**: same raw path always produces same normalized result
- **Thread pool**: CPU-bound normalization runs in 4-thread pool, doesn't block async loop

### 5.3 Dedup Strategy

- **Primary key**: `(CWE, location_fingerprint)` when both present
- **Fallback keys**: `(title_normalized, location)`, `(CWE, evidence_hash)`, `evidence_hash`
- **Fuzzy matching**: overlapping line ranges, related CWEs (parent/child), same file within N lines (default 5)
- **Precision-aware**: `EXACT_LINE` matches `LINE_RANGE` if within range; `FILE`-level findings don't merge with `EXACT_LINE` unless CWE matches exactly
- **Bloom filter**: O(k) fast-path reject for new findings before checking full index
- **Severity consensus**: weighted vote by parser confidence tier; ties break to more severe

### 5.4 Corroboration Scoring

```
confidence = base_confidence * corroboration_boost * tool_quality * fp_penalty

base_confidence = average of contributing tools' parser confidence tiers
corroboration_boost:
    1 tool: 1.0x
    2 tools same category: 1.2x
    2 tools different category (SAST+DAST): 1.4x
    3+ tools: 1.5x
tool_quality = historical effectiveness data (high FP rate → reduce, high confirmed rate → boost)
fp_penalty = 0.3 if previously_marked_fp, else 1.0
```

Parser confidence tiers:
- **Tier 1 (0.9)**: semgrep, trivy — structured, low FP rate
- **Tier 2 (0.7)**: nuclei, codebadger — good but noisier
- **Tier 3 (0.5)**: nmap, nikto — inferred findings
- **Tier 4 (0.3)**: regex-based extractors

### 5.5 Finding Lifecycle

| Transition | Trigger | Type |
|-----------|---------|------|
| discovered → confirmed | corroboration_count >= 2 OR confidence >= 0.85 | Auto |
| discovered → confirmed | User confirms | Manual |
| confirmed → reported | User exports/sends finding | Manual |
| reported → remediated | User marks fix applied | Manual |
| remediated → verified | Next scan doesn't find it (scan diff) | Auto |

### 5.6 Confidence Decay

Findings not reconfirmed in recent scans lose confidence over time:
- 100% for first 30 days
- -5% per 30-day period after that
- Floor: 20% (never fully disappear — needs explicit dismissal)

### 5.7 Parser Plugin System

Custom parsers live in discoverable directories:
- `packages/plugin/parsers/` (plugin-level)
- `~/.opentools/parsers/` (user-level)

Plugins implement the `ParserPlugin` protocol (`name`, `version`, `confidence_tier`, `validate()`, `parse()`). Plugin parsers override builtins of the same name.

### 5.8 CWE Hierarchy

Bundled from MITRE CWE catalog. Supports: parent/child relationships, OWASP Top 10 mapping, hierarchical suppression (suppress parent → suppresses children), related-CWE fuzzy matching.

### 5.9 Scan Diff

```python
class ScanDiff(BaseModel):
    scan_id: str
    baseline_id: str
    new_findings: list[DeduplicatedFinding]
    resolved_findings: list[DeduplicatedFinding]
    persistent_findings: list[DeduplicatedFinding]
    severity_changes: list[SeverityChange]
    new_tools_used: list[str]
    removed_tools: list[str]
    summary: DiffSummary

class DiffSummary(BaseModel):
    new_count: int
    resolved_count: int
    persistent_count: int
    severity_escalations: int
    severity_deescalations: int
    net_risk_change: str            # "increased", "decreased", "stable"
```

Matching uses the same semantic fingerprint as dedup.

### 5.10 Output Formats

| Format | Use Case |
|--------|---------|
| JSON | Full structured export, machine-readable, importable |
| SARIF 2.1 | CI/CD integration (GitHub, GitLab, Azure DevOps) |
| CSV | Spreadsheet analysis |
| Markdown | Documentation, PRs, Slack |
| HTML | Standalone client delivery report with interactive features |
| STIX 2.1 | Threat intel sharing (leverages existing stix_export.py) |

The SARIF importer enables ingesting findings from any SARIF-compatible tool (CodeQL, SonarQube, Snyk) into the same dedup pipeline.

---

## 6. Database, Shared Infrastructure, and Testing

### 6.1 Database Schema

New Alembic migration `006_scan_runner.py` adds 13 tables:

| Table | Purpose |
|-------|---------|
| `scan` | Core scan tracking with profile snapshot, status, timing |
| `scan_task` | DAG nodes with execution details, output, spawned_by audit |
| `raw_finding` | Individual tool findings before dedup |
| `dedup_finding` | Canonical findings after cross-tool merge |
| `finding_correlation` | Attack chains and kill chain mappings |
| `remediation_group` | Findings grouped by shared fix |
| `suppression_rule` | Path/CWE/severity/tool suppression rules |
| `fp_memory` | False positive memory keyed by target + fingerprint + CWE |
| `finding_annotation` | Shared annotations across surfaces (FP, severity override, notes) |
| `scan_event` | Progress events for SSE reconnection (with sequence number) |
| `steering_log_entry` | Claude's steering decisions with full context snapshots |
| `scan_attestation` | Cryptographic proof of scan results |
| `output_cache` | Content-fingerprint cache for tool output |
| `tool_effectiveness` | Historical tool accuracy stats per target type |
| `scan_batch` | Batch scan coordination |

SQLite adaptation follows the Phase 3C.1.5 pattern: JSON → TEXT, TIMESTAMP WITH TIME ZONE → TEXT (ISO 8601), UUID → TEXT.

### 6.2 Evidence Retention Policy

```python
class RetentionPolicy(BaseModel):
    raw_output_retention_days: int = 30
    raw_findings_retention: str = "forever"
    task_metadata_retention: str = "forever"
    # After retention: raw output deleted, hash preserved
    # Parsed findings and metadata never deleted
```

### 6.3 ScanStore Protocol

```python
class ScanStoreProtocol(Protocol):
    async def save_scan(self, scan: Scan) -> None: ...
    async def save_task(self, task: ScanTask) -> None: ...
    async def save_raw_finding(self, finding: RawFinding) -> None: ...
    async def save_dedup_finding(self, finding: DeduplicatedFinding) -> None: ...
    async def save_correlation(self, correlation: FindingCorrelation) -> None: ...
    async def save_event(self, event: ProgressEvent) -> None: ...
    async def update_task_status(self, task_id: str, status: TaskStatus, **fields) -> None: ...
    async def update_scan_status(self, scan_id: str, status: ScanStatus, **fields) -> None: ...
    async def get_scan(self, scan_id: str) -> Scan | None: ...
    async def get_scan_tasks(self, scan_id: str) -> list[ScanTask]: ...
    async def get_scan_findings(self, scan_id: str) -> list[DeduplicatedFinding]: ...
    async def get_engagement_findings(self, engagement_id: str) -> list[DeduplicatedFinding]: ...
    async def list_scans(self, engagement_id: str | None = None) -> list[Scan]: ...
    async def get_events_after(self, scan_id: str, sequence: int) -> AsyncIterator[ProgressEvent]: ...
    async def get_fp_memory(self, target: str, fingerprint: str, cwe: str) -> bool: ...
    async def save_fp_memory(self, target: str, fingerprint: str, cwe: str) -> None: ...
    async def get_output_cache(self, cache_key: str) -> CachedOutput | None: ...
    async def save_output_cache(self, cache_key: str, output: CachedOutput) -> None: ...
    async def get_tool_effectiveness(self, tool: str, target_type: str) -> ToolEffectiveness | None: ...
    async def update_tool_effectiveness(self, stats: ToolEffectiveness) -> None: ...
    async def find_fingerprint_across_engagements(self, fingerprint: str, cwe: str) -> list[dict]: ...
```

Two implementations: `SqliteScanStore` (CLI) and `PostgresScanStore` (web, via SQLAlchemy async).

### 6.4 Shared Infrastructure Extraction

New shared module used by both ScanEngine and RecipeRunner:

```
packages/cli/src/opentools/shared/
├── __init__.py
├── subprocess.py       # Async subprocess with streaming + timeout + cancellation
├── progress.py         # ProgressEvent protocol + EventBus (fan-out, backpressure, persistence)
├── retry.py            # RetryPolicy execution with backoff
└── resource_pool.py    # AdaptiveResourcePool with priority heap
```

RecipeRunner refactored to use `shared.subprocess.run_streaming()` — backward-compatible, same public API, shared internals.

### 6.5 Progress Estimation

```python
class ProgressEstimator:
    # Per-(tool, target_type, target_size_bucket) duration statistics
    # Updated on task completion
    # Formula: sum(estimated[task] for pending) / current_parallelism
    # Smoothed with exponential moving average
    # Default for unknown tools: FAST=15s, NORMAL=60s, HEAVY=180s
    # Accuracy improves over time as history accumulates
```

### 6.6 Scan Cost Estimation

```python
class ScanEstimate(BaseModel):
    estimated_duration_seconds: int
    tools_count: int
    containers_to_start: int
    mcp_connections_needed: int
    estimated_llm_calls: int | None     # assisted mode only
    estimated_findings_range: tuple[int, int]
    resource_requirements: ResourceEstimate
```

Shown to the user before scan execution (both `scan plan` CLI and web API plan response).

### 6.7 Testing Strategy

**Level 1: Unit tests** — pure logic, no I/O. Tests dedup engine, normalization, corroboration scoring, suppression, target detection, reactive edges, CWE hierarchy, finding lifecycle, confidence decay, bloom filter.

**Level 2: Integration tests** — real SQLite/Postgres store, mock tool executors returning canned output, real parsers. Tests full scan engine end-to-end: auto mode, reactive edges, cache hits, cancellation, pause/resume, retry, adaptive concurrency, scan diff, engagement-level dedup, lifecycle transitions, attestation.

**Level 3: E2E smoke tests** — real tools (gated by CI markers). Tests `opentools scan plan`, `scan run --ephemeral`, and `scan import` against a known vulnerable target.

**Golden file fixtures**: pre-recorded tool output in `tests/fixtures/tool_output/` for deterministic parser testing. Includes: nmap XML, semgrep JSON, nuclei JSONL, trivy JSON, codebadger MCP responses, gitleaks JSON, dedup scenarios (same finding from two tools, overlapping ranges, related CWEs), and external SARIF files for import testing.

**CI job**: `scanner-tests` workflow with Postgres service container, matching existing CI patterns.

---

## Appendix: Incremental CPG for Repeat Scans

For repeated scans of the same source target (common during engagements), track a `SourceFileManifest` (path → content hash). On repeat scan, diff manifests to find changed files. If CodeBadger supports incremental CPG updates, send only changed files. If not, use manifest diff to scope detector output to changed files, reducing noise and parse time.

## Appendix: Profile Auto-Tuning

Track `ToolEffectiveness` per (tool, target_type) from historical scans. Over time:
- High FP rate → lower priority, add `needs_review` flag
- High confirmed rate → higher priority, boost confidence
- Consistently slow + low yield → mark as optional in default profiles

Auto-tuning makes the scan-runner improve over time without manual profile adjustment.

## Appendix: Cross-Engagement Trend Detection

Same finding fingerprint in 3+ engagements triggers a `TrendResult`. Surfaces as: CLI warnings, web trends dashboard, report "Systemic Issues" section, and Claude steering context.
