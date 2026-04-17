<p align="center">
  <h1 align="center">OpenTools</h1>
  <p align="center"><strong>Security Toolkit for Claude Code</strong></p>
  <p align="center">50+ security tools orchestrated through AI-guided skills and a deterministic Python CLI. Penetration testing, reverse engineering, hardware security, digital forensics, cloud security, and mobile application security — all from your terminal.</p>
</p>

<p align="center">
  <a href="#why-opentools">Why OpenTools?</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#skills">Skills</a> &bull;
  <a href="#cli">CLI</a> &bull;
  <a href="#scanner">Scanner</a> &bull;
  <a href="#attack-chains">Attack Chains</a> &bull;
  <a href="#plugin-marketplace">Plugin Marketplace</a> &bull;
  <a href="#web-dashboard">Web Dashboard</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#tools">Tools</a> &bull;
  <a href="#recipes">Recipes</a> &bull;
  <a href="#configuration">Configuration</a> &bull;
  <a href="#development">Development</a> &bull;
  <a href="#roadmap">Roadmap</a>
</p>

<p align="center">
  <img alt="Tests" src="https://img.shields.io/badge/tests-1370%2B%20passing-brightgreen">
  <img alt="Skills" src="https://img.shields.io/badge/skills-6-blue">
  <img alt="Tools" src="https://img.shields.io/badge/tools-50%2B-orange">
  <img alt="Lines" src="https://img.shields.io/badge/lines-40K%20Python%20%7C%204K%20TypeScript-yellow">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-0078D4">
  <img alt="PRs" src="https://img.shields.io/badge/PRs-18%20merged-purple">
</p>

---

## Why OpenTools?

Security assessments involve dozens of tools with different output formats, configurations, and invocation patterns. Analysts spend more time wrangling tools than analyzing results. OpenTools fixes this:

| | Traditional | OpenTools |
|---|---|---|
| **Tool management** | Manual install, remember flags | `opentools preflight --skill pentest` verifies everything |
| **Engagement state** | Scattered notes, spreadsheets | SQLite-backed store with FTS search, IOC tracking, timeline |
| **Finding dedup** | Manual cross-referencing | Automatic CWE inference + location-based dedup across tools |
| **Scanning** | One tool at a time, manual config | `opentools scan run --profile source_full` — DAG-orchestrated multi-tool pipeline |
| **Attack chains** | Mental model in your head | Automated entity extraction, relation linking, path queries |
| **Reporting** | Copy-paste from 10 tools | `opentools report generate` with Jinja2 templates |
| **Methodology** | Checklist in your head | AI-guided skills with OWASP v4.2, MITRE ATT&CK coverage |
| **Workflows** | Custom scripts per engagement | Reusable recipes with async parallel execution |
| **CI/CD integration** | Tool-specific adapters | `opentools findings export --format sarif` (universal) |
| **Web dashboard** | Spreadsheets or custom apps | Full-stack Vue 3 + FastAPI dashboard with JWT auth |
| **Docker containers** | `docker compose up` + pray | `opentools containers start --profile pentest` with readiness polling |

---

## Quick Start

### Prerequisites

- Python 3.12+ and [uv](https://github.com/astral-sh/uv) (package manager)
- Docker Desktop (for security tool containers)
- Claude Code with the OpenTools plugin installed

### Install

```bash
git clone https://github.com/Emperiusm/OpenTools.git
cd OpenTools/packages/cli
uv pip install -e .
```

### Verify Your Environment

```bash
# Check what tools you have
opentools setup

# Preflight a specific skill
opentools preflight --skill pentest

# See all commands
opentools --help
```

### First Engagement

```bash
# Create an engagement
opentools engagement create my-audit --target "192.168.1.0/24" --type pentest

# Add findings (manually or via recipes)
opentools findings add my-audit --tool nmap --title "SSH on non-standard port" --severity medium

# Search findings
opentools findings search "injection"

# Export for reporting
opentools findings export my-audit --format sarif --output results.sarif
opentools report generate my-audit --template pentest-report
```

### Run a Multi-Tool Scan

```bash
# List available profiles
opentools scan profiles

# Dry-run to see the execution plan
opentools scan plan --target ./my-app --profile source_full

# Execute the scan
opentools scan run --target ./my-app --profile source_full

# Check status, view findings
opentools scan status <scan-id>
opentools scan findings <scan-id>
```

### Use with Claude Code

The real power is the AI-guided skills. In Claude Code:

```
/pentest          # Start a guided penetration test
/reverse          # Analyze a binary or deobfuscate code
/hardware-re      # Firmware extraction, UART/JTAG, IoT
/forensics        # Incident response, memory forensics
/cloud            # AWS/Azure/GCP security assessment
/mobile           # Android/iOS application security
/vuln-scan        # Quick multi-tool vulnerability scan
/recipe run       # Execute a saved workflow
```

---

## Skills

Six AI-guided security skill modules, each with structured methodology, tool orchestration, and report generation.

### Penetration Testing (`/pentest`)

Full lifecycle: scope & planning, passive/active recon, vulnerability analysis, exploitation, post-exploitation, reporting.

- **OWASP Testing Guide v4.2** checklist with 11 categories and per-test tracking
- **API-specific testing** — endpoint enumeration, IDOR, JWT attacks, GraphQL introspection
- **C2 safety gates** — Sliver operations require per-action authorization with audit logging
- **30+ Docker tools** — nmap, nuclei, sqlmap, ffuf, nikto, hashcat, gitleaks, shodan, and more

### Reverse Engineering (`/reverse`)

Triage unknown files, route to the right analysis pipeline, produce structured reports.

- **Multi-language** — PE/ELF/Mach-O native, .NET (ILSpy + de4dot), Java/Android (JADX), JavaScript (webcrack + synchrony), Python (pyinstxtractor + decompyle3), **Go** (symbol recovery, interface reconstruction), **Rust** (demangling, crate identification)
- **Ghidra integration** — via GhydraMCP for decompilation, cross-references, symbol analysis
- **Arkana** — 250+ binary analysis tools (angr, YARA, capa, Qiling/Speakeasy emulation)
- **Protocol RE** — wire format identification, message structure mapping, binary correlation

### Hardware RE (`/hardware-re`)

Embedded devices, firmware, IoT systems, PCB-level analysis.

- **Firmware extraction** — binwalk recursive extraction, filesystem survey, credential scanning
- **Debug interfaces** — UART identification (baud rate detection), JTAG/SWD pinout, SPI/I2C flash dump
- **Wireless** — BLE GATT enumeration, WiFi provisioning security, Zigbee/Z-Wave sniffing
- **Automotive** — CAN bus monitoring, message ID enumeration, UDS diagnostic testing
- **Side-channel awareness** — power analysis, timing attacks, fault injection countermeasure assessment

### Digital Forensics (`/forensics`)

Evidence collection through incident reporting with MITRE ATT&CK mapping.

- **Memory forensics** — full Volatility 3 workflow (pslist, malfind, netscan, registry, credential extraction) for both Windows and Linux
- **SIEM integration** — Wazuh alert correlation, Elasticsearch log search, timeline reconstruction
- **Log hunting** — Windows Event ID reference (4624/4625/4688/4697/7045), Linux auth/syslog analysis
- **IOC extraction** — structured indicators (network, host, behavioral) with cross-engagement search

### Cloud Security (`/cloud`)

AWS, Azure, and GCP security posture assessment.

- **Automated scanning** — Prowler (CIS benchmarks, SOC2, HIPAA, PCI-DSS), Trivy (IaC scanning)
- **AWS deep checks** — IAM policy analysis, S3 bucket exposure, security group audit, CloudTrail verification
- **Azure/GCP** — Security Center recommendations, storage public access, firewall rules, audit logging
- **Kubernetes** — privileged container detection, hostPath mounts, network policies, RBAC audit

### Mobile Security (`/mobile`)

Android and iOS application security with OWASP Mobile Top 10 coverage.

- **Static analysis** — JADX decompilation, manifest review, network security config, hardcoded secrets
- **Dynamic analysis** — Frida instrumentation, certificate pinning bypass, root detection bypass
- **Framework support** — Native Java/Kotlin, React Native (bundle extraction + deobfuscation), Flutter, Cordova
- **API testing** — endpoint discovery from decompiled source, JWT analysis, IDOR testing

---

## CLI

The `opentools` CLI provides deterministic orchestration — structured tool management, SQLite-backed engagement state, finding deduplication, and async recipe execution.

### Command Reference

```
opentools
├── setup                                    # Detect tools, generate environment profile
├── preflight [--skill X] [--json] [--fix]   # Health check tools
├── version                                  # Print CLI version
│
├── engagement
│   ├── create <name> --target T --type T    # Start new engagement
│   ├── list [--json]                        # List all engagements
│   ├── show <name>                          # Summary with stats
│   └── export <name> [--bundle]             # Export to JSON
│
├── findings
│   ├── list <engagement> [--severity X]     # List with filters
│   ├── add <engagement> --tool T --title T  # Add a finding
│   ├── search <query>                       # Full-text search (FTS5)
│   └── export <engagement> --format F       # SARIF, CSV, or JSON
│
├── containers
│   ├── status                               # All container states
│   └── start <names...> [--profile X]       # Start with readiness polling
│
├── recipe
│   ├── list                                 # Available recipes
│   └── run <id> --target T [--dry-run]      # Execute workflow
│
├── report
│   ├── generate <engagement> --template T   # Render Jinja2 template
│   └── templates                            # List available templates
│
├── iocs
│   ├── correlate <value>                    # Cross-engagement IOC correlation
│   ├── trending [--limit N] [--days N]      # Top trending IOCs
│   ├── enrich <value> --type T              # Fetch from enrichment providers
│   └── export <engagement> --format F       # CSV, JSON, or STIX 2.1
│
├── scan
│   ├── profiles                             # List available scan profiles
│   ├── plan --target T --profile P          # Show execution plan (dry-run)
│   ├── run --target T --profile P           # Plan and execute a scan
│   ├── status <scan-id>                     # Show scan progress
│   ├── history                              # List past scans
│   ├── findings <scan-id>                   # Show scan findings
│   └── cancel <scan-id>                     # Cancel a running scan
│
├── chain
│   ├── status                               # Entity/relation counts, last linker run
│   ├── rebuild <engagement>                 # Re-run extraction + linking
│   ├── entities [--type T]                  # List entities
│   ├── path --from X --to Y                 # K-shortest path query
│   ├── query <preset>                       # Run a named preset query
│   ├── query run <cypher>                   # Run a Cypher-style DSL query
│   ├── query session                        # Interactive DSL session
│   └── export <engagement>                  # Export chain data
│
├── plugin                                   # (22 subcommands)
│   ├── list / search / info                 # Browse plugins
│   ├── install / uninstall / update         # Transactional lifecycle
│   ├── up / down / logs / exec              # Docker compose integration
│   ├── pull / setup / link / sync           # Registry + local dev
│   ├── import / export                      # Portable bundles
│   └── verify / doctor                      # Integrity + health checks
│
├── config
│   ├── show                                 # Print resolved config
│   └── validate                             # Check YAML files
│
├── audit list [--engagement E]              # View audit trail
│
└── dashboard [--engagement E]               # Launch interactive TUI dashboard
```

Every command supports `--json` for structured output, enabling Claude Code skills to invoke the CLI and parse results programmatically.

### Engagement Store

All engagement data is stored in a single SQLite database (`engagements/opentools.db`) with:

- **WAL mode** — concurrent reads + writes for parallel recipe execution
- **FTS5 full-text search** — `opentools findings search "buffer overflow"` across all finding text
- **IOC upsert** — duplicate indicators merge automatically, tracking first/last seen
- **Soft delete** — findings aren't destroyed, they're marked for audit trail preservation
- **Schema migrations** — versioned, forward-compatible, refuses to open newer DBs

### Finding Deduplication

When multiple tools report the same vulnerability, OpenTools merges them automatically:

1. **CWE + location match** — same CWE and file within ±5 lines = duplicate
2. **CWE inference** — 20 CWE keyword patterns map tool-specific language to standard classifications
3. **Confidence scoring** — HIGH (explicit CWE, lines ±2), MEDIUM (explicit CWE, lines ±5), LOW (inferred CWE)
4. **Severity tracking** — when tools disagree on severity, both ratings are preserved for analyst review

### SARIF Export

Findings export to [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) for CI/CD integration:

- Grouped by tool (one SARIF "run" per scanner)
- `partialFingerprints` for cross-run tracking (GitHub, GitLab, Azure DevOps)
- Severity mapping: critical/high → error, medium → warning, low/info → note

---

## Scanner

The scan orchestration pipeline executes multi-tool security scans as a DAG (directed acyclic graph), with automatic finding normalization, deduplication, and correlation.

### Scan Profiles

Ten built-in YAML profiles for common scenarios:

| Profile | Tools | Use Case |
|---------|-------|----------|
| `source_quick` | Semgrep, Gitleaks | Fast source code sweep |
| `source_full` | Semgrep, Gitleaks, Trivy | Comprehensive source audit |
| `web_quick` | WhatWeb, Nuclei (auto-scan), Nikto | Quick web app scan |
| `web_full` | Nuclei, Nikto, ffuf, SQLMap | Full web app assessment |
| `app_server` | WhatWeb, Nuclei (weblogic/oracle/java tags), Nikto | Java app servers — WebLogic, Tomcat, JBoss |
| `network_recon` | Nmap (via `nmap-mcp`), Masscan | Network reconnaissance — supports `hostname:port` targets |
| `redis_audit` | Nmap, Nuclei (TCP/network templates) | Dedicated Redis service audit (CVE-2022-0543) |
| `container_audit` | Trivy | Container image audit |
| `binary_triage` | Capa, YARA, Binwalk | Binary analysis triage |
| `apk_analysis` | JADX, Gitleaks | Android APK analysis |

### Pipeline Architecture

```
Target → TargetDetector → ScanPlanner → ScanEngine → Parsers → Pipeline → Store
           │                  │              │           │          │
           │ detect type      │ build DAG    │ execute   │ parse    │ normalize
           │ validate         │ from profile │ tasks     │ output   │ deduplicate
           │                  │ add edges    │ stream    │          │ correlate
           │                  │              │ events    │          │ score
```

- **Executors** — Shell, Docker, MCP server (connection-pooled), Proxied Shell (ephemeral cloud proxy)
- **DAG engine** — dependency-aware task dispatch with reactive edges (one tool's output triggers another)
- **Dynamic mutation** — OutputAnalyzers extract structured intel from tool output, MutationStrategies inject new tasks into the DAG at runtime based on accumulated attack surface state (KillChainState)
- **HITL approval gates** — dangerous tasks (C2 deployment, exploitation) pause for operator approval with configurable timeouts, durable persistence, and write-before-signal crash safety
- **Ephemeral proxy routing** — high-throughput scans route through auto-provisioned cloud nodes (DigitalOcean, Vultr) for rate-limit resilience, with guaranteed teardown
- **Normalization** — paths, CWEs, severities, titles standardized across tools
- **Deduplication** — strict hash + fuzzy multi-pass matching across tools
- **Correlation** — cross-finding relation detection, remediation grouping
- **Confidence scoring** — corroboration from multiple tools boosts confidence, time decay reduces it

### Known-Vulnerable App Detection

Deliberately-vulnerable training targets (DVWA, DVGA, RestFlaw, WebGoat, bWAPP, Juice Shop, GuardianLeaks, ShadowLogic, CipherHeart) advertise their vulnerability classes as part of their purpose. When fingerprinting identifies one of these apps, the scanner synthesizes concrete findings for each documented class — closing a coverage gap where unauthenticated scanners would otherwise see only banners.

- **Title + URL matching** — substring match against WhatWeb/nuclei detection titles, with URL fallbacks for hosts whose HTML title doesn't contain the app name
- **Target-scoped** — matching constrained to the scan's primary target host:port to prevent spurious expansions from historical URLs
- **Per-scan output paths** — whatweb/nikto write to `/tmp/<tool>-{scan_id}.json` instead of a shared path, eliminating cross-scan contamination

### Automated Scan → Engagement → Chain Pipeline

`opentools scan run -e <engagement>` runs the full pipeline end-to-end without manual intervention:

1. **Scan** — DAG execution against the target
2. **Synthesis** — `synthesize_from_detections` emits vuln-class findings from known-app fingerprints
3. **Engagement import** — `engagement_bridge.import_scan_findings` converts RawFinding rows into engagement Finding records, deduping by `(scan_id, tool, title, file_path)`
4. **Chain rebuild** — entity extraction + relation linking runs automatically
5. **Queries ready** — `chain path` / `chain query preset` return attack paths immediately

Unified DB path — `chain/cli.py` now resolves to `<repo>/engagements/opentools.db` by default, matching the main CLI so findings written by one are visible to the other.

---

## Attack Chains

The chain subsystem extracts security entities (hosts, CVEs, credentials, malware, etc.) from findings and links them into attack graphs for path analysis.

### Entity Extraction

- **Regex-based** — IPs, domains, CVEs, hashes, emails, URLs extracted via security-aware patterns
- **Parser-aware** — tool-specific extractors (semgrep, nmap, trivy) add structured context
- **LLM-assisted** — optional Anthropic/OpenAI/Ollama pass for entity classification and relation inference

### Link Analysis

- **Rule-based linker** — cross-engagement IOC matching, CVE adjacency, MITRE ATT&CK chaining
- **Graph queries** — k-shortest path between any two entities (powered by rustworkx)
- **Preset queries** — `crown_jewel`, `lateral_movement`, `priv_esc_chains`, `external_to_internal`, `mitre_coverage`
- **Export** — chain data exportable as JSON for downstream tooling

### Cypher-Style Query DSL

A domain-specific query language modeled on Neo4j Cypher for expressing complex chain traversals. Parsed with Lark, planned against an in-memory virtual graph, and executed with resource limits (node visits, path depth, time).

```cypher
MATCH (h:host)-[:exposes]->(s:service)-[:vulnerable_to]->(c:cve)
WHERE c.severity = "critical"
RETURN h.address, s.port, c.id
```

- **Grammar** — `MATCH` / `WHERE` / `RETURN` with variable-length path patterns (`-[:rel*1..3]->`)
- **Planner** — rewrites queries into index-backed lookups before virtualization
- **Plugin API** — `chain/plugin_api.py` lets plugins register custom functions and relation types
- **Session state** — `chain query session` for interactive exploration with variable binding across queries

### Async Store Protocol

Chain data is persisted via `ChainStoreProtocol` with pluggable async backends:

- **aiosqlite** — local single-user CLI usage
- **PostgreSQL (SQLAlchemy)** — multi-user web dashboard

---

## Plugin Marketplace

Phase 3E ships a plugin system for distributing skills, recipes, and Docker-packaged tools with integrity verification and sandboxed execution.

### Plugin CLI

```
opentools plugin
├── list / search / info                  # Browse local + registry plugins
├── install / uninstall / update          # Transactional lifecycle with rollback
├── up / down / logs / exec               # Docker compose integration
├── pull / setup / link / sync            # Registry + local development flows
├── import / export                       # Portable plugin bundles
├── verify / doctor                       # Integrity + health checks
└── (22 subcommands total)
```

### Plugin Core (`packages/plugin-core/`)

| Module | Purpose |
|--------|---------|
| `models.py` | Pydantic v2 manifest, catalog, registry schemas |
| `index.py` | SQLite plugin index with integrity tracking |
| `cache.py` | Content-addressable plugin cache |
| `registry.py` | Registry client with catalog caching + search |
| `resolver.py` | Dependency resolver (cycle + conflict detection) |
| `verify.py` | Sigstore signature + SHA256 verification |
| `installer.py` | Transactional installer with staging and atomic promotion |
| `updater.py` | Version pruning + rollback on failure |
| `compose.py` | Per-plugin docker compose generator with sandbox injection |
| `sandbox.py` | Mount blocklist policy with organization-level overrides |
| `enforcement.py` | Recipe command enforcement via shlex parsing |
| `content_advisor.py` | Skill content advisory scanner |
| `errors.py` | `PluginError` hierarchy with actionable hints |

---

## Web Dashboard

A full-stack web interface for multi-user engagement management, built on FastAPI and Vue 3.

### Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | Vue 3.5, TypeScript 5.7, Vite 6, PrimeVue 4 |
| **State** | Pinia 3, TanStack Vue Query 5 |
| **Charts** | Chart.js 4.5 + vue-chartjs |
| **Backend** | FastAPI, SQLAlchemy, Alembic migrations |
| **Auth** | fastapi-users with JWT |
| **Database** | PostgreSQL |

### API Routes

```
/api/v1/auth/           Authentication (register, login, JWT)
/api/v1/engagements/    Engagement CRUD
/api/v1/findings/       Finding management
/api/v1/iocs/           IOC correlation and enrichment
/api/v1/containers/     Docker container management
/api/v1/recipes/        Workflow execution
/api/v1/reports/        Report generation
/api/v1/exports/        Data export
/api/v1/correlation/    Threat correlation
/api/v1/chain/          Attack chain analysis
/api/v1/scans/          Scan orchestration (CRUD, control, SSE, approval gates)
/api/v1/system/         System info and health
```

### Quick Start

```bash
cd packages/web
cp .env.example .env
# Edit .env with your POSTGRES_PASSWORD and SECRET_KEY

# Build frontend
cd frontend && npm install && npm run build && cd ..

# Start services
docker compose up -d
# Dashboard: http://localhost
# API docs: http://localhost:8000/docs
```

### Development

```bash
# Terminal 1: API with hot-reload
make dev-api

# Terminal 2: Frontend with HMR
make dev-ui

# Run tests
make test
```

---

## TUI Dashboard

An interactive terminal dashboard for local engagement management (requires `pip install opentools[dashboard]`).

- **Collapsible sidebar** — engagement list with summary stats
- **Tabbed content** — findings, IOCs, containers, timeline views
- **Finding detail modal** — full evidence and remediation view
- **Interactive CRUD** — create engagements, add findings/IOCs, delete entries
- **Recipe runner** — per-step progress via async generator
- **Bulk actions** — checkbox multi-select (Space, Ctrl+A, Ctrl+D)
- **Lazy data fetching** — only queries the visible tab
- **Auto-refresh** — configurable polling interval

```bash
opentools dashboard --engagement my-audit
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Claude Code Skills (packages/plugin/)                           │
│                                                                  │
│  ┌────────┐ ┌────┐ ┌───────┐ ┌─────┐ ┌─────┐ ┌──────┐          │
│  │pentest │ │ RE │ │hw-re  │ │forsc│ │cloud│ │mobile│          │
│  └───┬────┘ └──┬─┘ └───┬───┘ └──┬──┘ └──┬──┘ └──┬───┘          │
│      └─────────┴───────┴────────┴───────┴───────┘               │
│                        │ invoke                                  │
│                opentools <cmd> --json                            │
│                        │ stdout JSON                             │
└────────────────────────┼─────────────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│  CLI Toolkit (packages/cli/)                                     │
│                                                                  │
│  cli.py ──── typer commands (60+ subcommands)                    │
│    │                                                             │
│    ├── engagement/ ── SQLite store (WAL, FTS5, migrations)       │
│    ├── scanner/                                                  │
│    │   ├── engine.py ──── DAG task executor + mutation + gates    │
│    │   ├── planner.py ── profile → task graph builder            │
│    │   ├── pipeline.py ── normalize → dedup → correlate          │
│    │   ├── parsing/ ── semgrep, gitleaks, trivy, nmap, generic   │
│    │   ├── executor/ ── shell, docker, MCP, proxied shell        │
│    │   ├── mutation/ ── analyzers, strategies, kill chain state   │
│    │   ├── infra/ ── cloud providers, proxy tunnel, sweeper      │
│    │   ├── approval.py ── HITL gate registry                     │
│    │   ├── known_vuln_apps.py ── synthesize findings from banner │
│    │   ├── engagement_bridge.py ── raw findings → engagement DB  │
│    │   └── store.py ── scan-specific SQLite store                │
│    ├── chain/                                                    │
│    │   ├── extractors/ ── regex, parser-aware, LLM              │
│    │   ├── linker/ ── rule engine, LLM pass, graph cache         │
│    │   ├── cypher/ ── Lark grammar, planner, executor, session   │
│    │   ├── query/ ── path queries, presets, graph cache          │
│    │   ├── plugin_api.py ── custom functions + relation types    │
│    │   └── stores/ ── async SQLite, async PostgreSQL             │
│    ├── correlation/ ── cross-engagement IOC engine               │
│    ├── dashboard/ ── Textual TUI (optional)                      │
│    ├── plugin_cli.py ── 22 plugin subcommands                    │
│    ├── recipes.py ── asyncio DAG executor                        │
│    ├── findings.py ── CWE inference + dedup + SARIF              │
│    ├── stix_export.py ── STIX 2.1 bundle builder                │
│    └── shared/ ── subprocess, retry, resource pool, event bus    │
│                                                                  │
│  models.py ─── 29+ Pydantic models, 10+ enums                   │
└──────────────────────────────────────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│  Web Dashboard (packages/web/)                                   │
│                                                                  │
│  backend/  ── FastAPI + SQLAlchemy + Alembic + JWT auth          │
│  frontend/ ── Vue 3 + TypeScript + PrimeVue + Chart.js           │
└──────────────────────────────────────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────────────┐
│  Security Tools                                                  │
│                                                                  │
│  MCP Servers:  codebadger, arkana, ghydramcp, cyberchef          │
│                semgrep-mcp, nmap-mcp, wazuh-mcp, ...             │
│                                                                  │
│  Docker:       nuclei, sqlmap, ffuf, nikto, hashcat,             │
│                masscan, binwalk, radare2, capa, yara, ...        │
│                                                                  │
│  CLI:          jadx, ILSpy, retdec, webcrack, synchrony,         │
│                frida, volatility3, sliver, theHarvester           │
└──────────────────────────────────────────────────────────────────┘
```

### Package Map

| Package | Purpose | Key Files |
|---|---|---|
| `packages/plugin/` | Claude Code plugin — AI knowledge layer | 6 SKILL.md files, 9 commands, 5 recipes, YAML config |
| `packages/cli/` | Python CLI — deterministic orchestration | 140+ modules, 1370+ tests, typer entry point |
| `packages/plugin-core/` | Plugin marketplace core library | Manifest models, registry, resolver, installer, sandbox, sigstore verifier |
| `packages/web/backend/` | FastAPI web API — multi-user dashboard | SQLAlchemy models, 11 route modules, Alembic migrations |
| `packages/web/frontend/` | Vue 3 SPA — browser dashboard | PrimeVue components, Pinia stores, Chart.js visualizations |
| `docs/specs/` | Design specifications | Architecture decisions, data models, API contracts |
| `docs/plans/` | Implementation plans | Task breakdowns with TDD steps |
| `scripts/` | Profiling and benchmarking | cProfile, load testing, scan engine profiler |
| `engagements/` | Runtime data (gitignored) | SQLite DB, artifact files, reports |

---

## Tools

### MCP Servers (9)

| Server | Tools | Purpose |
|--------|-------|---------|
| **codebadger** | 15+ | Joern CPG analysis — taint flows, buffer overflows, format strings, use-after-free |
| **arkana** | 250+ | Binary analysis — PE/ELF/Mach-O, angr, YARA, capa, Qiling/Speakeasy emulation |
| **ghydramcp** | 30+ | Ghidra bridge — disassembly, decompilation, cross-references, struct management |
| **cyberchef** | 463 | Encoding, decoding, crypto, transforms |
| **semgrep-mcp** | - | Rule-based vulnerability scanning with custom rules |
| **nmap-mcp** | - | Network reconnaissance |
| **deobfuscate-mcp** | - | JS bundle analysis, AST deobfuscation, source map recovery |
| **wazuh-mcp** | - | SIEM alert analysis, threat hunting |
| **elasticsearch-mcp** | - | Log search, timeline reconstruction |

### Docker Containers (30+)

Managed via docker compose profiles — start only what you need:

```bash
opentools containers start --profile pentest    # nmap, nuclei, sqlmap, ffuf, nikto, ...
opentools containers start --profile re         # yara, capa, binwalk, radare2
opentools containers start --profile hardware   # binwalk, radare2, capa, yara, trivy
opentools containers start --profile cloud      # prowler, trivy
```

| Category | Containers |
|----------|-----------|
| **Recon** | nmap, masscan, whatweb, dnstwist, waybackurls, shodan, zoomeye, maigret |
| **Vuln scanning** | nuclei, nikto, ffuf, trivy |
| **Exploitation** | sqlmap, searchsploit, hashcat |
| **Secrets** | gitleaks, trufflehog |
| **Threat intel** | virustotal, otx, networksdb |
| **RE/Analysis** | yara, capa, binwalk, radare2 |
| **Cloud** | prowler |
| **Fuzzing** | boofuzz, dharma |

### CLI Tools (12)

| Tool | Purpose |
|------|---------|
| jadx | Java/Android decompilation |
| ILSpy | .NET decompilation |
| retdec | Multi-arch native decompilation (ARM, MIPS, x86, PPC → C) |
| webcrack | JS deobfuscation (obfuscator.io + webpack) |
| synchrony | JS deobfuscation (javascript-obfuscator) |
| frida | Dynamic instrumentation (mobile/native) |
| volatility3 | Memory forensics |
| sliver | C2 framework (authorized pentesting only) |
| theHarvester | OSINT email/subdomain harvesting |
| semgrep | Static analysis CLI |
| tshark | Packet capture analysis |
| joern | CPG analysis CLI |

---

## Recipes

Pre-built reusable workflows that chain multiple tools together. Execute with `opentools recipe run`.

| Recipe | What It Does | Parallel |
|--------|-------------|----------|
| `quick-web-audit` | Nuclei + Nikto + ffuf on a URL | Yes |
| `apk-analysis` | JADX decompile → codebadger taint analysis → gitleaks secrets → manifest review | No |
| `binary-triage` | Arkana format detection + capa ATT&CK mapping + YARA signatures + string analysis | Yes |
| `source-code-audit` | CPG generation → all vuln detectors → Semgrep → Gitleaks → Trufflehog | No |
| `firmware-extract` | Entropy analysis → signature scan → recursive extraction → filesystem survey → Trivy | No |

### Recipe Execution

```bash
# List available recipes
opentools recipe list

# Dry run (shows resolved commands without executing)
opentools recipe run quick-web-audit --target https://example.com --dry-run

# Execute with real targets
opentools recipe run source-code-audit --target ./my-app/src

# Execute with engagement tracking
opentools recipe run binary-triage --target ./malware.exe --engagement incident-2026
```

Recipes support:
- **Variable substitution** — `{{target}}`, `{{output_dir}}` replaced at runtime
- **DAG execution** — steps with `depends_on` wait for prerequisites; independent steps run in parallel via asyncio
- **Timeout enforcement** — per-step timeouts with graceful kill
- **Output parsing** — known tool outputs (semgrep, nuclei, trivy, gitleaks, capa) auto-extracted into findings

---

## Configuration

### Config Files

All configuration lives in `packages/plugin/config/`:

| File | Purpose |
|------|---------|
| `tools.yaml` | Centralized tool registry — all paths, containers, CLI tools, API keys |
| `mcp-servers.yaml` | MCP server connections, health checks, skill dependency mapping |
| `profiles.yaml` | User environment profile (auto-generated by `opentools setup`) |

### Environment Variables

Tool paths use `${VAR:-default}` syntax for portability:

```yaml
# In tools.yaml
cli_tools:
  semgrep:
    path: "${SEMGREP_PATH:-C:/Users/slabl/Tools/semgrep-mcp/.venv/Scripts/semgrep.exe}"
```

Resolution order: environment variable → profiles.yaml → tools.yaml default.

### API Keys

Copy `.env.example` to your security hub directory and fill in:

```bash
SHODAN_API_KEY=        # Internet device search
VIRUSTOTAL_API_KEY=    # Hash/URL/domain lookup
OTX_API_KEY=           # AlienVault threat intel
ZOOMEYE_API_KEY=       # Internet asset search
NETWORKSDB_API_KEY=    # Network/ASN lookup
```

### Validate Configuration

```bash
opentools config validate    # Check YAML syntax and file existence
opentools config show        # Print fully resolved config
```

---

## Development

### Building from Source

```bash
git clone https://github.com/Emperiusm/OpenTools.git
cd OpenTools/packages/cli
uv pip install -e ".[dev]"
python -m pytest tests/ -v
```

### Project Stats

```
4 packages | 260+ source files | 1,370+ tests | 40K Python + 4K TypeScript | 18 PRs merged
```

### Tech Stack

**CLI (Python)**

| Dependency | Purpose |
|-----------|---------|
| typer | CLI framework (type-hint-driven) |
| pydantic | Data models + validation |
| rich | Terminal output (tables, colors) |
| textual | TUI dashboard (optional) |
| sqlalchemy + aiosqlite | Async SQLite persistence |
| rustworkx | Graph algorithms (chain path queries) |
| httpx | Async HTTP client |
| orjson | Fast JSON serialization |
| ruamel.yaml | YAML loading (preserves comments) |
| jinja2 | Report template rendering |
| tldextract | Domain parsing for IOC extraction |
| aiolimiter | Async rate limiting |
| tenacity | Retry with exponential backoff |

**Web Backend (Python)**

| Dependency | Purpose |
|-----------|---------|
| fastapi | Async web framework |
| sqlalchemy | ORM + PostgreSQL |
| alembic | Database migrations |
| fastapi-users | JWT authentication |

**Web Frontend (TypeScript)**

| Dependency | Purpose |
|-----------|---------|
| vue 3.5 | Reactive UI framework |
| vite 6 | Build tool + HMR |
| primevue 4 | Component library |
| pinia 3 | State management |
| tanstack vue-query 5 | Server state + caching |
| chart.js + vue-chartjs | Data visualizations |

### Output Parsers

Adding a parser for a new tool is one file:

```python
# packages/cli/src/opentools/scanner/parsing/parsers/my_tool.py
from opentools.scanner.models import ScanFinding, Severity

def parse(raw_output: str, tool_name: str) -> list[ScanFinding]:
    """Parse my_tool output into ScanFinding models."""
    # ... parse raw_output, return list of ScanFinding objects
```

The parser router auto-discovers parser modules — no registration needed.

---

## Roadmap

### Phase 1

- [x] 6 AI-guided security skills (pentest, RE, hardware, forensics, cloud, mobile)
- [x] 9 slash commands with OWASP/MITRE methodology coverage
- [x] Centralized config with env var portability
- [x] 5 starter recipes (web audit, APK, binary triage, source audit, firmware)
- [x] 4 report templates (pentest, incident, cloud, mobile)
- [x] Python CLI with 40+ subcommands
- [x] SQLite engagement store (WAL, FTS5, migrations)
- [x] Finding deduplication with CWE inference
- [x] SARIF 2.1.0 export for CI/CD
- [x] Async recipe engine with DAG execution
- [x] 5 output parsers (semgrep, nuclei, trivy, gitleaks, capa)
- [x] Docker container lifecycle management with profiles
- [x] Preflight health checks with `--fix` auto-remediation

### Phase 2

- [x] Dedup-on-insert with word-boundary CWE inference, path normalization, SQL-side filtering
- [x] Report template conversion to Jinja2 with inheritance, shared macros, pre-computed mappings
- [x] Engagement export bundling (ZIP with artifact streaming, missing file manifest)
- [x] Additional output parsers (sqlmap, nmap XML+NSE, nikto, hashcat)
- [x] STIX 2.1 IOC export with Indicator + Malware/Infrastructure enrichment, TLP marking
- [x] Textual TUI dashboard — collapsible sidebar, summary strip, tabbed content, auto-refresh
- [x] Dashboard finding detail modal with full evidence/remediation view
- [x] Full interactive CRUD — engagement create/delete, finding add, IOC add
- [x] Recipe runner screen with per-step progress via `run_with_progress()` generator
- [x] Export/report/import dialogs with per-session memory
- [x] Bulk finding actions with checkbox multi-select (Space, Ctrl+A, Ctrl+D)
- [x] FormField and CheckboxTable reusable widgets

### Phase 3

- [x] Web dashboard (FastAPI + Vue 3) for multi-engagement management
- [x] JWT authentication with fastapi-users
- [x] Cross-engagement IOC correlation, trending, and enrichment
- [x] Attack chain extraction — entity detection, relation linking, graph path queries
- [x] Async store protocol — ChainStoreProtocol with SQLite and PostgreSQL backends
- [x] Scan runner pipeline — DAG engine, 8 profiles, 5 parsers, normalization, dedup, correlation
- [x] CLI scan commands — plan, run, status, history, findings, cancel
- [x] Web scan API with SSE streaming
- [x] Performance optimization pass — batch DB writes, lazy fetching, reverse indexes, singleton stores

### Phase 3.5: Reactive Engine Expansion

- [x] Dynamic DAG mutation — OutputAnalyzer → KillChainState → MutationStrategy pipeline
- [x] Nmap and Nuclei output analyzers for structured intel extraction
- [x] RedisProbeStrategy — auto-pivot on discovered Redis services
- [x] Ephemeral proxy routing — CloudNodeProvider ABC with DigitalOcean + Vultr
- [x] Shielded teardown — guaranteed cloud node destruction even under cancellation
- [x] ProxiedShellExecutor — transparent proxy routing for NETWORK_ISOLATED tasks
- [x] Orphan node sweeper for startup cleanup of leaked infrastructure
- [x] HITL approval gates — persistence-first, execution wrapper model
- [x] ApprovalRegistry — in-memory notification hub with database-owned expiry
- [x] FastAPI gate endpoints — list/approve/reject with write-before-signal guarantee
- [x] Command injection guard for strategy-spawned tasks

### Phase 3C: Chain Visualization & Query DSL

- [x] Phase 3C.2 — per-engagement attack chain graph view (force-directed)
- [x] Phase 3C.3 — global chain view, Bayesian confidence calibration, timeline, swim lanes, scoring, export
- [x] Phase 3C.4 — Cypher-style DSL with Lark grammar, planner, executor, session state
- [x] Plugin API for custom relation types and query functions

### Phase 3E: Plugin Marketplace

- [x] Pydantic v2 manifest, catalog, and registry models
- [x] SQLite plugin index with integrity tracking
- [x] Content-addressable plugin cache
- [x] Registry client with catalog caching and search
- [x] Dependency resolver with cycle and conflict detection
- [x] Sigstore and SHA256 signature verification
- [x] Transactional installer with staging + atomic promotion + rollback
- [x] Per-plugin docker compose generator with sandbox injection
- [x] Sandbox policy with mount blocklist and org-level overrides
- [x] Skill content advisory scanner
- [x] Recipe command enforcement with shlex parsing
- [x] `opentools plugin` CLI — 22 subcommands covering install, update, compose, registry, dev flows

### Phase 3F: Scan-to-Chain Automation

- [x] End-to-end `scan run -e <engagement>` pipeline — scan → synthesize → import → chain rebuild
- [x] `engagement_bridge.import_scan_findings` — RawFinding → engagement Finding with dedup
- [x] `known_vuln_apps` synthesis — DVWA/DVGA/RestFlaw/WebGoat/GuardianLeaks/ShadowLogic/CipherHeart coverage
- [x] `app_server` profile — WebLogic/Tomcat/JBoss templates (CVE-2023-21839 verified)
- [x] `redis_audit` profile — Redis TCP templates (CVE-2022-0543 verified)
- [x] `hostname:port` target support + `{target_port}` placeholder for TCP service scans
- [x] Unified DB path between `chain/cli.py` and main CLI

### Phase 4 (Planned)

- [ ] Team collaboration — shared engagements, finding assignment, comments
- [ ] Public plugin registry with community-contributed plugins
- [ ] Authenticated DAST crawling for DVWA-class targets (POST fuzzing, CSRF token handling)
- [ ] Chain narrative generation from DSL query results

---

## License

MIT

---

<p align="center">
  <strong>OpenTools</strong> — Security assessments, orchestrated.
</p>
