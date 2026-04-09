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
  <a href="#architecture">Architecture</a> &bull;
  <a href="#tools">Tools</a> &bull;
  <a href="#recipes">Recipes</a> &bull;
  <a href="#configuration">Configuration</a> &bull;
  <a href="#development">Development</a> &bull;
  <a href="#roadmap">Roadmap</a>
</p>

<p align="center">
  <img alt="Tests" src="https://img.shields.io/badge/tests-91%20passing-brightgreen">
  <img alt="Skills" src="https://img.shields.io/badge/skills-6-blue">
  <img alt="Tools" src="https://img.shields.io/badge/tools-50%2B-orange">
  <img alt="Lines" src="https://img.shields.io/badge/lines-5K%20Python-yellow">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-0078D4">
</p>

---

## Why OpenTools?

Security assessments involve dozens of tools with different output formats, configurations, and invocation patterns. Analysts spend more time wrangling tools than analyzing results. OpenTools fixes this:

| | Traditional | OpenTools |
|---|---|---|
| **Tool management** | Manual install, remember flags | `opentools preflight --skill pentest` verifies everything |
| **Engagement state** | Scattered notes, spreadsheets | SQLite-backed store with FTS search, IOC tracking, timeline |
| **Finding dedup** | Manual cross-referencing | Automatic CWE inference + location-based dedup across tools |
| **Reporting** | Copy-paste from 10 tools | `opentools report generate` with Jinja2 templates |
| **Methodology** | Checklist in your head | AI-guided skills with OWASP v4.2, MITRE ATT&CK coverage |
| **Workflows** | Custom scripts per engagement | Reusable recipes with async parallel execution |
| **CI/CD integration** | Tool-specific adapters | `opentools findings export --format sarif` (universal) |
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
├── config
│   ├── show                                 # Print resolved config
│   └── validate                             # Check YAML files
│
└── audit list [--engagement E]              # View audit trail
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

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Claude Code Skills (packages/plugin/)                   │
│                                                          │
│  ┌────────┐ ┌────┐ ┌───────┐ ┌─────┐ ┌─────┐ ┌──────┐  │
│  │pentest │ │ RE │ │hw-re  │ │forsc│ │cloud│ │mobile│  │
│  └───┬────┘ └──┬─┘ └───┬───┘ └──┬──┘ └──┬──┘ └──┬───┘  │
│      └─────────┴───────┴────────┴───────┴───────┘       │
│                        │ invoke                          │
│                opentools <cmd> --json                    │
│                        │ stdout JSON                     │
└────────────────────────┼─────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────┐
│  CLI Toolkit (packages/cli/)                             │
│                                                          │
│  cli.py ──── typer commands (40+ subcommands)            │
│    │                                                     │
│    ├── config.py ◄── tools.yaml, mcp-servers.yaml        │
│    ├── preflight.py ── health checks per skill           │
│    ├── containers.py ── docker compose lifecycle         │
│    ├── recipes.py ── asyncio DAG executor                │
│    ├── findings.py ── CWE inference + dedup + SARIF      │
│    ├── reports.py ── Jinja2 template rendering           │
│    └── parsers/ ── semgrep, nuclei, trivy, gitleaks, capa│
│                                                          │
│    engagement/                                           │
│      store.py ◄──► SQLite (WAL, FTS5, migrations)        │
│      export.py ── JSON export/import                     │
│                                                          │
│  models.py ─── 29 Pydantic models, 10 enums             │
└──────────────────────────────────────────────────────────┘
                         ▼
┌──────────────────────────────────────────────────────────┐
│  Security Tools                                          │
│                                                          │
│  MCP Servers:  codebadger, arkana, ghydramcp, cyberchef  │
│                semgrep-mcp, nmap-mcp, wazuh-mcp, ...     │
│                                                          │
│  Docker:       nuclei, sqlmap, ffuf, nikto, hashcat,     │
│                masscan, binwalk, radare2, capa, yara, ...│
│                                                          │
│  CLI:          jadx, ILSpy, retdec, webcrack, synchrony, │
│                frida, volatility3, sliver, theHarvester   │
└──────────────────────────────────────────────────────────┘
```

### Package Map

| Package | Purpose | Key Files |
|---|---|---|
| `packages/plugin/` | Claude Code plugin — AI knowledge layer | 6 SKILL.md files, 9 commands, 5 recipes, YAML config |
| `packages/cli/` | Python CLI — deterministic orchestration | 12 modules, 91 tests, typer entry point |
| `docs/specs/` | Design specifications | Architecture decisions, data models, API contracts |
| `docs/plans/` | Implementation plans | Task breakdowns with TDD steps |
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
uv pip install -e .
pip install pytest
python -m pytest tests/ -v    # Run all 91 tests
```

### Project Stats

```
2 packages | 12 modules | 91 tests | 5K lines of Python | 36 source files
```

### Tech Stack

| Dependency | Purpose |
|-----------|---------|
| typer | CLI framework (type-hint-driven) |
| pydantic | Data models + validation (29 models) |
| rich | Terminal output (tables, colors) |
| ruamel.yaml | YAML loading (preserves comments) |
| sqlite-utils | SQLite access (WAL, FTS5) |
| jinja2 | Report template rendering |

### Output Parsers

Adding a parser for a new tool is one file:

```python
# packages/cli/src/opentools/parsers/my_tool.py
from opentools.models import Finding, Severity

def parse(raw_output: str) -> list[Finding]:
    """Parse my_tool JSON output into Finding models."""
    # ... parse raw_output, return list of Finding objects
```

The registry auto-discovers parser modules — no registration needed.

---

## Roadmap

### Phase 1 (Current)

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

- [ ] Textual TUI dashboard (live engagement status, container monitoring, findings table)
- [ ] Dedup-on-insert in engagement store (currently standalone function)
- [ ] Report template conversion to Jinja2 (`.md` → `.md.j2`)
- [ ] Engagement export bundling (zip artifacts alongside JSON)
- [ ] Additional output parsers (sqlmap, nmap, nikto, hashcat)
- [ ] `opentools iocs export --format stix` (STIX 2.1 threat intel export)

### Phase 3

- [ ] Web dashboard (FastAPI + HTMX) for multi-engagement management
- [ ] Team collaboration — shared engagements, finding assignment
- [ ] Attack chain visualization (linked findings → narrative)
- [ ] Cross-engagement IOC correlation and trending
- [ ] Plugin marketplace integration

---

## License

MIT

---

<p align="center">
  <strong>OpenTools</strong> — Security assessments, orchestrated.
</p>
