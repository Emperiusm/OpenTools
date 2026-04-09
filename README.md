# OpenTools

Comprehensive security toolkit for Claude Code — penetration testing, reverse engineering, hardware security, digital forensics, cloud security, and mobile application security.

## Structure

```
OpenTools/
├── packages/
│   ├── plugin/    # Claude Code security plugin (skills, commands, config)
│   └── cli/       # Python CLI toolkit (opentools command)
├── engagements/   # Runtime data (gitignored)
└── docs/          # Design specs and plans
```

## Quick Start

```bash
# Install the CLI
cd packages/cli
uv pip install -e .

# Check your environment
opentools setup

# Verify tools
opentools preflight --skill pentest
```

## CLI (`opentools`)

The CLI provides deterministic orchestration for the security plugin:

| Command | Description |
|---------|-------------|
| `opentools setup` | Check tool availability, generate environment profile |
| `opentools preflight` | Health check tools for a specific skill |
| `opentools engagement create` | Start a new engagement |
| `opentools findings list` | List findings with severity/status filters |
| `opentools findings export --format sarif` | Export findings for CI/CD |
| `opentools recipe run <id>` | Execute a saved workflow recipe |
| `opentools containers start --profile pentest` | Start Docker containers by profile |
| `opentools report generate` | Generate reports from templates |

Run `opentools --help` for the full command list.

## Plugin Skills

| Skill | Description |
|-------|-------------|
| **pentest** | Penetration testing workflows with OWASP v4.2 coverage |
| **reverse-engineering** | Binary analysis (PE/ELF/Mach-O/.NET/Java/JS/Python/Go/Rust) |
| **hardware-re** | Firmware, UART/JTAG, BLE/WiFi, CAN bus, side-channel |
| **forensics** | Memory forensics, log analysis, timeline reconstruction |
| **cloud-security** | AWS/Azure/GCP assessment, IAM audit, compliance |
| **mobile** | Android/iOS static + dynamic analysis, OWASP Mobile Top 10 |

## Configuration

Tool paths and MCP server configs are in `packages/plugin/config/`:
- `tools.yaml` — centralized tool registry
- `mcp-servers.yaml` — MCP server connections and health checks
- `profiles.yaml` — user environment profile

Copy `.env.example` to `.env` and fill in API keys.

## Development

```bash
# Install dev dependencies
cd packages/cli
uv pip install -e .
pip install pytest

# Run tests
python -m pytest tests/ -v
```
