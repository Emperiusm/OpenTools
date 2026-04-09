---
description: Check tool availability and configure the security toolkit
---

# Setup Wizard

Validate the user's environment and report which tools are available, missing, or misconfigured.

## Workflow

### 1. Detect platform

```bash
uname -s 2>/dev/null || echo "Windows"
```

### 2. Check Docker

```bash
docker info > /dev/null 2>&1 && echo "PASS: Docker is running" || echo "FAIL: Docker is not available — many tools require Docker"
docker compose version > /dev/null 2>&1 && echo "PASS: Docker Compose available" || echo "FAIL: Docker Compose not found"
```

### 3. Check MCP server prerequisites

For each MCP server in `config/mcp-servers.yaml`, run its health check:

```bash
# CodeBadger
curl -sf http://localhost:4242/health && echo "PASS: CodeBadger" || echo "SKIP: CodeBadger (not running)"

# Ghidra
curl -sf http://localhost:18489/health && echo "PASS: Ghidra MCP" || echo "SKIP: Ghidra (not running)"

# Arkana Docker image
docker image inspect arkana:latest > /dev/null 2>&1 && echo "PASS: Arkana image" || echo "SKIP: Arkana (image not pulled)"
```

### 4. Check Docker containers

```bash
cd ${SECURITY_HUB:-C:/Users/slabl/Tools/mcp-security-hub}

# List all available containers from docker-compose.yml
docker compose config --services 2>/dev/null | while read svc; do
  echo "Available: $svc"
done

# Check which are running
docker ps --filter "name=-mcp" --format "RUNNING: {{.Names}}" 2>/dev/null
```

### 5. Check CLI tools

```bash
# Decompilers
test -f "${JADX_PATH:-C:/Users/slabl/Tools/jadx/jadx-1.5.5/bin/jadx.bat}" && echo "PASS: JADX" || echo "SKIP: JADX"
test -f "${ILSPY_PATH:-C:/Users/slabl/Tools/ilspy/ILSpy/ILSpy.exe}" && echo "PASS: ILSpy" || echo "SKIP: ILSpy"
test -f "${RETDEC_PATH:-C:/Users/slabl/Tools/retdec/retdec-v5.0/bin/retdec-decompiler.exe}" && echo "PASS: RetDec" || echo "SKIP: RetDec"

# JS tools
command -v webcrack > /dev/null 2>&1 && echo "PASS: webcrack" || echo "SKIP: webcrack (npm install -g webcrack)"
command -v synchrony > /dev/null 2>&1 && echo "PASS: synchrony" || echo "SKIP: synchrony (npm install -g synchrony)"

# Python tools
command -v frida > /dev/null 2>&1 && echo "PASS: Frida" || echo "SKIP: Frida (pip install frida-tools)"
command -v vol > /dev/null 2>&1 && echo "PASS: Volatility 3" || echo "SKIP: Volatility 3 (pip install volatility3)"
command -v theHarvester > /dev/null 2>&1 && echo "PASS: theHarvester" || echo "SKIP: theHarvester (pip install theHarvester)"

# Sliver
test -f "${SLIVER_PATH:-C:/Users/slabl/Tools/sliver/sliver-server.exe}" && echo "PASS: Sliver C2" || echo "SKIP: Sliver C2"

# Cloud CLIs
command -v aws > /dev/null 2>&1 && echo "PASS: AWS CLI" || echo "SKIP: AWS CLI"
command -v az > /dev/null 2>&1 && echo "PASS: Azure CLI" || echo "SKIP: Azure CLI"
command -v gcloud > /dev/null 2>&1 && echo "PASS: GCP CLI" || echo "SKIP: GCP CLI"
command -v kubectl > /dev/null 2>&1 && echo "PASS: kubectl" || echo "SKIP: kubectl"

# Mobile
command -v adb > /dev/null 2>&1 && echo "PASS: ADB" || echo "SKIP: ADB"
```

### 6. Check API keys

```bash
[ -n "$SHODAN_API_KEY" ] && echo "PASS: Shodan API key" || echo "SKIP: Shodan API key"
[ -n "$VIRUSTOTAL_API_KEY" ] && echo "PASS: VirusTotal API key" || echo "SKIP: VirusTotal API key"
[ -n "$OTX_API_KEY" ] && echo "PASS: OTX API key" || echo "SKIP: OTX API key"
[ -n "$ZOOMEYE_API_KEY" ] && echo "PASS: ZoomEye API key" || echo "SKIP: ZoomEye API key"
[ -n "$NETWORKSDB_API_KEY" ] && echo "PASS: NetworksDB API key" || echo "SKIP: NetworksDB API key"
```

### 7. Generate report

Output a summary table:

```markdown
# Security Toolkit Setup Report

## Environment
- Platform: [detected]
- Docker: [available/missing]
- Docker Compose: [available/missing]

## Tool Availability

### MCP Servers
| Server | Status | Notes |
|--------|--------|-------|
| codebadger | PASS/SKIP | [details] |
| ... | ... | ... |

### Docker Containers
| Container | Available | Running | Profile |
|-----------|-----------|---------|---------|
| nmap-mcp | YES/NO | YES/NO | pentest |
| ... | ... | ... | ... |

### CLI Tools
| Tool | Status | Install Command |
|------|--------|----------------|
| JADX | PASS/SKIP | [install instructions] |
| ... | ... | ... |

### API Keys
| Service | Status |
|---------|--------|
| Shodan | SET/NOT SET |
| ... | ... |

## Skill Availability
Based on your tools, these skills are fully/partially available:
- /pentest: [FULL/PARTIAL — missing: X, Y]
- /reverse: [FULL/PARTIAL]
- /hardware-re: [FULL/PARTIAL]
- /forensics: [FULL/PARTIAL]
- /cloud: [FULL/PARTIAL]
- /mobile: [FULL/PARTIAL]
- /vuln-scan: [FULL/PARTIAL]

## Recommended Next Steps
1. [Install X to unlock Y capability]
2. [Set Z API key for threat intel]
3. [Start containers with: docker compose --profile pentest up -d]
```

### 8. Offer to update profiles.yaml

Ask the user if they want to save the detected configuration to `config/profiles.yaml` for future reference.
