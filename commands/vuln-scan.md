---
description: Quick multi-tool vulnerability scan on a codebase or URL
---

# Quick Vulnerability Scan

Run a rapid multi-tool vulnerability scan. No full pentest ceremony — just findings.

## Workflow

### 1. Determine target type from user input

- **Local source code path** -> Source code scan
- **URL/domain** -> Web application scan
- **GitHub URL** -> Clone first, then source scan
- **Docker image** -> Container scan

### 2. Run scans in parallel based on target type

**For source code targets:**

```bash
# CodeBadger — CPG analysis (via MCP)
# Use: generate_cpg, then run ALL find_* vulnerability detectors:
# find_taint_flows, find_stack_overflow, find_heap_overflow,
# find_format_string_vulns, find_use_after_free, find_null_pointer_deref,
# find_integer_overflow, find_toctou, find_uninitialized_reads, find_double_free

# Semgrep — rule-based scanning
C:/Users/slabl/Tools/semgrep-mcp/.venv/Scripts/semgrep.exe --config auto <target_path> --json --severity ERROR --severity WARNING

# Gitleaks — secret scanning
cd C:/Users/slabl/Tools/mcp-security-hub && docker compose up gitleaks-mcp -d
docker exec gitleaks-mcp gitleaks detect --source=/target -v

# Trufflehog — additional secret scanning
docker run --rm -v <target_path>:/target trufflesecurity/trufflehog filesystem /target --json
```

**For URL/web targets:**
```bash
# Start containers
cd C:/Users/slabl/Tools/mcp-security-hub
docker compose up nuclei-mcp nikto-mcp -d

# Nuclei — template-based vuln scanning
docker exec nuclei-mcp nuclei -u <url> -as -severity critical,high,medium

# Nikto — web server scanning
docker exec nikto-mcp nikto -h <url>
```

**For Docker images:**
```bash
docker compose up trivy-mcp -d
docker exec trivy-mcp trivy image <image:tag> --severity HIGH,CRITICAL
```

### 3. Consolidate findings

Merge all tool outputs into one severity-ranked table:

```markdown
| # | Severity | Tool | Finding | Location | CWE |
|---|----------|------|---------|----------|-----|
| 1 | CRITICAL | codebadger | SQL injection via taint flow | src/api/users.py:42 | CWE-89 |
| 2 | HIGH | semgrep | Hardcoded password | config/db.py:15 | CWE-798 |
| 3 | HIGH | gitleaks | AWS access key exposed | .env.example:3 | CWE-798 |
| 4 | MEDIUM | nuclei | Missing CSP header | https://target.com | CWE-1021 |
```

### 4. Remediation summary

For each CRITICAL and HIGH finding, provide a specific one-line fix.

Flag likely false positives but still include them in the table.
