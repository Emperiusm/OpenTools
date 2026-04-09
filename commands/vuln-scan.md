---
description: Quick multi-tool vulnerability scan on a codebase, URL, or binary
---

# Quick Vulnerability Scan

Run a rapid multi-tool vulnerability scan. No full pentest ceremony — just findings.

## Workflow

### 1. Determine target type from user input

- **Local source code path** -> Source code scan
- **URL/domain** -> Web application scan
- **GitHub URL** -> Clone first, then source scan
- **Docker image** -> Container scan
- **Binary file (.exe, .dll, .elf, .so)** -> Binary scan
- **APK file** -> Mobile scan (decompile first)

### 2. Preflight — verify tools before scanning

```bash
# Quick tool check based on target type
echo "Checking tools..."
```

Report any unavailable tools and adjust scan scope. Don't silently skip scanners.

### 3. Run scans based on target type

**For source code targets:**

```bash
# CodeBadger — CPG analysis (via MCP)
# Use: generate_cpg, then run ALL find_* vulnerability detectors:
# find_taint_flows, find_stack_overflow, find_heap_overflow,
# find_format_string_vulns, find_use_after_free, find_null_pointer_deref,
# find_integer_overflow, find_toctou, find_uninitialized_reads, find_double_free

# Semgrep — rule-based scanning
${SEMGREP_PATH:-C:/Users/slabl/Tools/semgrep-mcp/.venv/Scripts/semgrep.exe} --config auto <target_path> --json --severity ERROR --severity WARNING

# Gitleaks — secret scanning
cd ${SECURITY_HUB:-C:/Users/slabl/Tools/mcp-security-hub} && docker compose up gitleaks-mcp -d
docker exec gitleaks-mcp gitleaks detect --source=/target -v

# Trufflehog — additional secret scanning
docker run --rm -v <target_path>:/target trufflesecurity/trufflehog filesystem /target --json
```

**For URL/web targets:**
```bash
cd ${SECURITY_HUB:-C:/Users/slabl/Tools/mcp-security-hub}
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

**For binary files (PE/ELF/Mach-O):**
```bash
# Use Arkana MCP for automated binary triage:
# - detect_binary_format — identify file type
# - get_triage_report — automated security triage
# - detect_packing — check for packers/protectors
# - get_capa_analysis_info — MITRE ATT&CK capability mapping
# - get_entropy_analysis — detect encrypted/packed sections
# - extract_strings_from_binary — string extraction and ranking
# - scan_for_vulnerability_patterns — known vuln patterns

# Use capa for capability analysis
docker exec capa-mcp capa <binary>

# YARA signature matching
docker exec yara-mcp yara /app/rules/*.yar <binary>

# Use codebadger on decompiled output (if RetDec available)
${RETDEC_PATH:-C:/Users/slabl/Tools/retdec/retdec-v5.0/bin/retdec-decompiler.exe} <binary>
# Then: generate_cpg on <binary>.c, run find_* detectors
```

**For APK files:**
```bash
# Decompile
${JADX_PATH:-C:/Users/slabl/Tools/jadx/jadx-1.5.5/bin/jadx.bat} -d ./apk_output <target.apk>

# Scan decompiled source with codebadger
# generate_cpg on ./apk_output/sources/, run find_taint_flows

# Semgrep on decompiled Java
${SEMGREP_PATH:-C:/Users/slabl/Tools/semgrep-mcp/.venv/Scripts/semgrep.exe} --config auto ./apk_output/sources/ --json --severity ERROR

# Secret scanning
docker exec gitleaks-mcp gitleaks detect --source=./apk_output -v

# Check manifest for security issues
# Parse AndroidManifest.xml for: debuggable, allowBackup, exported components, cleartext
```

### 4. Consolidate findings

Merge all tool outputs into one severity-ranked table. **Deduplicate** findings reported by multiple tools (list all tools that found it):

```markdown
| # | Severity | Tool(s) | Finding | Location | CWE |
|---|----------|---------|---------|----------|-----|
| 1 | CRITICAL | codebadger, semgrep | SQL injection via taint flow | src/api/users.py:42 | CWE-89 |
| 2 | HIGH | semgrep | Hardcoded password | config/db.py:15 | CWE-798 |
| 3 | HIGH | gitleaks | AWS access key exposed | .env.example:3 | CWE-798 |
| 4 | MEDIUM | nuclei | Missing CSP header | https://target.com | CWE-1021 |
```

### 5. SARIF output (optional)

If the user requests SARIF format (for CI/CD integration), convert findings:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "security-toolkit-vuln-scan",
          "version": "0.1.0",
          "rules": []
        }
      },
      "results": [
        {
          "ruleId": "CWE-89",
          "level": "error",
          "message": { "text": "SQL injection via taint flow" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/api/users.py" },
                "region": { "startLine": 42 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

Write SARIF to `<output_dir>/vuln-scan-results.sarif.json`.

### 6. Remediation summary

For each CRITICAL and HIGH finding, provide a specific one-line fix.

Flag likely false positives but still include them in the table (marked with `[FP?]`).
