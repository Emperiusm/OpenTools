# Phase 2B: Core Improvements — Design Specification

**Date:** 2026-04-09
**Status:** Approved
**Author:** slabl + Claude
**Depends on:** Phase 1 CLI toolkit (merged)

## 1. Overview

Phase 2B tightens and extends the CLI toolkit with four improvements:

1. **Dedup-on-insert** — integrate the standalone dedup algorithm into `EngagementStore.add_finding()` so duplicate findings are merged automatically on insert
2. **Report template conversion** — rewrite 4 static markdown templates as full Jinja2 templates with template inheritance, pre-computed mappings, and shared macros
3. **Export bundling** — add zip archive support to engagement export, bundling artifact files alongside JSON
4. **New parsers** — sqlmap, nmap (XML + NSE scripts), nikto, hashcat

No new modules. No architecture changes. All work modifies or extends existing files.

## 2. Dedup-on-Insert

### 2.1 Schema Migration v2

Add two partial indexes optimized for the dedup query patterns:

```sql
-- File-based dedup: engagement + file + line range scan
CREATE INDEX IF NOT EXISTS idx_findings_dedup_file
ON findings(engagement_id, file_path, line_start)
WHERE deleted_at IS NULL;

-- Network dedup: engagement + cwe (no file_path)
CREATE INDEX IF NOT EXISTS idx_findings_dedup_network
ON findings(engagement_id, cwe)
WHERE file_path IS NULL AND deleted_at IS NULL;
```

Added as `_migration_v2` in `engagement/schema.py`. `LATEST_VERSION` becomes 2.

### 2.2 Store Changes

`add_finding()` becomes a dedup-aware insert wrapped in `BEGIN IMMEDIATE` for atomicity under parallel recipe execution.

**Flow:**

```
BEGIN IMMEDIATE

1. Normalize finding.file_path (backslash → forward slash, strip ./ and leading /)

2. Query candidates from DB with SQL-side line filtering.
   Select ONE query path based on the new finding's attributes:
   
   a. If new finding HAS file_path AND line_start:
      WHERE engagement_id=? AND file_path=?
      AND line_start >= ?-5 AND line_start <= ?+5
      AND deleted_at IS NULL
   
   b. If new finding HAS file_path but NO line_start:
      WHERE engagement_id=? AND file_path=?
      AND deleted_at IS NULL
   
   c. If new finding has NO file_path (network finding):
      Query by CWE across ALL findings (file-based and network):
      WHERE engagement_id=? AND cwe=? AND deleted_at IS NULL
      This enables cross-perspective matching (nuclei URL vs codebadger file)

3. Convert candidates via model_construct() (skip Pydantic validation)

4. Call check_duplicate(new_finding, candidates):
   - CWE inference uses pre-compiled word-boundary regex
   - LOW confidence matches require title word overlap ≥ 30%

5. If DUPLICATE → merge:
   - UPDATE existing: append tool to corroborated_by, merge severity_by_tool,
     keep max severity, keep longer description, set dedup_confidence
   - Timeline event: "Finding corroborated by {tool}: {title}"
   - Return existing finding's ID

6. If DISTINCT → insert:
   - INSERT new finding (with normalized file_path)
   - Timeline event: "Finding discovered: {title}"
   - Return new finding's ID

COMMIT  ← single transaction for finding + timeline event
```

**New `add_findings_batch()` method** for bulk inserts from parser output:

```
BEGIN IMMEDIATE
Group findings by file_path
For each file group:
  Load candidates from DB ONCE
  For each finding:
    check_duplicate against candidates + previously inserted batch findings
    Insert or merge
COMMIT

Chunk at 100 findings per transaction to prevent long write locks.
Path normalization applied to every finding in the batch (same as single insert).
```

**Severity ranking for "keep max":**

```python
_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
```

### 2.3 Findings Module Changes

**`infer_cwe()` — word-boundary matching:**

Replace substring matching with pre-compiled `\b` regex patterns (compiled once at module load):

```python
_CWE_PATTERNS: dict[str, list[re.Pattern]] = {
    cwe: [re.compile(rf"\b{re.escape(kw)}\b", re.IGNORECASE) for kw in keywords]
    for cwe, keywords in CWE_KEYWORDS.items()
}
```

Eliminates false positives like "SQL Server" matching CWE-89.

**`check_duplicate()` — title overlap gate:**

For LOW confidence matches (inferred CWE), add a title similarity check. If word overlap < 30% (excluding stopwords), treat as DISTINCT:

```python
def _titles_overlap(a: str, b: str, threshold: float = 0.3) -> bool:
    words_a = set(a.lower().split())
    words_b = set(b.lower().split())
    if not words_a or not words_b:
        return True
    overlap = len(words_a & words_b) / min(len(words_a), len(words_b))
    return overlap >= threshold
```

**File path normalization:**

```python
def _normalize_path(p: str | None) -> str | None:
    if p is None:
        return None
    return p.replace("\\", "/").removeprefix("./").removeprefix("/")
```

Applied both in `_locations_overlap()` for comparison and in `add_finding()` before storage.

### 2.4 model_construct() for DB Reads

All `_row_to_*` methods in `store.py` switch from `Model(...)` (validates) to `Model.model_construct(...)` (trusts data). ~10x faster for DB reads where data was validated on write.

## 3. Report Template Conversion

### 3.1 Template Architecture

Jinja2 template inheritance replaces copy-paste document structure:

```
packages/plugin/shared/report-templates/
├── _macros.j2               ← reusable blocks (finding_table, ioc_table, etc.)
├── _base-report.md.j2       ← document skeleton with {% block %} override points
├── pentest-report.md.j2     ← extends base, adds OWASP matrix
├── incident-report.md.j2    ← extends base, adds ATT&CK mapping
├── cloud-security-report.md.j2  ← extends base, adds compliance table
└── mobile-security-report.md.j2 ← extends base, adds Mobile Top 10
```

Old `.md` files are deleted after conversion.

### 3.2 Shared Macros (`_macros.j2`)

Reusable blocks:
- `finding_table(findings)` — summary table with severity, CWE, tool (+ corroboration count), title, location
- `finding_detail(f, index)` — per-finding detail block with evidence (collapsible via `<details>` if > 500 chars), remediation, severity disagreement warning
- `ioc_table(iocs)` — IOC table with type, value, context, first/last seen
- `timeline_table(events)` — chronological event table with confidence
- `summary_counts(summary)` — severity breakdown counts

### 3.3 Base Template (`_base-report.md.j2`)

Defines the full document structure with override blocks:

```jinja2
{% from '_macros.j2' import finding_table, finding_detail, ioc_table, timeline_table, summary_counts %}

# {{ report_title }}: {{ engagement.name }}

## Engagement Details
- **Client**: {{ client | default("Not specified") }}
- **Assessor**: {{ assessor | default("Not specified") }}
- **Classification**: {{ classification | default("INTERNAL") }}
- **Target**: {{ engagement.target }}
- **Type**: {{ engagement.type }}
- **Scope**: {{ engagement.scope or "Not specified" }}
- **Date**: {{ engagement.created_at | datefmt("%Y-%m-%d") }} to {{ generated_at | datefmt("%Y-%m-%d") }}

## Executive Summary
{{ summary_counts(summary) }}
{% if severity_conflicts %}
> {{ severity_conflicts | length }} finding(s) have severity disagreements between tools.
{% endif %}
{% block extra_summary %}{% endblock %}

## Findings Overview
{{ finding_table(findings) }}

## Detailed Findings
{% for f in findings %}
{{ finding_detail(f, loop.index) }}
---
{% endfor %}

{% block methodology %}{% endblock %}

## Timeline
{{ timeline_table(timeline) }}

{% if iocs %}
## Indicators of Compromise
{% for ioc_type, ioc_list in iocs_by_type.items() %}
### {{ ioc_type | replace("_", " ") | title }}
{{ ioc_table(ioc_list) }}
{% endfor %}
{% endif %}

{% block extra_sections %}{% endblock %}

## Tools Used
{% for tool in tools_used %}
- {{ tool }}
{% endfor %}

---
*Generated {{ generated_at | datefmt }} by OpenTools*
```

Child templates override `extra_summary`, `methodology`, and `extra_sections` blocks. Each child template is ~20-50 lines.

### 3.4 Template-Specific Context Builders

Pre-computed in Python (in `reports.py`), not Jinja2 regex:

```python
OWASP_CWE_MAP = {
    "Information Gathering": [],  # counted by phase="recon"
    "Configuration": ["CWE-16", "CWE-1004", "CWE-614"],
    "Authentication": ["CWE-287", "CWE-798", "CWE-307", "CWE-521"],
    "Authorization": ["CWE-862", "CWE-863", "CWE-639"],
    "Session Management": ["CWE-384", "CWE-613", "CWE-614"],
    "Input Validation": ["CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-611", "CWE-918", "CWE-502"],
    "Error Handling": ["CWE-209", "CWE-200"],
    "Cryptography": ["CWE-327", "CWE-328", "CWE-330"],
    "Business Logic": [],  # manual assessment
    "Client-side": ["CWE-79", "CWE-1021", "CWE-352"],
}

MOBILE_TOP10_CWE_MAP = {
    "M1: Improper Credential Usage": ["CWE-798", "CWE-522", "CWE-256"],
    "M2: Inadequate Supply Chain Security": [],
    "M3: Insecure Authentication/Authorization": ["CWE-287", "CWE-306", "CWE-862"],
    "M4: Insufficient Input/Output Validation": ["CWE-89", "CWE-79", "CWE-78", "CWE-134"],
    "M5: Insecure Communication": ["CWE-319", "CWE-295"],
    "M6: Inadequate Privacy Controls": ["CWE-532", "CWE-200"],
    "M7: Insufficient Binary Protections": [],
    "M8: Security Misconfiguration": ["CWE-16"],
    "M9: Insecure Data Storage": ["CWE-312", "CWE-922"],
    "M10: Insufficient Cryptography": ["CWE-327", "CWE-330"],
}

CLOUD_CATEGORY_CWE_MAP = {
    "IAM": ["CWE-287", "CWE-862", "CWE-798", "CWE-521"],
    "Storage": ["CWE-312", "CWE-319", "CWE-922"],
    "Network": ["CWE-284", "CWE-668"],
    "Logging": ["CWE-778"],
    "Encryption": ["CWE-327", "CWE-311"],
    "Container": ["CWE-250", "CWE-269"],
}

ATTACK_TACTIC_CWE_MAP = {
    "Initial Access": ["CWE-287", "CWE-798", "CWE-79"],
    "Execution": ["CWE-78", "CWE-94", "CWE-502"],
    "Persistence": ["CWE-912"],
    "Privilege Escalation": ["CWE-269", "CWE-250"],
    "Defense Evasion": [],
    "Credential Access": ["CWE-522", "CWE-521", "CWE-798"],
    "Discovery": [],
    "Lateral Movement": [],
    "Collection": ["CWE-200", "CWE-532"],
    "Exfiltration": ["CWE-319"],
}

_TEMPLATE_CONTEXT_BUILDERS = {
    "pentest-report": _build_pentest_context,
    # Returns: {"owasp_matrix": {"Authentication": [Finding, ...], ...}}

    "incident-report": _build_incident_context,
    # Returns: {"attack_tactics": {"Initial Access": [Finding, ...], ...}}
    # Maps findings to MITRE ATT&CK tactics via ATTACK_TACTIC_CWE_MAP

    "cloud-security-report": _build_cloud_context,
    # Returns: {"cloud_categories": {"IAM": [Finding, ...], ...}}

    "mobile-security-report": _build_mobile_context,
    # Returns: {"mobile_top10": {"M1: Improper Credential Usage": [Finding, ...], ...}}
}
```

Each builder takes the base context (findings, engagement, etc.) and returns a dict of additional template variables.

### 3.5 Custom Jinja2 Filters

Registered on the `Environment` once:

```python
env.filters["datefmt"] = lambda dt, fmt="%Y-%m-%d %H:%M UTC": dt.strftime(fmt) if dt else "—"
env.filters["cwe_link"] = lambda cwe: f"[{cwe}](https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html)" if cwe and "-" in cwe else (cwe or "—")
env.filters["severity_icon"] = lambda s: {"critical": "!!!", "high": "!!", "medium": "!", "low": "~", "info": "."}[str(s)]
```

### 3.6 Extra Context Parameter

`generate()` accepts `extra_context: dict` for report metadata not in the Engagement model:

```python
def generate(self, engagement_id, template_name, output_path=None, extra_context=None):
```

CLI: `opentools report generate my-audit --template pentest-report --set client="Acme Corp" --set assessor="Jane Smith"`

Templates reference with defaults: `{{ client | default("Not specified") }}`

### 3.7 Collapsible Evidence

In `_macros.j2`, evidence blocks over 500 characters use GitHub-flavored `<details>` tags:

```jinja2
{% if f.evidence and f.evidence | length > 500 %}
<details><summary>Evidence ({{ f.evidence | length }} chars)</summary>

```
{{ f.evidence }}
```

</details>
{% elif f.evidence %}
```
{{ f.evidence }}
```
{% endif %}
```

## 4. Export Bundling

### 4.1 Changes to `engagement/export.py`

`export_engagement()` gains a `bundle: bool = False` parameter:

- **`bundle=False`** (default): existing behavior, writes JSON file
- **`bundle=True`**: creates a zip archive containing:
  - `engagement.json` — the full export data
  - `artifacts/` — copies of all artifact files referenced in the engagement
  - `missing_artifacts.txt` — manifest of files that couldn't be found (if any)

Uses `zipfile.ZipFile.write()` for streaming (no full file load into memory). `ZIP_DEFLATED` for compression.

### 4.2 Import Changes

`import_engagement()` detects zip vs JSON by file extension:

- `.json` — existing behavior
- `.zip` — extracts `engagement.json` from archive, imports data. Optionally extracts artifacts to a specified directory via `extract_artifacts_to` parameter.

### 4.3 CLI Changes

- `opentools engagement export <name> --bundle` passes the flag
- `opentools engagement import <path>` auto-detects format

## 5. New Parsers

### 5.1 sqlmap.py

Parses SQLmap API JSON output.

Input format:
```json
{"data": [{"type": 1, "value": [{"place": "GET", "parameter": "id", "dbms": "MySQL", "title": "AND boolean-based blind"}]}]}
```

Mapping:
- CWE: `CWE-89` (all sqlmap findings are SQL injection)
- Severity: `critical` (confirmed, exploitable SQLi)
- Title: `"SQL Injection ({technique}) in {parameter}"`
- file_path: target URL
- Evidence: technique details + DBMS

### 5.2 nmap.py

Parses nmap XML output (`-oX`). Uses `xml.etree.ElementTree` (stdlib).

Two finding types:

**Port/service findings** (informational):
- From `<port><state state="open"/><service name="..." version="..."/></port>`
- Severity: `info`
- Title: `"Open port {portid}/{protocol}: {service} {version}"`

**NSE script vulnerability findings**:
- From `<script id="..." output="...">` elements within `<port>`
- Severity: mapped from script ID and output content

NSE script → CWE/severity mapping:

| Script Pattern | CWE | Severity |
|---------------|-----|----------|
| `http-vuln-*` | Extracted from output or inferred | high |
| `ssl-enum-ciphers` (weak) | CWE-327 | medium |
| `ssl-heartbleed` | CWE-119 | critical |
| `vulners` | From CVE in output | varies (default high) |
| `smb-vuln-*` | From output | high |
| Other scripts with "VULNERABLE" | None | medium |
| Other scripts | Skipped (informational, not a finding) | — |

### 5.3 nikto.py

Parses Nikto JSON output (`-Format json`).

Input format:
```json
{"ip": "10.0.0.1", "port": "80", "vulnerabilities": [
  {"id": "000726", "OSVDB": "0", "method": "GET", "url": "/path", "msg": "..."}
]}
```

Severity heuristic (nikto doesn't classify severity):

| Pattern in msg | Severity |
|---------------|----------|
| "default password", "default credentials" | high |
| "directory listing", "directory indexing" | high |
| "server banner", "version disclosure" | low |
| Everything else | medium |

### 5.4 hashcat.py

Parses hashcat potfile format (one cracked hash per line: `{hash}:{plaintext}`).

Mapping:
- CWE: `CWE-521` (Weak Password Requirements)
- Severity: `high`
- Title: `"Weak password cracked ({hash_type})"`
- file_path: hash type as location (e.g., `"NTLM"`, `"SHA-256"`)
- Evidence: `"{hash}:{plaintext}"`

Hash type detection from format:

| Pattern | Hash Type |
|---------|-----------|
| 3+ fields separated by `:` | Machine-readable (first field = type) — parse first |
| 32 hex chars | MD5 |
| 40 hex chars | SHA-1 |
| 64 hex chars | SHA-256 |
| Starts with `$2` | bcrypt |
| Starts with `$6$` | SHA-512 crypt |
| Other | Unknown |

Detection order: check for machine-readable format (3+ colon-separated fields) first, then fall back to hash-length heuristic on the potfile format.

## 6. Files Changed Summary

| File | Change Type | Description |
|------|-------------|-------------|
| `engagement/schema.py` | Modify | Add `_migration_v2` with two partial indexes |
| `engagement/store.py` | Modify | Dedup-on-insert in `add_finding()`, new `add_findings_batch()`, `model_construct()` for all `_row_to_*`, single-transaction writes, path normalization |
| `findings.py` | Modify | Word-boundary regex for `infer_cwe()`, title overlap gate for LOW confidence, `_normalize_path()` |
| `engagement/export.py` | Modify | `bundle` parameter, zip streaming, missing artifact manifest, zip import detection |
| `reports.py` | Modify | Template-specific context builders, `extra_context` parameter, custom Jinja2 filters, CWE→category mapping dicts |
| `cli.py` | Modify | `--bundle` flag on export, `--set` flag on report generate |
| `shared/report-templates/_macros.j2` | Create | Shared macros (finding_table, finding_detail, ioc_table, timeline_table, summary_counts) |
| `shared/report-templates/_base-report.md.j2` | Create | Document skeleton with block override points |
| `shared/report-templates/pentest-report.md.j2` | Create (replace .md) | Extends base, OWASP matrix |
| `shared/report-templates/incident-report.md.j2` | Create (replace .md) | Extends base, ATT&CK mapping |
| `shared/report-templates/cloud-security-report.md.j2` | Create (replace .md) | Extends base, compliance table |
| `shared/report-templates/mobile-security-report.md.j2` | Create (replace .md) | Extends base, Mobile Top 10 |
| `parsers/sqlmap.py` | Create | SQLmap JSON parser |
| `parsers/nmap.py` | Create | Nmap XML parser with NSE script handling |
| `parsers/nikto.py` | Create | Nikto JSON parser with severity heuristic |
| `parsers/hashcat.py` | Create | Hashcat potfile parser with hash type detection |
| `tests/test_schema.py` | Modify | Migration v2 test (indexes exist, v1→v2 upgrade, idempotent) |
| `tests/test_engagement.py` | Modify | Dedup-on-insert tests, batch tests, export bundle tests |
| `tests/test_findings.py` | Modify | Word-boundary inference tests, title overlap tests, path normalization tests |
| `tests/test_reports.py` | Modify | Template inheritance tests, context builder tests, extra_context tests |
| `tests/test_parsers.py` | Modify | 4 new parser test suites (sqlmap, nmap with ports + NSE, nikto, hashcat) |

## 7. Testing Strategy

| Area | Tests |
|------|-------|
| Dedup-on-insert | Same CWE + close lines → merge; far lines → distinct; inferred CWE → LOW confidence; title overlap gate; path normalization (backslash, ./, /); batch dedup; parallel safety |
| Schema v2 | Migration applies cleanly; indexes exist; idempotent; v1→v2 upgrade |
| Report templates | Base template renders; child extends correctly; macros produce valid markdown; context builders compute correct OWASP/ATT&CK/cloud/mobile mappings; extra_context overrides; collapsible evidence |
| Export bundle | Creates valid zip; includes artifacts; logs missing files; import detects zip; round-trip export→import preserves data |
| Parsers | Each parser with realistic sample output; empty input; malformed input |
