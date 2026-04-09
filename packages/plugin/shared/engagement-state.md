# Engagement State System

All skills (pentest, RE, hardware-RE, forensics, cloud-security, mobile) share a common engagement log so findings flow between them.

## How It Works

At the start of any engagement, create a state file:

```
${ENGAGEMENT_DIR}/<name>/engagement.md
```

Where `ENGAGEMENT_DIR` defaults to `./engagements/` (relative to the project root) or the path set in `config/profiles.yaml`.

## State File Template

```markdown
# Engagement: [Name]
- **Started**: [date]
- **Target**: [description]
- **Type**: pentest | reverse-engineering | hardware-re | forensics | cloud-security | mobile | combined
- **Scope**: [authorized targets]
- **Status**: active | paused | complete

## Findings Log
| # | Time | Phase | Skill | Tool | Finding | Severity | CWE | Details |
|---|------|-------|-------|------|---------|----------|-----|---------|

## Artifacts
- [path to captured files, screenshots, pcaps, etc.]

## RE Notes
- [binary analysis results, decompiled code refs, etc.]

## IOCs Discovered
- Network: [IPs, domains, URLs, user agents]
- Host: [files, registry, mutexes, services, scheduled tasks]
- Hashes: [MD5, SHA256]

## Cloud Findings
- [misconfigurations, exposed resources, IAM issues]

## Mobile Findings
- [APK/IPA analysis, certificate pinning, API leaks]

## Timeline
| Time | Action | Tool | Result |
|------|--------|------|--------|
```

## Usage in Skills

- **Before any action**: Read the engagement file to check scope and prior findings
- **After any finding**: Append to the findings log immediately
- **Cross-referencing**: If pentest finds a suspicious binary, note it for RE. If RE finds a vuln, note it for pentest. If cloud-security finds exposed credentials, note for pentest.
- **Deduplication**: Before adding a finding, check if another tool already reported it. If so, add the new tool as corroboration rather than a duplicate entry.
