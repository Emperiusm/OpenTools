# Engagement State System

Both pentest and RE skills share a common engagement log so findings flow between them.

## How It Works

At the start of any engagement, create a state file:

```
C:\Users\slabl\Tools\security-skills\engagements\<name>\engagement.md
```

## State File Template

```markdown
# Engagement: [Name]
- **Started**: [date]
- **Target**: [description]
- **Type**: pentest | reverse-engineering | both
- **Scope**: [authorized targets]

## Findings Log
| # | Time | Phase | Tool | Finding | Severity | Details |
|---|------|-------|------|---------|----------|---------|

## Artifacts
- [path to captured files, screenshots, pcaps, etc.]

## RE Notes
- [binary analysis results, decompiled code refs, etc.]

## IOCs Discovered
- Network: [IPs, domains, URLs]
- Host: [files, registry, mutexes]
- Hashes: [MD5, SHA256]
```

## Usage in Skills

- **Before any action**: Read the engagement file to check scope and prior findings
- **After any finding**: Append to the findings log immediately
- **Cross-referencing**: If pentest finds a suspicious binary, note it for RE. If RE finds a vuln, note it for pentest.
