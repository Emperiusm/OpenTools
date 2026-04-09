# Incident Report: [Incident Name/ID]

## Incident Summary
- **Incident Type**: [malware, intrusion, data breach, insider threat, ransomware, phishing, etc.]
- **Detection Method**: [SIEM alert, user report, external notification, automated scan]
- **Detection Date**: [date/time UTC]
- **Estimated Incident Start**: [date/time UTC]
- **Containment Date**: [date/time UTC]
- **Eradication Date**: [date/time UTC]
- **Recovery Date**: [date/time UTC]
- **Status**: [investigating | contained | eradicated | recovered | closed]
- **Severity**: [Critical/High/Medium/Low]
- **Affected Systems**: [list of hosts, accounts, services]

## Root Cause Analysis
[How the attacker gained initial access, what vulnerability or misconfiguration was exploited, and the attack chain]

## Impact Assessment
- **Data affected**: [what was accessed, exfiltrated, encrypted, or destroyed]
- **Systems affected**: [count and description]
- **Business impact**: [operational disruption, financial, reputational]
- **Regulatory implications**: [GDPR, HIPAA, PCI-DSS notification requirements]

## Timeline of Events

| Timestamp (UTC) | Source | Event | Details | Confidence |
|-----------------|--------|-------|---------|------------|
| [time] | [log/memory/network] | [event description] | [details] | HIGH/MED/LOW |

## Attack Chain (MITRE ATT&CK)

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|---------|
| Initial Access | [technique] | [T-number] | [evidence] |
| Execution | [technique] | [T-number] | [evidence] |
| Persistence | [technique] | [T-number] | [evidence] |
| Privilege Escalation | [technique] | [T-number] | [evidence] |
| Defense Evasion | [technique] | [T-number] | [evidence] |
| Credential Access | [technique] | [T-number] | [evidence] |
| Discovery | [technique] | [T-number] | [evidence] |
| Lateral Movement | [technique] | [T-number] | [evidence] |
| Collection | [technique] | [T-number] | [evidence] |
| Exfiltration | [technique] | [T-number] | [evidence] |

## Indicators of Compromise

### Network
| Type | Value | First Seen | Last Seen | Context |
|------|-------|------------|-----------|---------|
| IP | [ip] | [date] | [date] | [C2/scan/exfil] |
| Domain | [domain] | [date] | [date] | [context] |
| URL | [url] | [date] | [date] | [context] |
| User-Agent | [ua] | [date] | [date] | [context] |

### Host
| Type | Value | Location | Context |
|------|-------|----------|---------|
| File | [path] | [host] | [dropper/payload/tool] |
| Hash (SHA256) | [hash] | [host] | [context] |
| Registry | [key] | [host] | [persistence/config] |
| Service | [name] | [host] | [persistence] |
| Scheduled Task | [name] | [host] | [persistence] |
| Mutex | [name] | [host] | [context] |

## Containment Actions Taken
1. [Action taken, time, by whom]
2. [Action taken, time, by whom]

## Eradication Actions Taken
1. [Action taken, time, by whom]
2. [Action taken, time, by whom]

## Recovery Actions
1. [Action taken, time, by whom]
2. [Action taken, time, by whom]

## Lessons Learned
- **What went well**: [list]
- **What could be improved**: [list]
- **Detection gaps identified**: [list]
- **Process improvements**: [list]

## Recommendations
1. **Immediate** (0-7 days): [actions]
2. **Short-term** (1-4 weeks): [actions]
3. **Long-term** (1-3 months): [actions]

## Appendix
- Tool outputs: [paths]
- Raw IOC export: [path]
- Memory analysis report: [path]
- Timeline CSV: [path]
- Engagement state file: [path]
