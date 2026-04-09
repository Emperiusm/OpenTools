# Mobile Application Security Assessment

## Application Details
- **App Name**: [name]
- **Package**: [com.example.app]
- **Version**: [version code / version name]
- **Platform**: [Android / iOS / Cross-platform]
- **Framework**: [Native Java/Kotlin / React Native / Flutter / Cordova / Unity]
- **Min SDK**: [API level]
- **Target SDK**: [API level]
- **Assessment Date**: [date]
- **Assessor**: [name]

## Executive Summary
[1-2 paragraphs for non-technical stakeholders]

**Risk Rating Summary:**
- Critical: X | High: X | Medium: X | Low: X | Info: X

## OWASP Mobile Top 10 Coverage

| # | Category | Status | Findings |
|---|----------|--------|----------|
| M1 | Improper Credential Usage | PASS/FAIL/N/A | [refs] |
| M2 | Inadequate Supply Chain Security | PASS/FAIL/N/A | [refs] |
| M3 | Insecure Authentication/Authorization | PASS/FAIL/N/A | [refs] |
| M4 | Insufficient Input/Output Validation | PASS/FAIL/N/A | [refs] |
| M5 | Insecure Communication | PASS/FAIL/N/A | [refs] |
| M6 | Inadequate Privacy Controls | PASS/FAIL/N/A | [refs] |
| M7 | Insufficient Binary Protections | PASS/FAIL/N/A | [refs] |
| M8 | Security Misconfiguration | PASS/FAIL/N/A | [refs] |
| M9 | Insecure Data Storage | PASS/FAIL/N/A | [refs] |
| M10 | Insufficient Cryptography | PASS/FAIL/N/A | [refs] |

## Findings

### [FINDING-001] [Title]
- **Severity**: Critical/High/Medium/Low
- **OWASP Mobile**: [M1-M10]
- **CWE**: [CWE-XXX]
- **Component**: [Manifest / Source / Native lib / API / Storage]
- **Description**: [what was found]
- **Evidence**:
  ```
  [Code snippet, config excerpt, Frida output, screenshot path]
  ```
- **Impact**: [what an attacker could achieve]
- **Remediation**:
  ```
  [Specific code fix or configuration change]
  ```

---

[Repeat for each finding]

## Static Analysis Results
- **Manifest issues**: [list]
- **Hardcoded secrets**: [list]
- **Insecure code patterns**: [list]
- **Native library findings**: [list]
- **Third-party SDK concerns**: [list]

## Dynamic Analysis Results
- **Certificate pinning**: [implemented / bypassed / not present]
- **Root/jailbreak detection**: [implemented / bypassed / not present]
- **Data leakage**: [clipboard, logs, screenshots, backups]
- **Runtime behavior**: [findings from Frida instrumentation]

## API Security Results
- **Endpoints tested**: [count]
- **Authentication issues**: [findings]
- **Authorization issues**: [findings]
- **Input validation issues**: [findings]

## Recommendations (Priority Order)
1. [Critical fixes]
2. [High-priority improvements]
3. [Best practice enhancements]

## Methodology
- **Tools used**: [JADX, Frida, codebadger, etc.]
- **Device/emulator**: [model, OS version, rooted/jailbroken]
- **Scope**: [static only / static + dynamic / full]

## Appendix
- Decompiled source: [path]
- Frida scripts used: [paths]
- API endpoint list: [path]
