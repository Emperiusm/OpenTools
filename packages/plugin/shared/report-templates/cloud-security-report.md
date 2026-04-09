# Cloud Security Assessment Report

## Engagement Details
- **Client**: [name]
- **Assessor**: [name]
- **Date**: [start] to [end]
- **Provider(s)**: [AWS / Azure / GCP]
- **Scope**: [accounts, subscriptions, projects]
- **Access Level**: [read-only audit / admin / specific role]
- **Compliance Frameworks**: [CIS / SOC2 / HIPAA / PCI-DSS / NIST]

## Executive Summary
[1-2 paragraphs for non-technical stakeholders]

**Risk Rating Summary:**
- Critical: X | High: X | Medium: X | Low: X | Info: X

## Findings

| # | Severity | Category | Finding | Affected Resource | Remediation |
|---|----------|----------|---------|-------------------|-------------|
| 1 | CRITICAL | IAM | [finding] | [resource ARN/ID] | [fix] |

### Detailed Findings

#### [FINDING-001] [Title]
- **Severity**: Critical/High/Medium/Low
- **Category**: IAM / Storage / Network / Logging / Encryption / Container / Compute
- **Resource**: [ARN / resource ID / subscription]
- **Provider**: [AWS / Azure / GCP]
- **Description**: [what was found]
- **Evidence**:
  ```
  [CLI output, config snippet, screenshot reference]
  ```
- **Risk**: [what could go wrong if exploited]
- **Remediation**:
  ```
  [Exact CLI command or IaC change to fix]
  ```
- **Reference**: [CIS benchmark control, AWS Well-Architected reference]

---

[Repeat for each finding]

## Compliance Summary

| Framework | Control | Status | Finding Ref |
|-----------|---------|--------|-------------|
| CIS 1.1 | Avoid root account usage | PASS/FAIL | FINDING-XXX |
| CIS 1.4 | Ensure MFA on root | PASS/FAIL | FINDING-XXX |

## Architecture Observations
[Notes on cloud architecture, multi-account strategy, network topology, VPC design]

## Recommendations (Priority Order)

### Immediate (0-7 days)
1. [Critical fixes]

### Short-term (1-4 weeks)
1. [High-priority improvements]

### Long-term (1-3 months)
1. [Architecture improvements, automation]

## Methodology
- **Tools used**: [Prowler, Trivy, AWS CLI, custom scripts]
- **Scan scope**: [all regions / specific regions]
- **Limitations**: [access restrictions, excluded services]

## Appendix
- Prowler full output: [path]
- Trivy scan results: [path]
- IAM policy analysis: [path]
