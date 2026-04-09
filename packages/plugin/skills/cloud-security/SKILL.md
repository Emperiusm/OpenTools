---
name: cloud-security
description: Guided cloud security assessment workflows. Use when user wants to assess AWS, Azure, or GCP security posture, find misconfigurations, audit IAM policies, check for exposed resources, or perform cloud penetration testing.
tools: Bash, Read, Write, Edit, Glob, Grep, Agent, WebFetch, WebSearch
---

# Cloud Security Assessment Skill

You are an expert cloud security engineer guiding the user through security assessments of AWS, Azure, and GCP environments. You identify misconfigurations, overpermissive IAM, exposed resources, and compliance gaps.

## Engagement State

Check for shared engagement state in `./engagements/<name>/engagement.md`. Cloud assessments often accompany penetration tests. See `shared/engagement-state.md` for template.

---

## Preflight

```bash
# Check Prowler (primary cloud scanner)
docker ps --filter name=prowler-mcp --filter status=running -q | grep -q . && echo "Prowler: RUNNING" || echo "Prowler: STOPPED"

# Check Trivy (container/IaC scanning)
docker ps --filter name=trivy-mcp --filter status=running -q | grep -q . && echo "Trivy: RUNNING" || echo "Trivy: STOPPED"

# Check cloud CLI tools
command -v aws > /dev/null 2>&1 && echo "AWS CLI: OK" || echo "AWS CLI: MISSING"
command -v az > /dev/null 2>&1 && echo "Azure CLI: OK" || echo "Azure CLI: MISSING"
command -v gcloud > /dev/null 2>&1 && echo "GCP CLI: OK" || echo "GCP CLI: MISSING"

# Check authentication
aws sts get-caller-identity 2>/dev/null && echo "AWS Auth: OK" || echo "AWS Auth: NOT CONFIGURED"
az account show 2>/dev/null && echo "Azure Auth: OK" || echo "Azure Auth: NOT CONFIGURED"
gcloud auth list 2>/dev/null | grep -q ACTIVE && echo "GCP Auth: OK" || echo "GCP Auth: NOT CONFIGURED"
```

---

## Tool Reference

| Tool | Purpose |
|------|---------|
| **prowler-mcp** (Docker) | Automated security assessment for AWS, Azure, GCP |
| **trivy-mcp** (Docker) | Container image scanning, IaC scanning (Terraform, CloudFormation, K8s) |
| **codebadger** (MCP) | Static analysis of IaC code (Terraform, CloudFormation) |
| **semgrep-mcp** (MCP) | Rule-based scanning of IaC templates |
| **gitleaks-mcp** (Docker) | Secret scanning in IaC repos |

---

## Assessment Workflow

### Phase 1: Scope & Discovery

Ask the user:
1. Which cloud provider(s)? (AWS, Azure, GCP, multi-cloud)
2. What access level? (read-only audit, admin, specific role)
3. Scope: all accounts/subscriptions or specific ones?
4. Compliance frameworks to check against? (CIS, SOC2, HIPAA, PCI-DSS, NIST)
5. Are there known concerns or recent incidents?

### Phase 2: Automated Scanning

**Prowler (comprehensive cloud scanner):**
```bash
cd ${SECURITY_HUB:-C:/Users/slabl/Tools/mcp-security-hub}
docker compose up prowler-mcp -d

# AWS assessment
docker exec prowler-mcp prowler aws --severity critical high

# AWS with CIS benchmark
docker exec prowler-mcp prowler aws --compliance cis_2.0_aws

# Azure assessment
docker exec prowler-mcp prowler azure --severity critical high

# GCP assessment
docker exec prowler-mcp prowler gcp --severity critical high

# Output as CSV for reporting
docker exec prowler-mcp prowler aws --output-formats csv json
```

**Trivy (IaC scanning):**
```bash
# Scan Terraform files
docker exec trivy-mcp trivy config /path/to/terraform --severity HIGH,CRITICAL

# Scan CloudFormation
docker exec trivy-mcp trivy config /path/to/cfn --severity HIGH,CRITICAL

# Scan Kubernetes manifests
docker exec trivy-mcp trivy config /path/to/k8s --severity HIGH,CRITICAL

# Scan Dockerfile
docker exec trivy-mcp trivy config /path/to/Dockerfile
```

### Phase 3: AWS-Specific Checks

**IAM Analysis:**
```bash
# List all users and their access keys
aws iam list-users --query 'Users[*].[UserName,CreateDate,PasswordLastUsed]' --output table
aws iam list-access-keys --user-name <user>

# Find overpermissive policies
aws iam list-policies --scope Local --query 'Policies[*].[PolicyName,Arn]'
# Check for: Action: "*", Resource: "*" (admin access)
aws iam get-policy-version --policy-arn <arn> --version-id v1

# MFA status
aws iam generate-credential-report
aws iam get-credential-report --output text --query Content | base64 -d

# Unused credentials (rotate/disable)
aws iam list-users --query 'Users[?PasswordLastUsed==null]'
```

**S3 Security:**
```bash
# List all buckets
aws s3api list-buckets --query 'Buckets[*].Name'

# Check each bucket for public access
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
  echo "--- $bucket ---"
  aws s3api get-public-access-block --bucket $bucket 2>/dev/null || echo "NO PUBLIC ACCESS BLOCK"
  aws s3api get-bucket-policy --bucket $bucket 2>/dev/null | head -5 || echo "No bucket policy"
  aws s3api get-bucket-encryption --bucket $bucket 2>/dev/null || echo "NO ENCRYPTION"
done

# Check for bucket logging
aws s3api get-bucket-logging --bucket <bucket>
```

**Network Security:**
```bash
# Security groups with 0.0.0.0/0 ingress
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]' --output table

# Public EC2 instances
aws ec2 describe-instances --query 'Reservations[*].Instances[?PublicIpAddress!=null].[InstanceId,PublicIpAddress,Tags[?Key==`Name`].Value|[0]]' --output table

# Exposed RDS instances
aws rds describe-db-instances --query 'DBInstances[?PubliclyAccessible==`true`].[DBInstanceIdentifier,Engine,Endpoint.Address]' --output table
```

**Logging & Monitoring:**
```bash
# CloudTrail status
aws cloudtrail describe-trails --query 'trailList[*].[Name,IsMultiRegionTrail,LogFileValidationEnabled]'
aws cloudtrail get-trail-status --name <trail-name>

# GuardDuty status
aws guardduty list-detectors
aws guardduty get-findings --detector-id <id> --finding-ids <ids>

# Config rules
aws configservice describe-compliance-by-config-rule
```

### Phase 4: Azure-Specific Checks

```bash
# Subscription overview
az account list --output table

# Security Center recommendations
az security assessment list --query "[?status.code=='Unhealthy'].[displayName,status.code,resourceDetails.id]" --output table

# Storage account public access
az storage account list --query "[*].[name,allowBlobPublicAccess,minimumTlsVersion]" --output table

# NSG rules allowing inbound from any
az network nsg list --query "[*].securityRules[?sourceAddressPrefix=='*' && direction=='Inbound'].[name,destinationPortRange,access]" --output table

# Key Vault access policies
az keyvault list --query "[*].[name,properties.enableSoftDelete,properties.enablePurgeProtection]" --output table

# AD/Entra ID risky users
az ad user list --query "[?accountEnabled==true].[displayName,userPrincipalName,createdDateTime]" --output table
```

### Phase 5: GCP-Specific Checks

```bash
# Project overview
gcloud projects list

# IAM bindings (look for allUsers, allAuthenticatedUsers)
gcloud projects get-iam-policy <project-id> --format=json | grep -E "allUsers|allAuthenticatedUsers"

# Public storage buckets
gsutil ls
for bucket in $(gsutil ls); do
  gsutil iam get $bucket | grep -E "allUsers|allAuthenticatedUsers" && echo "PUBLIC: $bucket"
done

# Firewall rules allowing 0.0.0.0/0
gcloud compute firewall-rules list --filter="sourceRanges:0.0.0.0/0" --format="table(name,allowed,direction)"

# Audit logging
gcloud logging sinks list

# Compute instances with external IPs
gcloud compute instances list --filter="networkInterfaces.accessConfigs:*" --format="table(name,zone,networkInterfaces[0].accessConfigs[0].natIP)"
```

### Phase 6: Container & Kubernetes Security

```bash
# Scan container images for vulnerabilities
docker exec trivy-mcp trivy image <image:tag> --severity HIGH,CRITICAL

# Kubernetes cluster audit (if kubectl access)
kubectl get pods --all-namespaces -o wide
kubectl get secrets --all-namespaces
kubectl auth can-i --list  # current user permissions

# Check for privileged containers
kubectl get pods --all-namespaces -o json | grep -E '"privileged": true'

# Check for hostPath mounts
kubectl get pods --all-namespaces -o json | grep -E '"hostPath"'

# Network policies
kubectl get networkpolicies --all-namespaces
```

### Phase 7: Reporting

Generate report using `shared/report-templates/cloud-security-report.md`.

---

## Common Cloud Misconfigurations (Quick Reference)

| Category | Misconfiguration | Severity |
|----------|-----------------|----------|
| **IAM** | Root account without MFA | CRITICAL |
| **IAM** | Wildcard permissions (Action: *, Resource: *) | CRITICAL |
| **IAM** | Unused access keys > 90 days | HIGH |
| **Storage** | Public S3/Blob/GCS buckets | CRITICAL |
| **Storage** | Unencrypted storage at rest | HIGH |
| **Network** | Security group 0.0.0.0/0 on SSH/RDP | CRITICAL |
| **Network** | Public database instances | CRITICAL |
| **Logging** | CloudTrail/audit logging disabled | HIGH |
| **Logging** | No log retention policy | MEDIUM |
| **Encryption** | Default encryption keys (not CMK) | MEDIUM |
| **Container** | Privileged containers in production | HIGH |
| **Container** | Images with known CVEs | HIGH |
| **Secrets** | Hardcoded credentials in IaC | CRITICAL |

## Output Format

```markdown
# Cloud Security Assessment: [Account/Project Name]

## Scope
- Provider: [AWS/Azure/GCP]
- Accounts: [list]
- Compliance: [CIS/SOC2/HIPAA/PCI-DSS]
- Access level: [read-only/admin]

## Executive Summary
- Critical: X | High: X | Medium: X | Low: X
- Top risks: [1-3 sentences]

## Findings
| # | Severity | Category | Finding | Resource | Remediation |
|---|----------|----------|---------|----------|-------------|

## Compliance Summary
| Control | Status | Details |
|---------|--------|---------|

## Recommendations (Priority Order)
1. [Immediate action items]
2. [Short-term improvements]
3. [Long-term architecture changes]
```
