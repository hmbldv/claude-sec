# CRBRS Security Review: Claude Code Enterprise Deployment

**Cycle:** 3
**Status:** Review Complete - APPROVED
**Review Date:** 2026-01-15
**Lead:** PALADIN | **Coordinator:** NEXUS

---

## Review Summary

Axiom has addressed stakeholder feedback with comprehensive updates:
- AWS-only deployment model strengthens security posture
- Cloud service integration paths verified and documented
- Command restriction analysis provides clear rationale for each control
- Conditional allow patterns balance security with usability

**Finding Status:**
| Severity | Status |
|----------|--------|
| Critical | 0 |
| High | 0 |
| Medium | 6 (accepted) |
| Low | 3 (accepted) |
| **New Issues** | 0 |

---

## Architecture Review: AWS-Only Deployment

### Assessment: APPROVED

The migration from local workstation to AWS-only deployment **significantly improves** security posture:

| Improvement | Security Impact |
|-------------|-----------------|
| No local data | Eliminates endpoint data leakage risk |
| SSM access | No SSH keys, no inbound ports, full recording |
| Network controls | All traffic through DNS/Network Firewall |
| Consistent enforcement | No variance in developer security posture |
| Ephemeral capability | Instances can be destroyed for max isolation |

**CRBRS Position:** AWS-only is now a **requirement**, not optional.

---

## Cloud Service Integration Review

### GitLab Integration: APPROVED

| Option | Security Level | CRBRS Recommendation |
|--------|---------------|---------------------|
| GitLab Dedicated + PrivateLink | HIGH | Preferred for sensitive projects |
| GitLab Self-Hosted (same VPC) | HIGH | Acceptable |
| GitLab.com via allowlist | MEDIUM | Acceptable for non-sensitive projects |

**Condition:** For projects handling sensitive data, GitLab Dedicated or self-hosted is required. GitLab.com SaaS acceptable only for general development.

### Atlassian (Jira/Confluence): APPROVED

Domain allowlisting approach is acceptable:
- `*.atlassian.net`
- `*.atlassian.com`
- `*.atl-paas.net`

**Condition:** Configure Atlassian IP allowlist to restrict access to Claude VPC NAT Gateway IPs.

### Package Registries: APPROVED WITH CONDITION

**Recommendation:** Implement private artifact proxy (Nexus/Artifactory) as the single allowlisted target.

**Rationale:**
- Package registries are supply chain attack vectors
- Proxy provides caching, vulnerability scanning, and audit logging
- Simplifies allowlist management

**Acceptable Alternative:** Direct registry access with:
- Lockfile integrity checks required
- npm/pip audit in CI/CD
- Regular dependency vulnerability scanning

---

## Command Restriction Analysis Review

### Category Assessment

#### curl/wget: APPROVED (Conditional Allow Pattern)

**CRBRS Decision:** The tiered permission model is acceptable.

| Pattern | Decision | Rationale |
|---------|----------|-----------|
| Deny POST/upload/pipe-to-shell | APPROVED | Blocks exfiltration and RCE |
| Allow HEAD requests | APPROVED | Safe read-only operation |
| Allow specific registries | APPROVED | Needed for package metadata |
| Ask for everything else | APPROVED | Human-in-loop for edge cases |

**Key Mitigations:**
1. Network Firewall allowlist provides second layer
2. Lakera Guard monitors for suspicious patterns
3. All operations logged and auditable

#### ssh: APPROVED (Conditional Allow with No Tunneling)

**CRBRS Decision:** SSH with human approval and no port forwarding is acceptable.

| Pattern | Decision | Rationale |
|---------|----------|-----------|
| Deny port forwarding (-D, -R, -L) | APPROVED | Prevents covert channels |
| Deny tunnel mode (-w, -N) | APPROVED | No VPN bypass |
| Deny remote dangerous commands | APPROVED | No chained attacks |
| Ask for basic SSH | APPROVED | Human approval required |

**Preferred Alternative:** AWS SSM for internal systems. SSH only for external systems not accessible via SSM.

**Condition:** Document approved SSH destinations in operational runbook.

#### Absolute Deny Commands: APPROVED

The following remain absolutely denied:
- `sudo` / `su`
- `nc` / `ncat` / `netcat` / `socat`
- `rm -rf /`
- `git push --force`
- `scp` / `rsync` / `ftp`

No exceptions. These represent unacceptable risk regardless of workflow need.

---

## Open Question Responses

### Q1: curl/wget controlled allow pattern
**CRBRS Answer:** Conditional allow with specific deny rules is ACCEPTABLE. The defense-in-depth approach (permission rules + network firewall + DLP) provides adequate protection.

### Q2: SSH with approval vs full block
**CRBRS Answer:** SSH with human approval and no tunneling is ACCEPTABLE. Recommend SSM for internal systems, SSH only where SSM is not available.

### Q3: Package registry access
**CRBRS Answer:** Recommend private artifact proxy (Nexus/Artifactory). Direct registry access acceptable with lockfile integrity checks and vulnerability scanning.

### Q4: GitLab.com via allowlist
**CRBRS Answer:** GitLab.com via allowlist is ACCEPTABLE for non-sensitive projects. Sensitive projects require GitLab Dedicated or self-hosted.

### Q5: Additional cloud services
**CRBRS Answer:** Defer to implementation phase. Services should be added to allowlist on documented business need with security review.

---

## Updated Conditions of Approval

### Mandatory (Before Production)
All previous conditions remain, plus:

1. **AWS-only deployment** - No local Claude Code installations permitted
2. **SSM for internal access** - Use SSM Session Manager instead of SSH for AWS resources
3. **Document approved destinations** - Maintain runbook of approved SSH targets (if any)
4. **Artifact proxy consideration** - Evaluate Nexus/Artifactory for package management

### Recommended (Within 30 Days)
1. Deploy private artifact proxy for package registries
2. Configure Atlassian IP allowlist
3. Create SSH destination approval process
4. Document curl/wget exception request workflow

---

## Residual Risk Assessment (Updated)

| Risk Category | Previous | Updated | Justification |
|---------------|----------|---------|---------------|
| Data Exposure | LOW | LOW | AWS-only + DLP unchanged |
| Prompt Injection | LOW | LOW | Lakera Guard unchanged |
| Audit Tampering | VERY LOW | VERY LOW | S3 Object Lock unchanged |
| Network Exfiltration | LOW | **VERY LOW** | AWS-only + controlled curl/wget |
| Code Integrity | VERY LOW | VERY LOW | PR workflow unchanged |
| Session Hijacking | LOW | **VERY LOW** | SSM replaces SSH |
| Command Injection | MEDIUM | **LOW** | Detailed deny patterns |

**Overall Residual Risk: LOW** (Improved from previous cycle)

---

## Verdict

**CRBRS REVIEW - CYCLE 3 - APPROVED**

The updated architecture with AWS-only deployment and detailed command restriction analysis **strengthens** the security posture. All stakeholder concerns have been adequately addressed.

**Summary of Improvements:**
- AWS-only deployment eliminates endpoint risk
- Command restriction analysis provides clear, defensible rationale
- Conditional allow patterns enable necessary workflows
- Cloud service integration paths documented and approved

---

**Approved: PALADIN, CRBRS Security Lead**
**Date: 2026-01-15**

---

**CRBRS REVIEW - CYCLE 3 - APPROVED**
