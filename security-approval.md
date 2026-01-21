# Security Approval: Claude Code Enterprise Deployment

**Document Type:** Formal Security Approval
**Status:** APPROVED
**Approval Date:** 2026-01-15
**Final Review Cycle:** 4
**Approved By:** PALADIN, CRBRS Security Lead

---

## Executive Summary

This document formally approves the deployment of Claude Code for enterprise development teams under the conditions and controls specified herein. The approval follows a comprehensive security review conducted over four iterative cycles by the CRBRS Security Team in collaboration with the Axiom Research Team.

**Approval Scope:**
- Claude Code CLI for software development workflows
- AWS-only deployment (EC2 instances in VPC)
- Access to internal code repositories (non-classified)
- OS-level operations within sandboxed environment
- MCP server integration with approved data sources
- Docker container operations with restrictions

---

## Approval Statement

Following thorough security assessment across four review cycles, I hereby approve the deployment of Claude Code for enterprise use subject to the conditions documented in this approval.

The security architecture demonstrates:
- Defense-in-depth across all attack vectors
- Comprehensive audit and accountability controls
- Alignment with NIST Cybersecurity Framework 2.0
- Appropriate compensating controls for accepted risks

**Formal Approval:**

```
APPROVED FOR PRODUCTION DEPLOYMENT

Approver: PALADIN
Role: CRBRS Security Lead
Date: 2026-01-15
Review Cycles: 4
```

---

## Residual Risk Assessment

### Risk Summary

| Risk Category | Level | Trend | Key Mitigations |
|---------------|-------|-------|-----------------|
| Data Exposure | LOW | Stable | DLP, encryption, network controls |
| Prompt Injection | LOW | Stable | Lakera Guard, behavioral monitoring |
| Audit Tampering | VERY LOW | Stable | S3 Object Lock, auditd |
| Network Exfiltration | VERY LOW | Stable | DNS/Network Firewall |
| Code Integrity | VERY LOW | Stable | PR-only workflow |
| Session Hijacking | VERY LOW | Stable | SSM, MFA, session limits |
| Command Injection | LOW | Stable | Tiered deny/ask/allow |
| MCP Data Access | LOW | New | managed-mcp.json, read-only |
| Container Escape | LOW | New | Docker restrictions |
| Audit Evasion | VERY LOW | New | HISTCONTROL hardening |

**Overall Residual Risk: LOW**

### Accepted Risk Rationale

| Finding | Severity | Acceptance Rationale |
|---------|----------|---------------------|
| MCP Server Governance | MEDIUM | managed-mcp.json eliminates shadow servers |
| Docker Escape Potential | MEDIUM | Comprehensive deny list prevents escape vectors |
| Sandbox Limitations | MEDIUM | Multi-layer defense compensates |
| Supply Chain Risk | MEDIUM | Artifact proxy + scanning mitigates |
| HISTCONTROL Bypass | LOW | Multi-layer defense (managed-settings + auditd) |
| DevContainer Credentials | LOW | Bypass mode disabled |

---

## Conditions of Approval

### Mandatory: Before Production

The following conditions MUST be satisfied before production deployment:

#### 1. Infrastructure Controls
- [ ] AWS-only deployment (no local installations)
- [ ] VPC with private subnets for Claude Code instances
- [ ] AWS SSM Session Manager for developer access
- [ ] DNS Firewall with explicit allowlist
- [ ] Network Firewall with domain filtering
- [ ] VPC endpoints for Bedrock, S3, CloudWatch, SSM

#### 2. Application Controls
- [ ] managed-settings.json deployed and enforced
- [ ] managed-mcp.json deployed (Option A - exclusive control)
- [ ] bubblewrap sandbox enabled
- [ ] PreToolUse hooks configured (DLP, Lakera, audit)
- [ ] disableBypassPermissionsMode set to "disable"

#### 3. Audit Controls
- [ ] Kinesis Firehose streaming to S3
- [ ] S3 bucket with Object Lock (COMPLIANCE mode)
- [ ] CloudTrail enabled for API audit
- [ ] SSM Session logging to CloudWatch
- [ ] auditd configured with execve monitoring

#### 4. Security Tools
- [ ] Lakera Guard deployed (prompt injection defense)
- [ ] TruffleHog/Gitleaks for secret scanning
- [ ] LLM Guard proxy for content filtering

#### 5. Shell Security
- [ ] `/etc/profile.d/history-security.sh` deployed
- [ ] auditd rules for command logging
- [ ] History file protection configured

#### 6. Access Controls
- [ ] IAM Identity Center integration
- [ ] MFA required for all access
- [ ] Session limits enforced (8hr max, 30min idle)

#### 7. Personnel
- [ ] Developer security training completed
- [ ] Training acknowledgment on file

### Mandatory: Within 30 Days

- [ ] Incident Response playbook for Claude-specific scenarios
- [ ] Tabletop exercise completed
- [ ] SOC integration verified
- [ ] Role documentation (operator/user/admin)
- [ ] Escalation procedures defined
- [ ] Communication templates created

### Mandatory: Within 90 Days

- [ ] Private artifact proxy deployed (Nexus/Artifactory)
- [ ] Syslog forwarding for real-time command logging
- [ ] Anomaly detection tuning completed
- [ ] First quarterly security review

### Ongoing Requirements

| Requirement | Frequency | Owner |
|-------------|-----------|-------|
| Log recovery testing | Quarterly | Security Operations |
| Security threshold review | Monthly (first 90 days), then quarterly | CRBRS |
| Developer training recertification | Annual | Training Team |
| Architecture reassessment | Annual | CRBRS + Axiom |
| Anthropic advisory subscription | Continuous | Security Operations |

---

## Finding Resolution Summary

### Remediated (6)

| ID | Finding | Resolution |
|----|---------|------------|
| CRIT-01 | No DLP Integration | Multi-layer DLP deployed |
| CRIT-02 | Prompt Injection Defense | Lakera Guard deployed |
| HIGH-01 | Audit Log Integrity | S3 Object Lock (COMPLIANCE) |
| HIGH-02 | Network Egress Controls | DNS + Network Firewall |
| HIGH-03 | Code Commit Review | PR-only workflow |
| HIGH-04 | Session Management | 8hr timeout + SSM |

### Accepted with Controls (13)

| Severity | Count | Compensating Controls |
|----------|-------|----------------------|
| Medium | 8 | managed-settings enforcement, audit logging, multi-layer defense |
| Low | 5 | Encryption, session limits, configuration hardening |

---

## Monitoring Requirements

### Real-Time Alerts

| Alert | Threshold | Response |
|-------|-----------|----------|
| Denied command attempt | Any | Log review, user notification |
| Prompt injection detected | Any | Session kill, SOC alert |
| Anomalous API pattern | >2 std dev | Session review |
| MCP query rate exceeded | >100/min | Rate limit, review |
| Docker privileged attempt | Any | Session kill, investigation |
| History evasion attempt | Any | Log, alert, review |

### Periodic Reviews

| Review | Frequency | Focus |
|--------|-----------|-------|
| Audit log sampling | Weekly | Compliance verification |
| Permission exceptions | Monthly | Ask-approved commands |
| MCP server usage | Monthly | Data access patterns |
| Training compliance | Quarterly | Certification status |
| Architecture review | Annual | Control effectiveness |

---

## Scope Limitations

### In Scope

- Software development workflows
- Code generation and completion
- Code review and debugging
- Test generation
- Documentation generation
- Git operations (with PR workflow)
- Database queries (read-only via MCP)
- Container operations (with restrictions)

### Out of Scope

This approval does NOT cover:

- Classified or restricted data access
- Production system access
- Customer data environments
- Financial transaction systems
- Healthcare/PII systems (requires additional controls)
- Direct database write operations
- Privileged container operations
- SSH tunneling or port forwarding

### Future Scope Considerations

Additional review required before enabling:
- Write access to databases
- Additional MCP servers
- External API integrations
- Cross-account access

---

## Amendment Process

Changes to this approval require:

1. **Minor Changes** (threshold adjustments, allowlist additions)
   - Security team approval
   - Documentation update
   - Change control ticket

2. **Moderate Changes** (new MCP servers, new cloud services)
   - CRBRS review
   - Risk assessment update
   - Stakeholder notification

3. **Major Changes** (architecture changes, new capabilities)
   - Full review cycle
   - PALADIN approval
   - Updated approval document

---

## Contact Information

| Role | Team | Responsibility |
|------|------|----------------|
| Security Lead | CRBRS (PALADIN) | Approval authority, policy decisions |
| Research Lead | Axiom (Thesis) | Architecture recommendations |
| Implementation | Cloud Operations | Infrastructure deployment |
| Training | Security Awareness | Developer enablement |
| Operations | Security Operations | Monitoring, incident response |

---

## Approval Signatures

### Security Approval

```
Approved: PALADIN
Title: CRBRS Security Lead
Date: 2026-01-15
Signature: [ELECTRONIC SIGNATURE]

Review Summary:
- Critical Findings: 0 (2 remediated)
- High Findings: 0 (4 remediated)
- Medium Findings: 8 (all accepted with controls)
- Low Findings: 5 (all accepted with controls)
- Overall Residual Risk: LOW
```

### Acknowledgments

This approval acknowledges the contributions of:
- **Axiom Research Team** - Comprehensive security research and architecture design
- **CRBRS Security Team** - Thorough security review and finding analysis
- **Stakeholders** - Feedback driving iterative improvements

---

## Document Control

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-01-15 | Initial approval (Cycle 2) | PALADIN |
| 1.1 | 2026-01-15 | AWS-only, command analysis (Cycle 3) | PALADIN |
| 2.0 | 2026-01-15 | MCP, Docker, HISTCONTROL, NIST (Cycle 4) | PALADIN |

**Review Cycle:** Quarterly or upon significant architecture change
**Next Review:** 2026-04-15

---

## Appendix A: Quick Reference

### Key Files

| File | Location | Purpose |
|------|----------|---------|
| managed-settings.json | /etc/claude-code/ | Permission enforcement |
| managed-mcp.json | /etc/claude-code/ | MCP server control |
| history-security.sh | /etc/profile.d/ | Shell hardening |
| claude-audit.rules | /etc/audit/rules.d/ | auditd configuration |

### Key Decisions

| Topic | Decision |
|-------|----------|
| Deployment model | AWS-only (mandatory) |
| MCP governance | Option A (exclusive control) |
| Database access | Read-only with conditions |
| Docker | Allowed with restrictions |
| curl/wget | Conditional allow |
| SSH | Ask with no tunneling |
| Developer training | Mandatory |

---

**END OF SECURITY APPROVAL DOCUMENT**
