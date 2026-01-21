# Claude Security Approval - Document Manifest

## Status: APPROVED

**Approval Date:** 2026-01-15
**Final Cycle:** 4
**Approved By:** PALADIN, CRBRS Security Lead

---

## Root Documents (Approved Artifacts)

| Document | Owner | Purpose |
|----------|-------|---------|
| `security-approval.md` | PALADIN/CRBRS | Formal security approval, residual risk assessment, conditions |
| `architecture-recommendation.md` | Axiom | Deployment architecture, configuration specs, implementation guide |
| `manifest.md` | - | This document index |
| `_loop-prompt.md` | - | Original research loop prompt |

---

## Working Directories

### `axiom/` - Research Team Documents

| Document | Purpose |
|----------|---------|
| `research.md` | Current security research and findings (Cycle 4) |
| `configurations.md` | Deployment configuration analysis |
| `archive/` | Historical versions from previous cycles |

### `crbrs/` - Security Team Documents

| Document | Purpose |
|----------|---------|
| `review.md` | Current security review and verdict (Cycle 4) |
| `findings.md` | Itemized findings tracker |
| `archive/` | Historical versions from previous cycles |

### `Archive/` - Previous Approved Documents

| Document | Purpose |
|----------|---------|
| `security-approval.md` | Cycle 3 approval (superseded) |
| `architecture-recommendation.md` | Cycle 3 architecture (superseded) |
| `manifest.md` | Cycle 3 manifest (superseded) |

---

## Scope

This approval covers Claude Code deployment for development teams with:

- **Deployment Model:** AWS-only (Linux EC2 instances in VPC) - NO local installations
- **Codebase Access:** Read/write to internal repositories (non-classified)
- **OS-level Access:** File system, terminal, development tools (sandboxed)
- **API Provider:** Amazon Bedrock via VPC Private Endpoints
- **Developer Access:** AWS SSM Session Manager (no SSH to instances)
- **Cloud Services:** GitLab, Jira/Confluence, package registries (allowlisted)
- **MCP Servers:** Pre-approved servers only (managed-mcp.json)
- **Docker:** Allowed with restrictions (no privileged mode, no host mounts)

### Supported Use Cases
- Code generation and completion
- Code review and debugging
- Test generation
- Documentation generation
- Refactoring assistance
- Git operations (with PR workflow)
- Database queries (read-only via MCP)
- Container operations (restricted)

### Out of Scope
- Classified/restricted data access
- Production system access
- Customer data environments
- Financial transaction systems
- Healthcare/PII systems (without additional controls)
- Database write operations
- Privileged container operations
- SSH tunneling/port forwarding

---

## Key Security Controls Summary

| Control Category | Implementation |
|-----------------|----------------|
| Isolation | bubblewrap sandbox |
| Policy Enforcement | managed-settings.json (non-overridable) |
| MCP Governance | managed-mcp.json (exclusive control) |
| DLP | TruffleHog + LLM Guard + egress DLP |
| Prompt Injection | Lakera Guard + output validation + behavioral monitoring |
| Audit | Kinesis → S3 Object Lock (COMPLIANCE mode) |
| Network | DNS Firewall + Network Firewall (explicit allowlist) |
| Code Integrity | PR-only workflow with human review |
| Session | 8hr max, 30min idle, SSM recording |
| Shell Security | HISTCONTROL hardening + auditd + syslog |
| Container | Docker restrictions (no privileged/host access) |

---

## Residual Risk Summary

| Category | Risk Level |
|----------|------------|
| Data Exposure | LOW |
| Prompt Injection | LOW |
| Audit Tampering | VERY LOW |
| Network Exfiltration | VERY LOW |
| Code Integrity | VERY LOW |
| Session Hijacking | VERY LOW |
| Command Injection | LOW |
| MCP Data Access | LOW |
| Container Escape | LOW |
| Audit Evasion | VERY LOW |
| **Overall** | **LOW** |

---

## Findings Summary

| Severity | Total | Remediated | Accepted |
|----------|-------|------------|----------|
| Critical | 2 | 2 | 0 |
| High | 4 | 4 | 0 |
| Medium | 8 | 0 | 8 |
| Low | 5 | 0 | 5 |
| **Total** | **19** | **6** | **13** |

---

## Conditions of Approval

### Before Production
1. Deploy Lakera Guard (commercial)
2. Configure S3 Object Lock in COMPLIANCE mode
3. Enable full session recording via SSM
4. Subscribe to Anthropic security advisories
5. Complete developer training
6. Deploy managed-mcp.json with approved servers only
7. Configure Docker restrictions
8. Deploy shell security configuration (history-security.sh + auditd)

### Within 30 Days
1. Create Claude-specific IR playbook
2. Complete tabletop exercise
3. Document role definitions (operator/user/admin)
4. Establish escalation procedures
5. Deploy private artifact proxy (Nexus/Artifactory)

### Ongoing
- Monthly threshold review (first 90 days)
- Quarterly log recovery testing
- Annual security reassessment
- Annual developer training recertification

---

## Research Cycle History

| Cycle | Date | Axiom Status | CRBRS Status | Outcome |
|-------|------|--------------|--------------|---------|
| 1 | 2026-01-15 | Complete | ITERATE | 2C/4H identified |
| 2 | 2026-01-15 | Complete | APPROVED | All C/H remediated |
| 3 | 2026-01-15 | Complete | APPROVED | AWS-only + command analysis |
| 4 | 2026-01-15 | Complete | APPROVED | MCP + Docker + HISTCONTROL + NIST |

---

## New in Cycle 4

### Security Domains Added

| Domain | Key Controls |
|--------|--------------|
| **MCP Server Security** | managed-mcp.json, read-only database, audit logging |
| **Docker/Container Security** | Escape prevention, registry restriction, resource limits |
| **Shell Security (HISTCONTROL)** | Deny rules, auditd, syslog forwarding |
| **NIST CSF 2.0 Alignment** | Coverage audit, gap identification, remediation plan |

### New Conditions Added

| Condition | Timeline |
|-----------|----------|
| Developer security training | Before production (mandatory) |
| Claude-specific IR playbook | Within 30 days |
| Role documentation | Within 30 days |
| Communication plan | Within 30 days |

### New Findings

| ID | Severity | Status |
|----|----------|--------|
| MED-07: MCP Server Governance | Medium | Accepted |
| MED-08: Docker Escape Potential | Medium | Accepted |
| LOW-04: HISTCONTROL Bypass | Low | Accepted |
| LOW-05: DevContainer Credential Risk | Low | Accepted |

---

## Contact Information

| Role | Team | Responsibility |
|------|------|----------------|
| Security Lead | CRBRS (PALADIN) | Approval authority, policy decisions |
| Research Lead | Axiom (Thesis) | Architecture recommendations |
| Implementation | Cloud Operations | Infrastructure deployment |
| Training | Security Awareness | Developer enablement |

---

## Document Control

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-15 | Initial approval (Cycle 2) |
| 1.1 | 2026-01-15 | AWS-only + command analysis (Cycle 3) |
| 2.0 | 2026-01-15 | MCP + Docker + HISTCONTROL + NIST (Cycle 4) |

**Review Cycle:** Quarterly or upon significant architecture change
**Next Review:** 2026-04-15

---

## Quick Reference

### Key Configuration Files

| File | Location | Purpose |
|------|----------|---------|
| managed-settings.json | /etc/claude-code/ | Permission enforcement |
| managed-mcp.json | /etc/claude-code/ | MCP server control |
| history-security.sh | /etc/profile.d/ | Shell hardening |
| claude-audit.rules | /etc/audit/rules.d/ | auditd configuration |

### Key Decisions Summary

| Topic | Decision |
|-------|----------|
| Deployment model | AWS-only (mandatory) |
| MCP governance | Option A (exclusive managed-mcp.json) |
| Database access | Read-only with conditions |
| Docker | Allowed with restrictions |
| curl/wget | Conditional allow |
| SSH | Ask with no tunneling |
| Developer training | Mandatory |
| IR playbook | Required within 30 days |

---

**SECURITY APPROVAL COMPLETE**

Final artifacts available at:
`02 - Resources/Research/Claude Security Approval/`

Key documents:
- `manifest.md` - This document index
- `security-approval.md` - PALADIN approval with residual risk
- `architecture-recommendation.md` - Implementation guide

Approval: **APPROVED**
Residual Risk: Critical: 0 | High: 0 | Medium: 8 | Low: 5
Overall Risk: **LOW**
